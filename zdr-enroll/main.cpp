// zdr-enroll — QtQuick photo-booth host for face enrollment.
//
// Usage:
//   zdr-enroll [path-to-zdr-enroll.qml]
//   zdr-enroll --probe
//
// Without arguments the QML is loaded from beside the binary when
// present, else /usr/share/zdr/zdr-enroll.qml (the packaged path).
//
// The enrollment logic lives in EnrollBackend (below), exposed to
// QML as the `backend` context property. It drives the daemon's
// frozen enroll contract on the system bus:
//
//   org.zdr.Authenticator at /org/zdr/Authenticator
//   BeginEnroll(user:s) -> (enroll_id:s)
//   EnrollCaptureWithPreview(enroll_id:s)
//       -> (state:s, captured:i, needed:i, kind:s,
//           rgb_png:ay, ir_png:ay)
//   FinishEnroll(enroll_id:s) -> (stored:i)
//   CancelEnroll(enroll_id:s) -> ()
//   signal AuthFeedback(request_id:s, kind:s, message:s)
//
// Every D-Bus call is asynchronous (QDBusConnection::asyncCall +
// QDBusPendingCallWatcher) with a generous 120 s pending-call
// timeout: BeginEnroll can block while the user types a password
// into their desktop polkit agent, and a capture can take seconds.
// The GUI thread never waits on the daemon.
//
// Lessons carried over from zdr-agent/prompt/main.cpp:
//   * QQmlApplicationEngine::exit/quit are wired to the
//     application, otherwise QML decisions never end the process.
//   * No stdin use at all (and no iostream reads anywhere): a
//     thread blocked in std::cin can deadlock process exit.

#include <QByteArray>
#include <QDBusConnection>
#include <QDBusError>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QFileInfo>
#include <QGuiApplication>
#include <QImage>
#include <QMutex>
#include <QMutexLocker>
#include <QObject>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickImageProvider>
#include <QSocketNotifier>
#include <QQuickWindow>
#include <QString>
#include <QTimer>
#include <QUrl>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <sys/socket.h>

#include <pwd.h>
#include <unistd.h>

#if __has_include(<LayerShellQt/Window.h>)
#include <LayerShellQt/Window.h>
#define ZDR_HAS_LAYER_SHELL 1
#endif

namespace {

const QString kService = QStringLiteral("org.zdr.Authenticator");
const QString kPath = QStringLiteral("/org/zdr/Authenticator");
const QString kInterface = QStringLiteral("org.zdr.Authenticator");
constexpr int kDbusTimeoutMs = 120000; // >= 60 s; polkit + capture are slow

QString usernameForUid()
{
    if (const passwd *pw = ::getpwuid(::getuid()); pw && pw->pw_name && pw->pw_name[0])
        return QString::fromUtf8(pw->pw_name);
    // getpwuid failed (exotic NSS setup); $USER is only a fallback
    // here, never the primary source.
    const QString envUser = qEnvironmentVariable("USER");
    return envUser.isEmpty() ? QStringLiteral("unknown") : envUser;
}

QString friendlyError(const QDBusError &error, const QString &what)
{
    const QString name = error.name();
    const QString message = error.message();
    if (name == QStringLiteral("org.freedesktop.DBus.Error.ServiceUnknown")
        || name == QStringLiteral("org.freedesktop.DBus.Error.NameHasNoOwner")) {
        return QStringLiteral(
            "The zdr daemon (org.zdr.Authenticator) is not running on the "
            "system bus. Start the zdrd service, then try again.");
    }
    if (name == QStringLiteral("org.freedesktop.DBus.Error.AccessDenied")
        || name.contains(QStringLiteral("AccessDenied"))
        || name.contains(QStringLiteral("PolicyKit"))
        || name.contains(QStringLiteral("policykit"), Qt::CaseInsensitive)) {
        return QStringLiteral(
            "Permission was denied. Enrollment needs you to authorize "
            "with your password in the prompt shown by your desktop; "
            "nothing was enrolled.");
    }
    if (error.type() == QDBusError::Timeout
        || name == QStringLiteral("org.freedesktop.DBus.Error.Timeout")
        || name == QStringLiteral("org.freedesktop.DBus.Error.NoReply")) {
        return what + QStringLiteral(
                   " timed out waiting for the daemon. Check that zdrd "
                   "and the camera are working, then try again.");
    }
    if (!message.isEmpty())
        return what + QStringLiteral(" failed: ") + message;
    return what + QStringLiteral(" failed (") + (name.isEmpty() ? QStringLiteral("unknown D-Bus error") : name)
        + QStringLiteral(").");
}

} // namespace

// Latest RGB/IR stills for QML `image://preview/...` URLs. Written
// only from pending-call watcher callbacks on the GUI thread; the
// mutex just keeps requestImage() safe if Qt ever calls off-thread.
class PreviewImageProvider : public QQuickImageProvider
{
public:
    PreviewImageProvider()
        : QQuickImageProvider(QQuickImageProvider::Image)
    {
    }

    QImage requestImage(const QString &id, QSize *size, const QSize &requestedSize) override
    {
        const QString key = id.section(QLatin1Char('/'), 0, 0);
        QImage image;
        {
            QMutexLocker locker(&m_mutex);
            image = (key == QStringLiteral("ir")) ? m_ir : m_rgb;
        }
        if (image.isNull()) {
            image = QImage(480, 360, QImage::Format_RGB32);
            image.fill(qRgb(0x29, 0x2d, 0x32)); // colSurfaceVariant fallback
        }
        if (size)
            *size = image.size();
        if (requestedSize.isValid() && requestedSize != image.size())
            image = image.scaled(requestedSize, Qt::KeepAspectRatio, Qt::SmoothTransformation);
        return image;
    }

    void setImage(const QString &key, const QImage &image)
    {
        QMutexLocker locker(&m_mutex);
        if (key == QStringLiteral("ir"))
            m_ir = image;
        else
            m_rgb = image;
    }

    void clear()
    {
        QMutexLocker locker(&m_mutex);
        m_rgb = QImage();
        m_ir = QImage();
    }

private:
    QMutex m_mutex;
    QImage m_rgb;
    QImage m_ir;
};

class EnrollBackend : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString username READ username CONSTANT)
    Q_PROPERTY(QString phase READ phase NOTIFY stateChanged)
    Q_PROPERTY(int captured READ captured NOTIFY stateChanged)
    Q_PROPERTY(int needed READ needed NOTIFY stateChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY stateChanged)
    Q_PROPERTY(bool cooldown READ cooldown NOTIFY stateChanged)
    Q_PROPERTY(QString guidance READ guidance NOTIFY stateChanged)
    Q_PROPERTY(QString guidanceKind READ guidanceKind NOTIFY stateChanged)
    Q_PROPERTY(QString rgbSource READ rgbSource NOTIFY stateChanged)
    Q_PROPERTY(QString irSource READ irSource NOTIFY stateChanged)
    Q_PROPERTY(bool hasCapture READ hasCapture NOTIFY stateChanged)
    Q_PROPERTY(int stored READ stored NOTIFY stateChanged)
    Q_PROPERTY(QString errorMessage READ errorMessage NOTIFY stateChanged)

public:
    explicit EnrollBackend(PreviewImageProvider *previews, QObject *parent = nullptr)
        : QObject(parent)
        , m_previews(previews)
        , m_username(usernameForUid())
    {
        QDBusConnection bus = QDBusConnection::systemBus();
        if (bus.isConnected()) {
            // During enrollment the daemon emits AuthFeedback with
            // request_id == enroll_id; other requests are ignored.
            bus.connect(kService, kPath, kInterface,
                        QStringLiteral("AuthFeedback"),
                        this, SLOT(onAuthFeedback(QString,QString,QString)));
        }
    }

    QString username() const { return m_username; }
    QString phase() const { return m_phase; }
    int captured() const { return m_captured; }
    int needed() const { return m_needed; }
    bool busy() const { return m_busy; }
    bool cooldown() const { return m_cooldown; }
    QString guidance() const { return m_guidance; }
    QString guidanceKind() const { return m_guidanceKind; }
    QString rgbSource() const { return m_rgbSource; }
    QString irSource() const { return m_irSource; }
    bool hasCapture() const { return m_hasCapture; }
    int stored() const { return m_stored; }
    QString errorMessage() const { return m_errorMessage; }

    // zdrctl wording (zdrd/src/bin/zdrctl.rs `guidance`).
    static QString guidanceForKind(const QString &kind)
    {
        if (kind == QStringLiteral("capturing"))
            return QStringLiteral("Capturing…");
        if (kind == QStringLiteral("no-face"))
            return QStringLiteral("No face detected — look at the camera and hold still.");
        if (kind == QStringLiteral("multiple-faces"))
            return QStringLiteral("Multiple faces detected — make sure only you are in frame.");
        if (kind == QStringLiteral("too-dark"))
            return QStringLiteral("Too dark — face a light source and try again.");
        if (kind == QStringLiteral("too-bright"))
            return QStringLiteral("Too bright — move away from direct light and try again.");
        if (kind == QStringLiteral("duplicate-pose"))
            return QStringLiteral("Too similar — turn your head slightly and try again.");
        if (kind == QStringLiteral("matched"))
            return QStringLiteral("Face matched.");
        if (kind == QStringLiteral("not-matched"))
            return QStringLiteral("Face not matched — try again.");
        if (kind == QStringLiteral("stored"))
            return QStringLiteral("Capture stored.");
        if (kind == QStringLiteral("error"))
            return QStringLiteral("Capture failed — check the camera and try again.");
        return QStringLiteral("Try again.");
    }

    Q_INVOKABLE void beginEnroll()
    {
        if (m_busy || !m_enrollId.isEmpty())
            return;
        QDBusConnection bus = QDBusConnection::systemBus();
        if (!bus.isConnected()) {
            fail(QStringLiteral(
                "Cannot connect to the system bus. Enrollment needs a "
                "running desktop session with D-Bus, then try again."));
            return;
        }
        m_phase = QStringLiteral("starting");
        m_busy = true;
        m_errorMessage.clear();
        setGuidance(QStringLiteral("Waiting for authorization… your desktop may show a password prompt."),
                    QStringLiteral("capturing"));
        emit stateChanged();

        QDBusMessage msg = QDBusMessage::createMethodCall(
            kService, kPath, kInterface, QStringLiteral("BeginEnroll"));
        msg << m_username;
        auto *watcher = new QDBusPendingCallWatcher(bus.asyncCall(msg, kDbusTimeoutMs), this);
        connect(watcher, &QDBusPendingCallWatcher::finished, this,
                [this, watcher]() {
                    watcher->deleteLater();
                    QDBusPendingReply<QString> reply = *watcher;
                    m_busy = false;
                    if (reply.isError()) {
                        fail(friendlyError(reply.error(), QStringLiteral("Starting enrollment")));
                        return;
                    }
                    m_enrollId = reply.value();
                    if (m_enrollId.isEmpty()) {
                        fail(QStringLiteral("The daemon started enrollment but returned no session id. Nothing was enrolled."));
                        return;
                    }
                    m_phase = QStringLiteral("active");
                    m_captured = 0;
                    m_needed = 5;
                    setGuidance(QStringLiteral("Look at the camera and press Capture."),
                                QStringLiteral("capturing"));
                    emit stateChanged();
                });
    }

    Q_INVOKABLE void capture()
    {
        if (m_busy || m_cooldown || m_enrollId.isEmpty() || m_phase != QStringLiteral("active"))
            return;
        QDBusConnection bus = QDBusConnection::systemBus();
        if (!bus.isConnected()) {
            fail(QStringLiteral("Lost the connection to the system bus. Nothing was enrolled."));
            return;
        }
        m_busy = true;
        setGuidance(guidanceForKind(QStringLiteral("capturing")), QStringLiteral("capturing"));
        emit stateChanged();

        const QString enrollId = m_enrollId;
        QDBusMessage msg = QDBusMessage::createMethodCall(
            kService, kPath, kInterface, QStringLiteral("EnrollCaptureWithPreview"));
        msg << enrollId;
        auto *watcher = new QDBusPendingCallWatcher(bus.asyncCall(msg, kDbusTimeoutMs), this);
        connect(watcher, &QDBusPendingCallWatcher::finished, this,
                [this, watcher, enrollId]() {
                    watcher->deleteLater();
                    // Session was cancelled/reset while in flight.
                    if (enrollId != m_enrollId)
                        return;
                    QDBusPendingReply<QString, int, int, QString, QByteArray, QByteArray> reply = *watcher;
                    m_busy = false;
                    if (reply.isError()) {
                        fail(friendlyError(reply.error(), QStringLiteral("Capture")));
                        return;
                    }
                    const QString state = reply.argumentAt<0>();
                    m_captured = reply.argumentAt<1>();
                    const int needed = reply.argumentAt<2>();
                    if (needed > 0)
                        m_needed = needed;
                    const QString kind = reply.argumentAt<3>();
                    updatePreview(QStringLiteral("rgb"), reply.argumentAt<4>());
                    updatePreview(QStringLiteral("ir"), reply.argumentAt<5>());

                    if (kind == QStringLiteral("error")) {
                        fail(QStringLiteral(
                            "The camera or face engine failed during capture. "
                            "Check the camera is not in use by another app, then try again."));
                        return;
                    }
                    setGuidance(guidanceForKind(kind), kind);
                    startCooldown();
                    emit stateChanged();

                    if (state == QStringLiteral("ready"))
                        finishEnroll();
                });
    }

    Q_INVOKABLE void finishEnroll()
    {
        if (m_busy || m_enrollId.isEmpty())
            return;
        QDBusConnection bus = QDBusConnection::systemBus();
        if (!bus.isConnected()) {
            fail(QStringLiteral("Lost the connection to the system bus before enrollment could be saved."));
            return;
        }
        m_phase = QStringLiteral("finishing");
        m_busy = true;
        setGuidance(QStringLiteral("Saving your enrollment…"), QStringLiteral("stored"));
        emit stateChanged();

        const QString enrollId = m_enrollId;
        QDBusMessage msg = QDBusMessage::createMethodCall(
            kService, kPath, kInterface, QStringLiteral("FinishEnroll"));
        msg << enrollId;
        auto *watcher = new QDBusPendingCallWatcher(bus.asyncCall(msg, kDbusTimeoutMs), this);
        connect(watcher, &QDBusPendingCallWatcher::finished, this,
                [this, watcher, enrollId]() {
                    watcher->deleteLater();
                    if (enrollId != m_enrollId)
                        return;
                    QDBusPendingReply<int> reply = *watcher;
                    m_busy = false;
                    // The session is over either way.
                    m_enrollId.clear();
                    if (reply.isError()) {
                        fail(friendlyError(reply.error(), QStringLiteral("Saving enrollment")));
                        return;
                    }
                    m_stored = reply.value();
                    m_phase = QStringLiteral("success");
                    setGuidance(QStringLiteral("Enrollment complete."), QStringLiteral("stored"));
                    emit stateChanged();
                });
    }

    // User Cancel button, and best-effort cancel on window close /
    // application quit. Fire-and-forget async call; the local
    // session id is dropped immediately so it is idempotent.
    Q_INVOKABLE void cancelSession()
    {
        const QString enrollId = m_enrollId;
        m_enrollId.clear();
        if (!enrollId.isEmpty()) {
            QDBusConnection bus = QDBusConnection::systemBus();
            if (bus.isConnected()) {
                QDBusMessage msg = QDBusMessage::createMethodCall(
                    kService, kPath, kInterface, QStringLiteral("CancelEnroll"));
                msg << enrollId;
                auto *watcher = new QDBusPendingCallWatcher(bus.asyncCall(msg, kDbusTimeoutMs), this);
                connect(watcher, &QDBusPendingCallWatcher::finished, watcher,
                        &QDBusPendingCallWatcher::deleteLater);
            }
        }
        if (m_phase != QStringLiteral("success")) {
            m_phase = QStringLiteral("idle");
            m_busy = false;
            m_captured = 0;
            m_needed = 5;
            m_stored = 0;
            setGuidance(QStringLiteral("Press Begin to start enrollment."), QString());
        }
        emit stateChanged();
    }

    // 'Try again' on the error panel: drop any live session
    // (best-effort) and return to the start state.
    Q_INVOKABLE void tryAgain()
    {
        cancelSession();
        if (m_previews)
            m_previews->clear();
        m_hasCapture = false;
        ++m_previewVersion;
        m_rgbSource.clear();
        m_irSource.clear();
        m_errorMessage.clear();
        m_phase = QStringLiteral("idle");
        setGuidance(QStringLiteral("Press Begin to start enrollment."), QString());
        emit stateChanged();
    }

public slots:
    void onAuthFeedback(const QString &requestId, const QString &kind, const QString &message)
    {
        if (m_enrollId.isEmpty() || requestId != m_enrollId)
            return;
        // Prefer the zdrctl wording for known kinds; fall back to
        // the daemon's own message for anything new.
        const QString known = guidanceForKind(kind);
        const bool isKnownKind = kind == QStringLiteral("capturing")
            || kind == QStringLiteral("no-face")
            || kind == QStringLiteral("multiple-faces")
            || kind == QStringLiteral("too-dark")
            || kind == QStringLiteral("too-bright")
            || kind == QStringLiteral("duplicate-pose")
            || kind == QStringLiteral("matched")
            || kind == QStringLiteral("not-matched")
            || kind == QStringLiteral("stored")
            || kind == QStringLiteral("error");
        setGuidance(isKnownKind ? known : (message.isEmpty() ? known : message), kind);
        emit stateChanged();
    }

private:
    void setGuidance(const QString &text, const QString &kind)
    {
        m_guidance = text;
        m_guidanceKind = kind;
    }

    void fail(const QString &message)
    {
        // Keep m_enrollId: tryAgain()/cancelSession() cancel it
        // best-effort. Just stop accepting captures.
        m_phase = QStringLiteral("error");
        m_busy = false;
        m_errorMessage = message;
        setGuidance(QStringLiteral("Something went wrong."), QStringLiteral("error"));
        emit stateChanged();
    }

    void updatePreview(const QString &key, const QByteArray &png)
    {
        if (png.isEmpty() || !m_previews)
            return;
        const QImage image = QImage::fromData(png, "PNG");
        if (image.isNull())
            return;
        m_previews->setImage(key, image);
        ++m_previewVersion;
        m_hasCapture = true;
        const QString url = QStringLiteral("image://preview/%1/%2").arg(key).arg(m_previewVersion);
        if (key == QStringLiteral("ir"))
            m_irSource = url;
        else
            m_rgbSource = url;
    }

    void startCooldown()
    {
        m_cooldown = true;
        QTimer::singleShot(1000, this, [this]() {
            m_cooldown = false;
            emit stateChanged();
        });
    }

    PreviewImageProvider *m_previews;
    QString m_username;
    QString m_enrollId;
    QString m_phase = QStringLiteral("idle");
    QString m_guidance = QStringLiteral("Press Begin to start enrollment.");
    QString m_guidanceKind;
    QString m_errorMessage;
    QString m_rgbSource;
    QString m_irSource;
    int m_captured = 0;
    int m_needed = 5;
    int m_stored = 0;
    int m_previewVersion = 0;
    bool m_busy = false;
    bool m_cooldown = false;
    bool m_hasCapture = false;

signals:
    void stateChanged();
};

int main(int argc, char *argv[])
{
    // The QML reads the Noctalia theme files via XMLHttpRequest on
    // file:// URLs, which Qt only allows with this opt-in (same as
    // the zdr-prompt host).
    if (qEnvironmentVariableIsEmpty("QML_XHR_ALLOW_FILE_READ"))
        qputenv("QML_XHR_ALLOW_FILE_READ", "1");

    for (int i = 1; i < argc; ++i) {
        if (qstrcmp(argv[i], "--probe") == 0) {
            if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM"))
                qputenv("QT_QPA_PLATFORM", "offscreen");
            QGuiApplication app(argc, argv);
            return 0;
        }
    }

    QGuiApplication app(argc, argv);
    QGuiApplication::setApplicationName(QStringLiteral("zdr-enroll"));

    // Exit cleanly (code from app.exec(), aboutToQuit still runs)
    // on SIGTERM/SIGINT instead of dying by signal: a one-byte
    // self-pipe wakes the event loop via QSocketNotifier.
    static int signalPipe[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, signalPipe) == 0) {
        auto *notifier = new QSocketNotifier(signalPipe[1], QSocketNotifier::Read, &app);
        QObject::connect(notifier, &QSocketNotifier::activated, &app, [notifier]() {
            // Single read only: the pipe is blocking, so draining
            // in a loop would freeze the event loop here forever.
            char byte;
            const ssize_t ignored = ::read(signalPipe[1], &byte, 1);
            (void)ignored;
            notifier->setEnabled(false);
            QCoreApplication::quit();
        });
        struct sigaction action {};
        action.sa_handler = [](int) {
            const char byte = 1;
            const ssize_t ignored = ::write(signalPipe[0], &byte, 1);
            (void)ignored;
        };
        sigemptyset(&action.sa_mask);
        sigaction(SIGTERM, &action, nullptr);
        sigaction(SIGINT, &action, nullptr);
    }

    QString qmlPath;
    for (int i = 1; i < argc; ++i) {
        const QString arg = QString::fromUtf8(argv[i]);
        if (arg.endsWith(QStringLiteral(".qml"))) {
            qmlPath = arg;
            break;
        }
    }
    if (qmlPath.isEmpty()) {
        const QString beside = QCoreApplication::applicationDirPath()
            + QStringLiteral("/zdr-enroll.qml");
        qmlPath = QFileInfo::exists(beside)
            ? beside
            : QStringLiteral("/usr/share/zdr/zdr-enroll.qml");
    }

    // Qt.exit()/Qt.quit() from QML only emit engine signals; wire
    // them to the application or the process never ends (the hard
    // lesson from zdr-prompt). Only an explicit QML decision (or
    // window close, which QML turns into Qt.quit()) ends us.
    QGuiApplication::setQuitOnLastWindowClosed(false);
    QQmlApplicationEngine engine;

    auto *previews = new PreviewImageProvider();
    EnrollBackend backend(previews);
    engine.rootContext()->setContextProperty(QStringLiteral("backend"), &backend);
    engine.addImageProvider(QStringLiteral("preview"), previews);

    QObject::connect(&engine, &QQmlApplicationEngine::exit, &app,
                     [](int code) { QCoreApplication::exit(code); });
    QObject::connect(&engine, &QQmlApplicationEngine::quit, &app,
                     &QCoreApplication::quit);
    // Closing the window already cancels via QML onClosing; this
    // is the belt-and-braces path for quit-by-other-means. It is
    // idempotent (the session id is cleared on first cancel).
    QObject::connect(&app, &QCoreApplication::aboutToQuit, &backend,
                     [&backend]() { backend.cancelSession(); });

    engine.load(QUrl::fromLocalFile(qmlPath));
    if (engine.rootObjects().isEmpty())
        return 1;

    // NOTE: unlike zdr-prompt this is a normal session window, so
    // even when LayerShellQt was found at build time (ZDR_HAS_LAYER_SHELL)
    // the window is deliberately NOT attached to a layer surface.

    const int rc = app.exec();
    std::_Exit(rc);
}

#include "main.moc"
