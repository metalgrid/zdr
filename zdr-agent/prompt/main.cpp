// zdr-prompt — minimal QtQuick host for zdr-prompt.qml.
//
// Usage:
//   zdr-prompt <path-to-zdr-prompt.qml> [service user tty label]
//   zdr-prompt --probe
//
// Without arguments the QML is loaded from
// /usr/share/zdr/zdr-prompt.qml. The remaining arguments stay in
// QCoreApplication::arguments(), which is exactly what the QML
// reads as Qt.application.arguments (it picks the fields after
// the .qml argument), so no extra forwarding plumbing is needed.
//
// Exit code: whatever the QML exits with via Qt.exit(code) —
// 0 = approve, 1 = deny. A QML load failure also returns 1, and
// zdr-agent maps every non-zero code to deny (fail closed).
//
// --probe: initialise QGuiApplication (forcing the offscreen
// platform when none was selected, so the probe is safe on a
// headless session), print nothing, exit 0. If a Qt library the
// binary needs is missing, the dynamic loader fails before main()
// runs and the probe exits non-zero — which is the point.
//
// Layer shell: when LayerShellQt headers are available at build
// time (__has_include), the window is attached to the Overlay
// layer with OnDemand keyboard interactivity and no anchors, so
// the compositor centres it. Without the library this is exactly
// the same program showing a plain window.

#include <QGuiApplication>
#include <QPointer>
#include <QQmlApplicationEngine>
#include <QQuickWindow>
#include <QUrl>

#include <iostream>
#include <string>
#include <thread>

#if __has_include(<LayerShellQt/Window.h>)
#include <LayerShellQt/Window.h>
#define ZDR_HAS_LAYER_SHELL 1
#endif

int main(int argc, char *argv[])
{
    // The QML reads the Noctalia theme files (and its own test
    // countdown override) via XMLHttpRequest on file:// URLs,
    // which Qt only allows with this opt-in.
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
    QGuiApplication::setApplicationName(QStringLiteral("zdr-prompt"));

    const QString qmlPath = (argc > 1)
        ? QString::fromUtf8(argv[1])
        : QStringLiteral("/usr/share/zdr/zdr-prompt.qml");

    QQmlApplicationEngine engine;
    engine.load(QUrl::fromLocalFile(qmlPath));
    if (engine.rootObjects().isEmpty())
        return 1;

    // Live feedback: a detached reader thread forwards stdin lines
    //   status: <message>       -> QML `statusText`
    //   status-kind: <kind>     -> QML `statusKind` (status tint)
    // to the root object on the GUI thread. All other lines are
    // ignored, and EOF (agent gone / stdin closed) just ends the
    // thread — the countdown and exit-code contract are untouched.
    // Under qml6 there is no host, so the QML defaults stand.
    {
        QPointer<QObject> rootObject(engine.rootObjects().constFirst());
        std::thread([rootObject]() {
            std::string raw;
            while (std::getline(std::cin, raw)) {
                const QString line = QString::fromUtf8(raw.c_str()).trimmed();
                QString property;
                QString value;
                if (line.startsWith(QStringLiteral("status-kind: "))) {
                    property = QStringLiteral("statusKind");
                    value = line.mid(13);
                } else if (line.startsWith(QStringLiteral("status: "))) {
                    property = QStringLiteral("statusText");
                    value = line.mid(8);
                } else {
                    continue;
                }
                if (!rootObject)
                    return;
                QMetaObject::invokeMethod(
                    rootObject,
                    [rootObject, property, value]() {
                        // std::cerr, not qDebug: Qt may have debug
                        // output routed away in the session.
                        if (rootObject && rootObject->setProperty(
                                               property.toUtf8().constData(), value))
                            std::cerr << "zdr-prompt: status update applied\n";
                    },
                    Qt::QueuedConnection);
            }
        }).detach();
    }

#ifdef ZDR_HAS_LAYER_SHELL
    if (auto *window = qobject_cast<QQuickWindow *>(engine.rootObjects().constFirst())) {
        // LayerShellQt::Window::get() must run before the surface
        // is mapped; the QML window is already visible, so close
        // it, attach, then show it again as a layer surface.
        window->close();
        if (auto *shell = LayerShellQt::Window::get(window)) {
            shell->setScope(QStringLiteral("zdr-prompt"));
            shell->setLayer(LayerShellQt::Window::LayerOverlay);
            shell->setKeyboardInteractivity(
                LayerShellQt::Window::KeyboardInteractivityOnDemand);
            shell->setAnchors(LayerShellQt::Window::AnchorNone);
            shell->setDesiredSize(window->size());
        }
        window->show();
    }
#endif

    return app.exec();
}
