// zdr-enroll.qml — face enrollment photo booth for zdr.
//
// Driven entirely by the `backend` context property (EnrollBackend
// in main.cpp), which talks to org.zdr.Authenticator on the system
// bus asynchronously. This file only renders state and forwards
// button clicks; it never blocks.
//
// Theming mirrors zdr-prompt.qml: at startup the Noctalia palette
// is loaded from $XDG_CONFIG_HOME/noctalia/colors.json (fallback
// ~/.config/noctalia/colors.json) and UI settings from
// settings.json in the same directory, discovered via
// /proc/self/environ; file access needs QML_XHR_ALLOW_FILE_READ=1,
// which the zdr-enroll host sets. Every colour/font/radius has a
// built-in dark fallback, and any read/parse failure simply keeps
// those fallbacks — the window always renders.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window

// `backend` is a C++ context property (EnrollBackend in main.cpp),
// so qmllint cannot know its type; the same applies to `root`
// lookups from the inline progress-dot delegate.
// qmllint disable unqualified
Window {
    id: root

    width: 560
    height: 640
    minimumWidth: 480
    minimumHeight: 560
    visible: true
    title: "zdr-enroll"
    color: root.colSurface

    // -- Theme (built-in dark fallbacks, Noctalia values override) --
    property color colSurface: "#202224"
    property color colOnSurface: "#fcfcfc"
    property color colOnSurfaceVariant: "#a1a9b1"
    property color colSurfaceVariant: "#292d32"
    property color colPrimary: "#3daee9"
    property color colOnPrimary: "#141618"
    property color colError: "#da4453"
    property color colOnError: "#fcfcfc"
    property color colOutline: "#707d8a"
    property color colHover: "#3daee9"
    property real cornerRadius: 12
    property string fontFamily: "Sans Serif"

    property bool closeHandled: false
    property bool confirmReenroll: false

    function templateModeLabel() {
        if (backend.templateMode === "ir")
            return "IR";
        if (backend.templateMode === "rgb")
            return "RGB-only \u2014 insecure";
        return "unknown mode";
    }

    function guidanceColor(kind) {
        if (kind === "matched" || kind === "stored")
            return root.colPrimary;
        if (kind === "not-matched" || kind === "error" || kind === "no-face")
            return root.colError;
        return root.colOnSurfaceVariant;
    }

    function loadTextFile(url, callback) {
        try {
            var xhr = new XMLHttpRequest();
            xhr.open("GET", url);
            xhr.onreadystatechange = function () {
                if (xhr.readyState === 4)
                    callback(xhr.responseText || "");
            };
            xhr.send();
        } catch (e) {
            callback("");
        }
    }

    function tryLoadJson(bases, index, relPath, apply) {
        if (index >= bases.length)
            return;
        root.loadTextFile("file://" + bases[index] + "/" + relPath, function (text) {
            var ok = false;
            if (text.length > 0) {
                try {
                    var obj = JSON.parse(text);
                    if (obj && typeof obj === "object") {
                        apply(obj);
                        ok = true;
                    }
                } catch (e) {
                    ok = false;
                }
            }
            if (!ok)
                root.tryLoadJson(bases, index + 1, relPath, apply);
        });
    }

    function applyColors(obj) {
        var mapping = {
            "mSurface": "colSurface",
            "mOnSurface": "colOnSurface",
            "mOnSurfaceVariant": "colOnSurfaceVariant",
            "mSurfaceVariant": "colSurfaceVariant",
            "mPrimary": "colPrimary",
            "mOnPrimary": "colOnPrimary",
            "mError": "colError",
            "mOnError": "colOnError",
            "mOutline": "colOutline",
            "mHover": "colHover"
        };
        for (var key in mapping) {
            var value = obj[key];
            if (typeof value === "string" && value.length > 0) {
                try {
                    root[mapping[key]] = value;
                } catch (e) {
                    // Keep the fallback for an unparsable colour.
                }
            }
        }
    }

    function applySettings(obj) {
        try {
            if (obj.general && obj.general.radiusRatio !== undefined
                    && obj.general.radiusRatio !== null) {
                var ratio = Number(obj.general.radiusRatio);
                if (isFinite(ratio) && ratio >= 0)
                    root.cornerRadius = Math.min(48, 12 * ratio);
            }
        } catch (e) {
            // Keep the fallback radius.
        }
        try {
            if (obj.ui && typeof obj.ui.fontDefault === "string"
                    && obj.ui.fontDefault.length > 0)
                root.fontFamily = obj.ui.fontDefault;
        } catch (e) {
            // Keep the fallback font.
        }
    }

    function loadTheme() {
        root.loadTextFile("file:///proc/self/environ", function (text) {
            var xdg = "";
            var home = "";
            try {
                var parts = String(text).split("\0");
                for (var i = 0; i < parts.length; ++i) {
                    var eq = parts[i].indexOf("=");
                    if (eq <= 0)
                        continue;
                    var key = parts[i].substring(0, eq);
                    var value = parts[i].substring(eq + 1);
                    if (key === "XDG_CONFIG_HOME")
                        xdg = value;
                    else if (key === "HOME")
                        home = value;
                }
            } catch (e) {
                // Fall through with whatever bases we have (none).
            }
            var bases = [];
            function pushBase(b) {
                if (b && bases.indexOf(b) < 0)
                    bases.push(b);
            }
            if (xdg.length > 0)
                pushBase(xdg);
            if (home.length > 0)
                pushBase(home + "/.config");
            if (bases.length === 0)
                return;
            root.tryLoadJson(bases, 0, "noctalia/colors.json", root.applyColors);
            root.tryLoadJson(bases, 0, "noctalia/settings.json", root.applySettings);
        });
    }

    // Closing cancels any live session (best-effort in the backend).
    // Give the async CancelEnroll call a brief moment to go out
    // before quitting, then close for real on the second pass.
    onClosing: function (close) {
        if (root.closeHandled)
            return;
        root.closeHandled = true;
        close.accepted = false;
        backend.cancelSession();
        closeTimer.start();
    }

    Timer {
        id: closeTimer
        interval: 300
        onTriggered: {
            root.close();
            Qt.quit();
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 12

        Text {
            Layout.fillWidth: true
            text: "Enroll your face"
            color: root.colOnSurface
            font.family: root.fontFamily
            font.pixelSize: 22
            font.bold: true
            elide: Text.ElideRight
        }

        Text {
            Layout.fillWidth: true
            text: "Enrolling for user: " + backend.username
            color: root.colOnSurfaceVariant
            font.family: root.fontFamily
            font.pixelSize: 14
            elide: Text.ElideRight
        }

        // Five progress dots (captured / needed).
        RowLayout {
            Layout.fillWidth: true
            visible: backend.phase === "starting" || backend.phase === "active"
                || backend.phase === "finishing"
            spacing: 8

            Repeater {
                model: backend.needed
                delegate: Rectangle {
                    required property int index
                    width: 16
                    height: 16
                    radius: 8
                    color: index < backend.captured ? root.colPrimary : root.colSurfaceVariant
                    border.color: index < backend.captured ? root.colPrimary : root.colOutline
                    border.width: 1
                }
            }

            Text {
                text: backend.captured + " / " + backend.needed + " captures"
                color: root.colOnSurfaceVariant
                font.family: root.fontFamily
                font.pixelSize: 13
            }

            Item {
                Layout.fillWidth: true
            }

            BusyIndicator {
                running: backend.busy
                visible: backend.busy
                Layout.preferredWidth: 24
                Layout.preferredHeight: 24
            }
        }

        // RGB + IR previews from the latest capture stills.
        RowLayout {
            Layout.fillWidth: true
            visible: backend.phase === "starting" || backend.phase === "active"
                || backend.phase === "finishing" || backend.phase === "testing"
                || backend.phase === "test-result"
            spacing: 12

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 230
                radius: root.cornerRadius
                color: root.colSurfaceVariant
                border.color: root.colOutline
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 8
                    spacing: 6

                    Text {
                        text: "RGB camera"
                        color: root.colOnSurfaceVariant
                        font.family: root.fontFamily
                        font.pixelSize: 12
                    }
                    Item {
                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        Image {
                            anchors.fill: parent
                            visible: backend.hasCapture
                            source: backend.rgbSource
                            cache: false
                            fillMode: Image.PreserveAspectFit
                        }
                        Text {
                            anchors.centerIn: parent
                            visible: !backend.hasCapture
                            text: "No capture yet"
                            color: root.colOnSurfaceVariant
                            font.family: root.fontFamily
                            font.pixelSize: 13
                        }
                    }
                }
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 230
                radius: root.cornerRadius
                color: root.colSurfaceVariant
                border.color: root.colOutline
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 8
                    spacing: 6

                    Text {
                        text: "IR camera"
                        color: root.colOnSurfaceVariant
                        font.family: root.fontFamily
                        font.pixelSize: 12
                    }
                    Item {
                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        Image {
                            anchors.fill: parent
                            visible: backend.hasCapture
                            source: backend.irSource
                            cache: false
                            fillMode: Image.PreserveAspectFit
                        }
                        Text {
                            anchors.centerIn: parent
                            visible: !backend.hasCapture
                            text: "No capture yet"
                            color: root.colOnSurfaceVariant
                            font.family: root.fontFamily
                            font.pixelSize: 13
                        }
                    }
                }
            }
        }

        // One guidance line, driven by the capture kind and by
        // AuthFeedback messages forwarded through the backend.
        Text {
            Layout.fillWidth: true
            visible: backend.phase === "starting" || backend.phase === "active"
                || backend.phase === "finishing" || backend.phase === "testing"
            text: backend.guidance
            color: root.guidanceColor(backend.guidanceKind)
            font.family: root.fontFamily
            font.pixelSize: 14
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
        }

        // Status screen: what the daemon says about this caller.
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: backend.phase === "loading" ? 64 : 168
            visible: backend.phase === "loading" || backend.phase === "idle"
            radius: root.cornerRadius
            color: root.colSurfaceVariant
            border.color: root.colOutline
            border.width: 1

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 14
                spacing: 6

                Text {
                    Layout.fillWidth: true
                    visible: backend.phase === "loading"
                    text: "Checking your enrollment status\u2026"
                    color: root.colOnSurfaceVariant
                    font.family: root.fontFamily
                    font.pixelSize: 14
                    wrapMode: Text.WordWrap
                }
                Text {
                    Layout.fillWidth: true
                    visible: backend.phase === "idle" && backend.templateCount > 0
                    text: "You are enrolled \u2014 " + backend.templateCount
                        + (backend.templateCount === 1 ? " template (" : " templates (")
                        + root.templateModeLabel() + ")"
                    color: root.colOnSurface
                    font.family: root.fontFamily
                    font.pixelSize: 15
                    font.bold: true
                    wrapMode: Text.WordWrap
                }
                Text {
                    Layout.fillWidth: true
                    visible: backend.phase === "idle" && backend.templateCount > 0
                    text: "Sealed password: " + (backend.hasSealed ? "yes" : "no")
                    color: root.colOnSurfaceVariant
                    font.family: root.fontFamily
                    font.pixelSize: 13
                    wrapMode: Text.WordWrap
                }
                Text {
                    Layout.fillWidth: true
                    visible: backend.phase === "idle" && backend.templateCount === 0
                    text: "Not enrolled yet"
                    color: root.colOnSurface
                    font.family: root.fontFamily
                    font.pixelSize: 15
                    font.bold: true
                    wrapMode: Text.WordWrap
                }
                Text {
                    Layout.fillWidth: true
                    visible: backend.phase === "idle" && backend.templateCount === 0
                    text: "Begin enrollment to take five good captures, turning "
                        + "your head slightly between them. Your desktop may show "
                        + "a password prompt to authorize enrollment \u2014 that "
                        + "password goes to your desktop's authentication agent, "
                        + "not to this app. Testing becomes available once you "
                        + "are enrolled."
                    color: root.colOnSurfaceVariant
                    font.family: root.fontFamily
                    font.pixelSize: 13
                    wrapMode: Text.WordWrap
                }
            }
        }

        // In-window confirmation before a re-enrollment replaces
        // the caller's current templates.
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 132
            visible: root.confirmReenroll && backend.phase === "idle"
                && backend.templateCount > 0
            radius: root.cornerRadius
            color: root.colSurfaceVariant
            border.color: root.colError
            border.width: 1

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 14
                spacing: 8

                Text {
                    Layout.fillWidth: true
                    text: "This replaces your current templates"
                    color: root.colOnSurface
                    font.family: root.fontFamily
                    font.pixelSize: 14
                    font.bold: true
                    wrapMode: Text.WordWrap
                }
                RowLayout {
                    spacing: 10

                    Button {
                        id: confirmReenrollButton
                        text: "Continue"
                        font.family: root.fontFamily
                        font.pixelSize: 14
                        onClicked: {
                            root.confirmReenroll = false;
                            backend.beginEnroll();
                        }
                        contentItem: Text {
                            text: confirmReenrollButton.text
                            color: root.colOnPrimary
                            font: confirmReenrollButton.font
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                        background: Rectangle {
                            implicitWidth: 110
                            implicitHeight: 36
                            radius: root.cornerRadius
                            color: confirmReenrollButton.hovered ? root.colHover : root.colPrimary
                            border.color: root.colPrimary
                            border.width: 1
                        }
                    }
                    Button {
                        id: cancelReenrollButton
                        text: "Cancel"
                        font.family: root.fontFamily
                        font.pixelSize: 14
                        onClicked: root.confirmReenroll = false
                        contentItem: Text {
                            text: cancelReenrollButton.text
                            color: root.colOnSurface
                            font: cancelReenrollButton.font
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                        background: Rectangle {
                            implicitWidth: 110
                            implicitHeight: 36
                            radius: root.cornerRadius
                            color: cancelReenrollButton.hovered ? root.colHover : root.colSurfaceVariant
                            border.color: root.colOutline
                            border.width: 1
                        }
                    }
                }
            }
        }

        // Self-test result banner.
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 64
            visible: backend.phase === "test-result"
            radius: root.cornerRadius
            color: root.colSurfaceVariant
            border.color: backend.testMatched ? root.colPrimary : root.colError
            border.width: 1

            Text {
                anchors.fill: parent
                anchors.margins: 14
                text: backend.testResultText
                color: backend.testMatched ? root.colPrimary : root.colError
                font.family: root.fontFamily
                font.pixelSize: 15
                font.bold: true
                wrapMode: Text.WordWrap
                verticalAlignment: Text.AlignVCenter
            }
        }

        // Success panel.
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 168
            visible: backend.phase === "success"
            radius: root.cornerRadius
            color: root.colSurfaceVariant
            border.color: root.colPrimary
            border.width: 1

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 14
                spacing: 6

                Text {
                    Layout.fillWidth: true
                    text: "Enrollment complete — " + backend.stored + " template(s) stored."
                    color: root.colOnSurface
                    font.family: root.fontFamily
                    font.pixelSize: 15
                    font.bold: true
                    wrapMode: Text.WordWrap
                }
                Text {
                    Layout.fillWidth: true
                    text: "You can also just try sudo in a terminal."
                    color: root.colOnSurfaceVariant
                    font.family: root.fontFamily
                    font.pixelSize: 13
                    wrapMode: Text.WordWrap
                }
                Button {
                    id: successTestButton
                    enabled: !backend.busy
                    opacity: enabled ? 1 : 0.45
                    text: "Test my face"
                    font.family: root.fontFamily
                    font.pixelSize: 14
                    font.bold: true
                    onClicked: backend.verifySelf()
                    contentItem: Text {
                        text: successTestButton.text
                        color: root.colOnPrimary
                        font: successTestButton.font
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                    background: Rectangle {
                        implicitWidth: 140
                        implicitHeight: 36
                        radius: root.cornerRadius
                        color: successTestButton.hovered ? root.colHover : root.colPrimary
                        border.color: root.colPrimary
                        border.width: 1
                    }
                }
            }
        }

        // Error panel.
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 176
            visible: backend.phase === "error"
            radius: root.cornerRadius
            color: root.colSurfaceVariant
            border.color: root.colError
            border.width: 1

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 14
                spacing: 8

                Text {
                    Layout.fillWidth: true
                    text: "Something did not work"
                    color: root.colError
                    font.family: root.fontFamily
                    font.pixelSize: 15
                    font.bold: true
                    wrapMode: Text.WordWrap
                }
                Text {
                    Layout.fillWidth: true
                    text: backend.errorMessage
                    color: root.colOnSurface
                    font.family: root.fontFamily
                    font.pixelSize: 13
                    wrapMode: Text.WordWrap
                }
                Button {
                    id: tryAgainButton
                    text: "Try again"
                    font.family: root.fontFamily
                    font.pixelSize: 14
                    onClicked: backend.tryAgain()
                    contentItem: Text {
                        text: tryAgainButton.text
                        color: root.colOnPrimary
                        font: tryAgainButton.font
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                    background: Rectangle {
                        implicitWidth: 110
                        implicitHeight: 36
                        radius: root.cornerRadius
                        color: tryAgainButton.hovered ? root.colHover : root.colPrimary
                        border.color: root.colPrimary
                        border.width: 1
                    }
                }
            }
        }

        Item {
            Layout.fillHeight: true
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 10

            Button {
                id: cancelButton
                visible: backend.phase === "starting" || backend.phase === "active"
                    || backend.phase === "finishing"
                enabled: backend.phase === "starting" || backend.phase === "active"
                    || backend.phase === "finishing"
                opacity: enabled ? 1 : 0.45
                text: "Cancel"
                font.family: root.fontFamily
                font.pixelSize: 14
                onClicked: backend.cancelSession()
                contentItem: Text {
                    text: cancelButton.text
                    color: root.colError
                    font: cancelButton.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    implicitWidth: 96
                    implicitHeight: 38
                    radius: root.cornerRadius
                    color: cancelButton.hovered ? root.colHover : root.colSurfaceVariant
                    border.color: root.colError
                    border.width: 1
                }
            }

            Item {
                Layout.fillWidth: true
            }

            Button {
                id: testButton
                visible: backend.phase === "idle"
                enabled: backend.phase === "idle" && !backend.busy && backend.statusKnown
                    && backend.templateCount > 0
                opacity: enabled ? 1 : 0.45
                text: "Test my face"
                font.family: root.fontFamily
                font.pixelSize: 14
                onClicked: backend.verifySelf()
                contentItem: Text {
                    text: testButton.text
                    color: root.colOnPrimary
                    font: testButton.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    implicitWidth: 120
                    implicitHeight: 38
                    radius: root.cornerRadius
                    color: testButton.hovered ? root.colHover : root.colPrimary
                    border.color: root.colPrimary
                    border.width: 1
                }
            }

            Button {
                id: testAgainButton
                visible: backend.phase === "testing" || backend.phase === "test-result"
                enabled: backend.phase === "test-result" && !backend.busy
                opacity: enabled ? 1 : 0.45
                text: "Test again"
                font.family: root.fontFamily
                font.pixelSize: 14
                font.bold: true
                onClicked: backend.verifySelf()
                contentItem: Text {
                    text: testAgainButton.text
                    color: root.colOnPrimary
                    font: testAgainButton.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    implicitWidth: 120
                    implicitHeight: 38
                    radius: root.cornerRadius
                    color: testAgainButton.hovered ? root.colHover : root.colPrimary
                    border.color: root.colPrimary
                    border.width: 1
                }
            }

            Button {
                id: backButton
                visible: backend.phase === "testing" || backend.phase === "test-result"
                enabled: backend.phase === "test-result" && !backend.busy
                opacity: enabled ? 1 : 0.45
                text: "Back"
                font.family: root.fontFamily
                font.pixelSize: 14
                onClicked: {
                    root.confirmReenroll = false;
                    backend.backToStatus();
                }
                contentItem: Text {
                    text: backButton.text
                    color: root.colOnSurface
                    font: backButton.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    implicitWidth: 96
                    implicitHeight: 38
                    radius: root.cornerRadius
                    color: backButton.hovered ? root.colHover : root.colSurfaceVariant
                    border.color: root.colOutline
                    border.width: 1
                }
            }

            Button {
                id: beginButton
                visible: backend.phase === "idle" || backend.phase === "starting"
                enabled: backend.phase === "idle" && !backend.busy && backend.statusKnown
                opacity: enabled ? 1 : 0.45
                text: backend.templateCount > 0 ? "Re-enroll (replaces current templates)"
                    : "Begin enrollment"
                font.family: root.fontFamily
                font.pixelSize: 14
                font.bold: true
                onClicked: {
                    if (backend.templateCount > 0)
                        root.confirmReenroll = true;
                    else
                        backend.beginEnroll();
                }
                contentItem: Text {
                    text: beginButton.text
                    color: root.colOnPrimary
                    font: beginButton.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    implicitWidth: backend.templateCount > 0 ? 300 : 160
                    implicitHeight: 38
                    radius: root.cornerRadius
                    color: beginButton.hovered ? root.colHover : root.colPrimary
                    border.color: root.colPrimary
                    border.width: 1
                }
            }

            Button {
                id: captureButton
                visible: backend.phase === "active" || backend.phase === "finishing"
                enabled: backend.phase === "active" && !backend.busy && !backend.cooldown
                opacity: enabled ? 1 : 0.45
                text: "Capture"
                font.family: root.fontFamily
                font.pixelSize: 14
                font.bold: true
                onClicked: backend.capture()
                contentItem: Text {
                    text: captureButton.text
                    color: root.colOnPrimary
                    font: captureButton.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    implicitWidth: 120
                    implicitHeight: 38
                    radius: root.cornerRadius
                    color: captureButton.hovered ? root.colHover : root.colPrimary
                    border.color: root.colPrimary
                    border.width: 1
                }
            }
        }
    }

    Component.onCompleted: root.loadTheme()
}
