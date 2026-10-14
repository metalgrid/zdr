// zdr-prompt.qml — QtQuick consent prompt for zdr-agent.
//
// Self-contained: run directly with qml6 or through the optional
// zdr-prompt C++ host (see main.cpp in this directory).
//
// Exit contract (interpreted fail-closed by zdr-agent):
//   Qt.exit(0)  — user approved ("Approve and scan")
//   Qt.exit(1)  — everything else: Deny, Escape, window close,
//                 countdown expiry.
//
// Arguments after the script name (a "--" separator after the
// script name is also accepted and stripped):
//   service, user, tty, label      (missing ones default to "")
//
// Theming: at startup the Noctalia palette is loaded from
//   $XDG_CONFIG_HOME/noctalia/colors.json
// (fallback ~/.config/noctalia/colors.json) and UI settings from
// settings.json in the same directory. XDG_CONFIG_HOME / HOME are
// discovered from /proc/self/environ because plain QML has no
// getenv(); file access needs QML_XHR_ALLOW_FILE_READ=1 in the
// environment, which the zdr-prompt host and zdr-agent both set
// for the child process. Every colour/font/radius has a built-in
// dark fallback, and any read/parse failure simply keeps those
// fallbacks — the prompt always renders.
//
// Testability: ZDR_PROMPT_SECONDS (read from /proc/self/environ,
// same mechanism) overrides the 30 s countdown for manual checks.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window

Window {
    id: root

    width: 440
    height: 300
    minimumWidth: 440
    maximumWidth: 440
    minimumHeight: 300
    maximumHeight: 300
    visible: true
    title: "zdr-prompt"
    color: root.colSurface

    // -- Request fields (from argv) ---------------------------------
    property string serviceText: ""
    property string userText: ""
    property string ttyText: ""
    property string labelText: ""

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

    // -- Countdown / decision state ---------------------------------
    property real totalSeconds: 30
    property real remainingSeconds: 30
    property bool decided: false

    function decide(approved) {
        if (root.decided)
            return;
        root.decided = true;
        countdown.stop();
        Qt.exit(approved ? 0 : 1);
    }

    function parseArgs() {
        var all = Qt.application.arguments || [];
        var start = (all.length > 0) ? 1 : 0;
        for (var i = 0; i < all.length; ++i) {
            var a = String(all[i]);
            if (a.length >= 4 && a.substring(a.length - 4) === ".qml") {
                start = i + 1;
                break;
            }
        }
        var fields = all.slice(start);
        if (fields.length > 0 && fields[0] === "--")
            fields = fields.slice(1);
        root.serviceText = (fields.length > 0) ? String(fields[0]) : "";
        root.userText = (fields.length > 1) ? String(fields[1]) : "";
        root.ttyText = (fields.length > 2) ? String(fields[2]) : "";
        root.labelText = (fields.length > 3) ? String(fields[3]) : "";
    }

    function loadTextFile(url, callback) {
        try {
            var xhr = new XMLHttpRequest();
            xhr.open("GET", url);
            xhr.onreadystatechange = function() {
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
        root.loadTextFile("file://" + bases[index] + "/" + relPath, function(text) {
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
        // Discover XDG_CONFIG_HOME / HOME (and the test countdown
        // override) from our own process environment.
        root.loadTextFile("file:///proc/self/environ", function(text) {
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
                    if (key === "XDG_CONFIG_HOME") {
                        xdg = value;
                    } else if (key === "HOME") {
                        home = value;
                    } else if (key === "ZDR_PROMPT_SECONDS") {
                        var secs = parseInt(value, 10);
                        if (isFinite(secs) && secs > 0 && secs <= 3600) {
                            root.totalSeconds = secs;
                            root.remainingSeconds = secs;
                        }
                    }
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

    onClosing: function(close) {
        // Any window close that is not an explicit decision denies.
        if (!root.decided)
            root.decide(false);
    }

    Shortcut {
        sequences: ["Return", "Enter"]
        onActivated: root.decide(true)
    }
    Shortcut {
        sequence: "Escape"
        onActivated: root.decide(false)
    }

    Timer {
        id: countdown
        interval: 100
        repeat: true
        running: true
        onTriggered: {
            root.remainingSeconds -= interval / 1000;
            if (root.remainingSeconds <= 0) {
                root.remainingSeconds = 0;
                root.decide(false);
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 12

        Text {
            Layout.fillWidth: true
            text: "Face authentication requested"
            color: root.colOnSurface
            font.family: root.fontFamily
            font.pixelSize: 19
            font.bold: true
            elide: Text.ElideRight
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 104
            radius: root.cornerRadius
            color: root.colSurfaceVariant
            border.color: root.colOutline
            border.width: 1

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 12
                spacing: 4

                Text {
                    Layout.fillWidth: true
                    text: "Service: " + root.serviceText
                    color: root.colOnSurface
                    font.family: root.fontFamily
                    font.pixelSize: 14
                    elide: Text.ElideRight
                }
                Text {
                    Layout.fillWidth: true
                    text: "User: " + root.userText
                    color: root.colOnSurfaceVariant
                    font.family: root.fontFamily
                    font.pixelSize: 14
                    elide: Text.ElideRight
                }
                Text {
                    Layout.fillWidth: true
                    text: "TTY: " + root.ttyText
                    color: root.colOnSurfaceVariant
                    font.family: root.fontFamily
                    font.pixelSize: 14
                    elide: Text.ElideRight
                }
                Text {
                    Layout.fillWidth: true
                    visible: root.labelText.length > 0
                    text: "\"" + root.labelText + "\""
                    color: root.colOnSurface
                    font.family: root.fontFamily
                    font.pixelSize: 14
                    font.italic: true
                    wrapMode: Text.WordWrap
                    maximumLineCount: 2
                    elide: Text.ElideRight
                }
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 4

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 6
                radius: 3
                color: root.colSurfaceVariant
                border.color: root.colOutline
                border.width: 1

                Rectangle {
                    anchors.left: parent.left
                    anchors.top: parent.top
                    anchors.bottom: parent.bottom
                    width: parent.width * Math.max(0, Math.min(1,
                            root.totalSeconds > 0
                            ? root.remainingSeconds / root.totalSeconds : 0))
                    radius: 3
                    color: root.remainingSeconds <= 5 ? root.colError : root.colPrimary
                }
            }

            Text {
                Layout.fillWidth: true
                text: "Denying automatically in " + Math.ceil(root.remainingSeconds) + " s"
                color: root.colOnSurfaceVariant
                font.family: root.fontFamily
                font.pixelSize: 12
                elide: Text.ElideRight
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 10

            Item {
                Layout.fillWidth: true
            }

            Button {
                id: denyButton
                text: "Deny"
                font.family: root.fontFamily
                font.pixelSize: 14
                onClicked: root.decide(false)
                contentItem: Text {
                    text: denyButton.text
                    color: root.colError
                    font: denyButton.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    implicitWidth: 96
                    implicitHeight: 36
                    radius: root.cornerRadius
                    color: denyButton.hovered ? root.colHover : root.colSurfaceVariant
                    border.color: root.colError
                    border.width: 1
                }
            }

            Button {
                id: approveButton
                text: "Approve and scan"
                font.family: root.fontFamily
                font.pixelSize: 14
                font.bold: true
                onClicked: root.decide(true)
                contentItem: Text {
                    text: approveButton.text
                    color: root.colOnPrimary
                    font: approveButton.font
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    implicitWidth: 168
                    implicitHeight: 36
                    radius: root.cornerRadius
                    color: approveButton.hovered ? root.colHover : root.colPrimary
                    border.color: root.colPrimary
                    border.width: 1
                }
            }
        }
    }

    Component.onCompleted: {
        root.parseArgs();
        root.loadTheme();
        approveButton.forceActiveFocus();
    }
}
