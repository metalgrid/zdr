#!/usr/bin/env bash
# Download the YuNet + SFace ONNX models into spike/models/ (gitignored).
# Models are never committed. SHA-256 hashes are pinned below: every run
# verifies an existing file and re-downloads + re-verifies on mismatch.
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p models
cd models

# YuNet face detector, 232,589 B, MIT
# https://github.com/opencv/opencv_zoo/tree/main/models/face_detection_yunet
YUNET_FILE="face_detection_yunet_2023mar.onnx"
YUNET_URL="https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx"
YUNET_SHA256="8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4"

# SFace face recognizer, 38,696,353 B, Apache-2.0
# https://github.com/opencv/opencv_zoo/tree/main/models/face_recognition_sface
SFACE_FILE="face_recognition_sface_2021dec.onnx"
SFACE_URL="https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx"
SFACE_SHA256="0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79"

verify() {
    local file="$1" want="$2"
    [ -f "$file" ] || return 1
    local got
    got="$(sha256sum "$file" | awk '{print $1}')"
    [ "$got" = "$want" ]
}

fetch() {
    local file="$1" url="$2" want="$3"
    if verify "$file" "$want"; then
        echo "ok (cached, sha256 verified): $file"
        return
    fi
    echo "downloading $file ..."
    # -L follows the Git-LFS redirect to the real object.
    curl -fL --retry 3 -o "$file.tmp" "$url"
    if ! verify "$file.tmp" "$want"; then
        echo "ERROR: sha256 mismatch for $file" >&2
        echo "  got:  $(sha256sum "$file.tmp" | awk '{print $1}')" >&2
        echo "  want: $want" >&2
        rm -f "$file.tmp"
        exit 1
    fi
    mv "$file.tmp" "$file"
    echo "ok (downloaded, sha256 verified): $file"
}

fetch "$YUNET_FILE" "$YUNET_URL" "$YUNET_SHA256"
fetch "$SFACE_FILE" "$SFACE_URL" "$SFACE_SHA256"
ls -l "$YUNET_FILE" "$SFACE_FILE"
