#!/usr/bin/env bash
# Builds the official Proton Pass Android app against a self-hosted leptiq.
# android-pass treats a PROD_ENV_URL build as a "custom build": it uses
# https://api.<host>/ and disables Proton's certificate pinning.
#
#   HOST=example.com ./build-android.sh
set -euo pipefail

: "${HOST:?set HOST, e.g. HOST=example.com (the API is served at api.HOST)}"
WORK="${WORK_DIR:-$(pwd)/android-pass}"

if [ ! -d "$WORK/.git" ]; then
    git clone --depth 1 https://github.com/protonpass/android-pass.git "$WORK"
fi
cd "$WORK"
PROD_ENV_URL="$HOST" ./gradlew :app:assembleProdRelease
echo "APK(s) under $WORK/app/build/outputs/apk/"
