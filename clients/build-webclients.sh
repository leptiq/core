#!/usr/bin/env bash
# Builds the official Proton Pass browser extension (and optionally the web
# apps) from ProtonMail/WebClients, pointed at a self-hosted passhost.
#
#   DOMAIN=example.com ./build-webclients.sh            # Chrome extension
#   DOMAIN=example.com BUILD_TARGET=firefox ./build-webclients.sh
#
# The extension then talks to https://pass.$DOMAIN/api and logs in through
# the account app at https://account.$DOMAIN (see docs/clients.md).
set -euo pipefail

: "${DOMAIN:?set DOMAIN, e.g. DOMAIN=example.com}"
REF="${WEBCLIENTS_REF:-main}"
WORK="${WORK_DIR:-$(pwd)/webclients}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$WORK/.git" ]; then
    git clone --depth 1 --branch "$REF" https://github.com/ProtonMail/WebClients.git "$WORK"
fi

python3 "$HERE/patch-extension-manifests.py" "$WORK" "$DOMAIN"

cd "$WORK"
corepack enable
pnpm install --frozen-lockfile

cd applications/pass-extension
API_ENV="$DOMAIN" BUILD_TARGET="${BUILD_TARGET:-chrome}" pnpm run build:extension:env
echo "Extension built in $WORK/applications/pass-extension/dist"
