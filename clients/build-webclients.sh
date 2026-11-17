#!/usr/bin/env bash
# Builds the official Proton Pass browser extension, the Pass web app and the
# Proton account app (login/signup) from ProtonMail/WebClients, pointed at a
# self-hosted leptiq.
#
#   DOMAIN=example.com ./build-webclients.sh                       # Chrome
#   DOMAIN=example.com BUILD_TARGET=firefox ./build-webclients.sh  # Firefox
#   DOMAIN=example.test:8443 BUILD_TARGET=firefox ./build-webclients.sh
#
# The extension talks to https://pass.$DOMAIN/api and logs in through the
# account app at https://account.$DOMAIN (see docs/clients.md). A port in
# DOMAIN is kept in the URLs but removed from the manifest match patterns,
# which may not contain ports.
#
# Outputs:
#   $WORK/applications/pass-extension/dist   unpacked extension
#   $WORK/applications/pass/dist             Pass web app (static files)
#   $WORK/applications/account/dist          account app (static files)
set -euo pipefail

: "${DOMAIN:?set DOMAIN, e.g. DOMAIN=example.com}"
REF="${WEBCLIENTS_REF:-main}"
WORK="${WORK_DIR:-$(pwd)/webclients}"
TARGET="${BUILD_TARGET:-chrome}"
PNPM="${PNPM:-npx -y pnpm@$(sed -n 's/.*"packageManager": "pnpm@\([^"]*\)".*/\1/p' "$WORK/package.json" 2>/dev/null || echo latest)}"

if [ ! -d "$WORK/.git" ]; then
    git clone --depth 1 --branch "$REF" https://github.com/ProtonMail/WebClients.git "$WORK"
    PNPM="npx -y pnpm@$(sed -n 's/.*"packageManager": "pnpm@\([^"]*\)".*/\1/p' "$WORK/package.json")"
fi
cd "$WORK"

# --- Workarounds for building the public mirror outside Proton's network ---
# 1. The root preinstall hook runs a script that is not in the public mirror.
mkdir -p utilities/repo-rules/src/enforce-pnpm
[ -f utilities/repo-rules/src/enforce-pnpm/run.ts ] || : > utilities/repo-rules/src/enforce-pnpm/run.ts
# 2. Proton's scoped packages resolve to internal registries; the same
#    versions are published on npmjs (the lockfile's integrity hashes still
#    apply). `@tpe` packages exist only internally and are used only by the
#    `tests` workspace, which the mirror does not include.
sed -i -E 's#^(@proton|@protontech|@proton-meet|@proton-docs):registry=.*#\1:registry=https://registry.npmjs.org/#' .npmrc
python3 - pnpm-lock.yaml <<'EOF'
import re, sys
path = sys.argv[1]
out, skip = [], False
for line in open(path).read().split('\n'):
    m = re.match(r'^  (\S.*):$', line)
    if m or (line and not line.startswith('  ')):
        key = m.group(1).strip("'") if m else ''
        skip = bool(m) and (key == 'tests' or key.startswith('tests/') or key.startswith('@tpe/'))
    if not skip:
        out.append(line)
open(path, 'w').write('\n'.join(out))
EOF
# 3. The lockfile release-age policy queries every package's metadata,
#    including the internal-only ones.
sed -i 's/^minimumReleaseAge: .*/minimumReleaseAge: 0/' pnpm-workspace.yaml

CI=true $PNPM install --frozen-lockfile --filter 'proton-pass-extension...' --filter 'proton-pass...' --filter 'proton-account...'

export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=8192}"

# --- Account app: same-origin API (`/api` on account.$DOMAIN) ---
(
    cd applications/account
    NODE_ENV=production TS_NODE_PROJECT=../../tsconfig.webpack.json \
        npx proton-pack build --appMode=sso --api=/api
)

# --- Pass web app: same-origin API (`/api` on pass.$DOMAIN) ---
(
    cd applications/pass
    NODE_ENV=production TS_NODE_PROJECT=../../tsconfig.webpack.json \
        npx proton-pack build --appMode=sso --api=/api --noLogicalScss
)

# --- Extension ---
(
    cd applications/pass-extension
    rm -rf dist
    API_ENV="$DOMAIN" BUILD_TARGET="$TARGET" NODE_ENV=production npx webpack --config webpack.config.ts
    case "$DOMAIN" in
        *:*)
            host="${DOMAIN%%:*}"
            sed -i "s#${DOMAIN//./\\.}/\\*#${host}/*#g" dist/manifest.json
            ;;
    esac
)

echo "Extension:   $WORK/applications/pass-extension/dist"
echo "Web app:     $WORK/applications/pass/dist"
echo "Account app: $WORK/applications/account/dist"
