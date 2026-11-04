#!/bin/bash
# 可玩 / Feather 云端与本机出包脚本
#   ./build.sh            # 构建 iOS IPA → packages/Feather.ipa
#   ./build.sh clean      # 清理构建产物
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

NAME="Feather"
SCHEME="Feather"
WORKSPACE="Feather.xcworkspace"
TMP="${TMPDIR:-/tmp}/${NAME}-build"
PACKAGES="$ROOT/packages"
PAYLOAD_DIR="$ROOT/_build/Payload"

if [[ "${1:-}" == "clean" ]]; then
  rm -rf "$TMP" "$PACKAGES" "$ROOT/_build" "$ROOT/deps" Payload
  echo "cleaned"
  exit 0
fi

echo "==> deps (TLS materials for local install server)"
rm -rf deps
mkdir -p deps

CERT_OK=0
if curl -fsSL --connect-timeout 15 "https://i.kyzsalist.cn/loopback-pack.json" -o /tmp/cert-pack.json; then
  if jq -e '.cert and (.key1 or .key) and .info.domains.commonName' /tmp/cert-pack.json >/dev/null 2>&1; then
    jq -r '.cert' /tmp/cert-pack.json > deps/server.crt
    if jq -e '.key1 and .key2' /tmp/cert-pack.json >/dev/null 2>&1; then
      jq -r '.key1, .key2' /tmp/cert-pack.json > deps/server.pem
    else
      jq -r '.key // .key1' /tmp/cert-pack.json > deps/server.pem
    fi
    jq -r '.info.domains.commonName' /tmp/cert-pack.json > deps/commonName.txt
    CERT_OK=1
    echo "using https://i.kyzsalist.cn/loopback-pack.json ($(cat deps/commonName.txt))"
  fi
fi

if [[ "$CERT_OK" -ne 1 ]]; then
  echo "fallback https://backloop.dev/pack.json"
  curl -fsSL "https://backloop.dev/pack.json" -o /tmp/cert-pack.json
  jq -r '.cert' /tmp/cert-pack.json > deps/server.crt
  jq -r '.key1, .key2' /tmp/cert-pack.json > deps/server.pem
  jq -r '.info.domains.commonName' /tmp/cert-pack.json > deps/commonName.txt
fi

echo "==> resolve SPM packages (workspace)"
rm -rf "$ROOT/_build" "$TMP"
mkdir -p "$ROOT/_build"

# Prefer workspace to avoid Xcode 26 SPM crash with -project:
# NSMutableArray insertObjects:atIndexes count mismatch
xcodebuild -resolvePackageDependencies \
  -workspace "$WORKSPACE" \
  -scheme "$SCHEME" \
  -derivedDataPath "$TMP/iphoneos"

echo "==> xcodebuild iphoneos ($SCHEME via $WORKSPACE)"
xcodebuild \
  -workspace "$WORKSPACE" \
  -scheme "$SCHEME" \
  -configuration Release \
  -destination "generic/platform=iOS" \
  -derivedDataPath "$TMP/iphoneos" \
  -skipPackagePluginValidation \
  -disableAutomaticPackageResolution \
  CODE_SIGNING_ALLOWED=NO \
  ALWAYS_EMBED_SWIFT_STANDARD_LIBRARIES=NO

APP_SRC=""
if [[ -d "$ROOT/_build/Applications" ]]; then
  APP_SRC="$(find "$ROOT/_build/Applications" -maxdepth 1 -name '*.app' | head -1 || true)"
fi
if [[ -z "$APP_SRC" ]]; then
  APP_SRC="$(find "$TMP/iphoneos/Build/Products" -type d -name '*.app' | head -1 || true)"
fi
if [[ -z "$APP_SRC" || ! -d "$APP_SRC" ]]; then
  echo "ERROR: built .app not found"
  find "$TMP/iphoneos/Build/Products" -maxdepth 4 -type d -name '*.app' 2>/dev/null || true
  exit 1
fi

echo "==> package $APP_SRC"
rm -rf "$PAYLOAD_DIR"
mkdir -p "$PAYLOAD_DIR"
cp -R "$APP_SRC" "$PAYLOAD_DIR/Feather.app"
chmod -R 0755 "$PAYLOAD_DIR/Feather.app"
cp deps/server.crt deps/server.pem deps/commonName.txt "$PAYLOAD_DIR/Feather.app/" || true
codesign --force --sign - --timestamp=none "$PAYLOAD_DIR/Feather.app" || true

mkdir -p "$PACKAGES"
rm -f "$PACKAGES/Feather.ipa"
(
  cd "$ROOT/_build"
  ditto -c -k --sequesterRsrc --keepParent Payload "$PACKAGES/Feather.ipa"
)

ls -lh "$PACKAGES/Feather.ipa"
echo "OK: $PACKAGES/Feather.ipa"
