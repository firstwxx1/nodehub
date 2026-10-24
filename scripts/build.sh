#!/usr/bin/env bash
# Builds the master, the agents (amd64/arm64) and sing-box with per-user stats (v2ray_api) into ./build
# usage: ./scripts/build.sh            (needs Go 1.24+)
set -euo pipefail
cd "$(dirname "$0")/.."
SINGBOX_VERSION="${SINGBOX_VERSION:-1.12.12}"
OUT="${OUT:-build}"
LDFLAGS="-s -w"
mkdir -p "$OUT/dist"
OUT="$(cd "$OUT" && pwd)"   # absolute, so builds inside temp dirs land in the right place
export CGO_ENABLED=0

echo "==> master (linux/amd64, linux/arm64)"
for a in amd64 arm64; do
  GOOS=linux GOARCH=$a go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/nodehub-linux-$a" ./cmd/master
done

echo "==> agent"
for a in amd64 arm64; do
  GOOS=linux GOARCH=$a go build -trimpath -ldflags "$LDFLAGS" -o "$OUT/dist/nodehub-agent-linux-$a" ./cmd/agent
done

if [ "${SKIP_SINGBOX:-0}" != 1 ]; then
  echo "==> sing-box $SINGBOX_VERSION with v2ray_api (per-user traffic stats)"
  TMP=$(mktemp -d)
  ( cd "$TMP" && go mod init sbbuild >/dev/null 2>&1 && go get "github.com/sagernet/sing-box@v$SINGBOX_VERSION" )
  for a in amd64 arm64; do
    ( cd "$TMP" && GOOS=linux GOARCH=$a go build -trimpath \
        -ldflags "$LDFLAGS -X github.com/sagernet/sing-box/constant.Version=$SINGBOX_VERSION" \
        -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_v2ray_api" \
        -o "$OUT/dist/sing-box-linux-$a" github.com/sagernet/sing-box/cmd/sing-box )
  done
  rm -rf "$TMP"
fi

( cd "$OUT" && sha256sum nodehub-linux-* dist/* > SHA256SUMS )
echo "done -> $OUT/"
ls -la "$OUT" "$OUT/dist"
