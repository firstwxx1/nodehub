#!/usr/bin/env bash
# NodeHub agent installer
# usage: curl -fsSL __MASTER_URL__/install.sh | bash -s -- --master __MASTER_URL__ --token <TOKEN> [--insecure] [--no-xray] [--no-singbox]
set -euo pipefail

MASTER="__MASTER_URL__"
TOKEN=""
INSECURE=0
WITH_XRAY=1
WITH_SINGBOX=1
XRAY_VERSION="${XRAY_VERSION:-v25.10.15}"
SINGBOX_VERSION="${SINGBOX_VERSION:-1.12.12}"
GH="${GH_PROXY:-}"   # optional mirror prefix, e.g. https://ghfast.top/

while [ $# -gt 0 ]; do
  case "$1" in
    --master) MASTER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    --no-xray) WITH_XRAY=0; shift ;;
    --no-singbox) WITH_SINGBOX=0; shift ;;
    --uninstall)
      systemctl disable --now nodehub-agent 2>/dev/null || true
      rm -f /etc/systemd/system/nodehub-agent.service
      rm -rf /usr/local/nodehub /etc/nodehub
      systemctl daemon-reload
      echo "NodeHub agent removed"; exit 0 ;;
    *) echo "unknown arg $1"; exit 1 ;;
  esac
done

[ -z "$TOKEN" ] && { echo "missing --token"; exit 1; }
[ "$(id -u)" -ne 0 ] && { echo "please run as root"; exit 1; }

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64; XARCH=64 ;;
  aarch64|arm64) ARCH=arm64; XARCH=arm64-v8a ;;
  *) echo "unsupported arch $(uname -m)"; exit 1 ;;
esac

need() { command -v "$1" >/dev/null 2>&1; }
if ! need curl || ! need unzip || ! need tar; then
  if need apt-get; then apt-get update -y && apt-get install -y curl unzip tar ca-certificates
  elif need dnf; then dnf install -y curl unzip tar ca-certificates
  elif need yum; then yum install -y curl unzip tar ca-certificates
  elif need apk; then apk add --no-cache curl unzip tar ca-certificates bash
  fi
fi

CURL="curl -fsSL --retry 3"
[ "$INSECURE" = 1 ] && CURL="$CURL -k"

BIN=/usr/local/nodehub
mkdir -p "$BIN" /etc/nodehub
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

echo "==> downloading agent ($ARCH)"
$CURL -o "$TMP/agent" "$MASTER/dl/agent?arch=$ARCH"
install -m 755 "$TMP/agent" "$BIN/nodehub-agent"

if [ "$WITH_XRAY" = 1 ]; then
  echo "==> installing Xray $XRAY_VERSION"
  $CURL -o "$TMP/xray.zip" "${GH}https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XARCH}.zip"
  unzip -oq "$TMP/xray.zip" -d "$TMP/xray"
  install -m 755 "$TMP/xray/xray" "$BIN/xray"
  cp -f "$TMP/xray/geoip.dat" "$TMP/xray/geosite.dat" "$BIN/" 2>/dev/null || true
fi

if [ "$WITH_SINGBOX" = 1 ]; then
  echo "==> installing sing-box $SINGBOX_VERSION"
  # prefer the build served by the master (compiled with v2ray_api for per-user traffic stats)
  if $CURL -o "$TMP/sing-box" "$MASTER/dl/sing-box-linux-$ARCH" 2>/dev/null; then
    install -m 755 "$TMP/sing-box" "$BIN/sing-box"
  else
    echo "    master has no sing-box build, falling back to the official release (no per-user stats for sing-box nodes)"
    $CURL -o "$TMP/sb.tgz" "${GH}https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${ARCH}.tar.gz"
    tar xzf "$TMP/sb.tgz" -C "$TMP"
    install -m 755 "$TMP"/sing-box-*/sing-box "$BIN/sing-box"
  fi
fi

ARGS="-config /etc/nodehub/agent.json -master $MASTER -token $TOKEN"
[ "$INSECURE" = 1 ] && ARGS="$ARGS -insecure"
"$BIN/nodehub-agent" $ARGS -init

cat > /etc/systemd/system/nodehub-agent.service <<EOF
[Unit]
Description=NodeHub Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN/nodehub-agent -config /etc/nodehub/agent.json
Restart=always
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# kernel tuning for proxies (BBR + larger buffers), only if not already set
if ! grep -q nodehub /etc/sysctl.conf 2>/dev/null; then
cat >> /etc/sysctl.conf <<'EOF'
# nodehub
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_fastopen=3
EOF
sysctl -p >/dev/null 2>&1 || true
fi

systemctl daemon-reload
systemctl enable --now nodehub-agent
systemctl restart nodehub-agent
sleep 2
systemctl --no-pager --lines=5 status nodehub-agent || true
echo
echo "NodeHub agent installed. Logs: journalctl -u nodehub-agent -f"
