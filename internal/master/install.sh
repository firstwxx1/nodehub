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
$CURL -D "$TMP/agent.hdr" -o "$TMP/agent" "$MASTER/dl/agent?arch=$ARCH"
WANT_SHA="$(awk 'BEGIN{IGNORECASE=1}/^X-Checksum-Sha256:/{gsub(/\r/,""); print $2; exit}' "$TMP/agent.hdr" 2>/dev/null || true)"
if [ -n "$WANT_SHA" ] && need sha256sum; then
  GOT_SHA="$(sha256sum "$TMP/agent" | awk '{print $1}')"
  if [ "$GOT_SHA" != "$WANT_SHA" ]; then
    echo "checksum mismatch for nodehub-agent (want $WANT_SHA, got $GOT_SHA)" >&2
    exit 1
  fi
fi
chmod 755 "$TMP/agent"
# stage on same filesystem before atomic rename so live upgrades never hit ETXTBSY across tmpfs
cp -f "$TMP/agent" "$BIN/nodehub-agent.new"
chmod 755 "$BIN/nodehub-agent.new"
mv -f "$BIN/nodehub-agent.new" "$BIN/nodehub-agent"

if [ "$WITH_XRAY" = 1 ]; then
  echo "==> installing Xray $XRAY_VERSION"
  $CURL -o "$TMP/xray.zip" "${GH}https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XARCH}.zip"
  unzip -oq "$TMP/xray.zip" -d "$TMP/xray"
  cp -f "$TMP/xray/xray" "$BIN/xray.new"
  chmod 755 "$BIN/xray.new"
  mv -f "$BIN/xray.new" "$BIN/xray"
  cp -f "$TMP/xray/geoip.dat" "$TMP/xray/geosite.dat" "$BIN/" 2>/dev/null || true
fi

if [ "$WITH_SINGBOX" = 1 ]; then
  echo "==> installing sing-box $SINGBOX_VERSION"
  # prefer the build served by the master (compiled with v2ray_api for per-user traffic stats)
  if $CURL -o "$TMP/sing-box" "$MASTER/dl/sing-box-linux-$ARCH" 2>/dev/null; then
    cp -f "$TMP/sing-box" "$BIN/sing-box.new"
    chmod 755 "$BIN/sing-box.new"
    mv -f "$BIN/sing-box.new" "$BIN/sing-box"
  else
    echo "    master has no sing-box build, falling back to the official release (no per-user stats for sing-box nodes)"
    $CURL -o "$TMP/sb.tgz" "${GH}https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${ARCH}.tar.gz"
    tar xzf "$TMP/sb.tgz" -C "$TMP"
    cp -f "$TMP"/sing-box-*/sing-box "$BIN/sing-box.new"
    chmod 755 "$BIN/sing-box.new"
    mv -f "$BIN/sing-box.new" "$BIN/sing-box"
  fi
fi

ARGS="-config /etc/nodehub/agent.json -master $MASTER -token $TOKEN"
[ "$INSECURE" = 1 ] && ARGS="$ARGS -insecure"
"$BIN/nodehub-agent" $ARGS -init

# Scale cgroup memory budget with host RAM so agent + child proxy cores (xray/sing-box) never OOM-kill under load
MEM_KB="$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 1048576)"
[ -n "$MEM_KB" ] && [ "$MEM_KB" -gt 0 ] 2>/dev/null || MEM_KB=1048576
if [ "$MEM_KB" -ge 3600000 ]; then
  MEM_HIGH="512M"; MEM_MAX="768M"
elif [ "$MEM_KB" -ge 1500000 ]; then
  MEM_HIGH="384M"; MEM_MAX="512M"
else
  MEM_HIGH="220M"; MEM_MAX="320M"
fi

cat > /etc/systemd/system/nodehub-agent.service <<EOF
[Unit]
Description=NodeHub Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN/nodehub-agent -config /etc/nodehub/agent.json
MemoryHigh=$MEM_HIGH
MemoryMax=$MEM_MAX
Restart=always
RestartSec=2
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# Kernel & NIC tuning for high-BDP TCP (BBR + fq pacing) and UDP/QUIC (Hysteria2)
MEM_PAGES=$(( MEM_KB / 4 ))
TCP_MIN=$(( MEM_PAGES / 16 )); [ "$TCP_MIN" -lt 8192 ] && TCP_MIN=8192
TCP_PRESS=$(( MEM_PAGES / 8 )); [ "$TCP_PRESS" -lt 16384 ] && TCP_PRESS=16384
TCP_MAX=$(( MEM_PAGES / 4 )); [ "$TCP_MAX" -lt 32768 ] && TCP_MAX=32768
UDP_MIN=$(( MEM_PAGES / 32 )); [ "$UDP_MIN" -lt 4096 ] && UDP_MIN=4096
UDP_PRESS=$(( MEM_PAGES / 16 )); [ "$UDP_PRESS" -lt 16384 ] && UDP_PRESS=16384
UDP_MAX=$(( MEM_PAGES / 4 )); [ "$UDP_MAX" -lt 32768 ] && UDP_MAX=32768
if [ "$MEM_KB" -ge 3600000 ]; then CT_MAX=524288
elif [ "$MEM_KB" -ge 1500000 ]; then CT_MAX=262144
else CT_MAX=131072
fi

CC_ALGO="cubic"
if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
  CC_ALGO="bbr"
fi

mkdir -p /etc/sysctl.d
rm -f /etc/sysctl.d/99-nodehub.conf /etc/sysctl.d/99-hysteria2.conf
cat > /etc/sysctl.d/99-z-nodehub.conf <<EOF
# NodeHub proxy network stack tuning (auto-scaled for ${MEM_KB}KB RAM)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = ${CC_ALGO}
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.tcp_mem = ${TCP_MIN} ${TCP_PRESS} ${TCP_MAX}
net.ipv4.udp_mem = ${UDP_MIN} ${UDP_PRESS} ${UDP_MAX}
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_ecn = 0
net.core.netdev_max_backlog = 32768
net.core.netdev_budget = 600
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 65535
net.netfilter.nf_conntrack_max = ${CT_MAX}
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180
fs.file-max = 1048576
EOF
sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-z-nodehub.conf >/dev/null 2>&1 || true

# Apply fq qdisc and NIC ring/offload tuning immediately without requiring a reboot
MAIN_IFACE="$(ip route show default 2>/dev/null | awk '{print $5; exit}' || true)"
if [ -n "$MAIN_IFACE" ]; then
  if need tc; then
    tc qdisc replace dev "$MAIN_IFACE" root fq >/dev/null 2>&1 || true
  fi
  if need ethtool; then
    RX_MAX="$(ethtool -g "$MAIN_IFACE" 2>/dev/null | awk '/Pre-set maximums:/{s=1;next} /Current hardware/{s=0} s && /^RX:/{print $2; exit}')"
    TX_MAX="$(ethtool -g "$MAIN_IFACE" 2>/dev/null | awk '/Pre-set maximums:/{s=1;next} /Current hardware/{s=0} s && /^TX:/{print $2; exit}')"
    [ -n "$RX_MAX" ] && [ "$RX_MAX" -gt 4096 ] 2>/dev/null && RX_MAX=4096
    [ -n "$TX_MAX" ] && [ "$TX_MAX" -gt 4096 ] 2>/dev/null && TX_MAX=4096
    [ -n "$RX_MAX" ] && [ -n "$TX_MAX" ] && ethtool -G "$MAIN_IFACE" rx "$RX_MAX" tx "$TX_MAX" >/dev/null 2>&1 || true
    ethtool -K "$MAIN_IFACE" gro on gso on tso on lro off >/dev/null 2>&1 || true
  fi
fi

systemctl daemon-reload
systemctl enable --now nodehub-agent
systemctl restart nodehub-agent
sleep 2
systemctl --no-pager --lines=5 status nodehub-agent || true
echo
echo "NodeHub agent installed. Logs: journalctl -u nodehub-agent -f"
