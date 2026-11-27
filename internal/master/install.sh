#!/usr/bin/env bash
# NodeHub agent installer (parallel compressed downloads + version skip + concurrent kernel tuning)
# usage: curl -fsSL __MASTER_URL__/install.sh | bash -s -- --master __MASTER_URL__ --token <TOKEN> [--insecure] [--no-xray] [--no-singbox] [--fast] [--force]
set -euo pipefail

T_START=$(date +%s)
MASTER="__MASTER_URL__"
TOKEN=""
INSECURE=0
WITH_XRAY=1
WITH_SINGBOX=1
FAST=0
FORCE=0
XRAY_VERSION="${XRAY_VERSION:-v25.10.15}"
SINGBOX_VERSION="${SINGBOX_VERSION:-1.12.12}"
GH="${GH_PROXY:-}"   # optional mirror prefix, e.g. https://ghfast.top/

while [ $# -gt 0 ]; do
  case "$1" in
    --master) MASTER="${2%/}"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    --no-xray) WITH_XRAY=0; shift ;;
    --no-singbox) WITH_SINGBOX=0; shift ;;
    --fast) FAST=1; shift ;;
    --force) FORCE=1; shift ;;
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

pkg_install() {
  if need apt-get; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null
  elif need dnf; then dnf install -y -q "$@" >/dev/null
  elif need yum; then yum install -y -q "$@" >/dev/null
  elif need apk; then apk add --no-cache -q "$@" >/dev/null
  fi
}

# Only invoke package manager if curl is actually missing (avoid 15-30s apt-get update just for unzip)
if ! need curl; then
  pkg_install curl ca-certificates
fi

CURL="curl -fsSL --compressed --connect-timeout 8 --retry 2 --retry-delay 1"
CURL_HEAD="curl -fsSI --connect-timeout 5 --max-time 8"
if [ "$INSECURE" = 1 ]; then
  CURL="$CURL -k"
  CURL_HEAD="$CURL_HEAD -k"
fi

BIN=/usr/local/nodehub
mkdir -p "$BIN" /etc/nodehub
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

header_val() {
  local name="$1" file="$2"
  tr -d '\r' < "$file" 2>/dev/null | awk -v k="${name}:" 'tolower($1)==k{print $2; exit}' || true
}

verify_sha() {
  local file="$1" hdr="$2" label="$3"
  local want got
  want="$(header_val "x-checksum-sha256" "$hdr")"
  if [ -n "$want" ] && need sha256sum; then
    got="$(sha256sum "$file" | awk '{print $1}')"
    if [ "$got" != "$want" ]; then
      echo "checksum mismatch for $label (want $want, got $got)" >&2
      return 1
    fi
  fi
}

atomic_install() {
  local src="$1" dst="$2"
  # stage on same filesystem before atomic rename so live upgrades never hit ETXTBSY across tmpfs
  cp -f "$src" "${dst}.new"
  chmod 755 "${dst}.new"
  mv -f "${dst}.new" "$dst"
}

extract_zip_member() {
  local zip="$1" member="$2" dest="$3"
  if need unzip; then
    unzip -p "$zip" "$member" > "$dest"
  elif need python3; then
    python3 -c 'import zipfile,sys; open(sys.argv[3],"wb").write(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]))' "$zip" "$member" "$dest"
  elif need bsdtar; then
    bsdtar -xOf "$zip" "$member" > "$dest"
  else
    pkg_install unzip
    unzip -p "$zip" "$member" > "$dest"
  fi
}

install_agent() {
  if [ "$FORCE" = 0 ] && [ -x "$BIN/nodehub-agent" ] && need sha256sum; then
    local want cur
    $CURL_HEAD "$MASTER/dl/agent?arch=$ARCH" >"$TMP/agent.head" 2>/dev/null || true
    want="$(header_val "x-checksum-sha256" "$TMP/agent.head")"
    cur="$(sha256sum "$BIN/nodehub-agent" | awk '{print $1}')"
    if [ -n "$want" ] && [ "$want" = "$cur" ]; then
      echo "==> nodehub-agent ($ARCH) 已是最新版本，跳过下载"
      return 0
    fi
  fi
  echo "==> downloading agent ($ARCH)"
  $CURL -D "$TMP/agent.hdr" -o "$TMP/agent" "$MASTER/dl/agent?arch=$ARCH"
  verify_sha "$TMP/agent" "$TMP/agent.hdr" "nodehub-agent"
  atomic_install "$TMP/agent" "$BIN/nodehub-agent"
}

install_xray() {
  [ "$WITH_XRAY" = 1 ] || return 0
  if [ "$FORCE" = 0 ] && [ -x "$BIN/xray" ]; then
    local xver
    xver="$("$BIN/xray" version 2>/dev/null || true)"
    if printf '%s' "$xver" | grep -qF "${XRAY_VERSION#v}"; then
      echo "==> Xray $XRAY_VERSION 已安装，跳过下载"
      return 0
    fi
  fi
  echo "==> installing Xray $XRAY_VERSION"
  # Prefer pre-compressed standalone binary from master (no unzip & no 15MB unused geoip/geosite)
  if $CURL -D "$TMP/xray.hdr" -o "$TMP/xray.bin" "$MASTER/dl/xray-linux-$ARCH" 2>/dev/null; then
    verify_sha "$TMP/xray.bin" "$TMP/xray.hdr" "xray"
    atomic_install "$TMP/xray.bin" "$BIN/xray"
    return 0
  fi
  $CURL -o "$TMP/xray.zip" "${GH}https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XARCH}.zip"
  extract_zip_member "$TMP/xray.zip" "xray" "$TMP/xray.bin"
  atomic_install "$TMP/xray.bin" "$BIN/xray"
}

install_singbox() {
  [ "$WITH_SINGBOX" = 1 ] || return 0
  if [ "$FORCE" = 0 ] && [ -x "$BIN/sing-box" ]; then
    local sver
    sver="$("$BIN/sing-box" version 2>/dev/null || true)"
    if printf '%s' "$sver" | grep -qF "$SINGBOX_VERSION"; then
      echo "==> sing-box $SINGBOX_VERSION 已安装，跳过下载"
      return 0
    fi
  fi
  echo "==> installing sing-box $SINGBOX_VERSION"
  # Prefer the build served by master (compiled with v2ray_api for per-user traffic stats & gzip pre-compressed)
  if $CURL -D "$TMP/sb.hdr" -o "$TMP/sing-box.bin" "$MASTER/dl/sing-box-linux-$ARCH" 2>/dev/null; then
    verify_sha "$TMP/sing-box.bin" "$TMP/sb.hdr" "sing-box"
    atomic_install "$TMP/sing-box.bin" "$BIN/sing-box"
    return 0
  fi
  echo "    master has no sing-box build, falling back to official release"
  need tar || pkg_install tar
  $CURL -o "$TMP/sb.tgz" "${GH}https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${ARCH}.tar.gz"
  tar xzf "$TMP/sb.tgz" -C "$TMP"
  atomic_install "$TMP"/sing-box-*/sing-box "$BIN/sing-box"
}

echo "==> 并行拉取核心组件 (agent / xray / sing-box) 并同步执行内核网络调优..."
install_agent   >"$TMP/log.agent"   2>&1 & PID_A=$!
install_xray    >"$TMP/log.xray"    2>&1 & PID_X=$!
install_singbox >"$TMP/log.singbox" 2>&1 & PID_S=$!

# Run local systemd + sysctl + NIC tuning concurrently while downloads are in flight!
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

# Preserve IPv4 forwarding if already active or Docker is installed
IP_FWD_LINE=""
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ] || command -v docker >/dev/null 2>&1; then
  IP_FWD_LINE="net.ipv4.ip_forward = 1"
fi

mkdir -p /etc/sysctl.d
rm -f /etc/sysctl.d/99-nodehub.conf /etc/sysctl.d/99-hysteria2.conf
cat > /etc/sysctl.d/99-z-nodehub.conf <<EOF
# NodeHub proxy network stack tuning (auto-scaled for ${MEM_KB}KB RAM)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = ${CC_ALGO}
${IP_FWD_LINE}
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
# Targeted apply is instant (~10ms) and avoids cloud-init sysctl files overriding ip_forward
sysctl -p /etc/sysctl.d/99-z-nodehub.conf >/dev/null 2>&1 || true

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

# Wait for all 3 parallel downloads and print logs
DL_FAIL=0
wait "$PID_A" || DL_FAIL=1
wait "$PID_X" || DL_FAIL=1
wait "$PID_S" || DL_FAIL=1
cat "$TMP/log.agent" "$TMP/log.xray" "$TMP/log.singbox" 2>/dev/null || true
if [ "$DL_FAIL" != 0 ]; then
  echo "组件下载或安装失败，请检查上述输出" >&2
  exit 1
fi

ARGS="-config /etc/nodehub/agent.json -master $MASTER -token $TOKEN"
[ "$INSECURE" = 1 ] && ARGS="$ARGS -insecure"
"$BIN/nodehub-agent" $ARGS -init

systemctl daemon-reload
systemctl enable nodehub-agent >/dev/null 2>&1 || true
systemctl restart nodehub-agent

if [ "$FAST" = 0 ]; then
  sleep 1
  systemctl --no-pager --lines=5 status nodehub-agent || true
fi
ELAPSED=$(( $(date +%s) - T_START ))
echo
echo "NodeHub agent installed in ${ELAPSED}s. Logs: journalctl -u nodehub-agent -f"
