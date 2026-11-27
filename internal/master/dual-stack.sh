#!/usr/bin/env bash
# NodeHub 一键新机四协议全栈部署脚本（VLESS-Reality 443 + Hysteria2 跳跃 + CF 橙云 CDN 2053 + AnyTLS-WARP 8446）
#
# 用法：
#   curl -fsSL __MASTER_URL__/dual-stack.sh | bash -s -- \
#     --key <NODEHUB_API_KEY> \
#     --name "洛杉矶" \
#     [--domain la.你的域名.com | --domain la] \
#     [--region US] \
#     [--tcp-port 443] \
#     [--hy2-port 44443] \
#     [--cdn-port 2053] \
#     [--warp-port 8446] \
#     [--hop-ports 20000-40000] \
#     [--reality-dest www.apple.com:443] \
#     [--groups ""] \
#     [--skip-cdn] [--skip-warp] [--no-cf] [--reinstall] [--force]
set -euo pipefail

T_START=$(date +%s)
MASTER="__MASTER_URL__"
API_KEY=""
NAME=""
DOMAIN=""
REGION=""
HY2_PORT=44443
TCP_PORT=0
CDN_PORT=2053
WARP_PORT=8446
HOP_PORTS="20000-40000"
REALITY_DEST="www.apple.com:443"
NODE_GROUPS=""
NO_CF=0
SKIP_CDN=0
SKIP_WARP=0
REINSTALL=0
INSECURE=0
FORCE=0
IP_OVERRIDE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --master)       MASTER="${2%/}"; shift 2 ;;
    --key)          API_KEY="$2"; shift 2 ;;
    --name)         NAME="$2"; shift 2 ;;
    --domain)       DOMAIN="$2"; shift 2 ;;
    --region)       REGION="$2"; shift 2 ;;
    --ip)           IP_OVERRIDE="$2"; shift 2 ;;
    --hy2-port)     HY2_PORT="$2"; shift 2 ;;
    --tcp-port)     TCP_PORT="$2"; shift 2 ;;
    --cdn-port)     CDN_PORT="$2"; shift 2 ;;
    --warp-port)    WARP_PORT="$2"; shift 2 ;;
    --hop-ports)    HOP_PORTS="$2"; shift 2 ;;
    --reality-dest) REALITY_DEST="$2"; shift 2 ;;
    --groups)       NODE_GROUPS="$2"; shift 2 ;;
    --no-cf)        NO_CF=1; shift ;;
    --skip-cdn)     SKIP_CDN=1; shift ;;
    --skip-warp)    SKIP_WARP=1; shift ;;
    --reinstall)    REINSTALL=1; shift ;;
    --insecure)     INSECURE=1; shift ;;
    --force)        FORCE=1; shift ;;
    -h|--help)
      sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done

[ "$(id -u)" -ne 0 ] && { echo "请使用 root 运行此脚本" >&2; exit 1; }
[ -z "$API_KEY" ] && { echo "缺少必填参数 --key <NodeHub API Key>（可在 NodeHub 面板 → API 与 Webhook 中创建）" >&2; exit 1; }
[ -z "$NAME" ] && NAME="$(hostname -s 2>/dev/null || hostname || echo vps-node)"

need() { command -v "$1" >/dev/null 2>&1; }
if ! need curl; then
  if need apt-get; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates >/dev/null
  elif need dnf; then dnf install -y -q curl ca-certificates >/dev/null
  elif need yum; then yum install -y -q curl ca-certificates >/dev/null
  elif need apk; then apk add --no-cache -q curl ca-certificates bash >/dev/null
  fi
fi

CURL="curl -fsSL --compressed --connect-timeout 8 --retry 2 --retry-delay 1"
[ "$INSECURE" = 1 ] && CURL="$CURL -k"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# 1. 并发探测公网 IPv4 与地区代码（最快 ~0.2s 完成，避免串行等待）
PUB_IP="$IP_OVERRIDE"
PID_IP=""
PID_RG=""
if [ -z "$PUB_IP" ]; then
  (
    ip=""
    for ep in "https://api4.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip"; do
      ip="$(curl -4 -fsS --connect-timeout 2 --max-time 3 "$ep" 2>/dev/null | tr -d '[:space:]' || true)"
      if printf '%s' "$ip" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        printf '%s' "$ip" > "$TMP/pub_ip"
        exit 0
      fi
    done
  ) &
  PID_IP=$!
fi
if [ -z "$REGION" ]; then
  (
    rg="$(curl -4 -fsS --connect-timeout 2 --max-time 3 "https://ipinfo.io/country" 2>/dev/null | tr -d '[:space:]' | tr 'a-z' 'A-Z' || true)"
    if printf '%s' "$rg" | grep -Eq '^[A-Z]{2}$'; then
      printf '%s' "$rg" > "$TMP/region"
    fi
  ) &
  PID_RG=$!
fi
[ -n "$PID_IP" ] && wait "$PID_IP" || true
[ -n "$PID_RG" ] && wait "$PID_RG" || true
[ -z "$PUB_IP" ] && [ -f "$TMP/pub_ip" ] && PUB_IP="$(cat "$TMP/pub_ip")"
[ -z "$REGION" ] && [ -f "$TMP/region" ] && REGION="$(cat "$TMP/region")"

[ -z "$PUB_IP" ] && { echo "无法自动获取公网 IPv4，请用 --ip <IP> 手动指定" >&2; exit 1; }

echo "==> [1/3] 正在向 NodeHub 注册服务器并编排四协议全栈节点（IP: ${PUB_IP}${REGION:+, 地区: $REGION}）..."

json_esc() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

NO_CF_BOOL="false";     [ "$NO_CF" = 1 ]     && NO_CF_BOOL="true"
SKIP_CDN_BOOL="false";  [ "$SKIP_CDN" = 1 ]  && SKIP_CDN_BOOL="true"
SKIP_WARP_BOOL="false"; [ "$SKIP_WARP" = 1 ] && SKIP_WARP_BOOL="true"
RESET_TOK_BOOL="false"; [ "$REINSTALL" = 1 ] && RESET_TOK_BOOL="true"

PAYLOAD=$(cat <<EOF
{
  "name": "$(json_esc "$NAME")",
  "region": "$(json_esc "$REGION")",
  "ip": "$(json_esc "$PUB_IP")",
  "domain": "$(json_esc "$DOMAIN")",
  "no_cf": ${NO_CF_BOOL},
  "skip_cdn": ${SKIP_CDN_BOOL},
  "skip_warp": ${SKIP_WARP_BOOL},
  "reset_token": ${RESET_TOK_BOOL},
  "hy2_port": ${HY2_PORT},
  "tcp_port": ${TCP_PORT},
  "cdn_port": ${CDN_PORT},
  "warp_port": ${WARP_PORT},
  "hop_ports": "$(json_esc "$HOP_PORTS")",
  "reality_dest": "$(json_esc "$REALITY_DEST")",
  "groups": "$(json_esc "$NODE_GROUPS")"
}
EOF
)

HTTP_CODE="$(curl -sS --compressed --connect-timeout 8 $([ "$INSECURE" = 1 ] && echo -k) -o "$TMP/resp.json" -w '%{http_code}' \
  -X POST "${MASTER}/api/open/v1/provision" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")"

if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
  echo "注册/创建节点失败 (HTTP ${HTTP_CODE}):" >&2
  cat "$TMP/resp.json" >&2
  echo "" >&2
  exit 1
fi

# 解析响应字段（优先 python3，其次 jq）
parse_resp() {
  if need python3; then
    python3 - "$TMP/resp.json" <<'PY'
import json, shlex, sys
d = json.load(open(sys.argv[1]))
hy2 = d.get("hy2_node") or {}
vl = d.get("vless_node") or {}
cdn = d.get("cdn_node") or {}
warp = d.get("warp_node") or {}
for k, v in [
    ("AGENT_TOKEN", d.get("token") or ""),
    ("RES_DOMAIN", d.get("domain") or ""),
    ("RES_DNS_ACTION", d.get("dns_action") or ""),
    ("RES_CDN_DOMAIN", d.get("cdn_domain") or ""),
    ("RES_CDN_DNS_ACTION", d.get("cdn_dns_action") or ""),
    ("RES_CERT_MODE", d.get("cert_mode") or ""),
    ("RES_HY2_ID", str(hy2.get("id") or "")),
    ("RES_HY2_PORT", str(hy2.get("port") or "")),
    ("RES_VLESS_ID", str(vl.get("id") or "")),
    ("RES_VLESS_PORT", str(vl.get("port") or "")),
    ("RES_CDN_ID", str(cdn.get("id") or "")),
    ("RES_CDN_PORT", str(cdn.get("port") or "")),
    ("RES_WARP_ID", str(warp.get("id") or "")),
    ("RES_WARP_PORT", str(warp.get("port") or "")),
    ("RES_WARNINGS", "; ".join(d.get("warnings") or [])),
]:
    print(f"{k}={shlex.quote(v)}")
PY
  elif need jq; then
    jq -r '
      "AGENT_TOKEN=" + ((.token // "") | @sh),
      "RES_DOMAIN=" + ((.domain // "") | @sh),
      "RES_DNS_ACTION=" + ((.dns_action // "") | @sh),
      "RES_CDN_DOMAIN=" + ((.cdn_domain // "") | @sh),
      "RES_CDN_DNS_ACTION=" + ((.cdn_dns_action // "") | @sh),
      "RES_CERT_MODE=" + ((.cert_mode // "") | @sh),
      "RES_HY2_ID=" + (((.hy2_node.id // "") | tostring) | @sh),
      "RES_HY2_PORT=" + (((.hy2_node.port // "") | tostring) | @sh),
      "RES_VLESS_ID=" + (((.vless_node.id // "") | tostring) | @sh),
      "RES_VLESS_PORT=" + (((.vless_node.port // "") | tostring) | @sh),
      "RES_CDN_ID=" + (((.cdn_node.id // "") | tostring) | @sh),
      "RES_CDN_PORT=" + (((.cdn_node.port // "") | tostring) | @sh),
      "RES_WARP_ID=" + (((.warp_node.id // "") | tostring) | @sh),
      "RES_WARP_PORT=" + (((.warp_node.port // "") | tostring) | @sh),
      "RES_WARNINGS=" + (((.warnings // []) | join("; ")) | @sh)
    ' "$TMP/resp.json"
  else
    echo "需要 python3 或 jq 解析返回 JSON" >&2; exit 1
  fi
}

eval "$(parse_resp)"

echo "    直连域名:   ${RES_DOMAIN:-无（自签证书）}${RES_DNS_ACTION:+ [Cloudflare A记录: ${RES_DNS_ACTION}]}"
[ -n "$RES_CDN_DOMAIN" ] && echo "    CDN 域名:   ${RES_CDN_DOMAIN}${RES_CDN_DNS_ACTION:+ [Cloudflare 橙云代理: ${RES_CDN_DNS_ACTION}]}"
echo "    证书模式:   ${RES_CERT_MODE:-self}"
[ -n "$RES_VLESS_ID" ] && echo "    Reality:    节点 #${RES_VLESS_ID} · TCP ${RES_VLESS_PORT}"
[ -n "$RES_HY2_ID" ]   && echo "    Hysteria2:  节点 #${RES_HY2_ID} · UDP ${RES_HY2_PORT}${HOP_PORTS:+ (跳跃 ${HOP_PORTS})}"
[ -n "$RES_CDN_ID" ]   && echo "    CF CDN:     节点 #${RES_CDN_ID} · TCP ${RES_CDN_PORT} (VLESS-WS-TLS)"
[ -n "$RES_WARP_ID" ]  && echo "    AnyTLS-WRP: 节点 #${RES_WARP_ID} · TCP ${RES_WARP_PORT} (自动注册 WARP 出站)"
[ -n "$RES_WARNINGS" ] && echo "    提示:       ${RES_WARNINGS}"

# 重装/接管模式：清理可能占着 443/2053/8446/44443 的独立旧代理服务
if [ "$REINSTALL" = 1 ]; then
  echo "==> [重接清理] 正在停止可能冲突的独立 xray / sing-box / hysteria 服务..."
  for svc in xray sing-box hysteria-server hysteria; do
    if systemctl is-active --quiet "$svc" 2>/dev/null || systemctl is-enabled --quiet "$svc" 2>/dev/null; then
      systemctl stop "$svc" 2>/dev/null || true
      systemctl disable "$svc" 2>/dev/null || true
      echo "    已停用旧服务: ${svc}.service"
    fi
  done
fi

# 2. 若返回新 Agent Token，并行极速安装 agent + xray + sing-box + BBR 调优
if [ -n "$AGENT_TOKEN" ]; then
  echo "==> [2/3] 正在并行安装 NodeHub Agent + Xray + sing-box 并执行内核网络调优..."
  INST_ARGS="--master ${MASTER} --token ${AGENT_TOKEN} --fast"
  [ "$INSECURE" = 1 ] && INST_ARGS="${INST_ARGS} --insecure"
  if [ "$FORCE" = 1 ] || [ "$REINSTALL" = 1 ]; then
    INST_ARGS="${INST_ARGS} --force"
  fi
  $CURL "${MASTER}/install.sh" | bash -s -- $INST_ARGS
else
  echo "==> [2/3] 服务器已接入 NodeHub，跳过 Agent 重装，触发立即拉取四协议配置..."
  systemctl restart nodehub-agent 2>/dev/null || true
fi

# 3. 高频检测（0.5s 轮询）xray 与 sing-box 全栈端口就绪
echo "==> [3/3] 等待 Agent 同步配置、自动注册 WARP 并拉起双内核..."
XRAY_OK=0
HY2_OK=0
CDN_OK=0
WARP_OK=0
for i in $(seq 1 60); do
  if [ -n "$RES_VLESS_PORT" ] && ss -tlnp 2>/dev/null | grep -Eq ":${RES_VLESS_PORT}[[:space:]].*xray"; then
    XRAY_OK=1
  fi
  if [ -n "$RES_HY2_PORT" ] && ss -ulnp 2>/dev/null | grep -Eq ":${RES_HY2_PORT}[[:space:]].*sing-box"; then
    HY2_OK=1
  fi
  if [ -n "$RES_CDN_PORT" ] && ss -tlnp 2>/dev/null | grep -Eq ":${RES_CDN_PORT}[[:space:]].*sing-box"; then
    CDN_OK=1
  fi
  if [ -n "$RES_WARP_PORT" ] && ss -tlnp 2>/dev/null | grep -Eq ":${RES_WARP_PORT}[[:space:]].*sing-box"; then
    WARP_OK=1
  fi
  if { [ -z "$RES_VLESS_PORT" ] || [ "$XRAY_OK" = 1 ]; } \
     && { [ -z "$RES_HY2_PORT" ] || [ "$HY2_OK" = 1 ]; } \
     && { [ -z "$RES_CDN_PORT" ] || [ "$CDN_OK" = 1 ]; } \
     && { [ -z "$RES_WARP_PORT" ] || [ "$WARP_OK" = 1 ]; }; then
    break
  fi
  sleep 0.5
done

ELAPSED=$(( $(date +%s) - T_START ))
TCP_PORTS=""
for p in "$RES_VLESS_PORT" "$RES_CDN_PORT" "$RES_WARP_PORT"; do
  [ -n "$p" ] && TCP_PORTS="${TCP_PORTS:+${TCP_PORTS}、}${p}"
done
echo ""
echo "================================================================"
echo " NodeHub 一键四协议全栈部署完成：${NAME} (${PUB_IP}) · 总耗时 ${ELAPSED}s"
if [ -n "$RES_DOMAIN" ]; then
  echo " 直连域名：${RES_DOMAIN}（$([ "$RES_CERT_MODE" = "acme_dns" ] && echo 'Cloudflare DNS-01 自动签发与续期证书' || echo "证书模式: ${RES_CERT_MODE:-self}")）"
fi
if [ -n "$RES_CDN_DOMAIN" ]; then
  echo " CDN 域名：${RES_CDN_DOMAIN}（Cloudflare 橙云代理，抗 IP 封锁兜底）"
fi
[ -n "$RES_VLESS_PORT" ] && echo " [TCP] VLESS-Reality :${RES_VLESS_PORT} -> xray     $([ "$XRAY_OK" = 1 ] && echo '运行中 ✓' || echo '启动中，请查看 /etc/nodehub/xray.log')"
[ -n "$RES_HY2_PORT" ]   && echo " [UDP] Hysteria2     :${RES_HY2_PORT} (跳跃 ${HOP_PORTS:-关}) -> sing-box $([ "$HY2_OK" = 1 ] && echo '运行中 ✓' || echo '启动中，请查看 /etc/nodehub/sing-box.log')"
[ -n "$RES_CDN_PORT" ]   && echo " [TCP] CF CDN (WS)   :${RES_CDN_PORT} -> sing-box $([ "$CDN_OK" = 1 ] && echo '运行中 ✓' || echo '启动中，请查看 /etc/nodehub/sing-box.log')"
[ -n "$RES_WARP_PORT" ]  && echo " [TCP] AnyTLS + WARP :${RES_WARP_PORT} -> sing-box $([ "$WARP_OK" = 1 ] && echo '运行中 ✓' || echo '启动中，请查看 /etc/nodehub/sing-box.log')"
if [ "$RES_CERT_MODE" = "acme_dns" ] || [ -n "$RES_CDN_PORT" ]; then
  echo " 提示：首次 ACME DNS-01 签发域名证书约需 20-45 秒，sing-box 会自动完成并永久续期。"
fi
echo " 请确认防火墙/安全组放行：TCP ${TCP_PORTS:-无}；UDP ${RES_HY2_PORT:-无}${HOP_PORTS:+ 及 UDP ${HOP_PORTS}}"
echo "================================================================"
