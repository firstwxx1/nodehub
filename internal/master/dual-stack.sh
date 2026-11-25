#!/usr/bin/env bash
# NodeHub 一键新机双栈部署脚本（自动接入 Agent + Cloudflare DNS 解析 + DNS-01 域名证书 + Hysteria2 + VLESS-Reality TCP）
#
# 用法：
#   curl -fsSL __MASTER_URL__/dual-stack.sh | bash -s -- \
#     --key <NODEHUB_API_KEY> \
#     --name "日本新机" \
#     [--domain jp2.你的域名.com | --domain jp2] \
#     [--region JP] \
#     [--hy2-port 44443] \
#     [--tcp-port 44443] \
#     [--hop-ports 20000-40000] \
#     [--reality-dest www.apple.com:443] \
#     [--groups ""] \
#     [--no-cf]
set -euo pipefail

MASTER="__MASTER_URL__"
API_KEY=""
NAME=""
DOMAIN=""
REGION=""
HY2_PORT=44443
TCP_PORT=0
HOP_PORTS="20000-40000"
REALITY_DEST="www.apple.com:443"
NODE_GROUPS=""
NO_CF=0
INSECURE=0
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
    --hop-ports)    HOP_PORTS="$2"; shift 2 ;;
    --reality-dest) REALITY_DEST="$2"; shift 2 ;;
    --groups)       NODE_GROUPS="$2"; shift 2 ;;
    --no-cf)        NO_CF=1; shift ;;
    --insecure)     INSECURE=1; shift ;;
    -h|--help)
      sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done

[ "$(id -u)" -ne 0 ] && { echo "请使用 root 运行此脚本" >&2; exit 1; }
[ -z "$API_KEY" ] && { echo "缺少必填参数 --key <NodeHub API Key>（可在 NodeHub 面板 → API 与通知 中创建）" >&2; exit 1; }
[ -z "$NAME" ] && NAME="$(hostname -s 2>/dev/null || hostname || echo vps-node)"
[ "$TCP_PORT" = "0" ] && TCP_PORT="$HY2_PORT"

need() { command -v "$1" >/dev/null 2>&1; }
if ! need curl; then
  if need apt-get; then apt-get update -y && apt-get install -y curl ca-certificates
  elif need dnf; then dnf install -y curl ca-certificates
  elif need yum; then yum install -y curl ca-certificates
  elif need apk; then apk add --no-cache curl ca-certificates bash
  fi
fi

CURL="curl -fsSL --retry 3"
[ "$INSECURE" = 1 ] && CURL="$CURL -k"

# 1. 检测公网 IPv4 与地区代码
PUB_IP="$IP_OVERRIDE"
if [ -z "$PUB_IP" ]; then
  for ep in "https://api4.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip"; do
    PUB_IP="$(curl -4 -fsS --max-time 6 "$ep" 2>/dev/null | tr -d '[:space:]' || true)"
    if printf '%s' "$PUB_IP" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
      break
    fi
    PUB_IP=""
  done
fi
[ -z "$PUB_IP" ] && { echo "无法自动获取公网 IPv4，请用 --ip <IP> 手动指定" >&2; exit 1; }

if [ -z "$REGION" ]; then
  REGION="$(curl -4 -fsS --max-time 5 "https://ipinfo.io/country" 2>/dev/null | tr -d '[:space:]' | tr 'a-z' 'A-Z' || true)"
  if ! printf '%s' "$REGION" | grep -Eq '^[A-Z]{2}$'; then
    REGION=""
  fi
fi

echo "==> [1/3] 正在向 NodeHub 注册服务器并创建双栈节点（IP: ${PUB_IP}${REGION:+, 地区: $REGION}）..."

json_esc() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

NO_CF_BOOL="false"
[ "$NO_CF" = 1 ] && NO_CF_BOOL="true"

PAYLOAD=$(cat <<EOF
{
  "name": "$(json_esc "$NAME")",
  "region": "$(json_esc "$REGION")",
  "ip": "$(json_esc "$PUB_IP")",
  "domain": "$(json_esc "$DOMAIN")",
  "no_cf": ${NO_CF_BOOL},
  "hy2_port": ${HY2_PORT},
  "tcp_port": ${TCP_PORT},
  "hop_ports": "$(json_esc "$HOP_PORTS")",
  "reality_dest": "$(json_esc "$REALITY_DEST")",
  "groups": "$(json_esc "$NODE_GROUPS")"
}
EOF
)

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
HTTP_CODE="$(curl -sS $([ "$INSECURE" = 1 ] && echo -k) -o "$TMP/resp.json" -w '%{http_code}' \
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
for k, v in [
    ("AGENT_TOKEN", d.get("token") or ""),
    ("RES_DOMAIN", d.get("domain") or ""),
    ("RES_DNS_ACTION", d.get("dns_action") or ""),
    ("RES_CERT_MODE", d.get("cert_mode") or ""),
    ("RES_HY2_ID", str(hy2.get("id") or "")),
    ("RES_HY2_PORT", str(hy2.get("port") or "")),
    ("RES_VLESS_ID", str(vl.get("id") or "")),
    ("RES_VLESS_PORT", str(vl.get("port") or "")),
    ("RES_WARNINGS", "; ".join(d.get("warnings") or [])),
]:
    print(f"{k}={shlex.quote(v)}")
PY
  elif need jq; then
    jq -r '
      "AGENT_TOKEN=" + ((.token // "") | @sh),
      "RES_DOMAIN=" + ((.domain // "") | @sh),
      "RES_DNS_ACTION=" + ((.dns_action // "") | @sh),
      "RES_CERT_MODE=" + ((.cert_mode // "") | @sh),
      "RES_HY2_ID=" + (((.hy2_node.id // "") | tostring) | @sh),
      "RES_HY2_PORT=" + (((.hy2_node.port // "") | tostring) | @sh),
      "RES_VLESS_ID=" + (((.vless_node.id // "") | tostring) | @sh),
      "RES_VLESS_PORT=" + (((.vless_node.port // "") | tostring) | @sh),
      "RES_WARNINGS=" + (((.warnings // []) | join("; ")) | @sh)
    ' "$TMP/resp.json"
  else
    echo "需要 python3 或 jq 解析返回 JSON" >&2; exit 1
  fi
}

eval "$(parse_resp)"

echo "    域名:       ${RES_DOMAIN:-无（自签证书）}${RES_DNS_ACTION:+ [Cloudflare A记录: ${RES_DNS_ACTION}]}"
echo "    证书模式:   ${RES_CERT_MODE:-self}"
[ -n "$RES_HY2_ID" ] && echo "    Hysteria2:  节点 #${RES_HY2_ID} · UDP ${RES_HY2_PORT}${HOP_PORTS:+ (跳跃 ${HOP_PORTS})}"
[ -n "$RES_VLESS_ID" ] && echo "    Reality:    节点 #${RES_VLESS_ID} · TCP ${RES_VLESS_PORT}"
[ -n "$RES_WARNINGS" ] && echo "    提示:       ${RES_WARNINGS}"

# 2. 若返回新 Agent Token，自动执行 NodeHub 官方安装脚本安装 agent + xray + sing-box + BBR 调优
if [ -n "$AGENT_TOKEN" ]; then
  echo "==> [2/3] 正在安装 NodeHub Agent + Xray + sing-box 并执行内核网络调优..."
  INST_ARGS="--master ${MASTER} --token ${AGENT_TOKEN}"
  [ "$INSECURE" = 1 ] && INST_ARGS="${INST_ARGS} --insecure"
  $CURL "${MASTER}/install.sh" | bash -s -- $INST_ARGS
else
  echo "==> [2/3] 服务器已接入 NodeHub，跳过 Agent 重装，等待心跳自动拉取双栈配置..."
  systemctl restart nodehub-agent 2>/dev/null || true
fi

# 3. 等待 xray 与 sing-box 双内核拉起并校验监听
echo "==> [3/3] 等待 Agent 同步配置并拉起双内核（最长 35 秒）..."
XRAY_OK=0
SB_OK=0
for i in $(seq 1 18); do
  if [ -n "$RES_VLESS_PORT" ] && ss -tlnp 2>/dev/null | grep -Eq ":${RES_VLESS_PORT}[[:space:]].*xray"; then
    XRAY_OK=1
  fi
  if [ -n "$RES_HY2_PORT" ] && ss -ulnp 2>/dev/null | grep -Eq ":${RES_HY2_PORT}[[:space:]].*sing-box"; then
    SB_OK=1
  fi
  if { [ -z "$RES_VLESS_PORT" ] || [ "$XRAY_OK" = 1 ]; } && { [ -z "$RES_HY2_PORT" ] || [ "$SB_OK" = 1 ]; }; then
    break
  fi
  sleep 2
done

echo ""
echo "================================================================"
echo " NodeHub 一键双栈部署完成：${NAME} (${PUB_IP})"
if [ -n "$RES_DOMAIN" ]; then
  echo " 绑定域名：${RES_DOMAIN}（$([ "$RES_CERT_MODE" = "acme_dns" ] && echo 'Cloudflare DNS-01 自动签发与续期证书' || echo "证书模式: ${RES_CERT_MODE:-self}")）"
fi
[ -n "$RES_HY2_PORT" ] && echo " [UDP] Hysteria2     :${RES_HY2_PORT} (跳跃 ${HOP_PORTS:-关}) -> sing-box $([ "$SB_OK" = 1 ] && echo '运行中 ✓' || echo '启动中，请查看 /etc/nodehub/sing-box.log')"
[ -n "$RES_VLESS_PORT" ] && echo " [TCP] VLESS-Reality :${RES_VLESS_PORT} -> xray $([ "$XRAY_OK" = 1 ] && echo '运行中 ✓' || echo '启动中，请查看 /etc/nodehub/xray.log')"
if [ "$RES_CERT_MODE" = "acme_dns" ]; then
  echo " 提示：首次 ACME DNS-01 签发证书约需 20-45 秒，sing-box 会自动完成并永久续期。"
fi
echo " 请确认云厂商安全组已放行：TCP ${RES_VLESS_PORT}、UDP ${RES_HY2_PORT}${HOP_PORTS:+ 及 UDP ${HOP_PORTS}}"
echo "================================================================"
