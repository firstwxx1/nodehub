# NodeHub — 多 VPS / 多节点管理系统

一个主控面板管理所有 VPS 上的代理节点：一条命令接入 VPS，网页上建节点、管用户、看流量和 IP 质量，并提供开放 API 和 Webhook 对接你的 VPN 商城；也可以作为 Xboard / V2Board / SSPanel 的节点后端。

```
┌────────────── 主控 (nodehub) ──────────────┐          ┌──────── VPS ────────┐
│ 管理后台  开放 API  订阅  Webhook/Telegram   │◀─心跳───│ nodehub-agent        │
│ 面板对接(Xboard/V2Board/SSPanel)  IP 检测    │──配置──▶│  ├─ Xray   (多节点)   │
│ SQLite                                      │◀─流量───│  └─ sing-box (多节点) │
└─────────────────────────────────────────────┘          └─────────────────────┘
```

Agent 主动连接主控（HTTPS 轮询），VPS 不需要开放任何管理端口；主控宕机时 Agent 用最后一次的配置继续提供服务，恢复后补报流量。

## 功能

**服务器**
- 一条 `curl | bash` 命令安装 Agent，自动安装 Xray 与 sing-box、systemd 守护、开启 BBR
- 实时 CPU / 内存 / 磁盘 / 负载 / 网速 / 连接数，系统与内核版本
- VPS 账单信息：服务商、价格、到期日（到期前提醒）、月流量额度与重置日（超 90% 提醒）
- 流媒体与 AI 解锁检测（ChatGPT、Claude、Gemini、Netflix、YouTube Premium、Disney+、TikTok），从 VPS 本机发起，定时或手动
- 远程命令：重启内核、重新下发配置、解锁检测、升级 Agent（不提供任意命令执行）
- 离线检测与告警

**节点**
- 一台 VPS 上可以有任意多个节点，Xray 与 sing-box 同时运行
- 协议：VLESS（TCP / WS / gRPC / XHTTP / HTTPUpgrade，TLS / REALITY / Vision）、VMess、Trojan、Shadowsocks（2022 与传统加密）、Hysteria2、TUIC v5、AnyTLS
- REALITY 密钥、SS2022 密钥、Short ID 自动生成；TLS 可用自签证书或服务器上的证书文件
- 配置先经 `xray -test` / `sing-box check` 校验再生效，失败自动回滚，错误显示在后台
- 节点分组、流量倍率、排序、复制节点、自定义连接地址（CDN / 中转）
- 在线 IP、累计流量、7 天排行

**IP 质量**（参照你给的截图做的页面）
- 原生 / 广播（RDAP 注册地 vs 实际地理位置）、机房 / 家宽 / 移动 / 企业、双 ISP、代理 / VPN / 滥用 / Tor 标记、欺诈分、ASN 与归属
- 多数据源聚合：RDAP、ip-api、ipapi.is 免费可用；填 Key 后接入 IPQualityScore、Scamalytics、AbuseIPDB、ipinfo
- 按「全部 / 原生 / 广播 / 双 ISP / 有风险 / 未检测」筛选，单个或全部重新检测，历史记录，风险变化告警

**用户与订阅**
- 流量额度、到期时间、设备数、分组、周期重置（每月 1 号或指定日）、启用 / 停用
- 到期 / 流量用尽自动从节点移除，续费后 10 秒内恢复
- 订阅按客户端自动识别格式：V2Ray Base64、Clash Meta / mihomo、sing-box、Surge，带 `Subscription-Userinfo` 用量头
- 过期用户的订阅显示「⚠️ 套餐已到期，请续费」提示节点
- 批量创建、重置 UUID / 订阅链接、30 天流量图

**对接商城**
- 开放 API（Bearer Key、读 / 写权限、IP 白名单、幂等键）：开通、续费、加流量、停用、重置、删除、订阅链接、节点状态与 IP 质量 —— 见 [docs/API.md](docs/API.md)
- Webhook（HMAC 签名、重试）：用户到期 / 用尽 / 恢复、服务器离线 / 到期、IP 风险变化等
- Telegram 通知
- 现成的 SubStore Platform 适配器：[integrations/substore](integrations/substore)
- 也可以反过来当 **Xboard / V2Board / SSPanel 的节点后端**：从面板拉用户、上报流量（原始字节）、在线 IP（`ip_节点ID` 格式，Xboard 设备数限制可用）和节点负载；Xboard / V2Board 还能直接同步端口与协议参数

**后台**
- 管理员登录（bcrypt、登录限流、可选两步验证 TOTP）、操作审计、系统事件
- 深色模式、手机可用
- 一键下载数据库备份

## 部署主控

### Docker（推荐）

```bash
git clone <你的仓库> nodehub && cd nodehub
# 修改 docker-compose.yml 里的域名 nodes.example.com 与 NODEHUB_PUBLIC_URL
docker compose up -d --build
docker compose logs nodehub | grep 初始管理员     # 没设 NODEHUB_ADMIN_PASS 时，随机密码在这里
```

自带 Caddy 自动申请 HTTPS 证书。构建时会顺便编译 amd64 / arm64 的 Agent 和带流量统计的 sing-box，供 VPS 安装时下载。

### 直接运行二进制

```bash
./scripts/build.sh                       # 需要 Go 1.24+，产物在 build/
sudo mkdir -p /opt/nodehub && sudo cp -r build/* /opt/nodehub/
sudo NODEHUB_PUBLIC_URL=https://nodes.example.com \
     /opt/nodehub/nodehub-linux-amd64 -listen 127.0.0.1:8080 -data /opt/nodehub/data -dist /opt/nodehub/dist
```

前面用 Nginx / Caddy 做 HTTPS 反代，并设置 `NODEHUB_TRUST_PROXY=1`。

环境变量：

| 变量 | 默认 | 说明 |
|---|---|---|
| `NODEHUB_LISTEN` | `:8080` | 监听地址 |
| `NODEHUB_DATA` | `./data` | 数据目录（SQLite） |
| `NODEHUB_DIST` | `./dist` | Agent / sing-box 二进制目录，供 `/dl/` 下载 |
| `NODEHUB_PUBLIC_URL` | 按访问地址 | 对外地址，用于安装命令与订阅 |
| `NODEHUB_ADMIN_USER` / `NODEHUB_ADMIN_PASS` | admin / 随机 | 仅首次启动时创建管理员 |
| `NODEHUB_TRUST_PROXY` | 关 | 设为 `1` 才信任 `X-Forwarded-For`（只在反代后面开） |
| `TZ` | | 时区，影响每日流量统计与重置 |

忘记密码：`nodehub reset-password admin 新密码`（同时关闭两步验证）。

## 接入 VPS

1. 后台「服务器 → 添加服务器」，保存后得到安装命令；
2. 在 VPS 上以 root 执行，例如：
   ```bash
   curl -fsSL https://nodes.example.com/install.sh | bash -s -- --master https://nodes.example.com --token XXXX
   ```
   国内 VPS 下载 GitHub 慢时加镜像：`GH_PROXY=https://你的镜像/ bash -s -- ...`
3. 十几秒后服务器显示「在线」；
4. 「节点 → 添加节点」，选服务器、协议、端口，保存后 10 秒内生效。

Agent 文件：`/usr/local/nodehub/`（程序与内核）、`/etc/nodehub/`（配置、证书、日志）。日志：`journalctl -u nodehub-agent -f`。卸载：`bash install.sh --uninstall`。

Agent 默认阻止访问内网地址和 BT 流量，可在 `/etc/nodehub/agent.json` 中用 `block_private` / `block_bt` 关闭。

## 对接 VPN 商城

两种方式，可以混用：

**A. 商城调 NodeHub 的 API（用户在 NodeHub）**——适合自研商城。下单成功时调用：

```bash
curl -X PUT https://nodes.example.com/api/open/v1/users/by-external/订单号 \
  -H "Authorization: Bearer nhk_xxx" -H "Idempotency-Key: 订单号_paid" \
  -d '{"traffic_limit_gb":200,"extend_days":30,"groups":"vip"}'
```

返回里的 `sub_url` 就是给客户的订阅链接。完整接口见 [docs/API.md](docs/API.md)。

**B. NodeHub 当面板的节点后端（用户在面板）**——你已经在用 Xboard / V2Board / SSPanel 时：「面板对接」里添加面板地址与通讯密钥，然后建节点时选「对接面板」并填写面板里的节点 ID。

### SubStore Platform

[integrations/substore/nodehub-provider.adapter.ts](integrations/substore/nodehub-provider.adapter.ts) 实现了 SubStore commerce 侧的 `ProviderAdapter`，已对照 `apps/api/src/providers/provider-adapter.ts`、`@substore/shared` 的 `ProviderError` 和 `outbound-url.ts` 做过严格模式类型检查，并对运行中的 NodeHub 跑通了开通、重试、续费（重试不会重复加天数）、`queryByRequestId` 恢复、停用、删除和各类错误分类。接入说明见 [integrations/substore/README.md](integrations/substore/README.md)。

## 已知限制

请在上线前了解：

- **按用户限速不生效**：Xray / sing-box 原生不支持按用户限速，`speed_limit` 只会保存并下发给面板，不会在节点上限速。
- **设备数限制不强制**：NodeHub 记录并上报在线 IP（后台可见；Xboard 会用它做设备限制），但本地用户超出设备数时不会被踢下线。
- **sing-box 节点拿不到客户端 IP**：Hysteria2 / TUIC / AnyTLS 等 sing-box 节点只能统计「在线」，没有具体 IP。
- **sing-box 流量统计需要 `with_v2ray_api` 编译**：官方发布版没有这个功能，所以主控会提供自编译版本（`build.sh` / Docker 自动完成）。如果 VPS 装的是官方版，sing-box 节点能用但没有用户流量。
- **Xray 不记录 127.0.0.1 的在线 IP**（Xray 自身行为），本机测试时看不到 IP 属正常。
- **解锁检测是启发式的**：依据各网站当前页面判断，网站改版后结果可能不准。
- **IP 质量免费模式精度有限**：没有 Key 时欺诈分是按标记估算的（界面标「估」）；ipapi.is 免 Key 只返回基础信息，双 ISP 判断需要它的免费 Key。
- **TLS 证书**：目前支持自签与服务器上的证书文件，没有内置 ACME。正式域名证书可以用 acme.sh 申请后填路径。
- 主控用 SQLite（单文件、免维护），数据库在 `data/nodehub.db`，后台可下载备份；还没有做过大规模压测。

## 测试

```bash
go test ./...                                            # 单元与 HTTP 流程测试
XRAY_BIN=/path/xray SINGBOX_BIN=/path/sing-box go test ./internal/agent/   # 用真实内核校验 16 种协议组合的配置
```

开发时实际验证过（Xray 25.10.15、sing-box 1.12.12）：6 种协议各下载 5 MB 的真实代理流量、按倍率计费精确到字节、分组可见性、流量用尽 → 自动下线 → 续费恢复、签名 Webhook、Xboard 模拟面板的配置同步 / 用户拉取 / 流量与在线 IP 上报、主控宕机期间节点继续服务并补报流量、离线告警、后台各页面无前端报错。

## 目录

```
cmd/master        主控入口       cmd/agent      Agent 入口       cmd/ipcheck-cli  IP 检测命令行（调试用）
internal/master   主控 HTTP、调度、订阅、通知、面板同步
internal/agent    配置渲染、内核守护、流量与在线 IP 采集、解锁检测
internal/ipcheck  IP 质量多源聚合     internal/panel  Xboard / V2Board / SSPanel 客户端
internal/store    SQLite 数据层       web/dist        管理后台（原生 JS，无需构建）
integrations/     商城适配器          docs/API.md     开放 API 文档
```
