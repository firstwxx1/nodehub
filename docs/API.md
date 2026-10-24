# NodeHub 开放 API

给 VPN 商城调用的接口：开通 / 续费 / 停用用户、获取订阅、读取节点状态与 IP 质量。

- 基础地址：`https://你的面板域名/api/open/v1`
- 认证：`Authorization: Bearer nhk_xxx`（也可用 `X-API-Key: nhk_xxx`）。在后台「API 与 Webhook」创建，Key 只显示一次。
- 权限：`read`（只读）或 `read,write`。可设置 IP 白名单（逗号分隔，支持 CIDR）。
- 格式：请求与响应都是 JSON；错误返回 `{"error": "说明"}` 和对应 HTTP 状态码。
- 时间：Unix 秒。流量：字节（输入也可用 `*_gb` 字段）。

## 幂等

`POST` / `PUT` / `PATCH` 支持 `Idempotency-Key` 请求头：

- 同一个 Key（同一个 API Key 下）再次请求时，直接返回第一次的响应，并带 `Idempotent-Replayed: true`，**不会重复执行**。
- 同一个 Key 用在另一个接口上会返回 `422`。
- Key 保留 7 天。5xx 响应不会被记录，可以用同一个 Key 重试。
- 超时后不确定是否成功时，用 `GET /idempotency/{key}` 查询（见下文），不要换一个新 Key 重试。

建议：开通用订单号（如 `provision:{orderId}:{itemId}`），续费用支付单号（如 `renew:{subId}:{paymentId}`）。

## 用户引用 `{ref}`

路径里的 `{ref}` 可以是：

| 写法 | 含义 |
|---|---|
| `123` | NodeHub 用户 ID |
| `ext:order_1001` | 外部 ID（商城里的用户 / 订单 ID） |
| `uuid:xxxxxxxx-...` | 用户 UUID |

## 用户对象

```json
{
  "id": 12,
  "uuid": "eeb47318-d4ce-475f-a14f-d14c80103045",
  "username": "alice",
  "external_id": "order_1001",
  "sub_token": "m5gRt4J9OYIydz7Ms_daeIht",
  "sub_url": "https://nodes.example.com/sub/m5gRt4J9OYIydz7Ms_daeIht",
  "traffic_limit": 107374182400,
  "up": 1048576,
  "down": 52428800,
  "used": 53477376,
  "remaining": 107320705024,
  "expire_at": 1795405158,
  "expire_days": 30,
  "speed_limit": 0,
  "device_limit": 3,
  "online_ips": 1,
  "groups": "vip",
  "reset_strategy": "monthly",
  "reset_day": 1,
  "enabled": true,
  "status": "active",
  "note": "",
  "created_at": 1792813000,
  "updated_at": 1792813000
}
```

- `status`：`active` 正常 / `expired` 已到期 / `exhausted` 流量用尽 / `disabled` 已停用。由系统根据额度、到期时间与 `enabled` 自动计算，非 `active` 的用户会在 10 秒内从所有节点移除。
- `traffic_limit` 为 0 表示不限流量；`expire_at` 为 0 表示永不过期；`remaining` 为 -1 表示不限。
- 流量按节点倍率计费（倍率 2 的节点，用 1 GB 记 2 GB）。

## 用户写入字段

创建和修改都使用同一组字段，**不传的字段保持不变**：

| 字段 | 类型 | 说明 |
|---|---|---|
| `username` | string | 显示名 |
| `external_id` | string | 外部 ID，全局唯一 |
| `uuid` | string | 指定 UUID（一般不用传，自动生成） |
| `traffic_limit` | int | 流量额度，字节 |
| `traffic_limit_gb` | number | 流量额度，GB（与上一项二选一） |
| `add_traffic_gb` | number | 在当前额度上增加（加油包） |
| `expire_at` | int | 到期时间，0 = 永久 |
| `extend_days` | int | 从 max(现在, 当前到期时间) 起延长天数 |
| `speed_limit` | int | 限速 Mbps，0 = 不限（见 README 的限制说明） |
| `device_limit` | int | 设备（IP）数，0 = 不限 |
| `groups` | string | 节点分组，逗号分隔；节点分组为空表示所有用户可用 |
| `reset_strategy` | string | `none` / `monthly`（每月 1 号）/ `day_of_month` |
| `reset_day` | int | `day_of_month` 时每月几号重置，1-28 |
| `enabled` | bool | 启用 / 停用 |
| `note` | string | 备注 |
| `reset_traffic` | bool | 为 true 时清零已用流量 |

## 接口列表

### 连通性

`GET /ping` → `{"ok": true, "key": "商城生产环境", "time": 1792813000}`

### 创建用户

`POST /users` → `201` 用户对象

```bash
curl -X POST $BASE/users -H "$AUTH" -H "Content-Type: application/json" \
  -H "Idempotency-Key: provision:ord_9:item_1" \
  -d '{"external_id":"ord_9","username":"alice","traffic_limit_gb":100,"extend_days":30,"groups":"vip","device_limit":3}'
```

`external_id` 已存在时返回 `409`。

### 按外部 ID 创建或更新（推荐用于下单）

`PUT /users/by-external/{ext}` → 不存在时创建（`201`），存在时按字段更新（`200`）。

```bash
curl -X PUT $BASE/users/by-external/order_1001 -H "$AUTH" -H "Content-Type: application/json" \
  -H "Idempotency-Key: order_1001_paid" \
  -d '{"username":"alice","traffic_limit_gb":200,"extend_days":30,"reset_traffic":true}'
```

### 查询 / 列表

- `GET /users/{ref}` → 用户对象
- `GET /users?q=关键词&status=active&offset=0&limit=100` → `{"items": [...], "total": 1234}`（limit 最大 1000）

### 修改

`PATCH /users/{ref}` → 用户对象

```bash
# 加 50 GB
curl -X PATCH $BASE/users/ext:order_1001 -H "$AUTH" -d '{"add_traffic_gb":50}'
# 续 30 天并清零流量
curl -X PATCH $BASE/users/ext:order_1001 -H "$AUTH" -H "Idempotency-Key: renew:1001:pay_77" -d '{"extend_days":30,"reset_traffic":true}'
# 换套餐
curl -X PATCH $BASE/users/ext:order_1001 -H "$AUTH" -d '{"traffic_limit_gb":500,"groups":"vip,premium"}'
```

### 快捷操作

| 接口 | 作用 |
|---|---|
| `POST /users/{ref}/enable` | 启用 |
| `POST /users/{ref}/disable` | 停用（节点上立即移除） |
| `POST /users/{ref}/reset-traffic` | 清零已用流量 |
| `POST /users/{ref}/reset-credentials` | 重置 UUID 与订阅链接，body 可选 `{"uuid":true,"token":true}` |
| `DELETE /users/{ref}` | 删除 |

### 订阅

`GET /users/{ref}/subscription`

```json
{
  "sub_url": "https://nodes.example.com/sub/TOKEN",
  "formats": {
    "auto": "https://nodes.example.com/sub/TOKEN",
    "v2ray": ".../sub/TOKEN?target=v2ray",
    "clash": ".../sub/TOKEN?target=clash",
    "singbox": ".../sub/TOKEN?target=singbox",
    "surge": ".../sub/TOKEN?target=surge",
    "json": ".../sub/TOKEN/info"
  },
  "links": ["vless://...", "hysteria2://..."]
}
```

订阅地址本身不需要 API Key：

- `GET /sub/{token}`：按客户端 UA 自动返回格式（Clash/mihomo/Stash → Clash YAML；sing-box/SFA/SFI → sing-box JSON；Surge → Surge 配置；其他 → Base64 分享链接），`?target=` 可强制指定。
- 响应头带 `Subscription-Userinfo: upload=…; download=…; total=…; expire=…`，客户端会显示用量与到期时间。
- 用户到期 / 流量用尽 / 停用时，订阅里只剩一个提示节点（如「⚠️ 套餐已到期，请续费」）。
- `GET /sub/{token}/info`：JSON 格式的用量与可用节点列表，可直接在商城用户中心展示。

### 流量明细

`GET /users/{ref}/traffic?days=30&bucket=day|hour`

```json
{"user_id": 12, "up": 1048576, "down": 52428800, "series": [{"t": 1792771200, "up": 1024, "down": 2048}]}
```

### 在线 IP

`GET /users/{ref}/online` → 最近 5 分钟的 `[{"node_id":1,"user_key":"n1.u12","ip":"203.0.113.5","last_seen":1792813000}]`

（sing-box 内核的节点拿不到客户端 IP，`ip` 为 `-`。）

### 节点

`GET /nodes` / `GET /nodes/{id}`

```json
{
  "id": 1, "name": "东京 01", "protocol": "vless", "network": "tcp", "security": "reality",
  "address": "jp1.example.com", "port": 443, "region": "JP", "groups": ["vip"], "rate": 1,
  "enabled": true, "online": true, "online_users": 37, "load": 0.42, "cpu": 12.5, "mem_percent": 41.2,
  "up_total": 123456789, "down_total": 987654321, "source": "local",
  "ip_quality": {
    "ip": "57.180.1.2", "native": true, "reg_country": "JP", "geo_country": "JP",
    "conn_type": "datacenter", "dual_isp": false, "risks": ["proxy", "vpn"],
    "fraud_score": 75, "asn": "AS16509", "org": "Amazon.com, Inc.", "checked_at": 1792813000
  },
  "unlock": {"checked_at": 1792813000, "items": {"ChatGPT": "yes (JP)", "Netflix": "originals only (JP)"}}
}
```

`conn_type`：`datacenter` 机房 / `residential` 家宽 / `mobile` 移动 / `business` 企业 / `unknown`。

### 服务器与统计

- `GET /servers` → 服务器在线状态、IP、节点数、实时负载
- `GET /stats` → 全局统计（在线服务器、在线连接、今日/本月流量、实时带宽…）

### 幂等记录查询

`GET /idempotency/{key}`

```json
{"found": true, "request": "PATCH /api/open/v1/users/12", "status": 200, "created_at": 1792813000, "response": { "...": "用户对象" }}
```

`found: false` 表示 NodeHub 没有收到或没有处理成功这个请求，可以用**同一个 Key** 安全重试。

## Webhook

在后台「API 与 Webhook」添加。NodeHub 以 `POST` 发送 JSON：

```json
{"id": 88, "type": "user.exhausted", "level": "warn", "message": "用户 alice 流量已用尽",
 "data": {"user_id": 12, "external_id": "order_1001", "status": "exhausted", "used": 107374182400, "traffic_limit": 107374182400, "expire_at": 1795405158},
 "created_at": 1792813000}
```

请求头：

| 头 | 说明 |
|---|---|
| `X-NodeHub-Event` | 事件类型 |
| `X-NodeHub-Timestamp` | Unix 秒 |
| `X-NodeHub-Signature` | `sha256=` + hex(HMAC-SHA256(secret, timestamp + "." + 原始 body)) |

非 2xx 会重试 3 次（2s / 4s / 6s）。

事件：

| 类型 | 触发 |
|---|---|
| `user.created` | 创建用户 |
| `user.exhausted` | 流量用尽 |
| `user.expired` | 到期 |
| `user.disabled` | 被停用 |
| `user.activated` | 从以上状态恢复 |
| `user.traffic_reset` | 周期性流量重置 |
| `server.online` / `server.offline` | 服务器上线 / 离线 |
| `server.expiring` | VPS 即将到期 |
| `server.traffic_high` | VPS 本期流量超过 90% |
| `ipcheck.risk_changed` | 节点 IP 原生性 / 风险状态变化 |
| `panel.error` / `panel.recovered` | 面板对接出错 / 恢复 |

订阅时可以写 `*`（全部）、`user.*`（一类）或逗号分隔的具体事件。

### 验签示例（Node.js / NestJS）

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

export function verifyNodeHub(rawBody: Buffer, ts: string, sig: string, secret: string): boolean {
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false; // 5 分钟窗口防重放
  const want = "sha256=" + createHmac("sha256", secret).update(`${ts}.`).update(rawBody).digest("hex");
  return want.length === sig.length && timingSafeEqual(Buffer.from(want), Buffer.from(sig));
}
```

### 验签示例（PHP）

```php
$want = 'sha256=' . hash_hmac('sha256', $_SERVER['HTTP_X_NODEHUB_TIMESTAMP'] . '.' . file_get_contents('php://input'), $secret);
$ok = hash_equals($want, $_SERVER['HTTP_X_NODEHUB_SIGNATURE']);
```

## 错误码

| 状态 | 含义 |
|---|---|
| 400 | 参数错误（具体原因在 `error`） |
| 401 | 缺少或错误的 API Key |
| 403 | 权限不足 / IP 不在白名单 |
| 404 | 用户或节点不存在 |
| 409 | `external_id` 已存在 |
| 422 | Idempotency-Key 已用于另一个请求 |
| 5xx | 服务端错误，可用同一 Idempotency-Key 重试 |
