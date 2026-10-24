# SubStore Platform × NodeHub

`nodehub-provider.adapter.ts` 是 SubStore commerce 侧 `ProviderAdapter` 的实现，让 SubStore 下单后的履约直接在 NodeHub 开通用户。

## 映射关系

| SubStore | NodeHub |
|---|---|
| `createSubscription(input)` | `POST /users`，`external_id = requestId`，`Idempotency-Key = requestId` |
| `extendSubscription(id, input)` | `PATCH /users/{id}`：`extend_days`、流量、默认清零已用流量，`Idempotency-Key = requestId` |
| `suspendSubscription(id)` | `POST /users/{id}/disable` |
| `revokeSubscription(id)` | `DELETE /users/{id}`（404 视为已删除） |
| `getSubscription` / `queryUsage` | `GET /users/{id}` |
| `queryByRequestId(requestId)` | `GET /idempotency/{requestId}`，找不到再查 `GET /users/ext:{requestId}` |
| `externalSubscriptionId` | NodeHub 用户 ID |
| `secrets` | `subscription_url`、`uuid`（SubStore 会加密保存） |
| `externalSku` | 通过 `skuGroups` 映射到 NodeHub 节点分组 |

错误分类：写操作遇到网络错误 / 超时 / 5xx → `UNKNOWN_OUTCOME`（worker 会走 `queryByRequestId`）；429 / 503 → `RETRYABLE`；其他 4xx → `CONFIRMED_FAILURE`。因为每个写请求都带 `Idempotency-Key = requestId`，且 NodeHub 保留 7 天，同一个 `requestId` 重试不会重复开通或重复续费。

## 接入

1. 复制到 `apps/api/src/providers/nodehub-provider.adapter.ts`；
2. 在 `provider-router.ts` 里按 `adapterType === "nodehub"` 构造：
   ```ts
   new NodeHubProviderAdapter(provider.id, {
     baseUrl: process.env.NODEHUB_BASE_URL!,          // https://nodes.example.com
     apiKey: process.env.NODEHUB_API_KEY!,            // nhk_...（read,write）
     outboundPolicy: { allowedHosts: [new URL(process.env.NODEHUB_BASE_URL!).hostname] },
     skuGroups: { "std-30d": "", "vip-30d": "vip" }, // "" = 不限分组
     resetTrafficOnExtend: true,
     resetStrategy: "monthly",
   });
   ```
3. 在 NodeHub 后台创建 API Key 时把 IP 白名单设为 SubStore worker 的出口 IP。

## 已验证

- 对照 `provider-adapter.ts`、`@substore/shared/errors.ts`、`outbound-url.ts` 用 TypeScript 严格模式检查通过；
- 对运行中的 NodeHub 实测：开通、同 `requestId` 重试返回同一用户、续费一次 +30 天且重试 +0 天、`queryByRequestId` 对开通和续费都能找到、未知请求返回 `null`、停用、重复删除、未映射 SKU / 错误 Key / 不可达 / 内网地址的错误分类。

没有在 SubStore 仓库里跑它自己的测试套件，接入后建议补一组集成用例。
