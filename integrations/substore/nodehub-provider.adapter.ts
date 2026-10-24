/**
 * NodeHub provider adapter for SubStore Platform (apps/api/src/providers).
 *
 * Drop this file into apps/api/src/providers/ and register it in the provider
 * router under adapterType "nodehub". It maps the commerce ProviderAdapter
 * contract onto NodeHub's open API (/api/open/v1):
 *
 *   createSubscription  -> POST  /users                 (external_id = requestId, Idempotency-Key = requestId)
 *   extendSubscription  -> PATCH /users/{id}            (extend_days / traffic, Idempotency-Key = requestId)
 *   suspendSubscription -> POST  /users/{id}/disable
 *   revokeSubscription  -> DELETE /users/{id}           (404 = already gone = success)
 *   getSubscription     -> GET   /users/{id}
 *   queryUsage          -> GET   /users/{id}
 *   queryByRequestId    -> GET   /idempotency/{requestId}, then GET /users/ext:{requestId}
 *
 * Outcome certainty follows @substore/shared ProviderError:
 *   - network error / timeout / 5xx on a mutating call -> UNKNOWN_OUTCOME (worker must queryByRequestId)
 *   - 429 / 503                                        -> RETRYABLE (same requestId, NodeHub dedupes it)
 *   - 4xx                                              -> CONFIRMED_FAILURE (nothing changed upstream)
 * Every mutating call carries Idempotency-Key = requestId, and NodeHub keeps keys for 7 days, so
 * retrying the same requestId inside that window can never apply twice.
 */
import { ProviderError } from "@substore/shared";
import type {
  ProviderAdapter,
  ProviderCapabilities,
  ProviderSubscriptionInput,
  ProviderSubscriptionResult,
  ProviderUsageResult,
} from "./provider-adapter.js";
import { assertSafeOutboundUrl, type OutboundUrlPolicy } from "./outbound-url.js";

export interface NodeHubAdapterConfig {
  /** e.g. https://nodes.example.com — must be on the outbound allow-list. */
  baseUrl: string;
  /** nhk_... key with read,write scope. Load from env / secret store, never from the DB in plain text. */
  apiKey: string;
  outboundPolicy: OutboundUrlPolicy;
  /** Map a catalog SKU to NodeHub node groups (e.g. "vip-30d" -> "vip"). Unknown SKUs are rejected by validateCatalog. */
  skuGroups: Record<string, string>;
  /** Clear used traffic when a subscription is renewed. Default true. */
  resetTrafficOnExtend?: boolean;
  /** "monthly" resets used traffic on the 1st of each month in NodeHub. Default "none". */
  resetStrategy?: "none" | "monthly" | "day_of_month";
  timeoutMs?: number;
}

/** Subset of NodeHub's user view that the adapter relies on. */
interface NodeHubUser {
  id: number;
  uuid: string;
  external_id: string;
  sub_token: string;
  sub_url: string;
  status: "active" | "expired" | "exhausted" | "disabled";
  up: number;
  down: number;
  traffic_limit: number;
  expire_at: number;
}

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export class NodeHubProviderAdapter implements ProviderAdapter {
  readonly adapterType = "nodehub";
  private readonly base: string;
  private validated: Promise<URL> | null = null;

  constructor(
    public readonly providerId: string,
    private readonly cfg: NodeHubAdapterConfig,
  ) {
    this.base = cfg.baseUrl.replace(/\/+$/, "") + "/api/open/v1";
  }

  getCapabilities(): ProviderCapabilities {
    return {
      createSubscription: true,
      extendSubscription: true,
      suspendSubscription: true,
      revokeSubscription: true,
      queryUsage: true,
      queryByRequestId: true,
    };
  }

  async healthCheck() {
    const t0 = Date.now();
    try {
      await this.call("GET", "/ping");
      return { ok: true, latencyMs: Date.now() - t0 };
    } catch (e) {
      return { ok: false, latencyMs: Date.now() - t0, detail: { error: e instanceof Error ? e.message : String(e) } };
    }
  }

  async validateCatalog() {
    const issues: string[] = [];
    if (Object.keys(this.cfg.skuGroups).length === 0) issues.push("skuGroups is empty: no SKU can be fulfilled");
    try {
      const nodes = await this.call<{ items: { groups: string[]; enabled: boolean }[] }>("GET", "/nodes");
      for (const [sku, group] of Object.entries(this.cfg.skuGroups)) {
        const usable = nodes.items.some((n) => n.enabled && (n.groups.length === 0 || n.groups.includes(group)));
        if (!usable) issues.push(`SKU ${sku}: no enabled NodeHub node serves group "${group}"`);
      }
    } catch (e) {
      issues.push(`cannot list nodes: ${e instanceof Error ? e.message : String(e)}`);
    }
    return { ok: issues.length === 0, issues };
  }

  async createSubscription(input: ProviderSubscriptionInput): Promise<ProviderSubscriptionResult> {
    const groups = this.groupsFor(input);
    try {
      const u = await this.call<NodeHubUser>(
        "POST",
        "/users",
        {
          external_id: input.requestId,
          username: input.requestId.slice(0, 64),
          extend_days: input.durationDays,
          traffic_limit_gb: input.trafficLimitGb ?? 0,
          device_limit: input.deviceLimit ?? 0,
          groups,
          reset_strategy: this.cfg.resetStrategy ?? "none",
          note: `sku=${input.externalSku} market=${input.marketCode}`,
        },
        input.requestId,
      );
      return toResult(u);
    } catch (e) {
      // 409 = a user with this external_id already exists, i.e. an earlier attempt of this same
      // request succeeded (e.g. its idempotency record expired). Return that user instead of failing.
      if (e instanceof ProviderError && e.code === "HTTP_409") {
        const existing = await this.findByExternal(input.requestId);
        if (existing) return toResult(existing);
      }
      throw e;
    }
  }

  async getSubscription(externalSubscriptionId: string): Promise<ProviderSubscriptionResult | null> {
    const u = await this.getUser(externalSubscriptionId);
    return u ? toResult(u) : null;
  }

  async extendSubscription(externalSubscriptionId: string, input: ProviderSubscriptionInput): Promise<ProviderSubscriptionResult> {
    const body: Record<string, unknown> = { extend_days: input.durationDays, enabled: true, groups: this.groupsFor(input) };
    if (input.trafficLimitGb != null) body.traffic_limit_gb = input.trafficLimitGb;
    if (input.deviceLimit != null) body.device_limit = input.deviceLimit;
    if (this.cfg.resetTrafficOnExtend ?? true) body.reset_traffic = true;
    const u = await this.call<NodeHubUser>("PATCH", `/users/${encodeURIComponent(externalSubscriptionId)}`, body, input.requestId);
    return toResult(u);
  }

  async suspendSubscription(externalSubscriptionId: string): Promise<boolean> {
    await this.call("POST", `/users/${encodeURIComponent(externalSubscriptionId)}/disable`);
    return true;
  }

  async revokeSubscription(externalSubscriptionId: string): Promise<boolean> {
    try {
      await this.call("DELETE", `/users/${encodeURIComponent(externalSubscriptionId)}`);
    } catch (e) {
      if (e instanceof ProviderError && e.code === "HTTP_404") return true; // already revoked
      throw e;
    }
    return true;
  }

  async queryUsage(externalSubscriptionId: string): Promise<ProviderUsageResult> {
    const u = await this.getUser(externalSubscriptionId);
    if (!u) throw new ProviderError("CONFIRMED_FAILURE", "No such NodeHub user", "NOT_FOUND", false);
    return {
      uploadBytes: BigInt(u.up),
      downloadBytes: BigInt(u.down),
      totalBytes: BigInt(u.up + u.down),
      expiresAt: u.expire_at ? new Date(u.expire_at * 1000) : undefined,
    };
  }

  /**
   * Did this requestId take effect? First ask NodeHub's idempotency store (covers create AND extend),
   * then fall back to the external_id lookup (covers creates whose idempotency record has expired).
   */
  async queryByRequestId(requestId: string): Promise<ProviderSubscriptionResult | null> {
    const rec = await this.call<{ found: boolean; status?: number; response?: NodeHubUser }>(
      "GET",
      `/idempotency/${encodeURIComponent(requestId)}`,
    );
    if (rec.found && rec.status && rec.status < 300 && rec.response) {
      // the stored response is the user as it was right after the request; return the current state
      const current = await this.getUser(String(rec.response.id));
      return toResult(current ?? rec.response);
    }
    const u = await this.findByExternal(requestId);
    return u ? toResult(u) : null;
  }

  // ---------------------------------------------------------------------------

  private groupsFor(input: ProviderSubscriptionInput): string {
    const g = this.cfg.skuGroups[input.externalSku];
    if (g === undefined) {
      throw new ProviderError("CONFIRMED_FAILURE", `SKU ${input.externalSku} is not mapped to NodeHub groups`, "SKU_UNMAPPED", false, input.requestId);
    }
    return g;
  }

  private async getUser(id: string): Promise<NodeHubUser | null> {
    try {
      return await this.call<NodeHubUser>("GET", `/users/${encodeURIComponent(id)}`);
    } catch (e) {
      if (e instanceof ProviderError && e.code === "HTTP_404") return null;
      throw e;
    }
  }

  private findByExternal(ext: string) {
    return this.getUser("ext:" + ext);
  }

  private async call<T = unknown>(method: string, path: string, body?: unknown, idempotencyKey?: string): Promise<T> {
    if (!this.validated) this.validated = assertSafeOutboundUrl(this.cfg.baseUrl, this.cfg.outboundPolicy);
    try {
      await this.validated;
    } catch (e) {
      this.validated = null;
      throw new ProviderError("CONFIRMED_FAILURE", `NodeHub URL rejected by outbound policy: ${String(e)}`, "UNSAFE_URL", false);
    }
    const headers: Record<string, string> = { Authorization: `Bearer ${this.cfg.apiKey}`, Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
    const mutating = MUTATING.has(method);
    let res: Response;
    try {
      res = await fetch(this.base + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.cfg.timeoutMs ?? 15_000),
        redirect: "error",
      });
    } catch (e) {
      // The request may have reached NodeHub: for writes we cannot know whether it applied.
      throw new ProviderError(
        mutating ? "UNKNOWN_OUTCOME" : "RETRYABLE",
        `NodeHub unreachable: ${e instanceof Error ? e.message : String(e)}`,
        "NETWORK",
        !mutating,
        idempotencyKey,
      );
    }
    const text = await res.text();
    if (res.ok) return (text ? JSON.parse(text) : null) as T;
    let message = text.slice(0, 200);
    try {
      message = (JSON.parse(text) as { error?: string }).error ?? message;
    } catch {
      /* non-JSON body */
    }
    const code = `HTTP_${res.status}`;
    if (res.status === 429 || res.status === 503) {
      throw new ProviderError("RETRYABLE", message, code, true, idempotencyKey);
    }
    if (res.status >= 500) {
      throw new ProviderError(mutating ? "UNKNOWN_OUTCOME" : "RETRYABLE", message, code, !mutating, idempotencyKey);
    }
    throw new ProviderError("CONFIRMED_FAILURE", message, code, false, idempotencyKey, { status: res.status });
  }
}

function toResult(u: NodeHubUser): ProviderSubscriptionResult {
  return {
    externalSubscriptionId: String(u.id),
    secrets: [
      { kind: "subscription_url", value: u.sub_url },
      { kind: "uuid", value: u.uuid },
    ],
    endsAt: u.expire_at ? new Date(u.expire_at * 1000) : undefined,
  };
}
