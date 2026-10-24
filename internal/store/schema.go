package store

// migrations are applied in order; each entry runs once.
var migrations = []string{
	`
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');

CREATE TABLE admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  pass_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  scopes TEXT NOT NULL DEFAULT 'read,write',
  ip_whitelist TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  last_used_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE servers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  host TEXT NOT NULL DEFAULT '',
  region TEXT NOT NULL DEFAULT '',
  tags TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT '',
  price TEXT NOT NULL DEFAULT '',
  expire_at INTEGER NOT NULL DEFAULT 0,
  traffic_limit INTEGER NOT NULL DEFAULT 0,
  traffic_reset_day INTEGER NOT NULL DEFAULT 1,
  note TEXT NOT NULL DEFAULT '',
  token_hash TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1,
  -- runtime (written by heartbeats)
  last_seen INTEGER NOT NULL DEFAULT 0,
  status_json TEXT NOT NULL DEFAULT '{}',
  public_ipv4 TEXT NOT NULL DEFAULT '',
  public_ipv6 TEXT NOT NULL DEFAULT '',
  agent_version TEXT NOT NULL DEFAULT '',
  applied_version TEXT NOT NULL DEFAULT '',
  apply_error TEXT NOT NULL DEFAULT '',
  month_rx INTEGER NOT NULL DEFAULT 0,
  month_tx INTEGER NOT NULL DEFAULT 0,
  last_rx_total INTEGER NOT NULL DEFAULT 0,
  last_tx_total INTEGER NOT NULL DEFAULT 0,
  unlock_json TEXT NOT NULL DEFAULT '',
  online INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE panels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT NOT NULL,           -- xboard | v2board | sspanel
  base_url TEXT NOT NULL,
  token TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  sync_interval INTEGER NOT NULL DEFAULT 60,
  last_sync_at INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  core TEXT NOT NULL,
  protocol TEXT NOT NULL,
  listen TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL,
  address TEXT NOT NULL DEFAULT '',      -- address clients connect to; default server ip
  egress_ip TEXT NOT NULL DEFAULT '',    -- IP to quality-check; default server ip
  settings_json TEXT NOT NULL DEFAULT '{}',
  rate REAL NOT NULL DEFAULT 1,
  groups TEXT NOT NULL DEFAULT '',
  sort INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  source TEXT NOT NULL DEFAULT 'local',  -- local | panel
  panel_id INTEGER NOT NULL DEFAULT 0,
  panel_node_id INTEGER NOT NULL DEFAULT 0,
  panel_node_type TEXT NOT NULL DEFAULT '',
  panel_sync_config INTEGER NOT NULL DEFAULT 0,
  speed_limit INTEGER NOT NULL DEFAULT 0,
  device_limit INTEGER NOT NULL DEFAULT 0,
  online_users INTEGER NOT NULL DEFAULT 0,
  up_total INTEGER NOT NULL DEFAULT 0,
  down_total INTEGER NOT NULL DEFAULT 0,
  note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_nodes_server ON nodes(server_id);

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  username TEXT NOT NULL DEFAULT '',
  external_id TEXT NOT NULL DEFAULT '',
  sub_token TEXT NOT NULL UNIQUE,
  traffic_limit INTEGER NOT NULL DEFAULT 0,
  up INTEGER NOT NULL DEFAULT 0,
  down INTEGER NOT NULL DEFAULT 0,
  expire_at INTEGER NOT NULL DEFAULT 0,
  speed_limit INTEGER NOT NULL DEFAULT 0,
  device_limit INTEGER NOT NULL DEFAULT 0,
  groups TEXT NOT NULL DEFAULT '',
  reset_strategy TEXT NOT NULL DEFAULT 'none', -- none | monthly | day_of_month
  reset_day INTEGER NOT NULL DEFAULT 1,
  last_reset_at INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active',  -- active | expired | exhausted | disabled
  note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_users_ext ON users(external_id) WHERE external_id <> '';

-- users pulled from a shop panel, per node
CREATE TABLE panel_users (
  node_id INTEGER NOT NULL,
  remote_id INTEGER NOT NULL,
  uuid TEXT NOT NULL,
  password TEXT NOT NULL DEFAULT '',
  speed_limit INTEGER NOT NULL DEFAULT 0,
  device_limit INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (node_id, remote_id)
);

-- traffic waiting to be pushed to a panel
CREATE TABLE panel_traffic_pending (
  node_id INTEGER NOT NULL,
  remote_id INTEGER NOT NULL,
  up INTEGER NOT NULL DEFAULT 0,
  down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (node_id, remote_id)
);

CREATE TABLE traffic_hourly (
  hour INTEGER NOT NULL,      -- unix ts truncated to hour
  node_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,   -- 0 = node total; -remote_id for panel users
  up INTEGER NOT NULL DEFAULT 0,
  down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (hour, node_id, user_id)
);
CREATE INDEX idx_traffic_user ON traffic_hourly(user_id, hour);

CREATE TABLE online_ips (
  node_id INTEGER NOT NULL,
  user_key TEXT NOT NULL,
  ip TEXT NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (node_id, user_key, ip)
);

CREATE TABLE ip_checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id INTEGER NOT NULL DEFAULT 0,
  server_id INTEGER NOT NULL DEFAULT 0,
  ip TEXT NOT NULL,
  native INTEGER NOT NULL DEFAULT 0,
  reg_country TEXT NOT NULL DEFAULT '',
  geo_country TEXT NOT NULL DEFAULT '',
  geo_city TEXT NOT NULL DEFAULT '',
  conn_type TEXT NOT NULL DEFAULT '',   -- datacenter | residential | mobile | business | unknown
  dual_isp INTEGER NOT NULL DEFAULT 0,
  is_proxy INTEGER NOT NULL DEFAULT 0,
  is_vpn INTEGER NOT NULL DEFAULT 0,
  is_tor INTEGER NOT NULL DEFAULT 0,
  is_abuse INTEGER NOT NULL DEFAULT 0,
  is_hosting INTEGER NOT NULL DEFAULT 0,
  fraud_score INTEGER NOT NULL DEFAULT -1,
  fraud_source TEXT NOT NULL DEFAULT '',
  asn TEXT NOT NULL DEFAULT '',
  org TEXT NOT NULL DEFAULT '',
  raw_json TEXT NOT NULL DEFAULT '{}',
  error TEXT NOT NULL DEFAULT '',
  checked_at INTEGER NOT NULL
);
CREATE INDEX idx_ipchecks_node ON ip_checks(node_id, checked_at);

CREATE TABLE commands (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  server_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  arg TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending', -- pending | sent | done | failed
  output TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE webhooks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  events TEXT NOT NULL DEFAULT '*',
  enabled INTEGER NOT NULL DEFAULT 1,
  last_status TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  level TEXT NOT NULL DEFAULT 'info',
  message TEXT NOT NULL,
  data_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_events_time ON events(created_at);

CREATE TABLE audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE idempotency (
  key TEXT PRIMARY KEY,
  response TEXT NOT NULL,
  status INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
`,
	// 2: remember which request an idempotency key belonged to, so a key reused for a different call is rejected
	`ALTER TABLE idempotency ADD COLUMN request TEXT NOT NULL DEFAULT '';`,
	// 3: optional per-user connection password (trojan / hysteria2 / tuic / anytls); empty = use the UUID
	`ALTER TABLE users ADD COLUMN password TEXT NOT NULL DEFAULT '';`,
}
