// Package proto defines the wire format shared by the master and the agent.
package proto

// AgentVersion is bumped whenever the agent changes in a way the master cares about.
const AgentVersion = "1.3.0"

// Heartbeat is sent by the agent every few seconds.
type Heartbeat struct {
	AgentVersion  string            `json:"agent_version"`
	Hostname      string            `json:"hostname"`
	OS            string            `json:"os"`
	Arch          string            `json:"arch"`
	Kernel        string            `json:"kernel"`
	CPUModel      string            `json:"cpu_model"`
	CPUCores      int               `json:"cpu_cores"`
	CPUUsage      float64           `json:"cpu_usage"` // percent
	Load1         float64           `json:"load1"`
	Load5         float64           `json:"load5"`
	Load15        float64           `json:"load15"`
	MemTotal      uint64            `json:"mem_total"`
	MemUsed       uint64            `json:"mem_used"`
	SwapTotal     uint64            `json:"swap_total"`
	SwapUsed      uint64            `json:"swap_used"`
	DiskTotal     uint64            `json:"disk_total"`
	DiskUsed      uint64            `json:"disk_used"`
	NetRxTotal    uint64            `json:"net_rx_total"`
	NetTxTotal    uint64            `json:"net_tx_total"`
	NetRxRate     uint64            `json:"net_rx_rate"` // bytes/s
	NetTxRate     uint64            `json:"net_tx_rate"`
	TCPConns      int               `json:"tcp_conns"`
	UDPConns      int               `json:"udp_conns"`
	Uptime        uint64            `json:"uptime"`
	PublicIPv4    string            `json:"public_ipv4"`
	PublicIPv6    string            `json:"public_ipv6"`
	CoreVersions  map[string]string `json:"core_versions"` // xray / sing-box
	CoreRunning   map[string]bool   `json:"core_running"`
	ConfigVersion string            `json:"config_version"` // version currently applied
	ApplyError    string            `json:"apply_error"`
	// Ports are the TCP/UDP ports in use on the host by programs other than the agent's own cores.
	Ports []ListenPort `json:"ports"`
}

// ListenPort is one listening socket owned by a foreign process.
type ListenPort struct {
	Proto string `json:"proto"` // tcp | udp
	Port  int    `json:"port"`
	Proc  string `json:"proc"`
}

// HeartbeatResp tells the agent whether to fetch a new config and what commands to run.
type HeartbeatResp struct {
	ConfigVersion string    `json:"config_version"`
	Commands      []Command `json:"commands"`
	ReportEvery   int       `json:"report_every"` // seconds
}

// Command is a queued instruction for an agent. There is no arbitrary shell execution by design.
type Command struct {
	ID   int64  `json:"id"`
	Type string `json:"type"` // restart_core | unlock_test | upgrade_agent | upgrade_core | reload
	Arg  string `json:"arg"`
}

// CommandResult is posted back after a command runs.
type CommandResult struct {
	ID     int64  `json:"id"`
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

// NodeConfig is the full desired state of a single node on a server.
type NodeConfig struct {
	ID       int64          `json:"id"`
	Name     string         `json:"name"`
	Core     string         `json:"core"`     // xray | singbox
	Protocol string         `json:"protocol"` // vless vmess trojan shadowsocks hysteria2 tuic anytls
	Listen   string         `json:"listen"`
	Port     int            `json:"port"`
	Settings NodeSettings   `json:"settings"`
	Users    []NodeUser     `json:"users"`
	Extra    map[string]any `json:"extra,omitempty"`
}

// NodeSettings carries transport/security parameters. Unused fields are ignored per protocol.
type NodeSettings struct {
	Network     string `json:"network,omitempty"`  // tcp ws grpc xhttp httpupgrade
	Security    string `json:"security,omitempty"` // none tls reality
	Flow        string `json:"flow,omitempty"`     // xtls-rprx-vision
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	SNI         string `json:"sni,omitempty"`
	ALPN        string `json:"alpn,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// TLS certificate: mode self (agent generates self-signed) or file
	CertMode string `json:"cert_mode,omitempty"`
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
	// Reality
	RealityDest       string `json:"reality_dest,omitempty"`
	RealityServerName string `json:"reality_server_name,omitempty"`
	RealityPrivateKey string `json:"reality_private_key,omitempty"`
	RealityPublicKey  string `json:"reality_public_key,omitempty"`
	RealityShortID    string `json:"reality_short_id,omitempty"`
	// Shadowsocks
	Cipher    string `json:"cipher,omitempty"`
	ServerKey string `json:"server_key,omitempty"`
	// Hysteria2
	UpMbps       int    `json:"up_mbps,omitempty"`
	DownMbps     int    `json:"down_mbps,omitempty"`
	Obfs         string `json:"obfs,omitempty"`
	ObfsPassword string `json:"obfs_password,omitempty"`
	// TUIC
	Congestion string `json:"congestion,omitempty"`
	// ACME (cert_mode=acme, sing-box only): certificate for SNI, issued via HTTP-01 on port 80
	ACMEEmail string `json:"acme_email,omitempty"`
	// SharedPassword is the single password of a script node (core "script"); the agent never receives it.
	SharedPassword string `json:"shared_password,omitempty"`
	// Port hopping for QUIC protocols: UDP range redirected to Port, e.g. "20000-40000"
	HopPorts string `json:"hop_ports,omitempty"`
	// DNS-01 ACME (cert_mode=acme_dns, sing-box only). The token is injected by the master from its
	// settings at config-build time and is never stored on the node.
	ACMEDNSProvider string `json:"acme_dns_provider,omitempty"`
	ACMEDNSToken    string `json:"acme_dns_token,omitempty"`
	// Hysteria2 masquerade: URL served to non-Hysteria HTTP/3 probes, e.g. https://www.bing.com
	Masquerade string `json:"masquerade,omitempty"`
}

// NodeUser is a user allowed on a node. Key is the stats identity (unique per node).
type NodeUser struct {
	Key         string `json:"key"`
	UUID        string `json:"uuid"`
	Password    string `json:"password"`
	SpeedLimit  int    `json:"speed_limit,omitempty"` // Mbps, 0 = unlimited
	DeviceLimit int    `json:"device_limit,omitempty"`
}

// AgentConfig is returned by GET /agent/v1/config.
type AgentConfig struct {
	Version string       `json:"version"`
	Nodes   []NodeConfig `json:"nodes"`
}

// Report is posted periodically by the agent with traffic deltas and online IPs.
type Report struct {
	Traffic   []TrafficDelta  `json:"traffic"`
	NodeStats []NodeTraffic   `json:"node_stats"`
	Online    []OnlineEntry   `json:"online"`
	Results   []CommandResult `json:"results"`
	Unlock    *UnlockResult   `json:"unlock,omitempty"`
}

// TrafficDelta is per-user traffic since the last report.
type TrafficDelta struct {
	NodeID int64  `json:"node_id"`
	Key    string `json:"key"`
	Up     int64  `json:"up"`
	Down   int64  `json:"down"`
}

// NodeTraffic is per-inbound traffic since the last report.
type NodeTraffic struct {
	NodeID int64 `json:"node_id"`
	Up     int64 `json:"up"`
	Down   int64 `json:"down"`
}

// OnlineEntry is a user with the IPs currently connected through a node.
type OnlineEntry struct {
	NodeID int64    `json:"node_id"`
	Key    string   `json:"key"`
	IPs    []string `json:"ips"`
}

// UnlockResult is the result of the streaming/AI service checks run from the VPS.
type UnlockResult struct {
	CheckedAt int64             `json:"checked_at"`
	Items     map[string]string `json:"items"` // service -> "yes (US)" / "no" / "originals only" / "error: ..."
}
