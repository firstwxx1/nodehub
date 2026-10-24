package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"nodehub/internal/proto"
)

const (
	XrayStatsService    = "xray.app.stats.command.StatsService"
	SingboxStatsService = "v2ray.core.app.stats.command.StatsService" // what sing-box actually registers at runtime
)

var privateCIDRs = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10", "::1/128"}

// RenderOptions are agent-local knobs for the generated configs.
type RenderOptions struct {
	XrayAPIPort    int
	SingboxAPIPort int
	BlockPrivate   bool
	BlockBT        bool
	CertDir        string
	ACMEDir        string
	IPv4Only       bool // server has no IPv6 route: resolve destinations to IPv4 only
}

func splitALPN(s string, def []string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

func listenAddr(n proto.NodeConfig) string {
	if n.Listen != "" {
		return n.Listen
	}
	return "0.0.0.0"
}

// certPaths returns cert/key paths for a node; for self mode the agent creates them before rendering.
func certPaths(n proto.NodeConfig, opt RenderOptions) (string, string) {
	if n.Settings.CertMode == "file" && n.Settings.CertFile != "" {
		return n.Settings.CertFile, n.Settings.KeyFile
	}
	return fmt.Sprintf("%s/node%d.crt", opt.CertDir, n.ID), fmt.Sprintf("%s/node%d.key", opt.CertDir, n.ID)
}

// ===================== Xray =====================

func RenderXray(nodes []proto.NodeConfig, opt RenderOptions) ([]byte, error) {
	inbounds := []any{}
	for _, n := range nodes {
		if n.Core != "xray" || len(n.Users) == 0 {
			continue
		}
		ib, err := xrayInbound(n, opt)
		if err != nil {
			return nil, fmt.Errorf("node %d (%s): %w", n.ID, n.Name, err)
		}
		inbounds = append(inbounds, ib)
	}
	rules := []any{}
	if opt.BlockBT {
		rules = append(rules, map[string]any{"type": "field", "protocol": []string{"bittorrent"}, "outboundTag": "block"})
	}
	if opt.BlockPrivate {
		rules = append(rules, map[string]any{"type": "field", "ip": privateCIDRs, "outboundTag": "block"})
	}
	cfg := map[string]any{
		"log":   map[string]any{"loglevel": "warning", "access": "none"},
		"api":   map[string]any{"tag": "api", "listen": "127.0.0.1:" + strconv.Itoa(opt.XrayAPIPort), "services": []string{"StatsService", "HandlerService"}},
		"stats": map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true, "handshake": 4, "connIdle": 300}},
			"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true},
		},
		"inbounds": inbounds,
		"outbounds": []any{
			map[string]any{"protocol": "freedom", "tag": "direct", "settings": map[string]any{"domainStrategy": xrayDomainStrategy(opt)}},
			map[string]any{"protocol": "blackhole", "tag": "block"},
		},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": rules},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func xrayInbound(n proto.NodeConfig, opt RenderOptions) (map[string]any, error) {
	s := n.Settings
	ib := map[string]any{
		"tag":      fmt.Sprintf("n%d", n.ID),
		"listen":   listenAddr(n),
		"port":     n.Port,
		"protocol": n.Protocol,
		"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
	}
	var clients []any
	switch n.Protocol {
	case "vless":
		for _, u := range n.Users {
			c := map[string]any{"id": u.UUID, "email": u.Key, "level": 0}
			if s.Flow != "" && (s.Network == "" || s.Network == "tcp" || s.Network == "raw") {
				c["flow"] = s.Flow
			}
			clients = append(clients, c)
		}
		ib["settings"] = map[string]any{"clients": clients, "decryption": "none"}
	case "vmess":
		for _, u := range n.Users {
			clients = append(clients, map[string]any{"id": u.UUID, "email": u.Key, "level": 0})
		}
		ib["settings"] = map[string]any{"clients": clients}
	case "trojan":
		for _, u := range n.Users {
			clients = append(clients, map[string]any{"password": u.Password, "email": u.Key, "level": 0})
		}
		ib["settings"] = map[string]any{"clients": clients}
	case "shadowsocks":
		method := s.Cipher
		if method == "" {
			method = "2022-blake3-aes-128-gcm"
		}
		if strings.HasPrefix(method, "2022-") {
			for _, u := range n.Users {
				clients = append(clients, map[string]any{"password": u.Password, "email": u.Key, "level": 0})
			}
			ib["settings"] = map[string]any{"method": method, "password": s.ServerKey, "clients": clients, "network": "tcp,udp"}
		} else {
			for _, u := range n.Users {
				clients = append(clients, map[string]any{"method": method, "password": u.Password, "email": u.Key, "level": 0})
			}
			ib["settings"] = map[string]any{"clients": clients, "network": "tcp,udp"}
		}
		return ib, nil // shadowsocks has no stream settings
	default:
		return nil, fmt.Errorf("xray 不支持协议 %s", n.Protocol)
	}

	network := s.Network
	if network == "" || network == "raw" {
		network = "tcp"
	}
	ss := map[string]any{"network": network}
	switch network {
	case "tcp":
	case "ws":
		ss["wsSettings"] = map[string]any{"path": orDefault(s.Path, "/"), "host": s.Host}
	case "grpc":
		ss["grpcSettings"] = map[string]any{"serviceName": s.ServiceName}
	case "xhttp":
		ss["xhttpSettings"] = map[string]any{"path": orDefault(s.Path, "/"), "host": s.Host, "mode": "auto"}
	case "httpupgrade":
		ss["httpupgradeSettings"] = map[string]any{"path": orDefault(s.Path, "/"), "host": s.Host}
	default:
		return nil, fmt.Errorf("不支持的传输 %s", network)
	}
	switch s.Security {
	case "tls":
		cert, key := certPaths(n, opt)
		ss["security"] = "tls"
		ss["tlsSettings"] = map[string]any{
			"serverName":   s.SNI,
			"alpn":         splitALPN(s.ALPN, []string{"h2", "http/1.1"}),
			"certificates": []any{map[string]any{"certificateFile": cert, "keyFile": key}},
		}
	case "reality":
		if n.Protocol != "vless" && n.Protocol != "trojan" {
			return nil, fmt.Errorf("reality 只支持 vless/trojan")
		}
		dest := orDefault(s.RealityDest, "www.cloudflare.com:443")
		if _, _, err := net.SplitHostPort(dest); err != nil {
			dest += ":443"
		}
		names := splitALPN(orDefault(s.RealityServerName, s.SNI), nil)
		if len(names) == 0 {
			h, _, _ := net.SplitHostPort(dest)
			names = []string{h}
		}
		ss["security"] = "reality"
		ss["realitySettings"] = map[string]any{
			"show": false, "dest": dest, "xver": 0, "serverNames": names,
			"privateKey": s.RealityPrivateKey, "shortIds": []string{s.RealityShortID},
		}
	}
	ib["streamSettings"] = ss
	return ib, nil
}

// ===================== sing-box =====================

func RenderSingbox(nodes []proto.NodeConfig, opt RenderOptions) ([]byte, error) {
	inbounds := []any{}
	var tags, users []string
	for _, n := range nodes {
		if n.Core != "singbox" || len(n.Users) == 0 {
			continue
		}
		ib, err := singboxInbound(n, opt)
		if err != nil {
			return nil, fmt.Errorf("node %d (%s): %w", n.ID, n.Name, err)
		}
		inbounds = append(inbounds, ib)
		tags = append(tags, fmt.Sprintf("n%d", n.ID))
		for _, u := range n.Users {
			users = append(users, u.Key)
		}
	}
	rules := []any{map[string]any{"action": "sniff"}}
	if opt.BlockBT {
		rules = append(rules, map[string]any{"protocol": []string{"bittorrent"}, "action": "reject"})
	}
	if opt.BlockPrivate {
		rules = append(rules, map[string]any{"ip_is_private": true, "action": "reject"})
	}
	cfg := map[string]any{
		"log":       map[string]any{"level": "warn", "timestamp": true},
		"inbounds":  inbounds,
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local"}}},
		"route":     map[string]any{"rules": rules, "final": "direct", "default_domain_resolver": map[string]any{"server": "local", "strategy": singboxStrategy(opt)}},
		"experimental": map[string]any{
			"v2ray_api": map[string]any{
				"listen": "127.0.0.1:" + strconv.Itoa(opt.SingboxAPIPort),
				"stats":  map[string]any{"enabled": true, "inbounds": tags, "users": users},
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func xrayDomainStrategy(opt RenderOptions) string {
	if opt.IPv4Only {
		return "UseIPv4"
	}
	return "UseIP"
}

func singboxStrategy(opt RenderOptions) string {
	if opt.IPv4Only {
		return "ipv4_only"
	}
	return "prefer_ipv4"
}

func singboxTLS(n proto.NodeConfig, opt RenderOptions, defALPN []string) map[string]any {
	s := n.Settings
	t := map[string]any{"enabled": true}
	if s.CertMode == "acme" || s.CertMode == "acme_dns" {
		// acme: HTTP-01 on port 80; certmagic storage is compatible with hysteria's own ACME directory,
		// so an imported certificate is reused instead of being issued again.
		// acme_dns: DNS-01 through the DNS provider's API, no inbound port needed.
		acme := map[string]any{"domain": []string{s.SNI}, "data_directory": opt.ACMEDir}
		if s.CertMode == "acme_dns" {
			acme["dns01_challenge"] = map[string]any{"provider": orDefault(s.ACMEDNSProvider, "cloudflare"), "api_token": s.ACMEDNSToken}
		} else {
			acme["disable_tls_alpn_challenge"] = true
		}
		if s.ACMEEmail != "" {
			acme["email"] = s.ACMEEmail
		}
		t["acme"] = acme
	} else {
		cert, key := certPaths(n, opt)
		t["certificate_path"], t["key_path"] = cert, key
	}
	if s.SNI != "" {
		t["server_name"] = s.SNI
	}
	if a := splitALPN(s.ALPN, defALPN); len(a) > 0 {
		t["alpn"] = a
	}
	return t
}

func singboxInbound(n proto.NodeConfig, opt RenderOptions) (map[string]any, error) {
	s := n.Settings
	if s.CertMode == "acme_dns" && s.ACMEDNSToken == "" {
		return nil, fmt.Errorf("DNS 验证需要先在「设置」里填写 Cloudflare API 令牌")
	}
	ib := map[string]any{
		"type":        n.Protocol,
		"tag":         fmt.Sprintf("n%d", n.ID),
		"listen":      strings.Replace(listenAddr(n), "0.0.0.0", "::", 1),
		"listen_port": n.Port,
	}
	users := []any{}
	switch n.Protocol {
	case "hysteria2":
		for _, u := range n.Users {
			users = append(users, map[string]any{"name": u.Key, "password": u.Password})
		}
		ib["users"] = users
		if s.UpMbps > 0 {
			ib["up_mbps"] = s.UpMbps
		}
		if s.DownMbps > 0 {
			ib["down_mbps"] = s.DownMbps
		}
		if s.Obfs == "salamander" && s.ObfsPassword != "" {
			ib["obfs"] = map[string]any{"type": "salamander", "password": s.ObfsPassword}
		}
		if s.Masquerade != "" {
			ib["masquerade"] = s.Masquerade
		}
		ib["tls"] = singboxTLS(n, opt, []string{"h3"})
		return ib, nil
	case "tuic":
		for _, u := range n.Users {
			users = append(users, map[string]any{"name": u.Key, "uuid": u.UUID, "password": u.Password})
		}
		ib["users"] = users
		ib["congestion_control"] = orDefault(s.Congestion, "bbr")
		ib["tls"] = singboxTLS(n, opt, []string{"h3"})
		return ib, nil
	case "anytls":
		for _, u := range n.Users {
			users = append(users, map[string]any{"name": u.Key, "password": u.Password})
		}
		ib["users"] = users
		ib["tls"] = singboxTLS(n, opt, nil)
		return ib, nil
	case "shadowsocks":
		method := orDefault(s.Cipher, "2022-blake3-aes-128-gcm")
		if !strings.HasPrefix(method, "2022-") {
			return nil, fmt.Errorf("sing-box 多用户 shadowsocks 只支持 2022 系列加密，请改用 xray 内核")
		}
		for _, u := range n.Users {
			users = append(users, map[string]any{"name": u.Key, "password": u.Password})
		}
		ib["method"] = method
		ib["password"] = s.ServerKey
		ib["users"] = users
		return ib, nil
	case "vless":
		for _, u := range n.Users {
			m := map[string]any{"name": u.Key, "uuid": u.UUID}
			if s.Flow != "" && (s.Network == "" || s.Network == "tcp") {
				m["flow"] = s.Flow
			}
			users = append(users, m)
		}
	case "vmess":
		for _, u := range n.Users {
			users = append(users, map[string]any{"name": u.Key, "uuid": u.UUID, "alterId": 0})
		}
	case "trojan":
		for _, u := range n.Users {
			users = append(users, map[string]any{"name": u.Key, "password": u.Password})
		}
	default:
		return nil, fmt.Errorf("sing-box 不支持协议 %s", n.Protocol)
	}
	ib["users"] = users
	switch s.Network {
	case "", "tcp":
	case "ws":
		tr := map[string]any{"type": "ws", "path": orDefault(s.Path, "/")}
		if s.Host != "" {
			tr["headers"] = map[string]any{"Host": s.Host}
		}
		ib["transport"] = tr
	case "grpc":
		ib["transport"] = map[string]any{"type": "grpc", "service_name": s.ServiceName}
	case "httpupgrade":
		ib["transport"] = map[string]any{"type": "httpupgrade", "path": orDefault(s.Path, "/"), "host": s.Host}
	default:
		return nil, fmt.Errorf("sing-box 不支持传输 %s（xhttp 请用 xray 内核）", s.Network)
	}
	switch s.Security {
	case "tls":
		ib["tls"] = singboxTLS(n, opt, nil)
	case "reality":
		dest := orDefault(s.RealityDest, "www.cloudflare.com:443")
		host, port, err := net.SplitHostPort(dest)
		if err != nil {
			host, port = dest, "443"
		}
		p, _ := strconv.Atoi(port)
		sni := orDefault(s.RealityServerName, orDefault(s.SNI, host))
		ib["tls"] = map[string]any{
			"enabled": true, "server_name": strings.Split(sni, ",")[0],
			"reality": map[string]any{
				"enabled": true, "handshake": map[string]any{"server": host, "server_port": p},
				"private_key": s.RealityPrivateKey, "short_id": []string{s.RealityShortID},
			},
		}
	}
	return ib, nil
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// NeedsCert reports whether a node needs a self-signed certificate generated by the agent.
func NeedsCert(n proto.NodeConfig) bool {
	if m := n.Settings.CertMode; m == "file" || m == "acme" || m == "acme_dns" {
		return false
	}
	switch n.Protocol {
	case "hysteria2", "tuic", "anytls":
		return true
	}
	return n.Settings.Security == "tls"
}
