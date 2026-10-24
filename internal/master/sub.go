package master

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"nodehub/internal/proto"
	"nodehub/internal/store"
	"nodehub/internal/util"
)

func storeNodeSettingsNone() proto.NodeSettings {
	return proto.NodeSettings{Network: "tcp", Security: "none"}
}

type subNode struct {
	Node    *store.Node
	Name    string
	Addr    string
	Country string
	// client bandwidth for hysteria2 (Mbps): >0 makes the server use Brutal instead of BBR
	UpMbps, DownMbps int
}

func flagEmoji(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return "🌐"
	}
	return string(rune(0x1F1E6+int(cc[0]-'A'))) + string(rune(0x1F1E6+int(cc[1]-'A')))
}

// userNodes returns the enabled local nodes a user can see, in display order.
func (s *Server) userNodes(u *store.User) []subNode {
	nodes, _ := s.st.ListNodes()
	servers, _ := s.st.ListServers()
	sm := map[int64]*store.Server{}
	for _, v := range servers {
		sm[v.ID] = v
	}
	checks, _ := s.st.LatestIPChecks()
	tpl := s.st.SettingOr("sub_name_template", "{flag} {name}")
	upM, _ := strconv.Atoi(s.st.Setting("sub_hy2_up_mbps"))
	downM, _ := strconv.Atoi(s.st.Setting("sub_hy2_down_mbps"))
	var out []subNode
	for _, n := range nodes {
		srv := sm[n.ServerID]
		if !n.Enabled || n.Source != "local" || srv == nil || !srv.Enabled || !nodeVisible(n, u) {
			continue
		}
		cc := ""
		if len(srv.Region) == 2 {
			cc = srv.Region
		} else if c := checks[n.ID]; c != nil {
			cc = c.GeoCountry
		}
		name := strings.NewReplacer("{flag}", flagEmoji(cc), "{name}", n.Name, "{region}", srv.Region, "{protocol}", n.Protocol,
			"{rate}", strconv.FormatFloat(n.Rate, 'f', -1, 64)).Replace(tpl)
		sn := subNode{Node: n, Name: strings.TrimSpace(name), Addr: s.connectAddr(n, srv), Country: cc}
		if n.Protocol == "hysteria2" && upM > 0 && downM > 0 {
			sn.UpMbps, sn.DownMbps = upM, downM
		}
		out = append(out, sn)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Node.Sort < out[j].Node.Sort })
	uniqueNames(out)
	return out
}

var protoLabels = map[string]string{"vless": "VLESS", "vmess": "VMess", "trojan": "Trojan", "shadowsocks": "SS", "hysteria2": "Hysteria2", "tuic": "TUIC", "anytls": "AnyTLS"}

// uniqueNames makes display names unique: Clash, sing-box and Surge reject duplicate proxy names.
// Clashing names first get the protocol appended, then a counter if that still collides.
func uniqueNames(l []subNode) {
	count := map[string]int{}
	for _, n := range l {
		count[n.Name]++
	}
	for i := range l {
		if count[l[i].Name] > 1 {
			if lb := protoLabels[l[i].Node.Protocol]; lb != "" {
				l[i].Name += " " + lb
			}
		}
	}
	seen := map[string]int{}
	for i := range l {
		base := l[i].Name
		seen[base]++
		if seen[base] > 1 {
			l[i].Name = fmt.Sprintf("%s %d", base, seen[base])
		}
	}
}

func hostPort(h string, p int) string { return net.JoinHostPort(h, strconv.Itoa(p)) }

// connPw is the password used by trojan / hysteria2 / tuic / anytls: the user's own password if set, else the UUID.
func connPw(u *store.User) string {
	if u.Password != "" {
		return u.Password
	}
	return u.UUID
}

func insecure(n *store.Node) bool { return n.Settings.CertMode == "self" }

func ssPassword(n *store.Node, u *store.User) string {
	if util.SSKeyLen(n.Settings.Cipher) > 0 {
		return n.Settings.ServerKey + ":" + util.SSUserKey(n.Settings.Cipher, u.UUID)
	}
	return u.UUID
}

// ---------------- share links ----------------

func shareLink(sn subNode, u *store.User) string {
	n, st := sn.Node, sn.Node.Settings
	frag := "#" + url.PathEscape(sn.Name)
	q := url.Values{}
	addTransport := func() {
		q.Set("type", st.Network)
		switch st.Network {
		case "ws", "httpupgrade", "xhttp":
			q.Set("path", orStr(st.Path, "/"))
			if st.Host != "" {
				q.Set("host", st.Host)
			}
			if st.Network == "xhttp" {
				q.Set("mode", "auto")
			}
		case "grpc":
			q.Set("serviceName", st.ServiceName)
			q.Set("mode", "gun")
		}
	}
	addSecurity := func() {
		switch st.Security {
		case "tls":
			q.Set("security", "tls")
			if st.SNI != "" {
				q.Set("sni", st.SNI)
			}
			if st.ALPN != "" {
				q.Set("alpn", st.ALPN)
			}
			if insecure(n) {
				q.Set("allowInsecure", "1")
			}
			q.Set("fp", orStr(st.Fingerprint, "chrome"))
		case "reality":
			q.Set("security", "reality")
			q.Set("pbk", st.RealityPublicKey)
			q.Set("sid", st.RealityShortID)
			q.Set("sni", strings.Split(orStr(st.RealityServerName, st.SNI), ",")[0])
			q.Set("fp", orStr(st.Fingerprint, "chrome"))
		default:
			q.Set("security", "none")
		}
	}
	switch n.Protocol {
	case "vless":
		q.Set("encryption", "none")
		addTransport()
		addSecurity()
		if st.Flow != "" {
			q.Set("flow", st.Flow)
		}
		return "vless://" + u.UUID + "@" + hostPort(sn.Addr, n.Port) + "?" + q.Encode() + frag
	case "vmess":
		m := map[string]string{"v": "2", "ps": sn.Name, "add": sn.Addr, "port": strconv.Itoa(n.Port), "id": u.UUID, "aid": "0", "scy": "auto",
			"net": st.Network, "type": "none", "host": st.Host, "path": st.Path, "tls": "", "sni": st.SNI}
		if st.Network == "grpc" {
			m["path"] = st.ServiceName
			m["type"] = "gun"
		}
		if st.Security == "tls" {
			m["tls"] = "tls"
			m["fp"] = orStr(st.Fingerprint, "chrome")
			if insecure(n) {
				m["allowInsecure"] = "1"
			}
		}
		b, _ := json.Marshal(m)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	case "trojan":
		addTransport()
		addSecurity()
		return "trojan://" + url.PathEscape(sn.pw(u)) + "@" + hostPort(sn.Addr, n.Port) + "?" + q.Encode() + frag
	case "shadowsocks":
		pw := ssPassword(n, u)
		if util.SSKeyLen(st.Cipher) > 0 {
			// SIP002: percent-encode the userinfo so "+", "/", "=" and the key separator survive
			return "ss://" + url.QueryEscape(st.Cipher) + ":" + url.QueryEscape(pw) + "@" + hostPort(sn.Addr, n.Port) + frag
		}
		return "ss://" + base64.RawURLEncoding.EncodeToString([]byte(st.Cipher+":"+pw)) + "@" + hostPort(sn.Addr, n.Port) + frag
	case "hysteria2":
		q.Set("sni", st.SNI)
		if st.HopPorts != "" {
			q.Set("mport", st.HopPorts)
		}
		if insecure(n) {
			q.Set("insecure", "1")
		}
		if st.Obfs == "salamander" {
			q.Set("obfs", "salamander")
			q.Set("obfs-password", st.ObfsPassword)
		}
		return "hysteria2://" + url.PathEscape(sn.pw(u)) + "@" + hostPort(sn.Addr, n.Port) + "?" + q.Encode() + frag
	case "tuic":
		q.Set("sni", st.SNI)
		q.Set("alpn", "h3")
		q.Set("congestion_control", orStr(st.Congestion, "bbr"))
		q.Set("udp_relay_mode", "native")
		if insecure(n) {
			q.Set("allow_insecure", "1")
		}
		return "tuic://" + u.UUID + ":" + url.PathEscape(sn.pw(u)) + "@" + hostPort(sn.Addr, n.Port) + "?" + q.Encode() + frag
	case "anytls":
		q.Set("sni", st.SNI)
		if insecure(n) {
			q.Set("insecure", "1")
		}
		return "anytls://" + url.PathEscape(sn.pw(u)) + "@" + hostPort(sn.Addr, n.Port) + "?" + q.Encode() + frag
	}
	return ""
}

func orStr(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// ---------------- clash / mihomo ----------------

func clashProxy(sn subNode, u *store.User) map[string]any {
	n, st := sn.Node, sn.Node.Settings
	p := map[string]any{"name": sn.Name, "server": sn.Addr, "port": n.Port, "udp": true}
	transport := func() bool {
		switch st.Network {
		case "", "tcp":
		case "ws":
			p["network"] = "ws"
			o := map[string]any{"path": orStr(st.Path, "/")}
			if st.Host != "" {
				o["headers"] = map[string]any{"Host": st.Host}
			}
			p["ws-opts"] = o
		case "httpupgrade":
			p["network"] = "ws"
			o := map[string]any{"path": orStr(st.Path, "/"), "v2ray-http-upgrade": true}
			if st.Host != "" {
				o["headers"] = map[string]any{"Host": st.Host}
			}
			p["ws-opts"] = o
		case "grpc":
			p["network"] = "grpc"
			p["grpc-opts"] = map[string]any{"grpc-service-name": st.ServiceName}
		case "xhttp":
			p["network"] = "xhttp"
			o := map[string]any{"path": orStr(st.Path, "/")}
			if st.Host != "" {
				o["host"] = st.Host
			}
			p["xhttp-opts"] = o
		default:
			return false
		}
		return true
	}
	security := func(sniKey string) {
		switch st.Security {
		case "tls":
			p["tls"] = true
			if st.SNI != "" {
				p[sniKey] = st.SNI
			}
			p["skip-cert-verify"] = insecure(n)
			p["client-fingerprint"] = orStr(st.Fingerprint, "chrome")
		case "reality":
			p["tls"] = true
			p[sniKey] = strings.Split(orStr(st.RealityServerName, st.SNI), ",")[0]
			p["reality-opts"] = map[string]any{"public-key": st.RealityPublicKey, "short-id": st.RealityShortID}
			p["client-fingerprint"] = orStr(st.Fingerprint, "chrome")
		}
	}
	switch n.Protocol {
	case "vless":
		p["type"] = "vless"
		p["uuid"] = u.UUID
		if !transport() {
			return nil
		}
		security("servername")
		if st.Flow != "" {
			p["flow"] = st.Flow
		}
	case "vmess":
		p["type"] = "vmess"
		p["uuid"] = u.UUID
		p["alterId"] = 0
		p["cipher"] = "auto"
		if !transport() {
			return nil
		}
		security("servername")
	case "trojan":
		p["type"] = "trojan"
		p["password"] = sn.pw(u)
		if !transport() {
			return nil
		}
		security("sni")
		delete(p, "tls")
	case "shadowsocks":
		p["type"] = "ss"
		p["cipher"] = st.Cipher
		p["password"] = ssPassword(n, u)
	case "hysteria2":
		p["type"] = "hysteria2"
		p["password"] = sn.pw(u)
		if st.HopPorts != "" {
			p["ports"] = st.HopPorts
			p["hop-interval"] = 30
		}
		p["sni"] = st.SNI
		p["skip-cert-verify"] = insecure(n)
		if st.Obfs == "salamander" {
			p["obfs"] = "salamander"
			p["obfs-password"] = st.ObfsPassword
		}
		if sn.DownMbps > 0 {
			p["up"], p["down"] = fmt.Sprintf("%d Mbps", sn.UpMbps), fmt.Sprintf("%d Mbps", sn.DownMbps)
		}
	case "tuic":
		p["type"] = "tuic"
		p["uuid"] = u.UUID
		p["password"] = sn.pw(u)
		p["sni"] = st.SNI
		p["alpn"] = []string{"h3"}
		p["congestion-controller"] = orStr(st.Congestion, "bbr")
		p["udp-relay-mode"] = "native"
		p["skip-cert-verify"] = insecure(n)
	case "anytls":
		p["type"] = "anytls"
		p["password"] = sn.pw(u)
		p["sni"] = st.SNI
		p["skip-cert-verify"] = insecure(n)
	default:
		return nil
	}
	return p
}

func yamlStr(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// smartRules: "global" (default) sends everything but the LAN through the proxy, like a single imported
// node; "smart" sends mainland-China sites DIRECT. ?rules=smart|global overrides the sub_rule_mode setting.
func (s *Server) smartRules(r *http.Request) bool {
	m := r.URL.Query().Get("rules")
	if m == "" {
		m = s.st.SettingOr("sub_rule_mode", "global")
	}
	return m == "smart"
}

func renderClash(nodes []subNode, u *store.User, site string, smart bool) string {
	var sb strings.Builder
	sb.WriteString("# " + site + " — generated by NodeHub\n")
	sb.WriteString("mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: info\nipv6: false\nunified-delay: true\ntcp-concurrent: true\n")
	sb.WriteString("dns:\n  enable: true\n  ipv6: false\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  default-nameserver: [223.5.5.5, 119.29.29.29]\n")
	sb.WriteString("  nameserver: ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query']\n")
	sb.WriteString("  fallback: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']\n")
	sb.WriteString("  fallback-filter: {geoip: true, geoip-code: CN}\n")
	sb.WriteString("proxies:\n")
	var names []string
	for _, sn := range nodes {
		p := clashProxy(sn, u)
		if p == nil {
			continue
		}
		sb.WriteString("  - " + yamlStr(p) + "\n")
		names = append(names, sn.Name)
	}
	if len(names) == 0 {
		names = []string{"DIRECT"}
	}
	sel := "🚀 节点选择"
	auto := "♻️ 自动选择"
	sb.WriteString("proxy-groups:\n")
	sb.WriteString("  - " + yamlStr(map[string]any{"name": sel, "type": "select", "proxies": append([]string{auto, "DIRECT"}, names...)}) + "\n")
	sb.WriteString("  - " + yamlStr(map[string]any{"name": auto, "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50, "proxies": names}) + "\n")
	sb.WriteString("rules:\n")
	rules := []string{"DOMAIN-SUFFIX,local,DIRECT", "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve"}
	// international sites of Chinese clouds sit on CDNs whose IPs are registered in China (and are listed in
	// geosite:cn), so they would go DIRECT and time out from mainland networks
	for _, d := range intlProxyDomains {
		rules = append(rules, "DOMAIN-SUFFIX,"+d+","+sel)
	}
	// GEOIP only for connections that already are IPs: resolving every domain to test its IP sends foreign
	// sites hosted on China-registered CDN ranges (EdgeOne, Alibaba CDN) DIRECT
	if smart {
		rules = append(rules, "GEOSITE,CN,DIRECT", "GEOIP,CN,DIRECT,no-resolve")
	}
	rules = append(rules, "MATCH,"+sel)
	for _, r := range rules {
		sb.WriteString("  - " + r + "\n")
	}
	return sb.String()
}

// intlProxyDomains always go through the proxy in generated client rules.
var intlProxyDomains = []string{"tencentcloud.com", "tencentcloud.co", "edgeone.ai", "alibabacloud.com",
	"byteplus.com", "tiktok.com", "tiktokv.com", "tiktokcdn.com"}

// ---------------- sing-box ----------------

func singboxOutbound(sn subNode, u *store.User) map[string]any {
	n, st := sn.Node, sn.Node.Settings
	o := map[string]any{"tag": sn.Name, "server": sn.Addr, "server_port": n.Port}
	tls := func(defALPN []string) map[string]any {
		t := map[string]any{"enabled": true, "insecure": insecure(n)}
		if st.SNI != "" {
			t["server_name"] = st.SNI
		}
		if a := strings.Split(st.ALPN, ","); st.ALPN != "" {
			t["alpn"] = a
		} else if defALPN != nil {
			t["alpn"] = defALPN
		}
		return t
	}
	transport := func() bool {
		switch st.Network {
		case "", "tcp":
		case "ws":
			tr := map[string]any{"type": "ws", "path": orStr(st.Path, "/")}
			if st.Host != "" {
				tr["headers"] = map[string]any{"Host": st.Host}
			}
			o["transport"] = tr
		case "httpupgrade":
			o["transport"] = map[string]any{"type": "httpupgrade", "path": orStr(st.Path, "/"), "host": st.Host}
		case "grpc":
			o["transport"] = map[string]any{"type": "grpc", "service_name": st.ServiceName}
		default:
			return false // xhttp is not supported by sing-box
		}
		return true
	}
	security := func() {
		switch st.Security {
		case "tls":
			t := tls(nil)
			t["utls"] = map[string]any{"enabled": true, "fingerprint": orStr(st.Fingerprint, "chrome")}
			o["tls"] = t
		case "reality":
			o["tls"] = map[string]any{"enabled": true, "server_name": strings.Split(orStr(st.RealityServerName, st.SNI), ",")[0],
				"utls":    map[string]any{"enabled": true, "fingerprint": orStr(st.Fingerprint, "chrome")},
				"reality": map[string]any{"enabled": true, "public_key": st.RealityPublicKey, "short_id": st.RealityShortID}}
		}
	}
	switch n.Protocol {
	case "vless":
		o["type"], o["uuid"] = "vless", u.UUID
		if st.Flow != "" {
			o["flow"] = st.Flow
		}
		if !transport() {
			return nil
		}
		security()
	case "vmess":
		o["type"], o["uuid"], o["security"], o["alter_id"] = "vmess", u.UUID, "auto", 0
		if !transport() {
			return nil
		}
		security()
	case "trojan":
		o["type"], o["password"] = "trojan", sn.pw(u)
		if !transport() {
			return nil
		}
		security()
	case "shadowsocks":
		o["type"], o["method"], o["password"] = "shadowsocks", st.Cipher, ssPassword(n, u)
	case "hysteria2":
		o["type"], o["password"] = "hysteria2", sn.pw(u)
		if st.HopPorts != "" {
			o["server_ports"] = []string{strings.Replace(st.HopPorts, "-", ":", 1)}
			o["hop_interval"] = "30s"
		}
		o["tls"] = tls([]string{"h3"})
		if st.Obfs == "salamander" {
			o["obfs"] = map[string]any{"type": "salamander", "password": st.ObfsPassword}
		}
		if sn.DownMbps > 0 {
			o["up_mbps"], o["down_mbps"] = sn.UpMbps, sn.DownMbps
		}
	case "tuic":
		o["type"], o["uuid"], o["password"] = "tuic", u.UUID, sn.pw(u)
		o["congestion_control"] = orStr(st.Congestion, "bbr")
		o["udp_relay_mode"] = "native"
		o["tls"] = tls([]string{"h3"})
	case "anytls":
		o["type"], o["password"] = "anytls", sn.pw(u)
		o["tls"] = tls(nil)
	default:
		return nil
	}
	return o
}

func renderSingbox(nodes []subNode, u *store.User) string {
	var obs []any
	var tags []string
	for _, sn := range nodes {
		if o := singboxOutbound(sn, u); o != nil {
			obs = append(obs, o)
			tags = append(tags, sn.Name)
		}
	}
	if len(tags) == 0 {
		tags = []string{"direct"}
	}
	outbounds := []any{
		map[string]any{"type": "selector", "tag": "proxy", "outbounds": append([]string{"auto"}, tags...), "default": "auto"},
		map[string]any{"type": "urltest", "tag": "auto", "outbounds": tags, "url": "https://www.gstatic.com/generate_204", "interval": "5m"},
	}
	outbounds = append(outbounds, obs...)
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})
	cfg := map[string]any{
		"log":       map[string]any{"level": "warn"},
		"inbounds":  []any{map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}},
		"outbounds": outbounds,
		"route": map[string]any{"auto_detect_interface": true, "final": "proxy",
			"rules": []any{map[string]any{"ip_is_private": true, "outbound": "direct"}}},
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

// ---------------- surge ----------------

func surgeLine(sn subNode, u *store.User) string {
	n, st := sn.Node, sn.Node.Settings
	name := strings.ReplaceAll(sn.Name, ",", " ")
	base := fmt.Sprintf("%s = ", name)
	skip := ""
	if insecure(n) {
		skip = ", skip-cert-verify=true"
	}
	ws := func() string {
		if st.Network == "ws" {
			s := ", ws=true, ws-path=" + orStr(st.Path, "/")
			if st.Host != "" {
				s += ", ws-headers=Host:" + st.Host
			}
			return s
		}
		return ""
	}
	if st.Network != "" && st.Network != "tcp" && st.Network != "ws" {
		return ""
	}
	switch n.Protocol {
	case "vmess":
		s := base + fmt.Sprintf("vmess, %s, %d, username=%s, vmess-aead=true", sn.Addr, n.Port, u.UUID) + ws()
		if st.Security == "tls" {
			s += ", tls=true, sni=" + st.SNI + skip
		}
		return s
	case "trojan":
		return base + fmt.Sprintf("trojan, %s, %d, password=%s, sni=%s", sn.Addr, n.Port, sn.pw(u), st.SNI) + ws() + skip
	case "shadowsocks":
		return base + fmt.Sprintf("ss, %s, %d, encrypt-method=%s, password=%s, udp-relay=true", sn.Addr, n.Port, st.Cipher, ssPassword(n, u))
	case "hysteria2":
		hop := ""
		if st.HopPorts != "" {
			hop = ", port-hopping=" + st.HopPorts + ", port-hopping-interval=30"
		}
		bw := ""
		if sn.DownMbps > 0 {
			bw = fmt.Sprintf(", download-bandwidth=%d", sn.DownMbps)
		}
		return base + fmt.Sprintf("hysteria2, %s, %d, password=%s, sni=%s", sn.Addr, n.Port, sn.pw(u), st.SNI) + hop + bw + skip
	case "tuic":
		return base + fmt.Sprintf("tuic-v5, %s, %d, uuid=%s, password=%s, sni=%s, alpn=h3", sn.Addr, n.Port, u.UUID, sn.pw(u), st.SNI) + skip
	case "anytls":
		return base + fmt.Sprintf("anytls, %s, %d, password=%s, sni=%s", sn.Addr, n.Port, sn.pw(u), st.SNI) + skip
	}
	return "" // vless is not supported by Surge
}

func renderSurge(nodes []subNode, u *store.User, selfURL string, smart bool) string {
	var sb strings.Builder
	sb.WriteString("#!MANAGED-CONFIG " + selfURL + " interval=43200 strict=false\n\n[General]\nloglevel = notify\nskip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local\n\n[Proxy]\n")
	var names []string
	for _, sn := range nodes {
		if l := surgeLine(sn, u); l != "" {
			sb.WriteString(l + "\n")
			names = append(names, strings.ReplaceAll(sn.Name, ",", " "))
		}
	}
	if len(names) == 0 {
		names = []string{"DIRECT"}
	}
	sb.WriteString("\n[Proxy Group]\nProxy = select, Auto, " + strings.Join(names, ", ") + "\n")
	sb.WriteString("Auto = url-test, " + strings.Join(names, ", ") + ", url=http://www.gstatic.com/generate_204, interval=300\n")
	sb.WriteString("\n[Rule]\n")
	for _, d := range intlProxyDomains {
		sb.WriteString("DOMAIN-SUFFIX," + d + ",Proxy\n")
	}
	if smart {
		sb.WriteString("GEOIP,CN,DIRECT,no-resolve\n")
	}
	sb.WriteString("FINAL,Proxy,dns-failed\n")
	return sb.String()
}

// ---------------- handlers ----------------

func detectTarget(r *http.Request) string {
	if t := strings.ToLower(r.URL.Query().Get("target")); t != "" {
		return t
	}
	if r.URL.Query().Get("flag") != "" {
		return strings.ToLower(r.URL.Query().Get("flag"))
	}
	ua := strings.ToLower(r.UserAgent())
	switch {
	case strings.Contains(ua, "clash") || strings.Contains(ua, "mihomo") || strings.Contains(ua, "stash") || strings.Contains(ua, "nyanpasu") || strings.Contains(ua, "flclash"):
		return "clash"
	case strings.Contains(ua, "sing-box") || strings.Contains(ua, "sfa") || strings.Contains(ua, "sfi") || strings.Contains(ua, "sfm"):
		return "singbox"
	case strings.Contains(ua, "surge"):
		return "surge"
	}
	return "v2ray"
}

// placeholderNodes is what an expired / exhausted user sees, so clients show why it stopped working.
func placeholderNodes(u *store.User) []subNode {
	reason := map[string]string{"expired": "⚠️ 套餐已到期，请续费", "exhausted": "⚠️ 流量已用尽，请续费或重置", "disabled": "⚠️ 账户已停用"}[u.Status]
	if reason == "" {
		reason = "⚠️ 当前不可用"
	}
	return []subNode{{Node: &store.Node{ID: 0, Protocol: "vless", Port: 1, Settings: storeNodeSettingsNone()}, Name: reason, Addr: "127.0.0.1"}}
}

func (s *Server) handleSub(w http.ResponseWriter, r *http.Request) {
	u, err := s.st.UserByToken(r.PathValue("token"))
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	var nodes []subNode
	if u.Status == "active" && u.Enabled {
		nodes = s.userNodes(u)
	} else {
		nodes = placeholderNodes(u)
	}
	site := s.st.SettingOr("site_name", "NodeHub")
	w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", u.Up, u.Down, u.TrafficLimit, u.ExpireAt))
	w.Header().Set("Profile-Update-Interval", "12")
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(site))
	if p := s.st.Setting("sub_support_url"); p != "" {
		w.Header().Set("Profile-Web-Page-Url", p)
	}
	w.Header().Set("Cache-Control", "no-store")
	switch detectTarget(r) {
	case "clash", "mihomo", "meta", "stash":
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		fmt.Fprint(w, renderClash(nodes, u, site, s.smartRules(r)))
	case "singbox", "sing-box", "sfa":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprint(w, renderSingbox(nodes, u))
	case "surge":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, renderSurge(nodes, u, s.subURL(r)+r.URL.RequestURI(), s.smartRules(r)))
	default:
		var lines []string
		for _, sn := range nodes {
			if l := shareLink(sn, u); l != "" {
				lines = append(lines, l)
			}
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n"))))
	}
}

func (s *Server) handleSubInfo(w http.ResponseWriter, r *http.Request) {
	u, err := s.st.UserByToken(r.PathValue("token"))
	if err != nil {
		writeErr(w, 404, "not found")
		return
	}
	nodes := s.userNodes(u)
	type n struct {
		Name     string  `json:"name"`
		Protocol string  `json:"protocol"`
		Country  string  `json:"country"`
		Rate     float64 `json:"rate"`
	}
	var list []n
	for _, sn := range nodes {
		list = append(list, n{sn.Name, sn.Node.Protocol, sn.Country, sn.Node.Rate})
	}
	v := s.viewUser(r, u)
	ok(w, map[string]any{"status": u.Status, "upload": u.Up, "download": u.Down, "total": u.TrafficLimit, "expire": u.ExpireAt,
		"remaining": v.Remaining, "expire_days": v.ExpireDays, "nodes": list, "updated_at": time.Now().Unix()})
}

// pw is the credential written into the subscription: script nodes (hysteria2-installer) authenticate every
// client with the owner password of that script, other nodes use the user's own password.
func (sn subNode) pw(u *store.User) string {
	if sn.Node.Core == "script" && sn.Node.Settings.SharedPassword != "" {
		return sn.Node.Settings.SharedPassword
	}
	return connPw(u)
}
