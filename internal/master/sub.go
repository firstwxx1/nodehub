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
	// optional front-end relay proxy or group name (Clash dialer-proxy / sing-box detour / Surge underlying-proxy)
	DialerProxy string
	// true for auto-generated Asia->US/EU relay variants
	IsRelay bool
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
		sn := subNode{
			Node:        n,
			Name:        strings.TrimSpace(name),
			Addr:        s.connectAddr(n, srv),
			Country:     cc,
			DialerProxy: strings.TrimSpace(n.Settings.DialerProxy),
		}
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
		if sn.UpMbps > 0 && sn.DownMbps > 0 {
			q.Set("upmbps", strconv.Itoa(sn.UpMbps))
			q.Set("downmbps", strconv.Itoa(sn.DownMbps))
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
		if st.HopPorts != "" && sn.DialerProxy == "" {
			p["ports"] = st.HopPorts
			p["hop-interval"] = 60
		}
		p["sni"] = st.SNI
		p["skip-cert-verify"] = insecure(n)
		// Disable QUIC PMTUD on clients so cellular / CGNAT / Wi-Fi hotspots (MTU ~1400-1440)
		// do not silently blackhole 1438-1449B UDP packets and stall the tunnel.
		p["disable-mtu-discovery"] = true
		if st.Obfs == "salamander" {
			p["obfs"] = "salamander"
			p["obfs-password"] = st.ObfsPassword
		}
		if sn.UpMbps > 0 && sn.DownMbps > 0 {
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
	if sn.DialerProxy != "" {
		p["dialer-proxy"] = sn.DialerProxy
	}
	return p
}

func yamlStr(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// smartRules: "smart" (default) sends mainland-China sites & CN CDNs DIRECT while routing
// overseas / AI / developer / streaming traffic cleanly; "global" sends everything except LAN
// through the proxy. ?rules=smart|global overrides the sub_rule_mode setting.
func (s *Server) smartRules(r *http.Request) bool {
	m := r.URL.Query().Get("rules")
	if m == "" {
		m = s.st.SettingOr("sub_rule_mode", "smart")
	}
	return m == "smart"
}

// autoRelay: "auto" (default) synthesizes Asia-relayed copies of US/EU landing nodes
// (via dialer-proxy / detour / underlying-proxy -> "🌏 亚洲中转") so clients bypass trans-Pacific
// packet loss while preserving native US/EU exit IPs; "off" disables auto-relays.
// ?relay=auto|off overrides sub_relay_mode.
func (s *Server) autoRelay(r *http.Request) bool {
	m := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("relay")))
	if m == "" {
		m = strings.ToLower(strings.TrimSpace(s.st.SettingOr("sub_relay_mode", "auto")))
	}
	return m != "off" && m != "0" && m != "false"
}

const (
	asiaRelayGroupName = "🌏 亚洲中转"
	usEuRelayGroupName = "🚀 欧美中转"
)

func isAsiaRelayRegion(regionKey string) bool {
	switch regionKey {
	case "HK", "TW", "JP", "SG", "KR":
		return true
	}
	return false
}

func isRelayTargetRegion(regionKey string) bool {
	return regionKey == "US" || regionKey == "EU"
}

func isUDPProtocol(protoName string) bool {
	return protoName == "hysteria2" || protoName == "tuic"
}

func relayDisplayName(base string) string {
	clean := strings.TrimSpace(base)
	for _, suf := range []string{"-TCP", " TCP", "-tcp", " tcp", " VLESS", " Hysteria2"} {
		if strings.HasSuffix(clean, suf) && len(clean) > len(suf) {
			clean = strings.TrimSpace(strings.TrimSuffix(clean, suf))
			break
		}
	}
	return "🚀 中转·" + clean
}

// buildAutoRelays returns direct Asia relay node names (for "🌏 亚洲中转") and synthesized relayed
// copies of US/EU landing nodes (one best node per server, preferring TCP protocols such as
// VLESS-Reality over UDP to avoid UDP-in-UDP encapsulation overhead).
func buildAutoRelays(directNodes []subNode, relayGroup string) (asiaRelays []string, relayed []subNode) {
	existingNames := map[string]bool{}
	for _, sn := range directNodes {
		existingNames[sn.Name] = true
		if sn.DialerProxy == "" && isAsiaRelayRegion(detectRegionKey(sn)) {
			asiaRelays = append(asiaRelays, sn.Name)
		}
	}
	if len(asiaRelays) == 0 {
		return nil, nil
	}

	type candidate struct {
		sn  subNode
		tcp bool
	}
	var order []string
	best := map[string]candidate{}
	for _, sn := range directNodes {
		if sn.DialerProxy != "" || sn.Node == nil || !isRelayTargetRegion(detectRegionKey(sn)) {
			continue
		}
		var key string
		if sn.Node.ServerID > 0 {
			key = fmt.Sprintf("s:%d", sn.Node.ServerID)
		} else {
			key = "a:" + sn.Addr + "|" + relayDisplayName(sn.Name)
		}
		tcp := !isUDPProtocol(sn.Node.Protocol)
		prev, ok := best[key]
		if !ok {
			order = append(order, key)
			best[key] = candidate{sn: sn, tcp: tcp}
		} else if !prev.tcp && tcp {
			best[key] = candidate{sn: sn, tcp: true}
		}
	}

	for _, k := range order {
		base := best[k].sn
		name := relayDisplayName(base.Name)
		if existingNames[name] {
			for i := 2; ; i++ {
				cand := fmt.Sprintf("%s %d", name, i)
				if !existingNames[cand] {
					name = cand
					break
				}
			}
		}
		existingNames[name] = true
		cp := base
		cp.Name = name
		cp.DialerProxy = relayGroup
		cp.IsRelay = true
		relayed = append(relayed, cp)
	}
	return asiaRelays, relayed
}

var netCheckExactDomains = []string{
	"ipinfo.io", "api.ipify.org", "api64.ipify.org",
	"ifconfig.me", "icanhazip.com", "ip.sb", "api.ip.sb",
}

var netCheckSuffixDomains = []string{
	"dnsleaktest.com", "ipleak.net", "browserleaks.com",
	"ping0.cc", "scamalytics.com", "ip.skk.moe", "whoer.net", "ipapi.is",
}

// aiProxyDomains ensures AI coding / LLM APIs (including Google Antigravity, Gemini, Claude,
// OpenAI, Cursor, Copilot, Grok, Perplexity) always match the dedicated AI group BEFORE broader
// Google / GitHub / Microsoft rules.
var aiProxyDomains = []string{
	"antigravity.google", "cloudcode-pa.googleapis.com", "daily-cloudcode-pa.sandbox.googleapis.com",
	"gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com",
	"alkalimakersuite-pa.clients6.google.com", "makersuite.google.com",
	"notebooklm.google.com", "notebooklm.google", "labs.google", "deepmind.com", "deepmind.google",
	"anthropic.com", "claude.ai", "claude.com", "clau.de",
	"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "sora.com",
	"cursor.sh", "cursor.com", "cursor-cdn.com", "windsurf.com", "codeium.com",
	"githubcopilot.com", "copilot.github.com", "copilot.microsoft.com",
	"perplexity.ai", "x.ai", "grok.com", "openrouter.ai", "groq.com",
	"huggingface.co", "hf.co", "poe.com", "midjourney.com", "elevenlabs.io", "civitai.com", "cerebras.ai",
}

var devProxyDomains = []string{
	"ghcr.io", "docker.io", "docker.com", "gcr.io", "quay.io",
	"npmjs.org", "pypi.org", "crates.io", "golang.org", "go.dev", "brew.sh",
	"cloudflare.com", "workers.dev", "pages.dev", "vercel.com", "vercel.app", "supabase.co", "jsdelivr.net",
}

var searchBypassDomains = []string{
	"bing.com", "bing.net", "bingapis.com",
	"duckduckgo.com", "duck.com",
	"yandex.com", "yandex.ru",
	"startpage.com", "brave.com",
	"ecosia.org", "qwant.com", "mojeek.com",
}

type regionBucket struct {
	Key   string
	Name  string
	Nodes []string
}

type nodeCatalog struct {
	Regions []regionBucket
	UDP     []string
	TCP     []string
	All     []string
}

func (c nodeCatalog) hasDualStack() bool { return len(c.UDP) > 0 && len(c.TCP) > 0 }

func (c nodeCatalog) regionNames(prefer ...string) []string {
	byKey := make(map[string]string, len(c.Regions))
	for _, r := range c.Regions {
		byKey[r.Key] = r.Name
	}
	var out []string
	seen := map[string]bool{}
	for _, k := range prefer {
		if nm, ok := byKey[k]; ok && !seen[nm] {
			out = append(out, nm)
			seen[nm] = true
		}
	}
	for _, r := range c.Regions {
		if !seen[r.Name] {
			out = append(out, r.Name)
			seen[r.Name] = true
		}
	}
	return out
}

func dedupStrings(groups ...[]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, g := range groups {
		for _, s := range g {
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

var euCountryCodes = map[string]bool{
	"SE": true, "DE": true, "NL": true, "GB": true, "UK": true, "FR": true,
	"CH": true, "FI": true, "NO": true, "IE": true, "IT": true, "ES": true,
	"PL": true, "AT": true, "BE": true, "LU": true, "CZ": true, "DK": true,
	"PT": true, "RO": true, "BG": true, "EE": true, "LV": true, "LT": true, "IS": true,
}

func detectRegionKey(sn subNode) string {
	// Always trust explicit ISO-2 country code first so vendor names never misclassify nodes.
	switch strings.ToUpper(strings.TrimSpace(sn.Country)) {
	case "HK":
		return "HK"
	case "TW":
		return "TW"
	case "JP":
		return "JP"
	case "SG":
		return "SG"
	case "US":
		return "US"
	case "KR":
		return "KR"
	default:
		if euCountryCodes[strings.ToUpper(strings.TrimSpace(sn.Country))] {
			return "EU"
		}
	}
	nm := sn.Name
	low := strings.ToLower(nm)
	switch {
	case strings.Contains(nm, "香港") || strings.Contains(nm, "HK"):
		return "HK"
	case strings.Contains(nm, "台湾") || strings.Contains(nm, "台灣") || strings.Contains(nm, "TW"):
		return "TW"
	case strings.Contains(nm, "日本") || strings.Contains(nm, "东京") || strings.Contains(nm, "東京") || strings.Contains(nm, "大阪") || strings.Contains(nm, "JP"):
		return "JP"
	case strings.Contains(nm, "新加坡") || strings.Contains(nm, "狮城") || strings.Contains(nm, "SG"):
		return "SG"
	case strings.Contains(nm, "美国") || strings.Contains(nm, "美國") || strings.Contains(nm, "洛杉矶") || strings.Contains(nm, "圣何塞") || strings.Contains(nm, "纽约") || strings.Contains(nm, "芝加哥") || strings.Contains(low, "racknerd") || strings.Contains(low, "servercheap") || strings.Contains(low, "chicago"):
		return "US"
	case strings.Contains(nm, "韩国") || strings.Contains(nm, "韓國") || strings.Contains(nm, "首尔") || strings.Contains(nm, "KR"):
		return "KR"
	case strings.Contains(nm, "瑞典") || strings.Contains(nm, "德国") || strings.Contains(nm, "德國") || strings.Contains(nm, "荷兰") || strings.Contains(nm, "荷蘭") || strings.Contains(nm, "英国") || strings.Contains(nm, "英國") || strings.Contains(nm, "法国") || strings.Contains(nm, "法國") || strings.Contains(nm, "欧洲") || strings.Contains(nm, "歐洲"):
		return "EU"
	default:
		return "OTHER"
	}
}

func classifySubNodes(nodes []subNode) nodeCatalog {
	order := []struct{ key, name string }{
		{"HK", "香港"}, {"TW", "台湾"}, {"JP", "日本"}, {"SG", "新加坡"},
		{"US", "美国"}, {"KR", "韩国"}, {"EU", "欧洲"}, {"OTHER", "其他地区"},
	}
	buckets := map[string][]string{}
	var cat nodeCatalog
	for _, sn := range nodes {
		cat.All = append(cat.All, sn.Name)
		k := detectRegionKey(sn)
		buckets[k] = append(buckets[k], sn.Name)
		if sn.Node != nil {
			switch sn.Node.Protocol {
			case "hysteria2", "tuic":
				cat.UDP = append(cat.UDP, sn.Name)
			default:
				cat.TCP = append(cat.TCP, sn.Name)
			}
		}
	}
	for _, spec := range order {
		if list := buckets[spec.key]; len(list) > 0 {
			cat.Regions = append(cat.Regions, regionBucket{Key: spec.key, Name: spec.name, Nodes: list})
		}
	}
	return cat
}

func renderClash(nodes []subNode, u *store.User, site string, smart, relay bool) string {
	var sb strings.Builder
	sb.WriteString("# " + site + " — generated by NodeHub\n")
	sb.WriteString("mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: warning\nipv6: false\nunified-delay: true\ntcp-concurrent: true\nfind-process-mode: strict\nkeep-alive-interval: 30\nexternal-controller: 127.0.0.1:9090\n\n")
	sb.WriteString("profile:\n  store-selected: true\n  store-fake-ip: true\n\n")
	sb.WriteString("geodata-mode: true\ngeo-auto-update: true\ngeo-update-interval: 24\n")
	sb.WriteString("geox-url:\n")
	sb.WriteString("  geoip: \"https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat\"\n")
	sb.WriteString("  geosite: \"https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat\"\n")
	sb.WriteString("  mmdb: \"https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb\"\n\n")
	sb.WriteString("dns:\n  enable: true\n  ipv6: false\n  prefer-h3: false\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  default-nameserver:\n    - 223.5.5.5\n    - 119.29.29.29\n")
	sb.WriteString("  direct-nameserver:\n    - 223.5.5.5\n    - 119.29.29.29\n")
	sb.WriteString("  nameserver:\n    - https://dns.alidns.com/dns-query\n    - https://doh.pub/dns-query\n")
	sb.WriteString("  proxy-server-nameserver:\n    - https://dns.alidns.com/dns-query\n    - https://doh.pub/dns-query\n")
	sb.WriteString("  fake-ip-filter:\n    - \"geosite:private\"\n    - \"geosite:connectivity-check\"\n    - \"*.lan\"\n    - \"*.local\"\n    - \"*.localhost\"\n    - \"*.localdomain\"\n    - \"time.*.com\"\n    - \"time.*.gov\"\n    - \"time.*.edu.cn\"\n    - \"time.*.apple.com\"\n    - \"ntp.*.com\"\n    - \"*.ntp.org.cn\"\n    - \"+.pool.ntp.org\"\n    - \"+.stun.*.*\"\n    - \"+.stun.*.*.*\"\n    - \"+.stun.*.*.*.*\"\n    - \"+.msftncsi.com\"\n    - \"+.msftconnecttest.com\"\n    - \"localhost.ptlogin2.qq.com\"\n    - \"localhost.sec.qq.com\"\n    - \"+.srv.nintendo.net\"\n    - \"+.stun.playstation.net\"\n    - \"xbox.*.microsoft.com\"\n    - \"+.xboxlive.com\"\n    - \"*.battlenet.com.cn\"\n    - \"*.wotgame.cn\"\n    - \"*.wggames.cn\"\n    - \"*.wowsgame.cn\"\n    - \"+.market.xiaomi.com\"\n    - \"+.tailscale.com\"\n    - \"*.ts.net\"\n\n")
	sb.WriteString("sniffer:\n  enable: true\n  parse-pure-ip: true\n  force-dns-mapping: true\n  override-destination: true\n  sniff:\n    HTTP:\n      ports: [80, 8080-8880]\n    TLS:\n      ports: [443, 8443]\n    QUIC:\n      ports: [443, 8443]\n  skip-domain:\n    - \"+.push.apple.com\"\n    - \"+.mijia.cloud\"\n    - \"+.wechat.com\"\n    - \"+.qpic.cn\"\n    - \"+.qq.com\"\n\n")

	sb.WriteString("proxies:\n")
	var validNodes []subNode
	for _, sn := range nodes {
		p := clashProxy(sn, u)
		if p == nil {
			continue
		}
		sb.WriteString("  - " + yamlStr(p) + "\n")
		validNodes = append(validNodes, sn)
	}
	var asiaRelays, relayNames []string
	if relay {
		var relayedNodes []subNode
		asiaRelays, relayedNodes = buildAutoRelays(validNodes, asiaRelayGroupName)
		for _, rn := range relayedNodes {
			if p := clashProxy(rn, u); p != nil {
				sb.WriteString("  - " + yamlStr(p) + "\n")
				validNodes = append(validNodes, rn)
				relayNames = append(relayNames, rn.Name)
			}
		}
	}

	cat := classifySubNodes(validNodes)
	names := cat.All
	if len(names) == 0 {
		names = []string{"DIRECT"}
	}

	sel := "一键代理"
	auto := "自动选择"
	fb := "故障转移"
	udpGrp := "⚡ 高速 UDP"
	tcpGrp := "🛡️ 稳定 TCP"
	direct := "国内直连"
	dual := cat.hasDualStack()
	hasRelay := len(relayNames) > 0 && len(asiaRelays) > 0

	protoGroups := []string{}
	if dual {
		protoGroups = []string{udpGrp, tcpGrp}
	}
	relayGroups := []string{}
	if hasRelay {
		relayGroups = []string{usEuRelayGroupName}
	}
	allRegions := cat.regionNames()
	aiRegions := cat.regionNames("US", "JP", "TW", "SG", "KR", "EU", "OTHER")
	ttRegions := cat.regionNames("JP", "US", "TW", "SG", "KR", "EU", "OTHER")
	tgRegions := cat.regionNames("SG", "JP", "TW", "US", "HK", "EU", "OTHER")
	mediaRegions := cat.regionNames("TW", "JP", "US", "SG", "HK", "EU", "OTHER")

	sb.WriteString("proxy-groups:\n")
	// 1. 核心调度组
	topList := dedupStrings([]string{auto, fb}, protoGroups, relayGroups, allRegions, []string{direct}, names)
	sb.WriteString("  - " + yamlStr(map[string]any{"name": sel, "type": "select", "proxies": topList}) + "\n")
	sb.WriteString("  - " + yamlStr(map[string]any{"name": auto, "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 180, "tolerance": 50, "lazy": true, "proxies": names}) + "\n")
	fbProxies := names
	if dual {
		// 正常优先高速 UDP（Hy2），运营商限速/阻断 UDP 时自动无缝切至稳定 TCP（Reality）
		fbProxies = []string{udpGrp, tcpGrp}
	}
	sb.WriteString("  - " + yamlStr(map[string]any{"name": fb, "type": "fallback", "url": "https://www.gstatic.com/generate_204", "interval": 120, "lazy": true, "proxies": fbProxies}) + "\n")
	if dual {
		sb.WriteString("  - " + yamlStr(map[string]any{"name": udpGrp, "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 180, "tolerance": 50, "lazy": true, "proxies": cat.UDP}) + "\n")
		sb.WriteString("  - " + yamlStr(map[string]any{"name": tcpGrp, "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 180, "tolerance": 50, "lazy": true, "proxies": cat.TCP}) + "\n")
	}
	if hasRelay {
		// 欧美中转组通过 🌏 亚洲中转 绕过跨太平洋晚高峰丢包，同时保留欧美原生出口 IP
		sb.WriteString("  - " + yamlStr(map[string]any{"name": usEuRelayGroupName, "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 180, "tolerance": 50, "lazy": true, "proxies": relayNames}) + "\n")
		sb.WriteString("  - " + yamlStr(map[string]any{"name": asiaRelayGroupName, "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 180, "tolerance": 50, "lazy": true, "proxies": asiaRelays}) + "\n")
	}

	// 2. 精准业务分流组
	stdBusiness := dedupStrings([]string{sel}, protoGroups, relayGroups, allRegions, []string{direct})
	aiTail := []string{sel, direct}
	if dual {
		aiTail = []string{tcpGrp, udpGrp, sel, direct}
	}
	sb.WriteString("  - " + yamlStr(map[string]any{"name": "AI", "type": "select", "proxies": dedupStrings(aiRegions, relayGroups, aiTail)}) + "\n")
	sb.WriteString("  - " + yamlStr(map[string]any{"name": "YouTube", "type": "select", "proxies": stdBusiness}) + "\n")
	sb.WriteString("  - " + yamlStr(map[string]any{"name": "Google", "type": "select", "proxies": stdBusiness}) + "\n")
	ghOpts := stdBusiness
	if dual {
		ghOpts = dedupStrings([]string{sel, tcpGrp, udpGrp}, relayGroups, allRegions, []string{direct})
	}
	sb.WriteString("  - " + yamlStr(map[string]any{"name": "GitHub", "type": "select", "proxies": ghOpts}) + "\n")
	sb.WriteString("  - " + yamlStr(map[string]any{"name": "国际流媒体", "type": "select", "proxies": dedupStrings([]string{sel}, mediaRegions, relayGroups, protoGroups, []string{direct})}) + "\n")
	sb.WriteString("  - " + yamlStr(map[string]any{"name": "Telegram", "type": "select", "proxies": dedupStrings([]string{sel}, tgRegions, protoGroups, []string{direct})}) + "\n")
	sb.WriteString("  - " + yamlStr(map[string]any{"name": "TikTok", "type": "select", "proxies": dedupStrings(ttRegions, relayGroups, []string{sel}, protoGroups, []string{direct})}) + "\n")
	sb.WriteString("  - " + yamlStr(map[string]any{"name": "Steam", "type": "select", "proxies": stdBusiness}) + "\n")
	sb.WriteString("  - " + yamlStr(map[string]any{"name": "Apple", "type": "select", "proxies": dedupStrings([]string{direct, sel}, allRegions)}) + "\n")
	sb.WriteString("  - " + yamlStr(map[string]any{"name": "Microsoft", "type": "select", "proxies": dedupStrings([]string{direct, sel}, allRegions)}) + "\n")
	sb.WriteString("  - " + yamlStr(map[string]any{"name": "网络检测", "type": "select", "proxies": stdBusiness}) + "\n")

	// 3. 真实地区分组（仅展示有节点的地区，避免出现空地区兜底组）
	for _, r := range cat.Regions {
		sb.WriteString("  - " + yamlStr(map[string]any{"name": r.Name, "type": "url-test", "url": "https://www.gstatic.com/generate_204", "interval": 180, "tolerance": 50, "lazy": true, "proxies": r.Nodes}) + "\n")
	}
	sb.WriteString("  - " + yamlStr(map[string]any{"name": direct, "type": "select", "proxies": []string{"DIRECT"}}) + "\n")

	sb.WriteString("rules:\n")
	rules := []string{
		// 1. 局域网与私有地址最高优先级直连
		"GEOSITE,private,DIRECT",
		"GEOIP,private,DIRECT,no-resolve",
		"DOMAIN-SUFFIX,local,DIRECT",
		"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
	}
	// 2. IP 与网络质量检测
	for _, d := range netCheckExactDomains {
		rules = append(rules, "DOMAIN,"+d+",网络检测")
	}
	for _, d := range netCheckSuffixDomains {
		rules = append(rules, "DOMAIN-SUFFIX,"+d+",网络检测")
	}
	// 3. AI 服务（必须排在 Google / GitHub / Microsoft 之前，避免误入普通代理或直连）
	for _, d := range aiProxyDomains {
		rules = append(rules, "DOMAIN-SUFFIX,"+d+",AI")
	}
	rules = append(rules, "GEOSITE,category-ai-!cn,AI")
	// 4. GitHub 与开发镜像/云平台
	rules = append(rules, "GEOSITE,github,GitHub")
	for _, d := range devProxyDomains {
		rules = append(rules, "DOMAIN-SUFFIX,"+d+",GitHub")
	}
	// 5. 核心海外业务与流媒体
	rules = append(rules,
		"GEOSITE,youtube,YouTube",
		"GEOSITE,google,Google",
		"GEOSITE,telegram,Telegram",
		"GEOIP,telegram,Telegram,no-resolve",
		"GEOSITE,tiktok,TikTok",
		"GEOSITE,netflix,国际流媒体",
		"GEOSITE,disney,国际流媒体",
		"GEOSITE,spotify,国际流媒体",
		"GEOSITE,hbo,国际流媒体",
		"GEOSITE,primevideo,国际流媒体",
		"GEOSITE,bahamut,国际流媒体",
	)
	// 6. Steam：智能模式下游戏下载 CDN 直连跑满宽带，商店/社区走代理
	if smart {
		rules = append(rules, "GEOSITE,steam@cn,DIRECT")
	}
	rules = append(rules, "GEOSITE,steam,Steam")
	// 7. 社交/支付/搜索引擎绕行/出海云服务（排在 Microsoft 之前防止 Bing 被吞进直连）
	rules = append(rules,
		"GEOSITE,twitter,"+sel,
		"GEOSITE,discord,"+sel,
		"GEOSITE,reddit,"+sel,
		"GEOSITE,paypal,"+sel,
	)
	for _, d := range searchBypassDomains {
		rules = append(rules, "DOMAIN-SUFFIX,"+d+","+sel)
	}
	for _, d := range intlProxyDomains {
		rules = append(rules, "DOMAIN-SUFFIX,"+d+","+sel)
	}
	// 8. Apple 与 Microsoft（智能模式下国内 CDN 自动直连）
	if smart {
		rules = append(rules, "GEOSITE,apple-cn,DIRECT")
	}
	rules = append(rules, "GEOSITE,apple,Apple")
	if smart {
		rules = append(rules, "GEOSITE,microsoft@cn,DIRECT")
	}
	rules = append(rules, "GEOSITE,microsoft,Microsoft")
	// 9. 国内直连（smart 模式）
	if smart {
		rules = append(rules,
			"GEOSITE,bilibili,DIRECT",
			"GEOSITE,CN,DIRECT",
			"GEOIP,CN,DIRECT,no-resolve",
		)
	}
	rules = append(rules, "MATCH,"+sel)

	for _, r := range rules {
		sb.WriteString("  - " + r + "\n")
	}
	return sb.String()
}

// intlProxyDomains always go through the proxy in generated client rules.
var intlProxyDomains = []string{"tencentcloud.com", "tencentcloud.co", "edgeone.ai", "alibabacloud.com", "byteplus.com"}

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
		if st.HopPorts != "" && sn.DialerProxy == "" {
			o["server_ports"] = []string{strings.Replace(st.HopPorts, "-", ":", 1)}
			o["hop_interval"] = "60s"
		}
		o["tls"] = tls([]string{"h3"})
		if st.Obfs == "salamander" {
			o["obfs"] = map[string]any{"type": "salamander", "password": st.ObfsPassword}
		}
		if sn.UpMbps > 0 && sn.DownMbps > 0 {
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
	if sn.DialerProxy != "" {
		o["detour"] = sn.DialerProxy
	}
	return o
}

func renderSingbox(nodes []subNode, u *store.User, smart, relay bool) string {
	var obs []any
	var validNodes []subNode
	for _, sn := range nodes {
		if o := singboxOutbound(sn, u); o != nil {
			obs = append(obs, o)
			validNodes = append(validNodes, sn)
		}
	}
	var asiaRelays, relayNames []string
	if relay {
		var relayedNodes []subNode
		asiaRelays, relayedNodes = buildAutoRelays(validNodes, asiaRelayGroupName)
		for _, rn := range relayedNodes {
			if o := singboxOutbound(rn, u); o != nil {
				obs = append(obs, o)
				validNodes = append(validNodes, rn)
				relayNames = append(relayNames, rn.Name)
			}
		}
	}
	cat := classifySubNodes(validNodes)
	tags := cat.All
	if len(tags) == 0 {
		tags = []string{"direct"}
	}

	sel := "一键代理"
	auto := "自动选择"
	udpGrp := "⚡ 高速 UDP"
	tcpGrp := "🛡️ 稳定 TCP"
	directTag := "国内直连"
	dual := cat.hasDualStack()
	hasRelay := len(relayNames) > 0 && len(asiaRelays) > 0

	protoGroups := []string{}
	if dual {
		protoGroups = []string{udpGrp, tcpGrp}
	}
	relayGroups := []string{}
	if hasRelay {
		relayGroups = []string{usEuRelayGroupName}
	}
	allRegions := cat.regionNames()
	aiRegions := cat.regionNames("US", "JP", "TW", "SG", "KR", "EU", "OTHER")
	ttRegions := cat.regionNames("JP", "US", "TW", "SG", "KR", "EU", "OTHER")
	tgRegions := cat.regionNames("SG", "JP", "TW", "US", "HK", "EU", "OTHER")
	mediaRegions := cat.regionNames("TW", "JP", "US", "SG", "HK", "EU", "OTHER")

	topOutbounds := dedupStrings([]string{auto}, protoGroups, relayGroups, allRegions, []string{directTag}, tags)
	stdBusiness := dedupStrings([]string{sel}, protoGroups, relayGroups, allRegions, []string{directTag})
	aiTail := []string{sel, directTag}
	if dual {
		aiTail = []string{tcpGrp, udpGrp, sel, directTag}
	}
	aiOpts := dedupStrings(aiRegions, relayGroups, aiTail)
	ttOpts := dedupStrings(ttRegions, relayGroups, []string{sel}, protoGroups, []string{directTag})
	ghOpts := stdBusiness
	if dual {
		ghOpts = dedupStrings([]string{sel, tcpGrp, udpGrp}, relayGroups, allRegions, []string{directTag})
	}

	outbounds := []any{
		map[string]any{"type": "selector", "tag": sel, "outbounds": topOutbounds, "default": auto, "interrupt_exist_connections": true},
		map[string]any{"type": "urltest", "tag": auto, "outbounds": tags, "url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50},
	}
	if dual {
		outbounds = append(outbounds,
			map[string]any{"type": "urltest", "tag": udpGrp, "outbounds": cat.UDP, "url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50},
			map[string]any{"type": "urltest", "tag": tcpGrp, "outbounds": cat.TCP, "url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50},
		)
	}
	if hasRelay {
		outbounds = append(outbounds,
			map[string]any{"type": "urltest", "tag": usEuRelayGroupName, "outbounds": relayNames, "url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50},
			map[string]any{"type": "urltest", "tag": asiaRelayGroupName, "outbounds": asiaRelays, "url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50},
		)
	}
	for _, r := range cat.Regions {
		outbounds = append(outbounds, map[string]any{"type": "urltest", "tag": r.Name, "outbounds": r.Nodes, "url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50})
	}
	outbounds = append(outbounds,
		map[string]any{"type": "selector", "tag": "AI", "default": aiOpts[0], "outbounds": aiOpts, "interrupt_exist_connections": true},
		map[string]any{"type": "selector", "tag": "YouTube", "default": sel, "outbounds": stdBusiness, "interrupt_exist_connections": true},
		map[string]any{"type": "selector", "tag": "Google", "default": sel, "outbounds": stdBusiness, "interrupt_exist_connections": true},
		map[string]any{"type": "selector", "tag": "GitHub", "default": sel, "outbounds": ghOpts, "interrupt_exist_connections": true},
		map[string]any{"type": "selector", "tag": "国际流媒体", "default": sel, "outbounds": dedupStrings([]string{sel}, mediaRegions, relayGroups, protoGroups, []string{directTag}), "interrupt_exist_connections": true},
		map[string]any{"type": "selector", "tag": "Steam", "default": sel, "outbounds": stdBusiness, "interrupt_exist_connections": true},
		map[string]any{"type": "selector", "tag": "Telegram", "default": sel, "outbounds": dedupStrings([]string{sel}, tgRegions, protoGroups, []string{directTag}), "interrupt_exist_connections": true},
		map[string]any{"type": "selector", "tag": "TikTok", "default": ttOpts[0], "outbounds": ttOpts, "interrupt_exist_connections": true},
		map[string]any{"type": "selector", "tag": "Apple", "default": directTag, "outbounds": dedupStrings([]string{directTag, sel}, allRegions), "interrupt_exist_connections": true},
		map[string]any{"type": "selector", "tag": "Microsoft", "default": directTag, "outbounds": dedupStrings([]string{directTag, sel}, allRegions), "interrupt_exist_connections": true},
		map[string]any{"type": "selector", "tag": "网络检测", "default": sel, "outbounds": stdBusiness, "interrupt_exist_connections": true},
	)
	outbounds = append(outbounds, obs...)
	outbounds = append(outbounds, map[string]any{"type": "selector", "tag": directTag, "outbounds": []string{"direct"}})
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})

	rules := []any{
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
		map[string]any{"ip_is_private": true, "outbound": "direct"},
		map[string]any{"domain_suffix": []string{"lan", "local", "localhost"}, "outbound": "direct"},
		map[string]any{"rule_set": []string{"geosite-private", "geoip-private"}, "outbound": "direct"},
		map[string]any{"clash_mode": "direct", "outbound": "direct"},
		map[string]any{"clash_mode": "global", "outbound": sel},
		map[string]any{"domain": netCheckExactDomains, "domain_suffix": netCheckSuffixDomains, "outbound": "网络检测"},
		map[string]any{"domain_suffix": aiProxyDomains, "outbound": "AI"},
		map[string]any{"rule_set": []string{"geosite-category-ai-!cn"}, "outbound": "AI"},
		map[string]any{"domain_suffix": devProxyDomains, "outbound": "GitHub"},
		map[string]any{"rule_set": []string{"geosite-github"}, "outbound": "GitHub"},
		map[string]any{"rule_set": []string{"geosite-youtube"}, "outbound": "YouTube"},
		map[string]any{"rule_set": []string{"geosite-google"}, "outbound": "Google"},
		map[string]any{"rule_set": []string{"geosite-telegram", "geoip-telegram"}, "outbound": "Telegram"},
		map[string]any{"rule_set": []string{"geosite-tiktok"}, "outbound": "TikTok"},
		map[string]any{"rule_set": []string{"geosite-netflix", "geosite-disney", "geosite-spotify"}, "outbound": "国际流媒体"},
	}
	if smart {
		rules = append(rules, map[string]any{"rule_set": []string{"geosite-steam@cn"}, "outbound": "direct"})
	}
	rules = append(rules,
		map[string]any{"rule_set": []string{"geosite-steam"}, "outbound": "Steam"},
		map[string]any{"rule_set": []string{"geosite-twitter", "geosite-discord", "geosite-reddit", "geosite-paypal"}, "outbound": sel},
		map[string]any{"domain_suffix": searchBypassDomains, "outbound": sel},
		map[string]any{"domain_suffix": intlProxyDomains, "outbound": sel},
	)
	if smart {
		rules = append(rules, map[string]any{"rule_set": []string{"geosite-apple-cn"}, "outbound": "direct"})
	}
	rules = append(rules, map[string]any{"rule_set": []string{"geosite-apple"}, "outbound": "Apple"})
	if smart {
		rules = append(rules, map[string]any{"rule_set": []string{"geosite-microsoft@cn"}, "outbound": "direct"})
	}
	rules = append(rules, map[string]any{"rule_set": []string{"geosite-microsoft"}, "outbound": "Microsoft"})
	if smart {
		rules = append(rules,
			map[string]any{"rule_set": []string{"geosite-bilibili"}, "outbound": "direct"},
			map[string]any{"rule_set": []string{"geosite-cn", "geoip-cn"}, "outbound": directTag},
		)
	}

	rs := func(tag, path string) map[string]any {
		return map[string]any{
			"tag": tag, "type": "remote", "format": "binary",
			"url":             "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/" + path,
			"download_detour": sel, "update_interval": "1d",
		}
	}
	ruleSets := []any{
		rs("geosite-category-ai-!cn", "geosite/category-ai-!cn.srs"),
		rs("geosite-github", "geosite/github.srs"),
		rs("geosite-youtube", "geosite/youtube.srs"),
		rs("geosite-google", "geosite/google.srs"),
		rs("geosite-netflix", "geosite/netflix.srs"),
		rs("geosite-disney", "geosite/disney.srs"),
		rs("geosite-spotify", "geosite/spotify.srs"),
		rs("geosite-steam", "geosite/steam.srs"),
		rs("geosite-telegram", "geosite/telegram.srs"),
		rs("geosite-tiktok", "geosite/tiktok.srs"),
		rs("geosite-twitter", "geosite/twitter.srs"),
		rs("geosite-discord", "geosite/discord.srs"),
		rs("geosite-reddit", "geosite/reddit.srs"),
		rs("geosite-paypal", "geosite/paypal.srs"),
		rs("geosite-apple", "geosite/apple.srs"),
		rs("geosite-microsoft", "geosite/microsoft.srs"),
		rs("geosite-private", "geosite/private.srs"),
		rs("geoip-telegram", "geoip/telegram.srs"),
		rs("geoip-private", "geoip/private.srs"),
	}
	if smart {
		ruleSets = append(ruleSets,
			rs("geosite-steam@cn", "geosite/steam@cn.srs"),
			rs("geosite-apple-cn", "geosite/apple-cn.srs"),
			rs("geosite-microsoft@cn", "geosite/microsoft@cn.srs"),
			rs("geosite-bilibili", "geosite/bilibili.srs"),
			rs("geosite-cn", "geosite/cn.srs"),
			rs("geoip-cn", "geoip/cn.srs"),
		)
	}

	dnsRules := []any{
		map[string]any{"clash_mode": "direct", "server": "local"},
		map[string]any{"clash_mode": "global", "server": "remote"},
	}
	if smart {
		dnsRules = append(dnsRules, map[string]any{"rule_set": []string{"geosite-cn", "geosite-private"}, "server": "local"})
	} else {
		dnsRules = append(dnsRules, map[string]any{"rule_set": []string{"geosite-private"}, "server": "local"})
	}

	cfg := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": sel},
				map[string]any{"type": "https", "tag": "local", "server": "223.5.5.5"},
			},
			"rules":    dnsRules,
			"final":    "remote",
			"strategy": "prefer_ipv4",
		},
		"inbounds": []any{
			map[string]any{
				"type": "tun", "tag": "tun-in",
				"address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
				"mtu": 9000, "auto_route": true, "strict_route": true, "stack": "system",
			},
			map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080},
		},
		"outbounds": outbounds,
		"route": map[string]any{
			"auto_detect_interface":   true,
			"final":                   sel,
			"default_domain_resolver": "local",
			"rules":                   rules,
			"rule_set":                ruleSets,
		},
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
	under := ""
	if sn.DialerProxy != "" {
		under = ", underlying-proxy=" + strings.ReplaceAll(sn.DialerProxy, ",", " ")
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
		return s + under
	case "trojan":
		return base + fmt.Sprintf("trojan, %s, %d, password=%s, sni=%s", sn.Addr, n.Port, sn.pw(u), st.SNI) + ws() + skip + under
	case "shadowsocks":
		return base + fmt.Sprintf("ss, %s, %d, encrypt-method=%s, password=%s, udp-relay=true", sn.Addr, n.Port, st.Cipher, ssPassword(n, u)) + under
	case "hysteria2":
		hop := ""
		if st.HopPorts != "" && sn.DialerProxy == "" {
			hop = ", port-hopping=" + st.HopPorts + ", port-hopping-interval=60"
		}
		bw := ""
		if sn.DownMbps > 0 {
			bw = fmt.Sprintf(", download-bandwidth=%d", sn.DownMbps)
		}
		return base + fmt.Sprintf("hysteria2, %s, %d, password=%s, sni=%s", sn.Addr, n.Port, sn.pw(u), st.SNI) + hop + bw + skip + under
	case "tuic":
		return base + fmt.Sprintf("tuic-v5, %s, %d, uuid=%s, password=%s, sni=%s, alpn=h3", sn.Addr, n.Port, u.UUID, sn.pw(u), st.SNI) + skip + under
	case "anytls":
		return base + fmt.Sprintf("anytls, %s, %d, password=%s, sni=%s", sn.Addr, n.Port, sn.pw(u), st.SNI) + skip + under
	}
	return "" // vless is not supported by Surge
}

func renderSurge(nodes []subNode, u *store.User, selfURL string, smart, relay bool) string {
	var sb strings.Builder
	sb.WriteString("#!MANAGED-CONFIG " + selfURL + " interval=43200 strict=false\n\n[General]\nloglevel = notify\nskip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local\n\n[Proxy]\n")
	var validNodes []subNode
	var names []string
	for _, sn := range nodes {
		if l := surgeLine(sn, u); l != "" {
			sb.WriteString(l + "\n")
			validNodes = append(validNodes, sn)
			names = append(names, strings.ReplaceAll(sn.Name, ",", " "))
		}
	}
	var asiaRelays, relayNames []string
	if relay {
		var relayedNodes []subNode
		rawAsia, relayedNodes := buildAutoRelays(validNodes, asiaRelayGroupName)
		for _, nm := range rawAsia {
			asiaRelays = append(asiaRelays, strings.ReplaceAll(nm, ",", " "))
		}
		for _, rn := range relayedNodes {
			if l := surgeLine(rn, u); l != "" {
				sb.WriteString(l + "\n")
				clean := strings.ReplaceAll(rn.Name, ",", " ")
				names = append(names, clean)
				relayNames = append(relayNames, clean)
			}
		}
	}
	if len(names) == 0 {
		names = []string{"DIRECT"}
	}
	hasRelay := len(relayNames) > 0 && len(asiaRelays) > 0
	sb.WriteString("\n[Proxy Group]\n")
	if hasRelay {
		sb.WriteString("Proxy = select, Auto, " + usEuRelayGroupName + ", " + strings.Join(names, ", ") + "\n")
		sb.WriteString("Auto = url-test, " + strings.Join(names, ", ") + ", url=http://www.gstatic.com/generate_204, interval=300\n")
		sb.WriteString(usEuRelayGroupName + " = url-test, " + strings.Join(relayNames, ", ") + ", url=http://www.gstatic.com/generate_204, interval=180\n")
		sb.WriteString(asiaRelayGroupName + " = url-test, " + strings.Join(asiaRelays, ", ") + ", url=http://www.gstatic.com/generate_204, interval=180\n")
	} else {
		sb.WriteString("Proxy = select, Auto, " + strings.Join(names, ", ") + "\n")
		sb.WriteString("Auto = url-test, " + strings.Join(names, ", ") + ", url=http://www.gstatic.com/generate_204, interval=300\n")
	}
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
	smart := s.smartRules(r)
	relay := s.autoRelay(r)
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
		fmt.Fprint(w, renderClash(nodes, u, site, smart, relay))
	case "singbox", "sing-box", "sfa":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprint(w, renderSingbox(nodes, u, smart, relay))
	case "surge":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, renderSurge(nodes, u, s.subURL(r)+r.URL.RequestURI(), smart, relay))
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
	if sn.Node.Core == "script" && sn.Node.Settings.SharedPassword != "" && !sn.Node.Settings.PortalUsers {
		return sn.Node.Settings.SharedPassword
	}
	return connPw(u)
}
