package master

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"nodehub/internal/proto"
	"nodehub/internal/store"
	"nodehub/internal/util"
)

// cfAPIBase is overridable in tests.
var cfAPIBase = "https://api.cloudflare.com/client/v4"

var cfHTTPClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	},
}

type cfZonesCacheEntry struct {
	zones   []cfZone
	expires time.Time
}

var (
	cfZonesMu    sync.Mutex
	cfZonesCache = map[string]cfZonesCacheEntry{}
)

type cfZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

func cfDo(token, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, cfAPIBase+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cfHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("Cloudflare API 请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var env struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("Cloudflare API 响应异常 (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if !env.Success || resp.StatusCode >= 400 {
		msg := fmt.Sprintf("HTTP %d", resp.StatusCode)
		if len(env.Errors) > 0 {
			msg = fmt.Sprintf("[%d] %s", env.Errors[0].Code, env.Errors[0].Message)
		}
		return fmt.Errorf("Cloudflare API 错误: %s", msg)
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

func cfListZones(token string) ([]cfZone, error) {
	ck := util.SHA256Hex(token) + "@" + cfAPIBase
	cfZonesMu.Lock()
	if e, ok := cfZonesCache[ck]; ok && time.Now().Before(e.expires) {
		cfZonesMu.Unlock()
		return e.zones, nil
	}
	cfZonesMu.Unlock()
	var zones []cfZone
	if err := cfDo(token, "GET", "/zones?per_page=50&status=active", nil, &zones); err != nil {
		return nil, err
	}
	cfZonesMu.Lock()
	cfZonesCache[ck] = cfZonesCacheEntry{zones: zones, expires: time.Now().Add(10 * time.Minute)}
	cfZonesMu.Unlock()
	return zones, nil
}

// cfMatchZone finds the longest matching active zone for fqdn (e.g. a.b.example.com -> example.com).
func cfMatchZone(zones []cfZone, fqdn string) *cfZone {
	fqdn = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	var best *cfZone
	for i := range zones {
		zn := strings.ToLower(strings.TrimSuffix(zones[i].Name, "."))
		if fqdn == zn || strings.HasSuffix(fqdn, "."+zn) {
			if best == nil || len(zn) > len(best.Name) {
				best = &zones[i]
			}
		}
	}
	return best
}

// cfUpsertRecord creates or updates a DNS-only (proxied=false) A/AAAA record in Cloudflare.
func cfUpsertRecord(token, fqdn, ip string) (action string, err error) {
	ip = strings.TrimSpace(ip)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("无效 IP 地址: %q", ip)
	}
	recType := "A"
	if parsed.To4() == nil {
		recType = "AAAA"
	}
	zones, err := cfListZones(token)
	if err != nil {
		return "", err
	}
	zone := cfMatchZone(zones, fqdn)
	if zone == nil {
		names := make([]string, 0, len(zones))
		for _, z := range zones {
			names = append(names, z.Name)
		}
		return "", fmt.Errorf("Cloudflare 令牌下找不到域名 %s 所属区域（可用区域: %s）", fqdn, strings.Join(names, ", "))
	}
	q := url.Values{"type": {recType}, "name": {fqdn}}
	var existing []cfDNSRecord
	if err := cfDo(token, "GET", "/zones/"+zone.ID+"/dns_records?"+q.Encode(), nil, &existing); err != nil {
		return "", err
	}
	payload := map[string]any{
		"type":    recType,
		"name":    fqdn,
		"content": ip,
		"ttl":     120,
		"proxied": false,
	}
	if len(existing) > 0 {
		rec := existing[0]
		if rec.Content == ip && !rec.Proxied {
			return "unchanged", nil
		}
		if err := cfDo(token, "PUT", "/zones/"+zone.ID+"/dns_records/"+rec.ID, payload, nil); err != nil {
			return "", err
		}
		return "updated", nil
	}
	if err := cfDo(token, "POST", "/zones/"+zone.ID+"/dns_records", payload, nil); err != nil {
		return "", err
	}
	return "created", nil
}

var dnsLabelBadRe = regexp.MustCompile(`[^a-z0-9-]+`)

func dnsLabelSlug(name string, serverID int64) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = dnsLabelBadRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 24 {
		s = strings.TrimRight(s[:24], "-")
	}
	if s == "" || !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= '0' && s[0] <= '9')) {
		return fmt.Sprintf("n%d", serverID)
	}
	return s
}

type dualStackReq struct {
	Domain      string `json:"domain"`       // FQDN (jp2.example.com) or bare subdomain label (jp2); empty = auto when CF enabled
	NoCF        bool   `json:"no_cf"`        // skip Cloudflare DNS & use self-signed cert for Hysteria2
	Hy2Port     int    `json:"hy2_port"`     // default 44443 (UDP)
	TCPPort     int    `json:"tcp_port"`     // default same as hy2_port (TCP), coexists with UDP
	HopPorts    string `json:"hop_ports"`    // default "20000-40000"; pass "none" to disable
	RealityDest string `json:"reality_dest"` // default "www.apple.com:443"
	Hy2Name     string `json:"hy2_name"`     // default srv.Name
	TCPName     string `json:"tcp_name"`     // default srv.Name + "-TCP"
	Groups      string `json:"groups"`
	Force       bool   `json:"force"`        // create even if server already has hy2 / vless
	IP          string `json:"ip"`           // optional override when server has not sent first heartbeat yet
	SkipHy2     bool   `json:"skip_hy2"`
	SkipReality bool   `json:"skip_reality"`
}

type dualStackRes struct {
	Server    *store.Server `json:"server"`
	Domain    string        `json:"domain,omitempty"`
	DNSAction string        `json:"dns_action,omitempty"`
	CertMode  string        `json:"cert_mode,omitempty"`
	Hy2Node   *store.Node   `json:"hy2_node,omitempty"`
	VlessNode *store.Node   `json:"vless_node,omitempty"`
	Warnings  []string      `json:"warnings,omitempty"`
}

func (s *Server) provisionDualStack(srv *store.Server, req dualStackReq) (*dualStackRes, error) {
	if srv == nil {
		return nil, errors.New("服务器不存在")
	}
	res := &dualStackRes{Server: srv}
	cfToken := strings.TrimSpace(s.st.Setting("cf_api_token"))
	baseDomain := strings.TrimSpace(strings.TrimPrefix(s.st.Setting("cf_base_domain"), "."))
	acmeEmail := strings.TrimSpace(s.st.Setting("acme_email"))

	ip := strings.TrimSpace(req.IP)
	if ip == "" {
		ip = strings.TrimSpace(srv.PublicIPv4)
	}
	if ip == "" && net.ParseIP(strings.TrimSpace(srv.Host)) != nil {
		ip = strings.TrimSpace(srv.Host)
	}

	// 1. Resolve domain & optionally upsert Cloudflare DNS A record
	fqdn := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Domain), "."))
	if !req.NoCF && cfToken != "" {
		if fqdn == "" {
			if baseDomain == "" {
				zones, err := cfListZones(cfToken)
				if err != nil {
					return nil, err
				}
				if len(zones) > 0 {
					baseDomain = zones[0].Name
				}
			}
			if baseDomain != "" {
				fqdn = dnsLabelSlug(srv.Name, srv.ID) + "." + baseDomain
			}
		} else if !strings.Contains(fqdn, ".") {
			if baseDomain == "" {
				zones, err := cfListZones(cfToken)
				if err != nil {
					return nil, err
				}
				if len(zones) > 0 {
					baseDomain = zones[0].Name
				}
			}
			if baseDomain == "" {
				return nil, fmt.Errorf("请填写完整域名（例如 %s.example.com），或在设置里填写默认根域名", fqdn)
			}
			fqdn = fqdn + "." + baseDomain
		}
		if fqdn != "" {
			if ip == "" {
				res.Warnings = append(res.Warnings, "服务器尚未上报公网 IP，跳过 Cloudflare DNS A 记录写入（请稍后手动或重新触发解析）")
			} else {
				act, err := cfUpsertRecord(cfToken, fqdn, ip)
				if err != nil {
					return nil, err
				}
				res.DNSAction = act
			}
			res.Domain = fqdn
			if srv.Host != fqdn {
				srv.Host = fqdn
				_ = s.st.UpdateServer(srv)
			}
		}
	} else if fqdn != "" {
		res.Domain = fqdn
		if srv.Host != fqdn {
			srv.Host = fqdn
			_ = s.st.UpdateServer(srv)
		}
	}

	// Inspect existing nodes on this server
	existing, _ := s.st.NodesByServer(srv.ID)
	var hasHy2, hasVless *store.Node
	for _, n := range existing {
		if n.Enabled && n.Protocol == "hysteria2" && hasHy2 == nil {
			hasHy2 = n
		}
		if n.Enabled && n.Protocol == "vless" && n.Settings.Security == "reality" && hasVless == nil {
			hasVless = n
		}
	}

	// Ports & hop defaults
	hy2Port := req.Hy2Port
	if hy2Port == 0 {
		hy2Port = 44443
	}
	hopPorts := strings.TrimSpace(req.HopPorts)
	if hopPorts == "" {
		hopPorts = "20000-40000"
	}
	if strings.EqualFold(hopPorts, "none") || hopPorts == "-" {
		hopPorts = ""
	}
	// If hy2Port sits inside the default hop range, pick a non-overlapping hop range
	if hopPorts != "" {
		if lo, hi, err := parseHopRange(hopPorts); err == nil && hy2Port >= lo && hy2Port <= hi {
			if hy2Port < 40001 {
				hopPorts = "40001-50000"
			} else {
				hopPorts = "20000-35000"
			}
		}
	}
	tcpPort := req.TCPPort
	if tcpPort == 0 {
		tcpPort = hy2Port
	}
	// If an existing Hysteria2 node already holds hop_ports and tcpPort collides with its range, move tcpPort to 8443
	for _, o := range existing {
		if olo, ohi, err := parseHopRange(o.Settings.HopPorts); err == nil && tcpPort >= olo && tcpPort <= ohi {
			tcpPort = 8443
			break
		}
	}

	// 2. Create Hysteria2 node (sing-box native + Cloudflare DNS-01 ACME when domain+CF available)
	if !req.SkipHy2 {
		if hasHy2 != nil && !req.Force {
			res.Hy2Node = hasHy2
			res.CertMode = hasHy2.Settings.CertMode
			res.Warnings = append(res.Warnings, fmt.Sprintf("服务器上已有 Hysteria2 节点「%s」（端口 %d），已保留未重复创建", hasHy2.Name, hasHy2.Port))
		} else {
			hy2Name := strings.TrimSpace(req.Hy2Name)
			if hy2Name == "" {
				hy2Name = srv.Name
			}
			certMode := "self"
			sni := "www.bing.com"
			if fqdn != "" {
				sni = fqdn
				if !req.NoCF && cfToken != "" {
					certMode = "acme_dns"
				} else {
					certMode = "acme"
				}
			}
			email := acmeEmail
			if email == "" && fqdn != "" {
				parts := strings.Split(fqdn, ".")
				if len(parts) >= 2 {
					email = "admin@" + strings.Join(parts[len(parts)-2:], ".")
				}
			}
			st := proto.NodeSettings{
				SNI:          sni,
				CertMode:     certMode,
				ACMEEmail:    email,
				UpMbps:       1000,
				DownMbps:     1000,
				Obfs:         "salamander",
				ObfsPassword: util.RandHex(16),
				HopPorts:     hopPorts,
				Masquerade:   "https://www.bing.com",
			}
			n := &store.Node{
				ServerID: srv.ID,
				Name:     hy2Name,
				Core:     "singbox",
				Protocol: "hysteria2",
				Port:     hy2Port,
				Address:  fqdn,
				Settings: st,
				Rate:     1,
				Groups:   strings.TrimSpace(req.Groups),
				Sort:     5,
				Enabled:  true,
				Source:   "local",
				Note:     "一键双栈 Hysteria2",
			}
			if err := s.normalizeNode(n); err != nil {
				return nil, fmt.Errorf("创建 Hysteria2 节点失败: %w", err)
			}
			id, err := s.st.CreateNode(n)
			if err != nil {
				return nil, fmt.Errorf("保存 Hysteria2 节点失败: %w", err)
			}
			n.ID = id
			res.Hy2Node = n
			res.CertMode = certMode
		}
	}

	// 3. Create VLESS + Reality (TCP) fallback node (Xray native)
	if !req.SkipReality {
		if hasVless != nil && !req.Force {
			res.VlessNode = hasVless
			res.Warnings = append(res.Warnings, fmt.Sprintf("服务器上已有 VLESS-Reality 节点「%s」（端口 %d），已保留未重复创建", hasVless.Name, hasVless.Port))
		} else {
			tcpName := strings.TrimSpace(req.TCPName)
			if tcpName == "" {
				tcpName = srv.Name + "-TCP"
			}
			dest := strings.TrimSpace(req.RealityDest)
			if dest == "" {
				dest = "www.apple.com:443"
			}
			destHost := strings.Split(dest, ":")[0]
			st := proto.NodeSettings{
				Network:           "tcp",
				Security:          "reality",
				Flow:              "xtls-rprx-vision",
				RealityDest:       dest,
				RealityServerName: destHost,
				Fingerprint:       "chrome",
			}
			n := &store.Node{
				ServerID: srv.ID,
				Name:     tcpName,
				Core:     "xray",
				Protocol: "vless",
				Port:     tcpPort,
				Address:  fqdn,
				Settings: st,
				Rate:     1,
				Groups:   strings.TrimSpace(req.Groups),
				Sort:     15,
				Enabled:  true,
				Source:   "local",
				Note:     "一键双栈 VLESS-Reality TCP",
			}
			if err := s.normalizeNode(n); err != nil {
				return nil, fmt.Errorf("创建 VLESS-Reality 节点失败: %w", err)
			}
			id, err := s.st.CreateNode(n)
			if err != nil {
				return nil, fmt.Errorf("保存 VLESS-Reality 节点失败: %w", err)
			}
			n.ID = id
			res.VlessNode = n
		}
	}

	s.bump()
	res.Server, _ = s.st.GetServer(srv.ID)
	return res, nil
}

// POST /api/servers/{id}/dual-stack (admin UI one-click)
func (s *Server) handleServerDualStack(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	srv, err := s.st.GetServer(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	var req dualStackReq
	if r.ContentLength > 0 {
		if err := readJSON(r, &req); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	res, err := s.provisionDualStack(srv, req)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.audit(r, a, "server.dual_stack", fmt.Sprint(srv.ID), fmt.Sprintf("domain=%s dns=%s cert=%s", res.Domain, res.DNSAction, res.CertMode))
	ok(w, res)
}

// POST /api/open/v1/provision (one-line VPS bootstrap script endpoint, authenticated by OpenAPI write key)
func (s *Server) openProvisionDualStack(w http.ResponseWriter, r *http.Request, k *store.APIKey) {
	var req struct {
		dualStackReq
		Name   string `json:"name"`
		Region string `json:"region"`
		Tags   string `json:"tags"`
		Note   string `json:"note"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.IP = strings.TrimSpace(req.IP)
	req.Region = strings.ToUpper(strings.TrimSpace(req.Region))
	if req.Name == "" {
		if req.IP != "" {
			req.Name = "vps-" + strings.ReplaceAll(req.IP, ".", "-")
		} else {
			writeErr(w, 400, "请提供 --name 服务器名称")
			return
		}
	}

	// Reuse existing server if matching public_ipv4 or exact name, otherwise create new
	var srv *store.Server
	createdServer := false
	token := ""
	if list, err := s.st.ListServers(); err == nil {
		for _, cand := range list {
			if (req.IP != "" && cand.PublicIPv4 == req.IP) || cand.Name == req.Name {
				srv = cand
				break
			}
		}
	}
	if srv == nil {
		v := store.Server{
			Name:            req.Name,
			Host:            req.IP,
			PublicIPv4:      req.IP,
			Region:          req.Region,
			Tags:            req.Tags,
			Note:            req.Note,
			Enabled:         true,
			TrafficResetDay: 1,
		}
		if err := validServer(&v); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		token = util.RandToken(24)
		id, err := s.st.CreateServer(&v, util.SHA256Hex(token))
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		srv, _ = s.st.GetServer(id)
		createdServer = true
	} else {
		changed := false
		if req.Region != "" && srv.Region == "" {
			srv.Region = req.Region
			changed = true
		}
		if req.IP != "" && srv.PublicIPv4 == "" {
			srv.PublicIPv4 = req.IP
			changed = true
		}
		if changed {
			_ = s.st.UpdateServer(srv)
		}
	}

	res, err := s.provisionDualStack(srv, req.dualStackReq)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	installCmd := ""
	if token != "" {
		installCmd = s.installCommand(r, token)
	}
	s.audit(r, nil, "open.provision", fmt.Sprint(srv.ID), fmt.Sprintf("key=%s name=%s domain=%s dns=%s", k.Name, srv.Name, res.Domain, res.DNSAction))
	ok(w, map[string]any{
		"server":          res.Server,
		"created_server":  createdServer,
		"token":           token,
		"install_command": installCmd,
		"domain":          res.Domain,
		"dns_action":      res.DNSAction,
		"cert_mode":       res.CertMode,
		"hy2_node":        res.Hy2Node,
		"vless_node":      res.VlessNode,
		"warnings":        res.Warnings,
	})
}

func (s *Server) handleDualStackScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	body := strings.ReplaceAll(dualStackScript, "\r\n", "\n")
	body = strings.ReplaceAll(body, "__MASTER_URL__", s.publicURL(r))
	_, _ = w.Write([]byte(body))
}
