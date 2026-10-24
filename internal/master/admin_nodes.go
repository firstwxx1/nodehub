package master

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"nodehub/internal/panel"
	"nodehub/internal/store"
	"nodehub/internal/util"
)

var protocolCores = map[string][]string{
	"vless":       {"xray", "singbox"},
	"vmess":       {"xray", "singbox"},
	"trojan":      {"xray", "singbox"},
	"shadowsocks": {"xray", "singbox"},
	"hysteria2":   {"singbox"},
	"tuic":        {"singbox"},
	"anytls":      {"singbox"},
}

// normalizeNode validates a node and fills in generated secrets and defaults.
func (s *Server) normalizeNode(n *store.Node) error {
	n.Name = strings.TrimSpace(n.Name)
	if n.Name == "" {
		return fmt.Errorf("节点名称不能为空")
	}
	cores, okk := protocolCores[n.Protocol]
	if !okk {
		return fmt.Errorf("不支持的协议 %q", n.Protocol)
	}
	if n.Core == "" {
		n.Core = cores[0]
	}
	valid := false
	for _, c := range cores {
		valid = valid || c == n.Core
	}
	if !valid {
		return fmt.Errorf("%s 协议需要使用 %s 内核", n.Protocol, strings.Join(cores, "/"))
	}
	if n.Port < 1 || n.Port > 65535 {
		return fmt.Errorf("端口必须在 1-65535 之间")
	}
	if _, err := s.st.GetServer(n.ServerID); err != nil {
		return fmt.Errorf("服务器不存在")
	}
	// the same port number may be reused when the transports differ (e.g. VLESS on TCP 443 and Hysteria2 on UDP 443)
	if others, _ := s.st.NodesByServer(n.ServerID); true {
		mine := nodeTransports(n)
		for _, o := range others {
			if o.ID == n.ID || o.Port != n.Port {
				continue
			}
			for _, t1 := range mine {
				for _, t2 := range nodeTransports(o) {
					if t1 == t2 {
						return fmt.Errorf("该服务器上端口 %d/%s 已被节点「%s」占用", n.Port, t1, o.Name)
					}
				}
			}
		}
	}
	if n.Rate <= 0 {
		n.Rate = 1
	}
	if n.Source == "" {
		n.Source = "local"
	}
	if n.Source == "panel" {
		p, err := s.st.GetPanel(n.PanelID)
		if err != nil {
			return fmt.Errorf("请选择要对接的面板")
		}
		if n.PanelNodeID <= 0 {
			return fmt.Errorf("请填写面板中的节点 ID")
		}
		if p.Type == "sspanel" && n.PanelSyncConfig {
			n.PanelSyncConfig = false
		}
	}
	st := &n.Settings
	switch n.Protocol {
	case "vless", "vmess", "trojan":
		if st.Network == "" || st.Network == "raw" {
			st.Network = "tcp"
		}
		if st.Network == "xhttp" && n.Core != "xray" {
			return fmt.Errorf("xhttp 传输只支持 xray 内核")
		}
		if n.Protocol == "trojan" && st.Security == "" {
			st.Security = "tls"
		}
		if st.Security == "" {
			st.Security = "none"
		}
		if st.Security == "reality" {
			if n.Protocol == "vmess" {
				return fmt.Errorf("vmess 不支持 reality")
			}
			if st.RealityPrivateKey == "" {
				priv, pub, err := util.RealityKeyPair()
				if err != nil {
					return err
				}
				st.RealityPrivateKey, st.RealityPublicKey = priv, pub
			} else if pub, err := util.RealityPublicKey(st.RealityPrivateKey); err == nil {
				st.RealityPublicKey = pub
			} else {
				return fmt.Errorf("reality 私钥格式错误")
			}
			if st.RealityShortID == "" {
				st.RealityShortID = util.RandHex(4)
			}
			if st.RealityDest == "" {
				st.RealityDest = "www.cloudflare.com:443"
			}
			if st.RealityServerName == "" {
				st.RealityServerName = strings.Split(st.RealityDest, ":")[0]
			}
			if st.Fingerprint == "" {
				st.Fingerprint = "chrome"
			}
		}
		if st.Flow != "" && (n.Protocol != "vless" || st.Network != "tcp" || st.Security == "none") {
			st.Flow = ""
		}
	case "shadowsocks":
		if st.Cipher == "" {
			st.Cipher = "2022-blake3-aes-128-gcm"
		}
		if util.SSKeyLen(st.Cipher) > 0 {
			if st.ServerKey == "" {
				st.ServerKey = util.SSServerKey(st.Cipher)
			}
		} else if n.Core == "singbox" {
			return fmt.Errorf("sing-box 多用户 shadowsocks 只支持 2022 系列加密")
		}
	case "hysteria2", "tuic", "anytls":
		if st.SNI == "" {
			st.SNI = "www.bing.com"
		}
		if n.Protocol == "tuic" && st.Congestion == "" {
			st.Congestion = "bbr"
		}
	}
	if (st.Security == "tls" || n.Protocol == "hysteria2" || n.Protocol == "tuic" || n.Protocol == "anytls") && st.CertMode == "" {
		st.CertMode = "self"
	}
	st.ACMEDNSProvider, st.ACMEDNSToken = "", "" // injected from settings when the agent config is built
	if st.CertMode == "acme" || st.CertMode == "acme_dns" {
		if n.Core != "singbox" {
			return fmt.Errorf("ACME 自动证书目前只支持 sing-box 内核的节点")
		}
		if st.SNI == "" || net.ParseIP(st.SNI) != nil || !strings.Contains(st.SNI, ".") {
			return fmt.Errorf("ACME 证书需要把 SNI 填成你的域名")
		}
		if st.CertMode == "acme_dns" && s.st.Setting("cf_api_token") == "" {
			return fmt.Errorf("DNS 验证需要先在「设置」里填写 Cloudflare API 令牌")
		}
	}
	st.HopPorts = strings.TrimSpace(st.HopPorts)
	if st.HopPorts != "" {
		if n.Protocol != "hysteria2" {
			return fmt.Errorf("端口跳跃只支持 Hysteria2")
		}
		lo, hi, err := parseHopRange(st.HopPorts)
		if err != nil {
			return err
		}
		if n.Port >= lo && n.Port <= hi {
			return fmt.Errorf("主端口 %d 不能落在跳跃区间 %s 内", n.Port, st.HopPorts)
		}
		st.HopPorts = fmt.Sprintf("%d-%d", lo, hi)
		others, _ := s.st.NodesByServer(n.ServerID)
		for _, o := range others {
			if o.ID == n.ID {
				continue
			}
			if o.Port >= lo && o.Port <= hi {
				return fmt.Errorf("跳跃区间 %s 包含了节点「%s」的端口 %d", st.HopPorts, o.Name, o.Port)
			}
			if olo, ohi, err := parseHopRange(o.Settings.HopPorts); err == nil && olo <= hi && lo <= ohi {
				return fmt.Errorf("跳跃区间与节点「%s」的 %s 重叠", o.Name, o.Settings.HopPorts)
			}
		}
	}
	// the new node's own port must not sit inside another node's hop range either
	if others, _ := s.st.NodesByServer(n.ServerID); true {
		for _, o := range others {
			if o.ID == n.ID {
				continue
			}
			if olo, ohi, err := parseHopRange(o.Settings.HopPorts); err == nil && n.Port >= olo && n.Port <= ohi {
				return fmt.Errorf("端口 %d 落在节点「%s」的跳跃区间 %s 内", n.Port, o.Name, o.Settings.HopPorts)
			}
		}
	}
	st.Masquerade = strings.TrimSpace(st.Masquerade)
	if st.Masquerade != "" {
		if n.Protocol != "hysteria2" {
			st.Masquerade = ""
		} else if u, err := url.Parse(st.Masquerade); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("伪装地址需要是 http(s):// 开头的网址")
		}
	}
	if st.CertMode == "file" && (st.CertFile == "" || st.KeyFile == "") {
		return fmt.Errorf("证书模式为文件时需要填写证书和私钥路径")
	}
	return nil
}

type nodeView struct {
	*store.Node
	ServerName   string         `json:"server_name"`
	ServerOnline bool           `json:"server_online"`
	ConnectAddr  string         `json:"connect_addr"`
	UserCount    int            `json:"user_count"`
	IPCheck      *store.IPCheck `json:"ip_check"`
	PanelName    string         `json:"panel_name,omitempty"`
}

func (s *Server) connectAddr(n *store.Node, srv *store.Server) string {
	if n.Address != "" {
		return n.Address
	}
	if srv == nil {
		return ""
	}
	if srv.Host != "" {
		return srv.Host
	}
	return srv.PublicIPv4
}

func (s *Server) nodeViews() ([]nodeView, error) {
	nodes, err := s.st.ListNodes()
	if err != nil {
		return nil, err
	}
	servers, _ := s.st.ListServers()
	sm := map[int64]*store.Server{}
	for _, v := range servers {
		sm[v.ID] = v
	}
	panels, _ := s.st.ListPanels()
	pm := map[int64]string{}
	for _, p := range panels {
		pm[p.ID] = p.Name
	}
	checks, _ := s.st.LatestIPChecks()
	users, _ := s.st.ActiveUsers()
	out := make([]nodeView, 0, len(nodes))
	for _, n := range nodes {
		v := nodeView{Node: n, IPCheck: checks[n.ID]}
		if srv := sm[n.ServerID]; srv != nil {
			v.ServerName, v.ServerOnline = srv.Name, srv.Online
			v.ConnectAddr = s.connectAddr(n, srv)
		}
		if n.Source == "panel" {
			v.UserCount = s.st.PanelUserCount(n.ID)
			v.PanelName = pm[n.PanelID]
		} else {
			for _, u := range users {
				if nodeVisible(n, u) {
					v.UserCount++
				}
			}
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	vs, err := s.nodeViews()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, vs)
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	n, err := s.st.GetNode(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	ok(w, n)
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	var n store.Node
	n.Enabled = true
	if err := readJSON(r, &n); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	n.ID = 0
	if err := s.normalizeNode(&n); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if r.URL.Query().Get("force") != "1" {
		if err := s.checkNodePorts(&n, nil); err != nil {
			writeErr(w, 409, err.Error())
			return
		}
	}
	id, err := s.st.CreateNode(&n)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	n.ID = id
	s.bump()
	s.audit(r, a, "node.create", fmt.Sprint(id), n.Name)
	if n.Source == "panel" {
		go s.syncPanelNode(context.Background(), id)
	}
	ok(w, n)
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	old, err := s.st.GetNode(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	n := *old
	if err := readJSON(r, &n); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	n.ID = old.ID
	if err := s.normalizeNode(&n); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if r.URL.Query().Get("force") != "1" {
		if err := s.checkNodePorts(&n, old); err != nil {
			writeErr(w, 409, err.Error())
			return
		}
	}
	if err := s.st.UpdateNode(&n); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if old.Source == "panel" && (n.Source != "panel" || n.PanelID != old.PanelID || n.PanelNodeID != old.PanelNodeID) {
		_, _ = s.st.ReplacePanelUsers(n.ID, nil)
		s.forgetPanelETag(old.PanelID, n.ID)
	}
	s.bump()
	s.audit(r, a, "node.update", fmt.Sprint(n.ID), n.Name)
	if n.Source == "panel" {
		go s.syncPanelNode(context.Background(), n.ID)
	}
	ok(w, n)
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	id := pathID(r)
	if err := s.st.DeleteNode(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.bump()
	s.audit(r, a, "node.delete", fmt.Sprint(id), "")
	ok(w, map[string]any{"ok": true})
}

func (s *Server) handleToggleNode(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	n, err := s.st.GetNode(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	n.Enabled = !n.Enabled
	if err := s.st.UpdateNode(n); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.bump()
	s.audit(r, a, "node.toggle", fmt.Sprint(n.ID), fmt.Sprint(n.Enabled))
	ok(w, n)
}

func (s *Server) handleCopyNode(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	n, err := s.st.GetNode(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	var req struct {
		ServerID int64 `json:"server_id"`
		Port     int   `json:"port"`
	}
	_ = readJSON(r, &req)
	c := *n
	c.ID = 0
	c.Name = n.Name + " 副本"
	c.Enabled = false
	c.UpTotal, c.DownTotal, c.OnlineUsers = 0, 0, 0
	if req.ServerID > 0 {
		c.ServerID = req.ServerID
	}
	c.Port = n.Port
	if req.Port > 0 {
		c.Port = req.Port
	}
	for s.st.PortInUse(c.ServerID, c.Port, 0) && c.Port < 65535 {
		c.Port++
	}
	// fresh secrets for the copy
	c.Settings.RealityPrivateKey, c.Settings.RealityPublicKey, c.Settings.RealityShortID = "", "", ""
	if c.Protocol == "shadowsocks" {
		c.Settings.ServerKey = ""
	}
	if c.Source == "panel" {
		c.Source, c.PanelID, c.PanelNodeID = "local", 0, 0
	}
	if err := s.normalizeNode(&c); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	id, err := s.st.CreateNode(&c)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	c.ID = id
	s.audit(r, a, "node.copy", fmt.Sprint(n.ID), fmt.Sprint(id))
	ok(w, c)
}

func (s *Server) handleNodeOnline(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	list, err := s.st.OnlineIPs(pathID(r), time.Now().Unix()-300)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, list)
}

func (s *Server) handleNodePanelSync(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	n, err := s.st.GetNode(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	if n.Source != "panel" {
		writeErr(w, 400, "该节点不是面板对接节点")
		return
	}
	s.forgetPanelETag(n.PanelID, n.ID)
	if err := s.syncPanelNode(r.Context(), n.ID); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	ok(w, map[string]any{"ok": true, "users": s.st.PanelUserCount(n.ID)})
}

func (s *Server) handleRealityKeypair(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	priv, pub, err := util.RealityKeyPair()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, map[string]string{"private_key": priv, "public_key": pub, "short_id": util.RandHex(4)})
}

func (s *Server) handleSSKey(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	var req struct{ Cipher string }
	_ = readJSON(r, &req)
	ok(w, map[string]string{"key": util.SSServerKey(req.Cipher)})
}

func parseHopRange(r string) (int, int, error) {
	var lo, hi int
	if _, err := fmt.Sscanf(strings.ReplaceAll(r, ":", "-"), "%d-%d", &lo, &hi); err != nil {
		return 0, 0, fmt.Errorf("跳跃区间格式应为 20000-40000")
	}
	if lo < 1024 || hi > 65535 || lo >= hi {
		return 0, 0, fmt.Errorf("跳跃区间需在 1024-65535 之间且起点小于终点")
	}
	return lo, hi, nil
}

// forgetPanelETag drops a cached ETag so the next sync refetches all users.
func (s *Server) forgetPanelETag(panelID, nodeID int64) {
	s.panelMu.Lock()
	c := s.panelCli[panelID]
	s.panelMu.Unlock()
	if c != nil {
		panel.ResetETag(c, nodeID)
	}
}
