package master

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nodehub/internal/store"
	"nodehub/internal/util"
)

// ---------------- dashboard ----------------

func (s *Server) dashboardData() (map[string]any, error) {
	servers, err := s.st.ListServers()
	if err != nil {
		return nil, err
	}
	nodes, _ := s.st.ListNodes()
	var online, nodesOn, onlineUsers int
	var rxRate, txRate uint64
	for _, v := range servers {
		if v.Online {
			online++
			var st struct {
				NetRxRate uint64 `json:"net_rx_rate"`
				NetTxRate uint64 `json:"net_tx_rate"`
			}
			_ = json.Unmarshal(v.Status, &st)
			rxRate += st.NetRxRate
			txRate += st.NetTxRate
		}
	}
	sm := map[int64]bool{}
	for _, v := range servers {
		sm[v.ID] = v.Online
	}
	for _, n := range nodes {
		if n.Enabled && sm[n.ServerID] {
			nodesOn++
		}
		onlineUsers += n.OnlineUsers
	}
	var users, active int
	_ = s.st.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(status='active'),0) FROM users`).Scan(&users, &active)
	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).Unix()
	var todayUp, todayDown, monthUp, monthDown sql.NullInt64
	_ = s.st.DB.QueryRow(`SELECT SUM(up),SUM(down) FROM traffic_hourly WHERE user_id=0 AND hour>=?`, dayStart).Scan(&todayUp, &todayDown)
	_ = s.st.DB.QueryRow(`SELECT SUM(up),SUM(down) FROM traffic_hourly WHERE user_id=0 AND hour>=?`, monthStart).Scan(&monthUp, &monthDown)
	checks, _ := s.st.LatestIPChecks()
	risky := 0
	for _, c := range checks {
		if c.Risky() {
			risky++
		}
	}
	return map[string]any{
		"servers_total": len(servers), "servers_online": online,
		"nodes_total": len(nodes), "nodes_online": nodesOn, "online_users": onlineUsers,
		"users_total": users, "users_active": active,
		"today_up": todayUp.Int64, "today_down": todayDown.Int64, "month_up": monthUp.Int64, "month_down": monthDown.Int64,
		"rx_rate": rxRate, "tx_rate": txRate, "ip_risky": risky, "ip_checked": len(checks),
		"uptime": int64(time.Since(s.start).Seconds()),
	}, nil
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	d, err := s.dashboardData()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	since := time.Now().Unix() - 7*86400
	d["top_users"], _ = s.st.TopUsers(since, 10)
	d["top_nodes"], _ = s.st.TopNodes(since, 10)
	d["events"], _ = s.st.ListEvents(15)
	ok(w, d)
}

func (s *Server) handleTrafficSeries(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	q := r.URL.Query()
	days := qInt(r, "days", 7)
	bucket := int64(86400)
	if q.Get("bucket") == "hour" {
		bucket = 3600
	}
	var id int64
	fmt.Sscan(q.Get("id"), &id)
	pts, err := s.st.TrafficSeries(q.Get("scope"), id, time.Now().Unix()-int64(days)*86400, bucket, tzOffset())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, pts)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	list, err := s.st.ListEvents(qInt(r, "limit", 100))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, list)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	list, err := s.st.ListAudit(qInt(r, "limit", 200))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, list)
}

// ---------------- panels ----------------

func validPanel(p *store.Panel) error {
	p.Name = strings.TrimSpace(p.Name)
	p.BaseURL = strings.TrimRight(strings.TrimSpace(p.BaseURL), "/")
	switch p.Type {
	case "xboard", "v2board", "sspanel":
	default:
		return fmt.Errorf("面板类型只能是 xboard / v2board / sspanel")
	}
	if p.Name == "" || !strings.HasPrefix(p.BaseURL, "http") || p.Token == "" {
		return fmt.Errorf("请填写名称、面板地址（http/https 开头）和通讯密钥")
	}
	if p.SyncInterval < 30 {
		p.SyncInterval = 60
	}
	return nil
}

func (s *Server) handleListPanels(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	list, err := s.st.ListPanels()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	for _, p := range list {
		p.Token = maskSecret(p.Token)
	}
	ok(w, list)
}

func maskSecret(s string) string {
	if len(s) <= 6 {
		return "******"
	}
	return s[:3] + "******" + s[len(s)-3:]
}

func (s *Server) handleCreatePanel(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	p := store.Panel{Enabled: true, SyncInterval: 60}
	if err := readJSON(r, &p); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := validPanel(&p); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	id, err := s.st.CreatePanel(&p)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "panel.create", fmt.Sprint(id), p.Name)
	ok(w, map[string]any{"id": id})
}

func (s *Server) handleUpdatePanel(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	old, err := s.st.GetPanel(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	p := *old
	if err := readJSON(r, &p); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if strings.Contains(p.Token, "******") {
		p.Token = old.Token
	}
	p.ID = old.ID
	if err := validPanel(&p); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.st.UpdatePanel(&p); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.panelMu.Lock()
	delete(s.panelCli, p.ID)
	s.panelMu.Unlock()
	s.audit(r, a, "panel.update", fmt.Sprint(p.ID), p.Name)
	ok(w, map[string]any{"ok": true})
}

func (s *Server) handleDeletePanel(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	if err := s.st.DeletePanel(pathID(r)); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.audit(r, a, "panel.delete", fmt.Sprint(pathID(r)), "")
	ok(w, map[string]any{"ok": true})
}

func (s *Server) handleSyncPanel(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	p, err := s.st.GetPanel(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	res := s.syncPanel(r.Context(), p, true)
	ok(w, res)
}

// ---------------- api keys ----------------

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	list, err := s.st.ListAPIKeys()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, list)
}

func normScopes(sc string) string {
	var out []string
	for _, x := range store.SplitTags(sc) {
		if x == "read" || x == "write" {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		return "read"
	}
	return strings.Join(out, ",")
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	var req struct {
		Name        string `json:"name"`
		Scopes      string `json:"scopes"`
		IPWhitelist string `json:"ip_whitelist"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, 400, "请填写名称")
		return
	}
	raw := "nhk_" + util.RandToken(30)
	id, err := s.st.CreateAPIKey(req.Name, raw[:10], util.SHA256Hex(raw), normScopes(req.Scopes), req.IPWhitelist)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "apikey.create", fmt.Sprint(id), req.Name)
	ok(w, map[string]any{"id": id, "key": raw})
}

func (s *Server) handleUpdateAPIKey(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	var req struct {
		Name        string `json:"name"`
		Scopes      string `json:"scopes"`
		IPWhitelist string `json:"ip_whitelist"`
		Enabled     bool   `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.st.UpdateAPIKey(pathID(r), req.Name, normScopes(req.Scopes), req.IPWhitelist, req.Enabled); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "apikey.update", fmt.Sprint(pathID(r)), req.Name)
	ok(w, map[string]any{"ok": true})
}

func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	if err := s.st.DeleteAPIKey(pathID(r)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "apikey.delete", fmt.Sprint(pathID(r)), "")
	ok(w, map[string]any{"ok": true})
}

// ---------------- webhooks ----------------

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	list, err := s.st.ListWebhooks()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	for _, h := range list {
		h.Secret = maskSecret(h.Secret)
	}
	ok(w, list)
}

func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	h := store.Webhook{Enabled: true, Events: "*"}
	if err := readJSON(r, &h); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !strings.HasPrefix(h.URL, "http") {
		writeErr(w, 400, "URL 必须以 http/https 开头")
		return
	}
	h.Secret = "whsec_" + util.RandToken(24)
	id, err := s.st.CreateWebhook(&h)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "webhook.create", fmt.Sprint(id), h.URL)
	ok(w, map[string]any{"id": id, "secret": h.Secret})
}

func (s *Server) handleUpdateWebhook(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	var h store.Webhook
	if err := readJSON(r, &h); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	h.ID = pathID(r)
	if err := s.st.UpdateWebhook(&h); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, map[string]any{"ok": true})
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	if err := s.st.DeleteWebhook(pathID(r)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "webhook.delete", fmt.Sprint(pathID(r)), "")
	ok(w, map[string]any{"ok": true})
}

func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	list, _ := s.st.ListWebhooks()
	for _, h := range list {
		if h.ID == pathID(r) {
			ev := store.Event{ID: 0, Type: "test", Level: "info", Message: "NodeHub webhook 测试", Data: json.RawMessage(`{}`), CreatedAt: time.Now().Unix()}
			st := s.deliverWebhook(h, ev)
			ok(w, map[string]any{"status": st})
			return
		}
	}
	writeErr(w, 404, "not found")
}

// ---------------- settings ----------------

var editableSettings = map[string]bool{
	"site_name": true, "public_url": true, "sub_url": true, "sub_name_template": true, "sub_support_url": true, "sub_rule_mode": true,
	"ipcheck_interval_hours": true, "unlock_interval_hours": true, "report_interval": true, "offline_after": true,
	"traffic_retention_days": true, "agent_insecure_tls": true,
	"ipcheck_ipqs_key": true, "ipcheck_ipinfo_token": true, "ipcheck_ipapiis_key": true, "ipcheck_scamalytics_url": true,
	"ipcheck_scamalytics_key": true, "ipcheck_abuseipdb_key": true,
	"cf_api_token": true, "installer_url": true, "tg_bot_token": true, "tg_chat_id": true, "notify_events": true, "server_expire_remind_days": true,
}

var secretSettings = map[string]bool{"ipcheck_ipqs_key": true, "ipcheck_ipinfo_token": true, "ipcheck_ipapiis_key": true,
	"ipcheck_scamalytics_key": true, "ipcheck_abuseipdb_key": true, "tg_bot_token": true, "cf_api_token": true}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	all := s.st.AllSettings()
	out := map[string]string{}
	for k := range editableSettings {
		v := all[k]
		if secretSettings[k] && v != "" {
			v = maskSecret(v)
		}
		out[k] = v
	}
	ok(w, out)
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	var m map[string]string
	if err := readJSON(r, &m); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var changed []string
	for k, v := range m {
		if !editableSettings[k] {
			continue
		}
		if secretSettings[k] && strings.Contains(v, "******") {
			continue
		}
		v = strings.TrimSpace(v)
		if k == "public_url" || k == "sub_url" {
			v = strings.TrimRight(v, "/")
		}
		if err := s.st.SetSetting(k, v); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		changed = append(changed, k)
	}
	s.bump()
	s.audit(r, a, "settings.update", "", strings.Join(changed, ","))
	ok(w, map[string]any{"ok": true})
}

func (s *Server) handleTestTelegram(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	if err := s.sendTelegram("✅ NodeHub 通知测试成功"); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ok(w, map[string]any{"ok": true})
}

// handleBackup streams a consistent copy of the database.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	tmp := filepath.Join(s.opt.DataDir, fmt.Sprintf("backup-%d.db", time.Now().UnixNano()))
	if _, err := s.st.DB.Exec(`VACUUM INTO ?`, tmp); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer os.Remove(tmp)
	s.audit(r, a, "backup.download", "", "")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=nodehub-%s.db", time.Now().Format("20060102-150405")))
	http.ServeFile(w, r, tmp)
}

// ---------------- ip checks ----------------

type ipRow struct {
	NodeID     int64           `json:"node_id"`
	ServerID   int64           `json:"server_id"`
	NodeName   string          `json:"node_name"` // shown as the row title: the server name (or the node name when a node has its own egress IP)
	ServerName string          `json:"server_name"`
	Nodes      []string        `json:"nodes"` // every node that exits through this IP
	Region     string          `json:"region"`
	IP         string          `json:"ip"`
	Check      *store.IPCheck  `json:"check"`
	Unlock     json.RawMessage `json:"unlock,omitempty"` // latest streaming/AI unlock test of the server
}

// handleListIPChecks returns one row per egress IP, so several nodes on one server show up once.
func (s *Server) handleListIPChecks(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	vs, err := s.nodeViews()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	servers, _ := s.st.ListServers()
	sm := map[int64]*store.Server{}
	for _, v := range servers {
		sm[v.ID] = v
	}
	out := []ipRow{}
	byIP := map[string]int{}
	perServerIPs := map[int64]map[string]bool{}
	for _, v := range vs {
		srv := sm[v.ServerID]
		ip := ""
		if srv != nil {
			ip = s.egressIP(v.Node, srv)
			if perServerIPs[srv.ID] == nil {
				perServerIPs[srv.ID] = map[string]bool{}
			}
			perServerIPs[srv.ID][ip] = true
		}
		key := ip
		if key == "" { // no IP known yet: keep the node visible on its own
			key = fmt.Sprintf("node-%d", v.ID)
		}
		if i, seen := byIP[key]; seen {
			out[i].Nodes = append(out[i].Nodes, v.Name)
			if out[i].Check == nil && v.IPCheck != nil {
				out[i].Check, out[i].NodeID = v.IPCheck, v.ID
			}
			continue
		}
		row := ipRow{NodeID: v.ID, ServerID: v.ServerID, NodeName: v.ServerName, ServerName: v.ServerName, Nodes: []string{v.Name}, IP: ip, Check: v.IPCheck}
		if srv != nil {
			row.Region = srv.Region
			if json.Valid(srv.Unlock) && len(srv.Unlock) > 2 {
				row.Unlock = srv.Unlock
			}
		}
		byIP[key] = len(out)
		out = append(out, row)
	}
	// a server with several distinct egress IPs (e.g. landing machines): tell the rows apart by node name
	for i := range out {
		for _, v := range vs {
			if v.ID == out[i].NodeID && len(perServerIPs[v.ServerID]) > 1 {
				out[i].NodeName = v.ServerName + " · " + v.Name
			}
		}
	}
	// servers without any node still get a row (their checks are stored with node_id = 0)
	sc, _ := s.st.LatestServerIPChecks()
	for _, srv := range servers {
		if perServerIPs[srv.ID] != nil {
			continue
		}
		row := ipRow{ServerID: srv.ID, NodeName: srv.Name, ServerName: srv.Name, Nodes: []string{}, Region: srv.Region,
			IP: s.egressIP(&store.Node{}, srv), Check: sc[srv.ID]}
		if json.Valid(srv.Unlock) && len(srv.Unlock) > 2 {
			row.Unlock = srv.Unlock
		}
		out = append(out, row)
	}
	ok(w, map[string]any{"items": out, "running": s.ipcheckBusy.Load()})
}

func (s *Server) handleServerIPCheck(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	id := pathID(r)
	if _, err := s.st.GetServer(id); err != nil {
		notFoundOr500(w, err)
		return
	}
	s.runIPChecks(r.Context(), 0, id)
	c, err := s.st.LatestServerIPCheck(id)
	if err != nil {
		writeErr(w, 502, "检测失败（这台服务器已有节点时请在节点行检测）："+err.Error())
		return
	}
	ok(w, c)
}

func (s *Server) handleServerIPCheckDetail(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	c, err := s.st.LatestServerIPCheck(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	hist, _ := s.st.ServerIPCheckHistory(pathID(r), 20)
	ok(w, map[string]any{"latest": c, "history": hist})
}

func (s *Server) handleRunIPChecks(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	if !s.ipcheckBusy.CompareAndSwap(false, true) {
		writeErr(w, 409, "检测正在进行中")
		return
	}
	go func() {
		defer s.ipcheckBusy.Store(false)
		s.runIPChecks(context.Background(), 0)
	}()
	s.audit(r, a, "ipcheck.run_all", "", "")
	ok(w, map[string]any{"ok": true, "started": true})
}

func (s *Server) handleNodeIPCheck(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	id := pathID(r)
	if _, err := s.st.GetNode(id); err != nil {
		notFoundOr500(w, err)
		return
	}
	s.runIPChecks(r.Context(), id)
	c, err := s.st.LatestIPCheck(id)
	if err != nil {
		writeErr(w, 502, "检测失败："+err.Error())
		return
	}
	ok(w, c)
}

func (s *Server) handleNodeIPCheckDetail(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	c, err := s.st.LatestIPCheck(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	hist, _ := s.st.IPCheckHistory(pathID(r), 20)
	ok(w, map[string]any{"latest": c, "history": hist})
}
