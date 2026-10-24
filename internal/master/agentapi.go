package master

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nodehub/internal/proto"
	"nodehub/internal/store"
	"nodehub/internal/util"
)

func (s *Server) agentAuth(h func(http.ResponseWriter, *http.Request, *store.Server)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" {
			writeErr(w, 401, "missing token")
			return
		}
		srv, err := s.st.ServerByToken(util.SHA256Hex(tok))
		if err != nil {
			writeErr(w, 401, "invalid token")
			return
		}
		h(w, r, srv)
	}
}

func (s *Server) agentHeartbeat(w http.ResponseWriter, r *http.Request, srv *store.Server) {
	var hb proto.Heartbeat
	if err := readJSON(r, &hb); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if hb.PublicIPv4 == "" {
		hb.PublicIPv4 = clientIP(r)
	}
	if hb.AgentVersion != "" && hb.Ports != nil {
		s.ports.set(srv.ID, hb.Ports)
	}
	hb.Ports = nil // not persisted in status_json
	wasOnline := srv.Online
	if err := s.st.UpdateServerHeartbeat(srv.ID, &hb); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !wasOnline && srv.LastSeen > 0 {
		s.emit("server.online", "info", fmt.Sprintf("服务器 %s 恢复在线", srv.Name), map[string]any{"server_id": srv.ID, "name": srv.Name})
	} else if !wasOnline {
		s.emit("server.online", "info", fmt.Sprintf("服务器 %s 首次上线（%s）", srv.Name, hb.PublicIPv4), map[string]any{"server_id": srv.ID, "name": srv.Name})
	}
	ver, err := s.configVersion(srv)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	cmds, _ := s.st.TakeCommands(srv.ID)
	every, _ := strconv.Atoi(s.st.SettingOr("report_interval", "60"))
	ok(w, proto.HeartbeatResp{ConfigVersion: ver, Commands: cmds, ReportEvery: every})
}

func (s *Server) agentConfig(w http.ResponseWriter, r *http.Request, srv *store.Server) {
	cfg, err := s.buildAgentConfig(srv)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, cfg)
}

// configVersion is cached per server and recomputed only after configGen changes.
func (s *Server) configVersion(srv *store.Server) (string, error) {
	gen := s.configGen.Load()
	s.verMu.Lock()
	e, okk := s.verCache[srv.ID]
	s.verMu.Unlock()
	if okk && e.gen == gen {
		return e.ver, nil
	}
	cfg, err := s.buildAgentConfig(srv)
	if err != nil {
		return "", err
	}
	s.verMu.Lock()
	s.verCache[srv.ID] = verEntry{gen: gen, ver: cfg.Version}
	s.verMu.Unlock()
	return cfg.Version, nil
}

func userKeyLocal(nodeID, userID int64) string   { return fmt.Sprintf("n%d.u%d", nodeID, userID) }
func userKeyPanel(nodeID, remoteID int64) string { return fmt.Sprintf("n%d.p%d", nodeID, remoteID) }

// nodeVisible reports whether a local user may use a node (empty node groups = everyone).
func nodeVisible(n *store.Node, u *store.User) bool {
	ng := store.SplitTags(n.Groups)
	if len(ng) == 0 {
		return true
	}
	for _, g := range store.SplitTags(u.Groups) {
		for _, h := range ng {
			if g == h {
				return true
			}
		}
	}
	return false
}

// localUserPassword prefers the user's own password for password-based protocols (used for imported users).
func localUserPassword(n *store.Node, u *store.User) string {
	if u.Password != "" && n.Protocol != "shadowsocks" {
		return u.Password
	}
	return userPassword(n, u.UUID)
}

func userPassword(n *store.Node, uuid string) string {
	if n.Protocol == "shadowsocks" {
		return util.SSUserKey(n.Settings.Cipher, uuid)
	}
	return uuid
}

func (s *Server) buildAgentConfig(srv *store.Server) (*proto.AgentConfig, error) {
	nodes, err := s.st.NodesByServer(srv.ID)
	if err != nil {
		return nil, err
	}
	var users []*store.User
	cfg := &proto.AgentConfig{Nodes: []proto.NodeConfig{}}
	if srv.Enabled {
		for _, n := range nodes {
			if !n.Enabled || n.Core == "script" { // script nodes are run by their own installer, not by the agent's cores
				continue
			}
			nc := proto.NodeConfig{ID: n.ID, Name: n.Name, Core: n.Core, Protocol: n.Protocol, Listen: n.Listen, Port: n.Port, Settings: n.Settings, Users: []proto.NodeUser{}}
			if nc.Settings.CertMode == "acme_dns" {
				nc.Settings.ACMEDNSProvider, nc.Settings.ACMEDNSToken = "cloudflare", s.st.Setting("cf_api_token")
			}
			if n.Source == "panel" {
				pus, err := s.st.PanelUsers(n.ID)
				if err != nil {
					return nil, err
				}
				for _, pu := range pus {
					pw := pu.Password
					if pw == "" || n.Protocol == "shadowsocks" && util.SSKeyLen(n.Settings.Cipher) > 0 {
						pw = userPassword(n, pu.UUID)
					}
					nc.Users = append(nc.Users, proto.NodeUser{Key: userKeyPanel(n.ID, pu.RemoteID), UUID: pu.UUID, Password: pw,
						SpeedLimit: pu.SpeedLimit, DeviceLimit: pu.DeviceLimit})
				}
			} else {
				if users == nil {
					if users, err = s.st.ActiveUsers(); err != nil {
						return nil, err
					}
				}
				for _, u := range users {
					if !nodeVisible(n, u) {
						continue
					}
					sl, dl := u.SpeedLimit, u.DeviceLimit
					if n.SpeedLimit > 0 && (sl == 0 || n.SpeedLimit < sl) {
						sl = n.SpeedLimit
					}
					if n.DeviceLimit > 0 && (dl == 0 || n.DeviceLimit < dl) {
						dl = n.DeviceLimit
					}
					nc.Users = append(nc.Users, proto.NodeUser{Key: userKeyLocal(n.ID, u.ID), UUID: u.UUID, Password: localUserPassword(n, u), SpeedLimit: sl, DeviceLimit: dl})
				}
			}
			cfg.Nodes = append(cfg.Nodes, nc)
		}
	}
	b, _ := json.Marshal(cfg.Nodes)
	h := sha256.Sum256(b)
	cfg.Version = hex.EncodeToString(h[:8])
	return cfg, nil
}

// ---------------- report processing ----------------

func parseUserKey(key string) (kind byte, id int64, ok bool) {
	i := strings.Index(key, ".")
	if i < 0 || i+2 > len(key) {
		return 0, 0, false
	}
	id, err := strconv.ParseInt(key[i+2:], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return key[i+1], id, true
}

func (s *Server) agentReport(w http.ResponseWriter, r *http.Request, srv *store.Server) {
	var rep proto.Report
	if err := readJSON(r, &rep); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	nodes, _ := s.st.NodesByServer(srv.ID)
	byID := map[int64]*store.Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	now := time.Now().Unix()
	hour := now - now%3600
	touched := map[int64]bool{}
	for _, t := range rep.Traffic {
		n := byID[t.NodeID]
		if n == nil || (t.Up <= 0 && t.Down <= 0) {
			continue
		}
		kind, id, okk := parseUserKey(t.Key)
		if !okk {
			continue
		}
		switch kind {
		case 'u':
			up, down := int64(float64(t.Up)*n.Rate), int64(float64(t.Down)*n.Rate)
			_ = s.st.AddUserTraffic(id, up, down)
			_ = s.st.AddHourly(hour, n.ID, id, up, down)
			touched[id] = true
		case 'p':
			// panels apply their own rate multiplier, so push raw bytes
			_ = s.st.AddPanelTraffic(n.ID, id, t.Up, t.Down)
		}
	}
	hasNodeStats := map[int64]bool{}
	for _, ns := range rep.NodeStats {
		if byID[ns.NodeID] == nil {
			continue
		}
		hasNodeStats[ns.NodeID] = true
		_ = s.st.AddHourly(hour, ns.NodeID, 0, ns.Up, ns.Down)
		_ = s.st.AddNodeTotals(ns.NodeID, ns.Up, ns.Down)
	}
	// fall back to summing user traffic for nodes without inbound counters
	sum := map[int64][2]int64{}
	for _, t := range rep.Traffic {
		if byID[t.NodeID] != nil && !hasNodeStats[t.NodeID] {
			v := sum[t.NodeID]
			v[0] += t.Up
			v[1] += t.Down
			sum[t.NodeID] = v
		}
	}
	for id, v := range sum {
		_ = s.st.AddHourly(hour, id, 0, v[0], v[1])
		_ = s.st.AddNodeTotals(id, v[0], v[1])
	}
	for _, o := range rep.Online {
		if byID[o.NodeID] == nil {
			continue
		}
		if len(o.IPs) == 0 {
			_ = s.st.TouchOnline(o.NodeID, o.Key, "-", now)
		}
		for _, ip := range o.IPs {
			_ = s.st.TouchOnline(o.NodeID, o.Key, ip, now)
		}
	}
	s.st.RefreshNodeOnlineCounts(now - 180)
	for _, res := range rep.Results {
		s.st.FinishCommand(srv.ID, res)
		if res.OK {
			s.afterScriptInstall(srv, res.ID)
		} else if c, err := s.st.GetCommand(res.ID); err == nil && c.Type == "install_hy2" {
			out := res.Output
			if i := strings.Index(out, "\n"); i > 0 {
				out = out[:i]
			}
			s.emit("node.script_failed", "warn", fmt.Sprintf("服务器 %s 安装原版脚本失败：%s（完整日志见 服务器 → 详情与命令记录）", srv.Name, out),
				map[string]any{"server_id": srv.ID, "command_id": res.ID})
		}
	}
	if rep.Unlock != nil {
		b, _ := json.Marshal(rep.Unlock)
		_ = s.st.SetServerUnlock(srv.ID, string(b))
	}
	for uid := range touched {
		s.refreshUserStatus(uid)
	}
	ok(w, map[string]any{"ok": true})
}

// refreshUserStatus recomputes a user's status and reacts to transitions.
func (s *Server) refreshUserStatus(uid int64) {
	u, err := s.st.GetUser(uid)
	if err != nil {
		return
	}
	st := u.ComputeStatus(time.Now().Unix())
	if st == u.Status {
		return
	}
	old := u.Status
	u.Status = st
	if err := s.st.UpdateUser(u); err != nil {
		return
	}
	s.bump()
	data := map[string]any{"user_id": u.ID, "external_id": u.ExternalID, "username": u.Username, "old_status": old, "status": st,
		"used": u.Up + u.Down, "traffic_limit": u.TrafficLimit, "expire_at": u.ExpireAt}
	switch st {
	case "exhausted":
		s.emit("user.exhausted", "warn", fmt.Sprintf("用户 %s 流量已用尽", displayUser(u)), data)
	case "expired":
		s.emit("user.expired", "warn", fmt.Sprintf("用户 %s 已到期", displayUser(u)), data)
	case "disabled":
		s.emit("user.disabled", "info", fmt.Sprintf("用户 %s 已停用", displayUser(u)), data)
	case "active":
		s.emit("user.activated", "info", fmt.Sprintf("用户 %s 恢复可用", displayUser(u)), data)
	}
}

func displayUser(u *store.User) string {
	if u.Username != "" {
		return u.Username
	}
	if u.ExternalID != "" {
		return "ext:" + u.ExternalID
	}
	return u.UUID[:8]
}

// ---------------- install & downloads ----------------

var safeName = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	io.WriteString(w, strings.ReplaceAll(installScript, "__MASTER_URL__", s.publicURL(r)))
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "agent" {
		arch := r.URL.Query().Get("arch")
		if arch == "" {
			arch = "amd64"
		}
		name = "nodehub-agent-linux-" + arch
	}
	if !safeName.MatchString(name) || s.opt.DistDir == "" {
		writeErr(w, 404, "not found")
		return
	}
	p := filepath.Join(s.opt.DistDir, name)
	f, err := os.Open(p)
	if err != nil {
		writeErr(w, 404, "not found: "+name)
		return
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if _, err := f.Seek(0, 0); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	st, _ := f.Stat()
	w.Header().Set("X-Checksum-Sha256", hex.EncodeToString(h.Sum(nil)))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, st.ModTime(), f)
	log.Printf("download %s by %s", name, clientIP(r))
}
