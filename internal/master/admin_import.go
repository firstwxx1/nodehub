package master

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"nodehub/internal/agent"
	"nodehub/internal/proto"
	"nodehub/internal/store"
)

// Import of nodes installed by other tools. Flow:
//   POST /api/servers/{id}/import/scan      -> queues "scan_import" on the agent
//   (UI polls /api/servers/{id}/commands until the scan finishes and shows the result)
//   POST /api/servers/{id}/import           -> creates the node + users from the stored scan, queues "takeover"
//   POST /api/servers/{id}/import/rollback  -> disables the node, queues "rollback_takeover"
// The scan result is read from the database, never from the browser, so the imported secrets are
// exactly what the agent reported.

func (s *Server) handleImportScan(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	srv, err := s.st.GetServer(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	if !srv.Online {
		writeErr(w, 400, "服务器不在线，无法扫描")
		return
	}
	id, err := s.st.QueueCommand(srv.ID, "scan_import", "")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "import.scan", fmt.Sprint(srv.ID), "")
	ok(w, map[string]any{"command_id": id})
}

func (s *Server) loadScan(serverID, cmdID int64) (*agent.ImportScan, error) {
	c, err := s.st.GetCommand(cmdID)
	if err != nil || c.ServerID != serverID || c.Type != "scan_import" {
		return nil, fmt.Errorf("找不到这次扫描")
	}
	if c.Status != "done" {
		return nil, fmt.Errorf("扫描还没完成或失败了: %s", c.Output)
	}
	if time.Since(time.Unix(c.UpdatedAt, 0)) > time.Hour {
		return nil, fmt.Errorf("扫描结果已超过 1 小时，请重新扫描")
	}
	var scan agent.ImportScan
	if err := json.Unmarshal([]byte(c.Output), &scan); err != nil {
		return nil, fmt.Errorf("扫描结果无法解析: %v", err)
	}
	return &scan, nil
}

// handleImportPreview returns the scan without secrets, for the confirmation dialog.
func (s *Server) handleImportPreview(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	var cid int64
	fmt.Sscan(r.URL.Query().Get("command_id"), &cid)
	c, err := s.st.GetCommand(cid)
	if err != nil || c.ServerID != pathID(r) {
		writeErr(w, 404, "not found")
		return
	}
	if c.Status == "pending" || c.Status == "sent" {
		ok(w, map[string]any{"status": c.Status})
		return
	}
	if c.Status == "failed" {
		ok(w, map[string]any{"status": "failed", "error": c.Output})
		return
	}
	scan, err := s.loadScan(c.ServerID, cid)
	if err != nil {
		ok(w, map[string]any{"status": "failed", "error": err.Error()})
		return
	}
	type pu struct {
		ID, Status, Note                 string
		ExpiresAt, LimitBytes, UsedBytes int64
		IPLimit                          int
		Exists                           bool
	}
	var users []pu
	for _, u := range scan.Users {
		_, exErr := s.st.UserByPassword(u.Password)
		users = append(users, pu{u.ID, u.Status, u.Note, u.ExpiresAt, u.LimitBytes, u.UsedBytes, u.IPLimit, exErr == nil})
	}
	conflict := ""
	if s.st.PortInUse(c.ServerID, scan.Port, 0) {
		conflict = fmt.Sprintf("NodeHub 里这台服务器已经有节点使用端口 %d", scan.Port)
	}
	ok(w, map[string]any{"status": "done", "scan": map[string]any{
		"kind": scan.Kind, "version": scan.Version, "port": scan.Port, "domain": scan.Domain, "cert_mode": scan.CertMode,
		"obfs": scan.ObfsPassword != "", "up_mbps": scan.UpMbps, "down_mbps": scan.DownMbps, "hop_ports": scan.HopPorts,
		"auth_mode": scan.AuthMode, "running": scan.Running, "warnings": scan.Warnings, "users": users, "conflict": conflict,
	}})
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	srv, err := s.st.GetServer(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	var req struct {
		CommandID  int64  `json:"command_id"`
		Name       string `json:"name"`
		Groups     string `json:"groups"`
		Masquerade string `json:"masquerade"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	scan, err := s.loadScan(srv.ID, req.CommandID)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Name == "" {
		req.Name = srv.Name + " Hysteria2"
	}
	st := proto.NodeSettings{SNI: scan.Domain, ObfsPassword: scan.ObfsPassword, UpMbps: scan.UpMbps, DownMbps: scan.DownMbps,
		HopPorts: scan.HopPorts, Masquerade: req.Masquerade, ACMEEmail: scan.ACMEEmail}
	if scan.ObfsPassword != "" {
		st.Obfs = "salamander"
	}
	switch scan.CertMode {
	case "acme":
		st.CertMode = "acme"
	case "file":
		st.CertMode, st.CertFile, st.KeyFile = "file", scan.CertFile, scan.KeyFile
	default:
		st.CertMode = "self"
	}
	node := &store.Node{ServerID: srv.ID, Name: req.Name, Core: "singbox", Protocol: "hysteria2", Port: scan.Port, Settings: st,
		Rate: 1, Groups: req.Groups, Enabled: true, Source: "local", Note: "imported from " + scan.Kind}
	if err := s.normalizeNode(node); err != nil {
		writeErr(w, 400, "无法创建节点: "+err.Error())
		return
	}

	// users first: matched by password so a repeated import does not duplicate them
	var created, reused []string
	groups := strings.Join(store.SplitTags(req.Groups), ",")
	for _, iu := range scan.Users {
		if iu.Password == "" {
			continue
		}
		if u, err := s.st.UserByPassword(iu.Password); err == nil {
			reused = append(reused, displayUser(u))
			continue
		}
		name := iu.ID
		if _, err := s.st.UserByUsername(name); err == nil {
			name = fmt.Sprintf("%s@%s", iu.ID, srv.Name)
		}
		enabled := iu.Status == "active"
		pw := iu.Password
		in := UserInput{Username: &name, Password: &pw, TrafficLimit: &iu.LimitBytes, Enabled: &enabled, Groups: &groups,
			DeviceLimit: &iu.IPLimit}
		note := strings.TrimSpace(iu.Note + " · imported from " + srv.Name)
		in.Note = &note
		if iu.ExpiresAt > 0 {
			in.ExpireAt = &iu.ExpiresAt
		}
		u, err := s.createUser(&in)
		if err != nil {
			writeErr(w, 400, fmt.Sprintf("导入用户 %s 失败: %v", iu.ID, err))
			return
		}
		if iu.UsedBytes > 0 { // carry over usage so quotas keep counting from where they were
			u.Down = iu.UsedBytes
			_ = s.st.UpdateUser(u)
			s.refreshUserStatus(u.ID)
		}
		created = append(created, displayUser(u))
	}
	id, err := s.st.CreateNode(node)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	node.ID = id
	if _, err := s.st.QueueCommand(srv.ID, "takeover", scan.Kind); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.bump()
	s.audit(r, a, "import.apply", fmt.Sprint(srv.ID), fmt.Sprintf("node=%d users=%d reused=%d", id, len(created), len(reused)))
	s.emit("node.imported", "info", fmt.Sprintf("服务器 %s 的 %s 节点已导入（端口 %d，新用户 %d 个）", srv.Name, scan.Kind, scan.Port, len(created)),
		map[string]any{"server_id": srv.ID, "node_id": id})
	ok(w, map[string]any{"node_id": id, "users_created": created, "users_reused": reused})
}

func (s *Server) handleImportRollback(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	var req struct {
		NodeID int64 `json:"node_id"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	n, err := s.st.GetNode(req.NodeID)
	if err != nil || n.ServerID != pathID(r) {
		writeErr(w, 404, "节点不存在")
		return
	}
	n.Enabled = false
	if err := s.st.UpdateNode(n); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.bump()
	if _, err := s.st.QueueCommand(n.ServerID, "rollback_takeover", ""); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "import.rollback", fmt.Sprint(n.ServerID), fmt.Sprint(n.ID))
	ok(w, map[string]any{"ok": true})
}
