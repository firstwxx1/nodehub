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

// Script nodes: Hysteria2 nodes created by running the hysteria2-installer script on the VPS (core "script").
//   POST /api/servers/{id}/script-node         -> queues "install_hy2" on the agent, returns command_id
//   (UI polls /api/servers/{id}/commands until it is done)
//   POST /api/servers/{id}/script-node/finish  -> creates the node from the installer's result
// NodeHub never runs a core for these nodes; deleting one with ?uninstall=1 queues "uninstall_hy2".

func (s *Server) handleScriptNodeInstall(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	srv, err := s.st.GetServer(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	if !srv.Online {
		writeErr(w, 400, "服务器不在线，无法安装")
		return
	}
	var req struct {
		Port     int    `json:"port"`
		CertType int    `json:"cert_type"`
		Domain   string `json:"domain"`
		Email    string `json:"email"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.CertType == 0 {
		req.CertType = 1
	}
	if req.Port == 0 {
		req.Port = s.defaultPort(srv.ID, []string{"udp"}, 0)
	}
	nodes, _ := s.st.NodesByServer(srv.ID)
	for _, n := range nodes {
		if n.Core == "script" {
			writeErr(w, 400, fmt.Sprintf("这台服务器上已经有原版脚本节点「%s」；一台服务器只能装一份", n.Name))
			return
		}
	}
	if req.CertType == 3 && !strings.Contains(req.Domain, ".") {
		writeErr(w, 400, "选择域名证书时必须填写域名（域名要先解析到这台服务器，并放行 TCP 80）")
		return
	}
	arg, _ := json.Marshal(agent.InstallReq{URL: s.st.Setting("installer_url"), Port: req.Port, CertType: req.CertType,
		Domain: strings.TrimSpace(req.Domain), Email: strings.TrimSpace(req.Email)})
	id, err := s.st.QueueCommand(srv.ID, "install_hy2", string(arg))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "script.install", fmt.Sprint(srv.ID), fmt.Sprintf("port=%d cert=%d", req.Port, req.CertType))
	ok(w, map[string]any{"command_id": id, "port": req.Port})
}

func (s *Server) handleScriptNodeFinish(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	srv, err := s.st.GetServer(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	var req struct {
		CommandID int64  `json:"command_id"`
		Name      string `json:"name"`
		Groups    string `json:"groups"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	c, err := s.st.GetCommand(req.CommandID)
	if err != nil || c.ServerID != srv.ID || c.Type != "install_hy2" {
		writeErr(w, 404, "找不到这次安装")
		return
	}
	if c.Status != "done" {
		writeErr(w, 400, "安装还没完成或失败了: "+c.Output)
		return
	}
	if time.Since(time.Unix(c.UpdatedAt, 0)) > 24*time.Hour {
		writeErr(w, 400, "安装结果已过期，请到「导入现有节点」重新扫描")
		return
	}
	var res agent.InstallResult
	if err := json.Unmarshal([]byte(c.Output), &res); err != nil || res.Scan == nil {
		writeErr(w, 400, "安装结果无法解析")
		return
	}
	nodes, _ := s.st.NodesByServer(srv.ID)
	for _, n := range nodes {
		if n.Core == "script" {
			writeErr(w, 400, "这台服务器的脚本节点已经创建过了")
			return
		}
	}
	id, err := s.createScriptNode(srv, res.Scan, req.Name, req.Groups)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.bump()
	s.audit(r, a, "script.finish", fmt.Sprint(srv.ID), fmt.Sprint(id))
	ok(w, map[string]any{"node_id": id})
}

// createScriptNode stores a script node from what the installer / scan reported (no command is queued).
func (s *Server) createScriptNode(srv *store.Server, scan *agent.ImportScan, name, groups string) (int64, error) {
	pw := scan.AuthPassword
	for _, u := range scan.Users {
		if pw == "" && u.Password != "" {
			pw = u.Password
		}
	}
	if pw == "" {
		return 0, fmt.Errorf("没能从脚本读到主密码，无法生成订阅")
	}
	if name == "" {
		name = srv.Name + " Hysteria2"
	}
	st := proto.NodeSettings{SNI: scan.Domain, ObfsPassword: scan.ObfsPassword, UpMbps: scan.UpMbps, DownMbps: scan.DownMbps,
		HopPorts: scan.HopPorts, SharedPassword: pw, ACMEEmail: scan.ACMEEmail}
	if scan.ObfsPassword != "" {
		st.Obfs = "salamander"
	}
	if scan.CertMode == "acme" {
		st.CertMode = "acme"
	} else if scan.CertMode == "file" && !scan.Insecure {
		st.CertMode, st.CertFile, st.KeyFile = "file", scan.CertFile, scan.KeyFile
	} else {
		st.CertMode = "self"
	}
	node := &store.Node{ServerID: srv.ID, Name: name, Core: "script", Protocol: "hysteria2", Port: scan.Port, Settings: st,
		Rate: 1, Groups: groups, Enabled: true, Source: "local", Note: "原版脚本 " + scan.Version}
	if err := s.normalizeNode(node); err != nil {
		return 0, fmt.Errorf("无法创建节点: %v", err)
	}
	return s.st.CreateNode(node)
}

// POST /api/servers/{id}/script-node/adopt: add an already running hysteria2-installer node to the panel as it is
// (from a finished scan_import command); nothing on the server is touched.
func (s *Server) handleScriptNodeAdopt(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	srv, err := s.st.GetServer(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	var req struct {
		CommandID int64  `json:"command_id"`
		Name      string `json:"name"`
		Groups    string `json:"groups"`
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
	nodes, _ := s.st.NodesByServer(srv.ID)
	for _, n := range nodes {
		if n.Core == "script" {
			writeErr(w, 400, "这台服务器的脚本节点已经在面板里了")
			return
		}
	}
	id, err := s.createScriptNode(srv, scan, req.Name, req.Groups)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.bump()
	s.audit(r, a, "script.adopt", fmt.Sprint(srv.ID), fmt.Sprint(id))
	ok(w, map[string]any{"node_id": id})
}
