package master

import (
	"fmt"
	"net/http"
	"strings"

	"nodehub/internal/store"
	"nodehub/internal/util"
)

func (s *Server) installCommand(r *http.Request, token string) string {
	u := s.publicURL(r)
	cmd := fmt.Sprintf("curl -fsSL %s/install.sh | bash -s -- --master %s --token %s", u, u, token)
	if strings.HasPrefix(u, "https://") && s.st.Setting("agent_insecure_tls") == "1" {
		cmd += " --insecure"
	}
	return cmd
}

func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	list, err := s.st.ListServers()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, list)
}

func (s *Server) handleGetServer(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	srv, err := s.st.GetServer(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	nodes, _ := s.st.NodesByServer(srv.ID)
	ok(w, map[string]any{"server": srv, "nodes": nodes})
}

func validServer(v *store.Server) error {
	v.Name = strings.TrimSpace(v.Name)
	if v.Name == "" {
		return fmt.Errorf("服务器名称不能为空")
	}
	if v.TrafficResetDay < 1 || v.TrafficResetDay > 28 {
		v.TrafficResetDay = 1
	}
	return nil
}

func (s *Server) handleCreateServer(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	v := store.Server{Enabled: true, TrafficResetDay: 1}
	if err := readJSON(r, &v); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := validServer(&v); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	token := util.RandToken(24)
	id, err := s.st.CreateServer(&v, util.SHA256Hex(token))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "server.create", fmt.Sprint(id), v.Name)
	srv, _ := s.st.GetServer(id)
	ok(w, map[string]any{"server": srv, "token": token, "install_command": s.installCommand(r, token)})
}

func (s *Server) handleUpdateServer(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	old, err := s.st.GetServer(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	v := *old
	if err := readJSON(r, &v); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	v.ID = old.ID
	if err := validServer(&v); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.st.UpdateServer(&v); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.bump()
	s.audit(r, a, "server.update", fmt.Sprint(v.ID), v.Name)
	ok(w, v)
}

func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	id := pathID(r)
	nodes, _ := s.st.NodesByServer(id)
	for _, n := range nodes {
		_ = s.st.DeleteNode(n.ID)
	}
	if err := s.st.DeleteServer(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.bump()
	s.audit(r, a, "server.delete", fmt.Sprint(id), "")
	ok(w, map[string]any{"ok": true})
}

func (s *Server) handleResetServerToken(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	id := pathID(r)
	if _, err := s.st.GetServer(id); err != nil {
		notFoundOr500(w, err)
		return
	}
	token := util.RandToken(24)
	if err := s.st.SetServerToken(id, util.SHA256Hex(token)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "server.token_reset", fmt.Sprint(id), "")
	ok(w, map[string]any{"token": token, "install_command": s.installCommand(r, token)})
}

var allowedCommands = map[string]bool{"restart_core": true, "reload": true, "unlock_test": true, "upgrade_agent": true}

func (s *Server) handleServerCommand(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	var req struct{ Type, Arg string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !allowedCommands[req.Type] {
		writeErr(w, 400, "不支持的命令")
		return
	}
	ids := []int64{pathID(r)}
	if pathID(r) == 0 { // id 0 = all servers
		ids = nil
		list, _ := s.st.ListServers()
		for _, v := range list {
			ids = append(ids, v.ID)
		}
	}
	for _, id := range ids {
		if _, err := s.st.QueueCommand(id, req.Type, req.Arg); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	s.audit(r, a, "server.command", fmt.Sprint(ids), req.Type)
	ok(w, map[string]any{"ok": true, "queued": len(ids)})
}

func (s *Server) handleServerCommands(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	list, err := s.st.ListCommands(pathID(r), 30)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	for i := range list {
		if list[i].Type == "scan_import" && list[i].Status == "done" {
			list[i].Output = "（扫描结果含密码，已隐藏；在「导入现有节点」里查看）"
		}
	}
	ok(w, list)
}

func (s *Server) handleServerResetTraffic(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	if err := s.st.ResetServerMonthTraffic(pathID(r)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "server.reset_traffic", fmt.Sprint(pathID(r)), "")
	ok(w, map[string]any{"ok": true})
}
