package master

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"nodehub/internal/panel"
	"nodehub/internal/store"
)

func (s *Server) panelClient(p *store.Panel) (panel.Client, error) {
	s.panelMu.Lock()
	defer s.panelMu.Unlock()
	if c := s.panelCli[p.ID]; c != nil {
		return c, nil
	}
	c, err := panel.New(p)
	if err != nil {
		return nil, err
	}
	s.panelCli[p.ID] = c
	return c, nil
}

// syncPanelNode pulls users (and optionally the protocol config) for one panel-bound node.
func (s *Server) syncPanelNode(ctx context.Context, nodeID int64) error {
	n, err := s.st.GetNode(nodeID)
	if err != nil {
		return err
	}
	if n.Source != "panel" {
		return nil
	}
	p, err := s.st.GetPanel(n.PanelID)
	if err != nil {
		return fmt.Errorf("panel %d not found", n.PanelID)
	}
	c, err := s.panelClient(p)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if n.PanelSyncConfig {
		rc, err := c.FetchConfig(ctx, n)
		if err != nil {
			return fmt.Errorf("拉取节点配置失败: %w", err)
		}
		changed := rc.Port != n.Port || rc.Protocol != n.Protocol
		a, _ := json.Marshal(rc.Settings)
		b, _ := json.Marshal(n.Settings)
		changed = changed || string(a) != string(b)
		if changed {
			nn := *n
			nn.Port, nn.Protocol, nn.Settings = rc.Port, rc.Protocol, rc.Settings
			nn.Core = ""
			if old := n.Core; protocolSupports(rc.Protocol, old) {
				nn.Core = old
			}
			if err := s.normalizeNode(&nn); err != nil {
				return fmt.Errorf("面板配置无法应用: %w", err)
			}
			if err := s.st.UpdateNode(&nn); err != nil {
				return err
			}
			s.bump()
			log.Printf("node %d config updated from panel", n.ID)
			n = &nn
		}
	}
	users, notModified, err := c.FetchUsers(ctx, n)
	if err != nil {
		return fmt.Errorf("拉取用户失败: %w", err)
	}
	if notModified {
		return nil
	}
	if n.Protocol == "shadowsocks" {
		for i := range users {
			users[i].Password = userPassword(n, users[i].UUID)
		}
	}
	changed, err := s.st.ReplacePanelUsers(n.ID, users)
	if err != nil {
		return err
	}
	if changed {
		s.bump()
	}
	return nil
}

func protocolSupports(proto, core string) bool {
	for _, c := range protocolCores[proto] {
		if c == core {
			return true
		}
	}
	return false
}

// pushPanelNode reports traffic, online IPs and status for one node.
func (s *Server) pushPanelNode(ctx context.Context, n *store.Node, c panel.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	items, err := s.st.PendingPanelTraffic(n.ID)
	if err != nil {
		return err
	}
	if len(items) > 0 {
		if err := c.PushTraffic(ctx, n, items); err != nil {
			return fmt.Errorf("上报流量失败: %w", err)
		}
		if err := s.st.SubtractPanelTraffic(n.ID, items); err != nil {
			return err
		}
	}
	online, _ := s.st.OnlineIPs(n.ID, time.Now().Unix()-180)
	alive := map[int64][]string{}
	for _, o := range online {
		kind, id, okk := parseUserKey(o.UserKey)
		if !okk || kind != 'p' || o.IP == "-" {
			continue
		}
		alive[id] = append(alive[id], o.IP)
	}
	if err := c.PushAlive(ctx, n, alive); err != nil {
		log.Printf("panel alive push node %d: %v", n.ID, err)
	}
	if srv, err := s.st.GetServer(n.ServerID); err == nil && srv.Online {
		var st struct {
			CPUUsage  float64 `json:"cpu_usage"`
			MemTotal  uint64  `json:"mem_total"`
			MemUsed   uint64  `json:"mem_used"`
			DiskTotal uint64  `json:"disk_total"`
			DiskUsed  uint64  `json:"disk_used"`
			Uptime    uint64  `json:"uptime"`
			Load1     float64 `json:"load1"`
			Load5     float64 `json:"load5"`
			Load15    float64 `json:"load15"`
		}
		_ = json.Unmarshal(srv.Status, &st)
		_ = c.PushStatus(ctx, n, panel.Status{CPU: st.CPUUsage, MemTotal: st.MemTotal, MemUsed: st.MemUsed, Disk: st.DiskTotal, DiskUsed: st.DiskUsed,
			Uptime: st.Uptime, Load: [3]float64{st.Load1, st.Load5, st.Load15}})
	}
	return nil
}

type panelSyncResult struct {
	Nodes  int      `json:"nodes"`
	Errors []string `json:"errors"`
}

// syncPanel pulls users and pushes traffic for every node bound to the panel.
func (s *Server) syncPanel(ctx context.Context, p *store.Panel, force bool) panelSyncResult {
	res := panelSyncResult{Errors: []string{}}
	nodes, err := s.st.PanelNodes(p.ID)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return res
	}
	c, err := s.panelClient(p)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return res
	}
	for _, n := range nodes {
		if force {
			panel.ResetETag(c, n.ID)
		}
		res.Nodes++
		if err := s.syncPanelNode(ctx, n.ID); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("节点 %s: %v", n.Name, err))
		}
		if err := s.pushPanelNode(ctx, n, c); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("节点 %s: %v", n.Name, err))
		}
	}
	msg := ""
	if len(res.Errors) > 0 {
		msg = res.Errors[0]
		if p.LastError == "" {
			s.emit("panel.error", "error", fmt.Sprintf("面板 %s 同步失败: %s", p.Name, msg), map[string]any{"panel_id": p.ID})
		}
	} else if p.LastError != "" {
		s.emit("panel.recovered", "info", fmt.Sprintf("面板 %s 同步恢复正常", p.Name), map[string]any{"panel_id": p.ID})
	}
	s.st.SetPanelSync(p.ID, msg)
	return res
}
