package master

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodehub/internal/agent"
	"nodehub/internal/store"
)

// Per-user accounts on script nodes: NodeHub mirrors its active users into each hysteria2-installer portal
// ("nh-<id>", own password / expiry / traffic cap / device limit), so the script authenticates and cuts off
// every customer by itself. Until a server's first successful sync, subscriptions keep using the script's
// owner password (Settings.PortalUsers marks the switch). Usage the portals report is added to the users.

const portalPrefix = "nh-"

type portalSyncState struct {
	mu      sync.Mutex
	hash    map[int64]string    // last desired-set hash queued per server
	at      map[int64]time.Time // when it was queued
	pending map[int64]int64     // command id still in flight
}

func (s *Server) portalDesired(n *store.Node, users []*store.User) []agent.PortalUser {
	out := []agent.PortalUser{}
	for _, u := range users {
		if u.Status != "active" || !nodeVisible(n, u) {
			continue
		}
		out = append(out, agent.PortalUser{ID: portalPrefix + strconv.FormatInt(u.ID, 10), Password: connPw(u),
			ExpiresAt: u.ExpireAt, TrafficGB: float64(u.TrafficLimit) / (1 << 30), IPLimit: u.DeviceLimit})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// portalSyncTick queues a portal_sync for every server with a script Hysteria2 node whose desired user set
// changed, and at least every 10 minutes to collect usage.
func (s *Server) portalSyncTick() {
	ps := &s.portal
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.hash == nil {
		ps.hash, ps.at, ps.pending = map[int64]string{}, map[int64]time.Time{}, map[int64]int64{}
	}
	nodes, err := s.st.ListNodes()
	if err != nil {
		return
	}
	users, err := s.st.AllUsers()
	if err != nil {
		return
	}
	for _, n := range nodes {
		if n.Core != "script" || n.Protocol != "hysteria2" || !n.Enabled {
			continue
		}
		srv, err := s.st.GetServer(n.ServerID)
		if err != nil || !srv.Online || versionLess(srv.AgentVersion, "1.3.2") {
			continue
		}
		if id := ps.pending[srv.ID]; id > 0 {
			if c, err := s.st.GetCommand(id); err == nil && (c.Status == "pending" || c.Status == "sent") && time.Since(time.Unix(c.CreatedAt, 0)) < 10*time.Minute {
				continue
			}
			delete(ps.pending, srv.ID)
		}
		want := s.portalDesired(n, users)
		b, _ := json.Marshal(agent.PortalSyncReq{Prefix: portalPrefix, Users: want})
		sum := sha256.Sum256(b)
		h := hex.EncodeToString(sum[:8])
		if h == ps.hash[srv.ID] && time.Since(ps.at[srv.ID]) < 10*time.Minute {
			continue
		}
		id, err := s.st.QueueCommand(srv.ID, "portal_sync", string(b))
		if err != nil {
			continue
		}
		ps.hash[srv.ID], ps.at[srv.ID], ps.pending[srv.ID] = h, time.Now(), id
	}
}

// afterPortalSync books the usage growth and switches the server's script node to per-user credentials.
func (s *Server) afterPortalSync(srv *store.Server, c *store.CommandRow) {
	var res agent.PortalSyncResult
	if json.Unmarshal([]byte(c.Output), &res) != nil {
		return
	}
	key := fmt.Sprintf("portal_usage_%d", srv.ID)
	prev := map[string]int64{}
	_ = json.Unmarshal([]byte(s.st.Setting(key)), &prev)
	next := map[string]int64{}
	for _, u := range res.Usage {
		next[u.ID] = u.Used
		uid, err := strconv.ParseInt(strings.TrimPrefix(u.ID, portalPrefix), 10, 64)
		if err != nil {
			continue
		}
		delta := u.Used - prev[u.ID]
		if delta < 0 { // counter was reset on the portal (e.g. user re-created)
			delta = u.Used
		}
		if _, seen := prev[u.ID]; !seen && len(prev) == 0 && s.st.Setting(key) == "" {
			delta = 0 // very first sample of this server: baseline only
		}
		if delta > 0 {
			_ = s.st.AddUserTraffic(uid, 0, delta)
			s.refreshUserStatus(uid)
		}
	}
	if b, err := json.Marshal(next); err == nil {
		_ = s.st.SetSetting(key, string(b))
	}
	if len(res.Errors) > 0 {
		return
	}
	nodes, _ := s.st.NodesByServer(srv.ID)
	for _, n := range nodes {
		if n.Core == "script" && n.Protocol == "hysteria2" && !n.Settings.PortalUsers {
			n.Settings.PortalUsers = true
			if err := s.st.UpdateNode(n); err == nil {
				s.bump()
				s.emit("node.script_portal", "info", fmt.Sprintf("服务器 %s 的原版脚本节点已切换为每个用户独立账号（%d 个用户）", srv.Name, res.Created+res.Updated),
					map[string]any{"server_id": srv.ID, "node_id": n.ID})
			}
		}
	}
}

// versionLess compares dotted versions numerically ("1.3.10" > "1.3.2").
func versionLess(a, b string) bool {
	pa, pb := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}
