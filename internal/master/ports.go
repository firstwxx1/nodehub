package master

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodehub/internal/proto"
	"nodehub/internal/store"
)

// Port awareness: agents report which ports other programs on the VPS hold. The master refuses a node
// port that is taken and suggests a free one. Data lives in memory only (it is refreshed every heartbeat).

type portSnap struct {
	at   time.Time
	list []proto.ListenPort
}

type portBook struct {
	mu sync.Mutex
	m  map[int64]portSnap
}

func (b *portBook) set(id int64, l []proto.ListenPort) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = map[int64]portSnap{}
	}
	b.m[id] = portSnap{time.Now(), l}
}

// get returns the snapshot if it is fresh (agents older than 1.2 never report, so it stays unknown).
func (b *portBook) get(id int64) (portSnap, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.m[id]
	return p, ok && time.Since(p.at) < 5*time.Minute
}

// nodeTransports lists the transports a node binds ("tcp", "udp").
func nodeTransports(n *store.Node) []string {
	switch n.Protocol {
	case "hysteria2", "tuic":
		return []string{"udp"}
	case "shadowsocks":
		return []string{"tcp", "udp"}
	}
	return []string{"tcp"}
}

func occupant(l []proto.ListenPort, transports []string, port int) (string, bool) {
	for _, p := range l {
		if p.Port != port {
			continue
		}
		for _, t := range transports {
			if p.Proto == t {
				return p.Proc, true
			}
		}
	}
	return "", false
}

// suggestPort returns the first port at or after `from` that is free on the host, not used by another
// node of the server, and outside any hop range.
func (s *Server) suggestPort(serverID int64, transports []string, from int, selfID int64) int {
	snap, _ := s.ports.get(serverID)
	nodes, _ := s.st.NodesByServer(serverID)
	if from < 1 || from > 65000 {
		from = 20443
	}
	for p := from; p <= 65535; p++ {
		if _, busy := occupant(snap.list, transports, p); busy {
			continue
		}
		clash := false
		for _, o := range nodes {
			if o.ID == selfID {
				continue
			}
			if o.Port == p {
				clash = true
			}
			if lo, hi, err := parseHopRange(o.Settings.HopPorts); err == nil && p >= lo && p <= hi {
				clash = true
			}
		}
		if !clash {
			return p
		}
	}
	return 0
}

// checkNodePorts rejects a node whose port (or ACME's port 80) is held by another program on the VPS.
func (s *Server) checkNodePorts(n *store.Node, old *store.Node) error {
	if n.Core == "script" {
		return nil // the installer owns its ports
	}
	snap, known := s.ports.get(n.ServerID)
	if !known || !n.Enabled {
		return nil
	}
	tr := nodeTransports(n)
	if old == nil || old.Port != n.Port || old.Protocol != n.Protocol {
		if proc, busy := occupant(snap.list, tr, n.Port); busy {
			sg := s.suggestPort(n.ServerID, tr, n.Port+1, n.ID)
			return fmt.Errorf("端口 %d/%s 已被服务器上的 %s 占用，建议改用 %d（也可换一个端口，或先停掉那个程序）", n.Port, strings.Join(tr, "+"), proc, sg)
		}
	}
	if n.Settings.CertMode == "acme" && (old == nil || old.Settings.CertMode != "acme") {
		if proc, busy := occupant(snap.list, []string{"tcp"}, 80); busy {
			return fmt.Errorf("ACME 的 HTTP 验证需要 80 端口，但它被 %s 占用了；请改用「ACME（DNS 验证）」或自签证书", proc)
		}
	}
	return nil
}

// GET /api/servers/{id}/ports?transport=udp&want=8443[&self=nodeID]
func (s *Server) handleServerPorts(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	id := pathID(r)
	if _, err := s.st.GetServer(id); err != nil {
		notFoundOr500(w, err)
		return
	}
	tr := []string{"tcp"}
	if t := r.URL.Query().Get("transport"); t != "" {
		tr = strings.Split(t, ",")
	}
	want, _ := strconv.Atoi(r.URL.Query().Get("want"))
	self, _ := strconv.ParseInt(r.URL.Query().Get("self"), 10, 64)
	snap, known := s.ports.get(id)
	out := map[string]any{"known": known}
	if !known {
		ok(w, out)
		return
	}
	out["age"] = int(time.Since(snap.at).Seconds())
	if want > 0 {
		proc, busy := occupant(snap.list, tr, want)
		out["want"] = want
		out["busy"] = busy
		out["proc"] = proc
		if busy {
			out["suggest"] = s.suggestPort(id, tr, want+1, self)
		}
	} else {
		out["suggest"] = s.defaultPort(id, tr, self)
	}
	_, p80 := occupant(snap.list, []string{"tcp"}, 80)
	out["port80_busy"] = p80
	if p80 {
		pr, _ := occupant(snap.list, []string{"tcp"}, 80)
		out["port80_proc"] = pr
	}
	ok(w, out)
}

// defaultPort prefers the usual HTTPS-looking ports and falls back to the first free high port.
func (s *Server) defaultPort(serverID int64, transports []string, selfID int64) int {
	for _, c := range []int{443, 8443, 2053, 2083, 2087, 2096, 4443, 9443} {
		if s.suggestPort(serverID, transports, c, selfID) == c {
			return c
		}
	}
	return s.suggestPort(serverID, transports, 20443, selfID)
}
