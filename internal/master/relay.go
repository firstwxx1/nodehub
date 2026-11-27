package master

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"nodehub/internal/proto"
	"nodehub/internal/store"
)

// ServerRelayMinAgentVersion is the minimum agent version that supports AgentConfig.Relays
// (single-port server-side multi-user routing to upstream US/EU landing nodes).
const ServerRelayMinAgentVersion = "1.3.6"

// deriveUUID produces a deterministic RFC 4122 v5-shaped UUID from parts via SHA-256.
func deriveUUID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	h[6] = (h[6] & 0x0f) | 0x50
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

func relayLandingUUID(target *store.Node) string {
	return deriveUUID(
		"nh-relay-landing-v1",
		strconv.FormatInt(target.ID, 10),
		target.Settings.RealityPrivateKey,
		target.Settings.RealityPublicKey,
		target.Settings.SNI,
		strconv.Itoa(target.Port),
	)
}

func relayEntryUUID(userUUID string, entryNodeID, targetNodeID int64) string {
	return deriveUUID(
		"nh-relay-entry-v1",
		userUUID,
		strconv.FormatInt(entryNodeID, 10),
		strconv.FormatInt(targetNodeID, 10),
	)
}

func relayEntryUserKey(entryNodeID, userID, targetNodeID int64) string {
	return fmt.Sprintf("n%d.u%d.r%d", entryNodeID, userID, targetNodeID)
}

func relayLandingUserKey(targetNodeID int64) string {
	return fmt.Sprintf("n%d.r0", targetNodeID)
}

type relayTarget struct {
	Node      *store.Node
	Server    *store.Server
	Country   string
	Addr      string
	LandingID string
	Outbound  proto.RelayOutbound
}

type relayPlan struct {
	EntryServer *store.Server
	EntryNode   *store.Node
	EntryAddr   string
	EntryReady  bool
	Targets     []relayTarget
}

func (s *Server) serverCountry(srv *store.Server, srvNodes []*store.Node, checks map[int64]*store.IPCheck) string {
	if len(srv.Region) == 2 {
		return strings.ToUpper(srv.Region)
	}
	for _, n := range srvNodes {
		if c := checks[n.ID]; c != nil && len(c.GeoCountry) == 2 {
			return strings.ToUpper(c.GeoCountry)
		}
	}
	return ""
}

func (s *Server) serverRegionKey(srv *store.Server, srvNodes []*store.Node, checks map[int64]*store.IPCheck) (regionKey, cc string) {
	cc = s.serverCountry(srv, srvNodes, checks)
	rk := detectRegionKey(subNode{Name: srv.Name, Country: cc})
	if rk == "OTHER" {
		for _, n := range srvNodes {
			if k := detectRegionKey(subNode{Name: n.Name, Country: cc}); k != "OTHER" {
				rk = k
				break
			}
		}
	}
	return rk, cc
}

func isRelayCapableVLESS(n *store.Node) bool {
	if !n.Enabled || n.Source != "local" || n.Core == "script" || n.Protocol != "vless" {
		return false
	}
	netw := strings.ToLower(strings.TrimSpace(n.Settings.Network))
	if netw != "" && netw != "tcp" && netw != "raw" {
		return false
	}
	return n.Settings.Security == "reality" || n.Settings.Security == "tls"
}

func relayTargetSNI(n *store.Node) string {
	st := n.Settings
	if st.Security == "reality" {
		if v := strings.Split(orStr(st.RealityServerName, st.SNI), ",")[0]; v != "" {
			return strings.TrimSpace(v)
		}
		if h, _, err := net.SplitHostPort(st.RealityDest); err == nil && h != "" {
			return h
		}
		return strings.TrimSpace(st.RealityDest)
	}
	return strings.TrimSpace(st.SNI)
}

func serverSupportsRelay(srv *store.Server) bool {
	if srv == nil || !srv.Enabled {
		return false
	}
	if srv.LastSeen > 0 && !srv.Online {
		return false
	}
	if srv.AgentVersion != "" && versionLess(srv.AgentVersion, ServerRelayMinAgentVersion) {
		return false
	}
	return true
}

// computeRelayPlan selects one Asia entry server (with an enabled Xray VLESS-Reality/TLS node)
// and all US/EU VLESS-Reality/TLS landing nodes to build zero-extra-port server-side transit relays.
func (s *Server) computeRelayPlan() relayPlan {
	mode := strings.ToLower(strings.TrimSpace(s.st.SettingOr("sub_relay_mode", "auto")))
	if mode == "off" || mode == "0" || mode == "false" || mode == "client" {
		return relayPlan{}
	}
	servers, err := s.st.ListServers()
	if err != nil || len(servers) == 0 {
		return relayPlan{}
	}
	nodes, err := s.st.ListNodes()
	if err != nil || len(nodes) == 0 {
		return relayPlan{}
	}
	checks, _ := s.st.LatestIPChecks()

	nodesBySrv := map[int64][]*store.Node{}
	for _, n := range nodes {
		nodesBySrv[n.ServerID] = append(nodesBySrv[n.ServerID], n)
	}
	for sid := range nodesBySrv {
		sort.SliceStable(nodesBySrv[sid], func(i, j int) bool {
			if nodesBySrv[sid][i].Sort != nodesBySrv[sid][j].Sort {
				return nodesBySrv[sid][i].Sort < nodesBySrv[sid][j].Sort
			}
			return nodesBySrv[sid][i].ID < nodesBySrv[sid][j].ID
		})
	}

	preferredEntryID, _ := strconv.ParseInt(strings.TrimSpace(s.st.Setting("sub_relay_entry_server_id")), 10, 64)

	type entryCand struct {
		srv   *store.Server
		node  *store.Node
		rk    string
		ready bool
	}
	var entries []entryCand
	type srvMeta struct {
		srv *store.Server
		rk  string
		cc  string
	}
	var targetsMeta []srvMeta

	for _, srv := range servers {
		if !srv.Enabled {
			continue
		}
		snodes := nodesBySrv[srv.ID]
		rk, cc := s.serverRegionKey(srv, snodes, checks)
		var bestEntry *store.Node
		for _, n := range snodes {
			if isRelayCapableVLESS(n) {
				if bestEntry == nil || (bestEntry.Core != "xray" && n.Core == "xray") {
					bestEntry = n
				}
			}
		}
		if bestEntry != nil && (isAsiaRelayRegion(rk) || (preferredEntryID > 0 && srv.ID == preferredEntryID)) {
			entries = append(entries, entryCand{srv: srv, node: bestEntry, rk: rk, ready: serverSupportsRelay(srv)})
		}
		if isRelayTargetRegion(rk) {
			targetsMeta = append(targetsMeta, srvMeta{srv: srv, rk: rk, cc: cc})
		}
	}
	if len(entries) == 0 || len(targetsMeta) == 0 {
		return relayPlan{}
	}

	// Pick entry server: explicit setting first, then ready+online, then JP/HK/TW/SG/KR, then lowest ID.
	regionRank := map[string]int{"JP": 1, "HK": 2, "TW": 3, "SG": 4, "KR": 5}
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if preferredEntryID > 0 && (a.srv.ID == preferredEntryID) != (b.srv.ID == preferredEntryID) {
			return a.srv.ID == preferredEntryID
		}
		if a.ready != b.ready {
			return a.ready
		}
		if a.srv.Online != b.srv.Online {
			return a.srv.Online
		}
		ra, rb := regionRank[a.rk], regionRank[b.rk]
		if ra == 0 {
			ra = 99
		}
		if rb == 0 {
			rb = 99
		}
		if ra != rb {
			return ra < rb
		}
		return a.srv.ID < b.srv.ID
	})
	chosen := entries[0]

	plan := relayPlan{
		EntryServer: chosen.srv,
		EntryNode:   chosen.node,
		EntryAddr:   s.connectAddr(chosen.node, chosen.srv),
		EntryReady:  chosen.ready,
	}

	sort.SliceStable(targetsMeta, func(i, j int) bool { return targetsMeta[i].srv.ID < targetsMeta[j].srv.ID })
	for _, tm := range targetsMeta {
		if tm.srv.ID == chosen.srv.ID {
			continue
		}
		var targetNode *store.Node
		for _, n := range nodesBySrv[tm.srv.ID] {
			if isRelayCapableVLESS(n) {
				targetNode = n
				break
			}
		}
		if targetNode == nil {
			continue
		}
		addr := s.connectAddr(targetNode, tm.srv)
		if addr == "" {
			continue
		}
		lUUID := relayLandingUUID(targetNode)
		plan.Targets = append(plan.Targets, relayTarget{
			Node:      targetNode,
			Server:    tm.srv,
			Country:   tm.cc,
			Addr:      addr,
			LandingID: lUUID,
			Outbound: proto.RelayOutbound{
				Tag:              fmt.Sprintf("relay-n%d", targetNode.ID),
				Protocol:         "vless",
				Address:          addr,
				Port:             targetNode.Port,
				UUID:             lUUID,
				Flow:             targetNode.Settings.Flow,
				Network:          orStr(targetNode.Settings.Network, "tcp"),
				Security:         targetNode.Settings.Security,
				SNI:              relayTargetSNI(targetNode),
				Fingerprint:      orStr(targetNode.Settings.Fingerprint, "chrome"),
				RealityPublicKey: targetNode.Settings.RealityPublicKey,
				RealityShortID:   targetNode.Settings.RealityShortID,
				Insecure:         insecure(targetNode),
			},
		})
	}
	return plan
}
