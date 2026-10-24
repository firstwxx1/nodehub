package master

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"nodehub/internal/ipcheck"
	"nodehub/internal/store"
)

func (s *Server) settingInt(k string, def int) int {
	if v, err := strconv.Atoi(s.st.Setting(k)); err == nil && v > 0 {
		return v
	}
	return def
}

func (s *Server) scheduler(ctx context.Context) {
	fast := time.NewTicker(15 * time.Second)
	minute := time.NewTicker(time.Minute)
	defer fast.Stop()
	defer minute.Stop()
	lastPanel := map[int64]time.Time{}
	var lastIP, lastUnlock, lastDaily time.Time
	// the first IP check pass runs a minute after boot so agents can report their IPs first
	lastIP = time.Now().Add(-time.Duration(s.settingInt("ipcheck_interval_hours", 24))*time.Hour + time.Minute)
	lastUnlock = time.Now().Add(-time.Duration(s.settingInt("unlock_interval_hours", 24))*time.Hour + 2*time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-fast.C:
			s.checkOffline()
		case <-minute.C:
			s.sweepUsers()
			panels, _ := s.st.ListPanels()
			for _, p := range panels {
				if p.Enabled && time.Since(lastPanel[p.ID]) >= time.Duration(p.SyncInterval)*time.Second {
					lastPanel[p.ID] = time.Now()
					go s.syncPanel(ctx, p, false)
				}
			}
			if h := s.settingInt("ipcheck_interval_hours", 24); time.Since(lastIP) >= time.Duration(h)*time.Hour {
				lastIP = time.Now()
				if s.ipcheckBusy.CompareAndSwap(false, true) {
					go func() {
						defer s.ipcheckBusy.Store(false)
						s.runIPChecks(ctx, 0)
					}()
				}
			}
			if h := s.settingInt("unlock_interval_hours", 24); time.Since(lastUnlock) >= time.Duration(h)*time.Hour {
				lastUnlock = time.Now()
				servers, _ := s.st.ListServers()
				for _, v := range servers {
					if v.Online {
						_, _ = s.st.QueueCommand(v.ID, "unlock_test", "")
					}
				}
			}
			if time.Since(lastDaily) >= 6*time.Hour {
				lastDaily = time.Now()
				s.dailyJobs()
			}
		}
	}
}

func (s *Server) checkOffline() {
	after := int64(s.settingInt("offline_after", 60))
	servers, err := s.st.ListServers()
	if err != nil {
		return
	}
	now := time.Now().Unix()
	for _, v := range servers {
		if v.Online && now-v.LastSeen > after {
			_ = s.st.SetServerOnline(v.ID, false)
			s.emit("server.offline", "error", fmt.Sprintf("服务器 %s 离线（%d 秒无心跳）", v.Name, now-v.LastSeen),
				map[string]any{"server_id": v.ID, "name": v.Name, "last_seen": v.LastSeen})
		}
	}
}

// sweepUsers handles expiry and periodic traffic resets.
func (s *Server) sweepUsers() {
	users, err := s.st.AllUsers()
	if err != nil {
		return
	}
	now := time.Now()
	for _, u := range users {
		if needsReset(u, now) {
			u.Up, u.Down = 0, 0
			u.LastResetAt = now.Unix()
			if err := s.st.UpdateUser(u); err == nil {
				s.emit("user.traffic_reset", "info", fmt.Sprintf("用户 %s 流量已按周期重置", displayUser(u)), map[string]any{"user_id": u.ID, "external_id": u.ExternalID})
			}
		}
		if u.ComputeStatus(now.Unix()) != u.Status {
			s.refreshUserStatus(u.ID)
		}
	}
}

func needsReset(u *store.User, now time.Time) bool {
	last := time.Unix(u.LastResetAt, 0).In(now.Location())
	switch u.ResetStrategy {
	case "monthly": // first day of each month
		return now.Year() != last.Year() || now.Month() != last.Month()
	case "day_of_month":
		day := u.ResetDay
		if day < 1 {
			day = 1
		}
		boundary := time.Date(now.Year(), now.Month(), day, 0, 0, 0, 0, now.Location())
		if now.Before(boundary) {
			boundary = boundary.AddDate(0, -1, 0)
		}
		return last.Before(boundary)
	}
	return false
}

func (s *Server) dailyJobs() {
	s.st.Prune(s.settingInt("traffic_retention_days", 90), 60)
	now := time.Now()
	servers, _ := s.st.ListServers()
	remind := int64(s.settingInt("server_expire_remind_days", 3))
	for _, v := range servers {
		// VPS billing-cycle traffic reset
		resetKey := fmt.Sprintf("server_reset_%d", v.ID)
		boundary := time.Date(now.Year(), now.Month(), max(1, v.TrafficResetDay), 0, 0, 0, 0, now.Location())
		if now.Before(boundary) {
			boundary = boundary.AddDate(0, -1, 0)
		}
		last, _ := strconv.ParseInt(s.st.Setting(resetKey), 10, 64)
		if last < boundary.Unix() {
			if last > 0 {
				_ = s.st.ResetServerMonthTraffic(v.ID)
			}
			_ = s.st.SetSetting(resetKey, strconv.FormatInt(now.Unix(), 10))
		}
		if v.TrafficLimit > 0 && v.MonthRx+v.MonthTx > v.TrafficLimit*9/10 {
			s.emit("server.traffic_high", "warn", fmt.Sprintf("服务器 %s 本期流量已用 %.0f%%", v.Name, float64(v.MonthRx+v.MonthTx)*100/float64(v.TrafficLimit)),
				map[string]any{"server_id": v.ID})
		}
		if v.ExpireAt > 0 {
			left := (v.ExpireAt - now.Unix()) / 86400
			key := fmt.Sprintf("server_expire_notified_%d", v.ID)
			if left <= remind && s.st.Setting(key) != now.Format("2006-01-02") {
				_ = s.st.SetSetting(key, now.Format("2006-01-02"))
				s.emit("server.expiring", "warn", fmt.Sprintf("服务器 %s 将在 %d 天后到期", v.Name, left), map[string]any{"server_id": v.ID, "expire_at": v.ExpireAt})
			}
		}
	}
}

// ---------------- IP checks ----------------

func (s *Server) ipKeys() ipcheck.Keys {
	return ipcheck.Keys{
		IPQS: s.st.Setting("ipcheck_ipqs_key"), IPInfo: s.st.Setting("ipcheck_ipinfo_token"), IPAPIIs: s.st.Setting("ipcheck_ipapiis_key"),
		ScamalyticsURL: s.st.Setting("ipcheck_scamalytics_url"), ScamalyticsKey: s.st.Setting("ipcheck_scamalytics_key"),
		AbuseIPDB: s.st.Setting("ipcheck_abuseipdb_key"),
	}
}

func (s *Server) egressIP(n *store.Node, srv *store.Server) string {
	if n.EgressIP != "" {
		return n.EgressIP
	}
	if srv.PublicIPv4 != "" {
		return srv.PublicIPv4
	}
	if net.ParseIP(srv.Host) != nil {
		return srv.Host
	}
	if ips, err := net.LookupIP(srv.Host); err == nil {
		for _, ip := range ips {
			if ip.To4() != nil {
				return ip.String()
			}
		}
	}
	return ""
}

// runIPChecks checks one node (nodeID>0) or all nodes; each distinct IP is queried once.
func (s *Server) runIPChecks(ctx context.Context, nodeID int64) {
	nodes, err := s.st.ListNodes()
	if err != nil {
		return
	}
	servers, _ := s.st.ListServers()
	sm := map[int64]*store.Server{}
	for _, v := range servers {
		sm[v.ID] = v
	}
	prev, _ := s.st.LatestIPChecks()
	cache := map[string]*ipcheck.Result{}
	keys := s.ipKeys()
	for _, n := range nodes {
		if nodeID > 0 && n.ID != nodeID {
			continue
		}
		srv := sm[n.ServerID]
		if srv == nil {
			continue
		}
		ip := s.egressIP(n, srv)
		if ip == "" {
			continue
		}
		res := cache[ip]
		if res == nil {
			res = ipcheck.Check(ctx, ip, keys)
			cache[ip] = res
			time.Sleep(1500 * time.Millisecond) // stay under ip-api's 45 req/min free limit
		}
		raw, _ := json.Marshal(map[string]any{"sources": res.Sources, "errors": res.Errors})
		c := &store.IPCheck{NodeID: n.ID, ServerID: srv.ID, IP: ip, Native: res.Native, RegCountry: res.RegCountry, GeoCountry: res.GeoCountry,
			GeoCity: res.GeoCity, ConnType: res.ConnType, DualISP: res.DualISP, IsProxy: res.IsProxy, IsVPN: res.IsVPN, IsTor: res.IsTor,
			IsAbuse: res.IsAbuse, IsHosting: res.IsHosting, FraudScore: res.FraudScore, FraudSource: res.FraudSource, ASN: res.ASN, Org: res.Org,
			Raw: raw, CheckedAt: time.Now().Unix()}
		if len(res.Sources) == 0 {
			c.Error = "所有数据源都失败了"
			for k, v := range res.Errors {
				c.Error += "; " + k + ": " + v
			}
		}
		if _, err := s.st.SaveIPCheck(c); err != nil {
			log.Printf("save ip check: %v", err)
			continue
		}
		if p := prev[n.ID]; p != nil && c.Error == "" && (p.Risky() != c.Risky() || p.Native != c.Native || p.IP != c.IP) {
			s.emit("ipcheck.risk_changed", "warn", fmt.Sprintf("节点 %s IP 质量变化：风险 %v→%v，原生 %v→%v，欺诈分 %d→%d",
				n.Name, p.Risky(), c.Risky(), p.Native, c.Native, p.FraudScore, c.FraudScore), map[string]any{"node_id": n.ID, "ip": ip})
		}
	}
}
