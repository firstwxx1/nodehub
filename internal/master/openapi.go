package master

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodehub/internal/store"
	"nodehub/internal/util"
)

// The open API is what a VPN shop calls to provision users and read node status.
// Auth: "Authorization: Bearer nhk_xxx". Keys have scopes (read / write) and an optional IP whitelist.
// POST/PUT/PATCH accept an "Idempotency-Key" header; replays return the original response.

func (s *Server) openRoutes(m *http.ServeMux) {
	p := "/api/open/v1"
	m.HandleFunc("GET "+p+"/ping", s.openAuth("read", func(w http.ResponseWriter, r *http.Request, k *store.APIKey) {
		ok(w, map[string]any{"ok": true, "key": k.Name, "time": time.Now().Unix()})
	}))
	m.HandleFunc("GET "+p+"/nodes", s.openAuth("read", s.openListNodes))
	m.HandleFunc("GET "+p+"/nodes/{id}", s.openAuth("read", s.openGetNode))
	m.HandleFunc("GET "+p+"/servers", s.openAuth("read", s.openListServers))
	m.HandleFunc("GET "+p+"/stats", s.openAuth("read", s.openStats))
	m.HandleFunc("GET "+p+"/idempotency/{key}", s.openAuth("read", s.openIdemLookup))

	m.HandleFunc("GET "+p+"/users", s.openAuth("read", s.openListUsers))
	m.HandleFunc("POST "+p+"/users", s.openAuth("write", s.idem(s.openCreateUser)))
	m.HandleFunc("PUT "+p+"/users/by-external/{ext}", s.openAuth("write", s.idem(s.openUpsertUser)))
	m.HandleFunc("GET "+p+"/users/{ref}", s.openAuth("read", s.openUser(s.openGetUser)))
	m.HandleFunc("PATCH "+p+"/users/{ref}", s.openAuth("write", s.idem(s.openUser(s.openPatchUser))))
	m.HandleFunc("DELETE "+p+"/users/{ref}", s.openAuth("write", s.openUser(s.openDeleteUser)))
	m.HandleFunc("POST "+p+"/users/{ref}/reset-traffic", s.openAuth("write", s.idem(s.openUser(s.openResetTraffic))))
	m.HandleFunc("POST "+p+"/users/{ref}/reset-credentials", s.openAuth("write", s.idem(s.openUser(s.openResetCreds))))
	m.HandleFunc("POST "+p+"/users/{ref}/enable", s.openAuth("write", s.openUser(s.openSetEnabled(true))))
	m.HandleFunc("POST "+p+"/users/{ref}/disable", s.openAuth("write", s.openUser(s.openSetEnabled(false))))
	m.HandleFunc("GET "+p+"/users/{ref}/traffic", s.openAuth("read", s.openUser(s.openUserTraffic)))
	m.HandleFunc("GET "+p+"/users/{ref}/subscription", s.openAuth("read", s.openUser(s.openUserSub)))
	m.HandleFunc("GET "+p+"/users/{ref}/online", s.openAuth("read", s.openUser(s.openUserOnline)))
}

type openHandler func(http.ResponseWriter, *http.Request, *store.APIKey)

func (s *Server) openAuth(scope string, h openHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if raw == "" {
			raw = r.Header.Get("X-API-Key")
		}
		if raw == "" {
			writeErr(w, 401, "missing API key")
			return
		}
		k, err := s.st.APIKeyByHash(util.SHA256Hex(raw))
		if err != nil || !k.Enabled {
			writeErr(w, 401, "invalid API key")
			return
		}
		if !strings.Contains(","+k.Scopes+",", ","+scope+",") {
			writeErr(w, 403, "API key lacks scope "+scope)
			return
		}
		if k.IPWhitelist != "" && !ipAllowed(clientIP(r), k.IPWhitelist) {
			writeErr(w, 403, "IP not allowed: "+clientIP(r))
			return
		}
		s.st.TouchAPIKey(k.ID)
		h(w, r, k)
	}
}

func ipAllowed(ip, list string) bool {
	pip := net.ParseIP(ip)
	for _, item := range store.SplitTags(list) {
		if strings.Contains(item, "/") {
			if _, cidr, err := net.ParseCIDR(item); err == nil && pip != nil && cidr.Contains(pip) {
				return true
			}
		} else if item == ip {
			return true
		}
	}
	return false
}

// idem replays stored responses for repeated Idempotency-Key values.
type captureWriter struct {
	http.ResponseWriter
	code int
	buf  bytes.Buffer
}

func (c *captureWriter) WriteHeader(code int) { c.code = code; c.ResponseWriter.WriteHeader(code) }
func (c *captureWriter) Write(b []byte) (int, error) {
	c.buf.Write(b)
	return c.ResponseWriter.Write(b)
}

var idemLocks sync.Map // key -> *sync.Mutex, serialises concurrent requests carrying the same key

func (s *Server) idem(h openHandler) openHandler {
	return func(w http.ResponseWriter, r *http.Request, k *store.APIKey) {
		key := r.Header.Get("Idempotency-Key")
		if key == "" {
			h(w, r, k)
			return
		}
		if len(key) > 200 {
			writeErr(w, 400, "Idempotency-Key too long (max 200)")
			return
		}
		full := fmt.Sprintf("%d:%s", k.ID, key)
		request := r.Method + " " + r.URL.Path
		mu, _ := idemLocks.LoadOrStore(full, &sync.Mutex{})
		mu.(*sync.Mutex).Lock()
		defer func() {
			mu.(*sync.Mutex).Unlock()
			idemLocks.Delete(full)
		}()
		if rec, found := s.st.IdemGet(full); found {
			if rec.Request != request {
				writeErr(w, 422, "Idempotency-Key already used for "+rec.Request)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Idempotent-Replayed", "true")
			w.WriteHeader(rec.Status)
			io.WriteString(w, rec.Response)
			return
		}
		cw := &captureWriter{ResponseWriter: w, code: 200}
		h(cw, r, k)
		if cw.code < 500 {
			s.st.IdemPut(full, request, cw.buf.String(), cw.code)
		}
	}
}

// openIdemLookup answers "did the request with this Idempotency-Key take effect?" — used by shops to
// recover from timeouts without repeating a non-idempotent call (e.g. an extension).
func (s *Server) openIdemLookup(w http.ResponseWriter, r *http.Request, k *store.APIKey) {
	rec, found := s.st.IdemGet(fmt.Sprintf("%d:%s", k.ID, r.PathValue("key")))
	if !found {
		ok(w, map[string]any{"found": false})
		return
	}
	ok(w, map[string]any{"found": true, "request": rec.Request, "status": rec.Status, "created_at": rec.CreatedAt, "response": json.RawMessage(rec.Response)})
}

func (s *Server) resolveUserRef(ref string) (*store.User, error) {
	switch {
	case strings.HasPrefix(ref, "ext:"):
		return s.st.UserByExternal(strings.TrimPrefix(ref, "ext:"))
	case strings.HasPrefix(ref, "uuid:"):
		return s.st.UserByUUID(strings.TrimPrefix(ref, "uuid:"))
	}
	id, err := strconv.ParseInt(ref, 10, 64)
	if err != nil {
		return nil, store.ErrNotFound
	}
	return s.st.GetUser(id)
}

func (s *Server) openUser(h func(http.ResponseWriter, *http.Request, *store.APIKey, *store.User)) openHandler {
	return func(w http.ResponseWriter, r *http.Request, k *store.APIKey) {
		u, err := s.resolveUserRef(r.PathValue("ref"))
		if err != nil {
			writeErr(w, 404, "user not found")
			return
		}
		h(w, r, k, u)
	}
}

// ---------------- nodes ----------------

type openNode struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Protocol    string          `json:"protocol"`
	Network     string          `json:"network,omitempty"`
	Security    string          `json:"security,omitempty"`
	Address     string          `json:"address"`
	Port        int             `json:"port"`
	Region      string          `json:"region"`
	Groups      []string        `json:"groups"`
	Rate        float64         `json:"rate"`
	Enabled     bool            `json:"enabled"`
	Online      bool            `json:"online"`
	OnlineUsers int             `json:"online_users"`
	Load        float64         `json:"load"`
	CPU         float64         `json:"cpu"`
	MemPercent  float64         `json:"mem_percent"`
	UpTotal     int64           `json:"up_total"`
	DownTotal   int64           `json:"down_total"`
	Source      string          `json:"source"`
	IPQuality   *openIPQuality  `json:"ip_quality"`
	Unlock      json.RawMessage `json:"unlock"`
}

type openIPQuality struct {
	IP         string   `json:"ip"`
	Native     bool     `json:"native"`
	RegCountry string   `json:"reg_country"`
	GeoCountry string   `json:"geo_country"`
	ConnType   string   `json:"conn_type"`
	DualISP    bool     `json:"dual_isp"`
	Risks      []string `json:"risks"`
	FraudScore int      `json:"fraud_score"`
	ASN        string   `json:"asn"`
	Org        string   `json:"org"`
	CheckedAt  int64    `json:"checked_at"`
}

func ipQualityOf(c *store.IPCheck) *openIPQuality {
	if c == nil {
		return nil
	}
	q := &openIPQuality{IP: c.IP, Native: c.Native, RegCountry: c.RegCountry, GeoCountry: c.GeoCountry, ConnType: c.ConnType, DualISP: c.DualISP,
		FraudScore: c.FraudScore, ASN: c.ASN, Org: c.Org, CheckedAt: c.CheckedAt, Risks: []string{}}
	if c.IsProxy {
		q.Risks = append(q.Risks, "proxy")
	}
	if c.IsVPN {
		q.Risks = append(q.Risks, "vpn")
	}
	if c.IsTor {
		q.Risks = append(q.Risks, "tor")
	}
	if c.IsAbuse {
		q.Risks = append(q.Risks, "abuse")
	}
	return q
}

func (s *Server) openNodes() ([]openNode, error) {
	vs, err := s.nodeViews()
	if err != nil {
		return nil, err
	}
	servers, _ := s.st.ListServers()
	sm := map[int64]*store.Server{}
	for _, v := range servers {
		sm[v.ID] = v
	}
	out := make([]openNode, 0, len(vs))
	for _, v := range vs {
		o := openNode{ID: v.ID, Name: v.Name, Protocol: v.Protocol, Network: v.Settings.Network, Security: v.Settings.Security,
			Address: v.ConnectAddr, Port: v.Port, Groups: store.SplitTags(v.Groups), Rate: v.Rate, Enabled: v.Enabled,
			Online: v.ServerOnline, OnlineUsers: v.OnlineUsers, UpTotal: v.UpTotal, DownTotal: v.DownTotal, Source: v.Source,
			IPQuality: ipQualityOf(v.IPCheck)}
		if o.Groups == nil {
			o.Groups = []string{}
		}
		if srv := sm[v.ServerID]; srv != nil {
			o.Region = srv.Region
			o.Unlock = srv.Unlock
			var st struct {
				CPUUsage float64 `json:"cpu_usage"`
				Load1    float64 `json:"load1"`
				MemTotal float64 `json:"mem_total"`
				MemUsed  float64 `json:"mem_used"`
			}
			_ = json.Unmarshal(srv.Status, &st)
			o.CPU, o.Load = st.CPUUsage, st.Load1
			if st.MemTotal > 0 {
				o.MemPercent = float64(int(st.MemUsed/st.MemTotal*1000)) / 10
			}
		}
		out = append(out, o)
	}
	return out, nil
}

func (s *Server) openListNodes(w http.ResponseWriter, r *http.Request, k *store.APIKey) {
	list, err := s.openNodes()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, map[string]any{"items": list, "total": len(list)})
}

func (s *Server) openGetNode(w http.ResponseWriter, r *http.Request, k *store.APIKey) {
	list, err := s.openNodes()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	id := pathID(r)
	for _, n := range list {
		if n.ID == id {
			ok(w, n)
			return
		}
	}
	writeErr(w, 404, "node not found")
}

func (s *Server) openListServers(w http.ResponseWriter, r *http.Request, k *store.APIKey) {
	list, err := s.st.ListServers()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	type srvOut struct {
		ID       int64           `json:"id"`
		Name     string          `json:"name"`
		Region   string          `json:"region"`
		Online   bool            `json:"online"`
		LastSeen int64           `json:"last_seen"`
		IPv4     string          `json:"ipv4"`
		Nodes    int             `json:"nodes"`
		Status   json.RawMessage `json:"status"`
	}
	out := []srvOut{}
	for _, v := range list {
		out = append(out, srvOut{v.ID, v.Name, v.Region, v.Online, v.LastSeen, v.PublicIPv4, v.NodeCount, v.Status})
	}
	ok(w, map[string]any{"items": out, "total": len(out)})
}

func (s *Server) openStats(w http.ResponseWriter, r *http.Request, k *store.APIKey) {
	d, err := s.dashboardData()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, d)
}

// ---------------- users ----------------

func (s *Server) openListUsers(w http.ResponseWriter, r *http.Request, k *store.APIKey) {
	limit := qInt(r, "limit", 100)
	if limit > 1000 {
		limit = 1000
	}
	list, total, err := s.st.ListUsers(r.URL.Query().Get("q"), r.URL.Query().Get("status"), qInt(r, "offset", 0), limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]userView, 0, len(list))
	for _, u := range list {
		out = append(out, s.viewUser(r, u))
	}
	ok(w, map[string]any{"items": out, "total": total})
}

func (s *Server) openCreateUser(w http.ResponseWriter, r *http.Request, k *store.APIKey) {
	var in UserInput
	if err := readJSON(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if in.ExternalID != nil && *in.ExternalID != "" {
		if _, err := s.st.UserByExternal(*in.ExternalID); err == nil {
			writeErr(w, 409, "external_id already exists; use PUT /users/by-external/{ext} to upsert")
			return
		}
	}
	u, err := s.createUser(&in)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.st.Audit("api:"+k.Name, "user.create", fmt.Sprint(u.ID), u.ExternalID, clientIP(r))
	writeJSON(w, 201, s.viewUser(r, u))
}

// openUpsertUser creates or updates the user with this external id — convenient for order fulfilment.
func (s *Server) openUpsertUser(w http.ResponseWriter, r *http.Request, k *store.APIKey) {
	ext := r.PathValue("ext")
	var in UserInput
	if err := readJSON(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	in.ExternalID = &ext
	u, err := s.st.UserByExternal(ext)
	if err == store.ErrNotFound {
		u, err = s.createUser(&in)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		s.st.Audit("api:"+k.Name, "user.upsert_create", fmt.Sprint(u.ID), ext, clientIP(r))
		writeJSON(w, 201, s.viewUser(r, u))
		return
	} else if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := s.updateUser(u, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.st.Audit("api:"+k.Name, "user.upsert_update", fmt.Sprint(u.ID), ext, clientIP(r))
	ok(w, s.viewUser(r, u))
}

func (s *Server) openGetUser(w http.ResponseWriter, r *http.Request, k *store.APIKey, u *store.User) {
	v := s.viewUser(r, u)
	v.OnlineIPs = s.onlineCounts()[u.ID]
	ok(w, v)
}

func (s *Server) openPatchUser(w http.ResponseWriter, r *http.Request, k *store.APIKey, u *store.User) {
	var in UserInput
	if err := readJSON(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.updateUser(u, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.st.Audit("api:"+k.Name, "user.update", fmt.Sprint(u.ID), u.ExternalID, clientIP(r))
	ok(w, s.viewUser(r, u))
}

func (s *Server) openDeleteUser(w http.ResponseWriter, r *http.Request, k *store.APIKey, u *store.User) {
	if err := s.st.DeleteUser(u.ID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.bump()
	s.st.Audit("api:"+k.Name, "user.delete", fmt.Sprint(u.ID), u.ExternalID, clientIP(r))
	ok(w, map[string]any{"ok": true})
}

func (s *Server) openResetTraffic(w http.ResponseWriter, r *http.Request, k *store.APIKey, u *store.User) {
	if err := s.updateUser(u, &UserInput{ResetTraffic: true}); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, s.viewUser(r, u))
}

func (s *Server) openResetCreds(w http.ResponseWriter, r *http.Request, k *store.APIKey, u *store.User) {
	var req struct {
		UUID  bool `json:"uuid"`
		Token bool `json:"token"`
	}
	_ = readJSON(r, &req)
	if !req.UUID && !req.Token {
		req.UUID, req.Token = true, true
	}
	if err := s.resetUserCredentials(u, req.UUID, req.Token); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, s.viewUser(r, u))
}

func (s *Server) openSetEnabled(en bool) func(http.ResponseWriter, *http.Request, *store.APIKey, *store.User) {
	return func(w http.ResponseWriter, r *http.Request, k *store.APIKey, u *store.User) {
		if err := s.updateUser(u, &UserInput{Enabled: &en}); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		ok(w, s.viewUser(r, u))
	}
}

func (s *Server) openUserTraffic(w http.ResponseWriter, r *http.Request, k *store.APIKey, u *store.User) {
	days := qInt(r, "days", 30)
	bucket := int64(86400)
	if r.URL.Query().Get("bucket") == "hour" {
		bucket = 3600
	}
	pts, err := s.st.TrafficSeries("user", u.ID, time.Now().Unix()-int64(days)*86400, bucket, tzOffset())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, map[string]any{"user_id": u.ID, "up": u.Up, "down": u.Down, "series": pts})
}

func (s *Server) openUserSub(w http.ResponseWriter, r *http.Request, k *store.APIKey, u *store.User) {
	nodes := s.userNodes(u)
	links := []string{}
	for _, sn := range nodes {
		if l := shareLink(sn, u); l != "" {
			links = append(links, l)
		}
	}
	base := s.subURL(r) + "/sub/" + u.SubToken
	ok(w, map[string]any{
		"sub_url": base,
		"formats": map[string]string{
			"auto": base, "v2ray": base + "?target=v2ray", "clash": base + "?target=clash",
			"singbox": base + "?target=singbox", "surge": base + "?target=surge", "json": base + "/info",
		},
		"links": links,
	})
}

func (s *Server) openUserOnline(w http.ResponseWriter, r *http.Request, k *store.APIKey, u *store.User) {
	list, _ := s.st.OnlineIPs(0, time.Now().Unix()-300)
	out := []store.OnlineIP{}
	for _, o := range list {
		if kind, id, okk := parseUserKey(o.UserKey); okk && kind == 'u' && id == u.ID {
			out = append(out, o)
		}
	}
	ok(w, out)
}
