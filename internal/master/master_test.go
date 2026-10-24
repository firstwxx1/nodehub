package master

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nodehub/internal/proto"
	"nodehub/internal/store"
	"nodehub/internal/util"
)

func TestNeedsReset(t *testing.T) {
	loc := time.Local
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, loc)
	cases := []struct {
		strategy string
		day      int
		last     time.Time
		want     bool
	}{
		{"none", 1, now.AddDate(-1, 0, 0), false},
		{"monthly", 1, time.Date(2026, 9, 30, 0, 0, 0, 0, loc), true},
		{"monthly", 1, time.Date(2026, 10, 1, 0, 0, 1, 0, loc), false},
		{"day_of_month", 20, time.Date(2026, 10, 19, 0, 0, 0, 0, loc), true},
		{"day_of_month", 20, time.Date(2026, 10, 20, 1, 0, 0, 0, loc), false},
		{"day_of_month", 28, time.Date(2026, 9, 27, 0, 0, 0, 0, loc), true},  // boundary is Sep 28
		{"day_of_month", 28, time.Date(2026, 9, 28, 1, 0, 0, 0, loc), false}, // already reset this cycle
	}
	for i, c := range cases {
		u := &store.User{ResetStrategy: c.strategy, ResetDay: c.day, LastResetAt: c.last.Unix()}
		if got := needsReset(u, now); got != c.want {
			t.Errorf("case %d (%s day %d last %s): got %v want %v", i, c.strategy, c.day, c.last, got, c.want)
		}
	}
}

func TestHelpers(t *testing.T) {
	if !eventMatches("user.*,server.offline", "user.expired") || eventMatches("user.*", "server.offline") || !eventMatches("*", "x") {
		t.Fatal("eventMatches")
	}
	if k, id, ok := parseUserKey("n12.p345"); !ok || k != 'p' || id != 345 {
		t.Fatal("parseUserKey panel")
	}
	if _, _, ok := parseUserKey("garbage"); ok {
		t.Fatal("parseUserKey garbage")
	}
	if flagEmoji("jp") != "🇯🇵" || flagEmoji("") != "🌐" {
		t.Fatal("flagEmoji")
	}
	n := &store.Node{Groups: "vip, pro"}
	if !nodeVisible(n, &store.User{Groups: "pro"}) || nodeVisible(n, &store.User{Groups: "basic"}) || !nodeVisible(&store.Node{}, &store.User{}) {
		t.Fatal("nodeVisible")
	}
}

func TestShareLinks(t *testing.T) {
	u := &store.User{UUID: "eeb47318-d4ce-475f-a14f-d14c80103045"}
	ss := subNode{Name: "SS", Addr: "1.2.3.4", Node: &store.Node{Protocol: "shadowsocks", Port: 8388,
		Settings: proto.NodeSettings{Cipher: "2022-blake3-aes-128-gcm", ServerKey: "zhnUqw+nBgzVhdlummT/dQ=="}}}
	l := shareLink(ss, u)
	if strings.ContainsAny(strings.SplitN(strings.TrimPrefix(l, "ss://"), "@", 2)[0], "+/=") {
		t.Fatalf("ss userinfo not percent-encoded: %s", l)
	}
	v6 := subNode{Name: "v6", Addr: "2001:db8::1", Node: &store.Node{Protocol: "hysteria2", Port: 443, Settings: proto.NodeSettings{SNI: "a.com", CertMode: "self"}}}
	if l := shareLink(v6, u); !strings.Contains(l, "@[2001:db8::1]:443") || !strings.Contains(l, "insecure=1") {
		t.Fatalf("ipv6 link: %s", l)
	}
}

// ---------------- HTTP flow ----------------

type client struct {
	t   *testing.T
	srv *httptest.Server
}

func (c *client) do(method, path, auth string, body any, hdr ...string) (int, map[string]any) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, rd)
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func TestOpenAPIAndAgentFlow(t *testing.T) {
	s, err := New(Options{DataDir: t.TempDir(), AdminPass: "test-pass-123"})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.middleware(s.mux))
	defer ts.Close()
	c := &client{t: t, srv: ts}

	// a server with one local node in group "vip"
	agentTok := util.RandToken(24)
	sid, _ := s.st.CreateServer(&store.Server{Name: "s1", Enabled: true, TrafficResetDay: 1}, util.SHA256Hex(agentTok))
	n := &store.Node{ServerID: sid, Name: "n1", Protocol: "vless", Port: 443, Groups: "vip", Enabled: true}
	if err := s.normalizeNode(n); err != nil {
		t.Fatal(err)
	}
	nid, _ := s.st.CreateNode(n)

	raw := "nhk_" + util.RandToken(30)
	_, _ = s.st.CreateAPIKey("shop", raw[:10], util.SHA256Hex(raw), "read,write", "")
	auth := "Bearer " + raw

	if code, _ := c.do("GET", "/api/open/v1/ping", "Bearer nope", nil); code != 401 {
		t.Fatalf("bad key: %d", code)
	}
	code, u := c.do("PUT", "/api/open/v1/users/by-external/o1", auth, map[string]any{"traffic_limit_gb": 1, "extend_days": 30, "groups": "vip"}, "Idempotency-Key", "k1")
	if code != 201 || u["status"] != "active" {
		t.Fatalf("upsert: %d %v", code, u)
	}
	uid := int64(u["id"].(float64))
	// replay returns the same response, reuse on another endpoint is rejected
	if code, u2 := c.do("PUT", "/api/open/v1/users/by-external/o1", auth, map[string]any{"extend_days": 30}, "Idempotency-Key", "k1"); code != 201 || u2["expire_at"] != u["expire_at"] {
		t.Fatalf("replay: %d %v", code, u2)
	}
	if code, _ := c.do("PATCH", "/api/open/v1/users/ext:o1", auth, map[string]any{"extend_days": 1}, "Idempotency-Key", "k1"); code != 422 {
		t.Fatalf("key reuse: %d", code)
	}
	if code, r := c.do("GET", "/api/open/v1/idempotency/k1", auth, nil); code != 200 || r["found"] != true {
		t.Fatalf("idem lookup: %v", r)
	}

	// agent sees the user on the node
	code, cfg := c.do("GET", "/agent/v1/config", "Bearer "+agentTok, nil)
	if code != 200 {
		t.Fatalf("agent config %d", code)
	}
	nodes := cfg["nodes"].([]any)
	users := nodes[0].(map[string]any)["users"].([]any)
	if len(users) != 1 || users[0].(map[string]any)["key"] != userKeyLocal(nid, uid) {
		t.Fatalf("agent users: %v", users)
	}
	ver1 := cfg["version"]

	// report 2 GB of traffic -> user exhausted -> removed from the node config
	rep := proto.Report{Traffic: []proto.TrafficDelta{{NodeID: nid, Key: userKeyLocal(nid, uid), Up: 0, Down: 2 << 30}}}
	if code, _ := c.do("POST", "/agent/v1/report", "Bearer "+agentTok, rep); code != 200 {
		t.Fatalf("report %d", code)
	}
	_, u = c.do("GET", "/api/open/v1/users/ext:o1", auth, nil)
	if u["status"] != "exhausted" {
		t.Fatalf("expected exhausted, got %v", u["status"])
	}
	_, cfg = c.do("GET", "/agent/v1/config", "Bearer "+agentTok, nil)
	if cfg["version"] == ver1 || len(cfg["nodes"].([]any)[0].(map[string]any)["users"].([]any)) != 0 {
		t.Fatalf("exhausted user still on node: %v", cfg)
	}
	// top-up brings the user back
	_, u = c.do("PATCH", "/api/open/v1/users/ext:o1", auth, map[string]any{"add_traffic_gb": 5})
	if u["status"] != "active" {
		t.Fatalf("after top-up: %v", u["status"])
	}
	// subscription reflects usage and the user's nodes
	resp, err := http.Get(ts.URL + "/sub/" + u["sub_token"].(string) + "?target=clash")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Subscription-Userinfo"), "download=2147483648") || !strings.Contains(string(body), `"type":"vless"`) {
		t.Fatalf("sub: %s\n%s", resp.Header.Get("Subscription-Userinfo"), body)
	}
}

func TestPortCheckAndDNSCert(t *testing.T) {
	s, err := New(Options{DataDir: t.TempDir(), AdminPass: "test-pass-123"})
	if err != nil {
		t.Fatal(err)
	}
	agentTok := util.RandToken(24)
	sid, _ := s.st.CreateServer(&store.Server{Name: "s1", Enabled: true, TrafficResetDay: 1}, util.SHA256Hex(agentTok))

	hy := &store.Node{ServerID: sid, Name: "hy", Protocol: "hysteria2", Port: 8443, Enabled: true}
	if err := s.normalizeNode(hy); err != nil {
		t.Fatal(err)
	}
	// no report yet: unknown, never blocks
	if err := s.checkNodePorts(hy, nil); err != nil {
		t.Fatalf("unknown host must not block: %v", err)
	}
	s.ports.set(sid, []proto.ListenPort{{Proto: "tcp", Port: 8443, Proc: "xray"}, {Proto: "udp", Port: 8444, Proc: "x"}, {Proto: "tcp", Port: 80, Proc: "nginx"}})
	// hysteria2 is UDP: TCP 8443 does not clash
	if err := s.checkNodePorts(hy, nil); err != nil {
		t.Fatalf("tcp 8443 must not block a udp node: %v", err)
	}
	vl := &store.Node{ServerID: sid, Name: "vl", Protocol: "vless", Port: 8443, Enabled: true}
	err = s.checkNodePorts(vl, nil)
	if err == nil || !strings.Contains(err.Error(), "xray") || !strings.Contains(err.Error(), "8444") {
		t.Fatalf("expected conflict naming xray and suggesting 8444, got %v", err)
	}
	// editing an existing node without moving its port is allowed
	if err := s.checkNodePorts(vl, &store.Node{Port: 8443, Protocol: "vless"}); err != nil {
		t.Fatalf("unchanged port must pass: %v", err)
	}
	// ACME over HTTP needs port 80
	ac := &store.Node{ServerID: sid, Name: "ac", Protocol: "hysteria2", Port: 9443, Enabled: true, Settings: proto.NodeSettings{CertMode: "acme"}}
	if err := s.checkNodePorts(ac, nil); err == nil || !strings.Contains(err.Error(), "nginx") {
		t.Fatalf("expected port 80 conflict, got %v", err)
	}
	// DNS mode needs the Cloudflare token first, then is injected into the agent config only
	dn := &store.Node{ServerID: sid, Name: "dn", Protocol: "hysteria2", Port: 9443, Enabled: true, Settings: proto.NodeSettings{CertMode: "acme_dns", SNI: "us.example.com"}}
	if err := s.normalizeNode(dn); err == nil {
		t.Fatal("expected error without cloudflare token")
	}
	_ = s.st.SetSetting("cf_api_token", "cf-secret")
	if err := s.normalizeNode(dn); err != nil {
		t.Fatal(err)
	}
	dn.Settings.ACMEDNSToken = "client-supplied" // must be stripped
	if err := s.normalizeNode(dn); err != nil || dn.Settings.ACMEDNSToken != "" {
		t.Fatalf("token must not be stored on the node: %v %q", err, dn.Settings.ACMEDNSToken)
	}
	if _, err := s.st.CreateNode(dn); err != nil {
		t.Fatal(err)
	}
	srv, _ := s.st.GetServer(sid)
	cfg, err := s.buildAgentConfig(srv)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, n := range cfg.Nodes {
		if n.Name == "dn" {
			got = n.Settings.ACMEDNSToken
		}
	}
	if got != "cf-secret" {
		t.Fatalf("agent config must carry the token, got %q", got)
	}
}

func TestDefaultPortSkipsBusy(t *testing.T) {
	s, err := New(Options{DataDir: t.TempDir(), AdminPass: "test-pass-123"})
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := s.st.CreateServer(&store.Server{Name: "s1", Enabled: true, TrafficResetDay: 1}, util.SHA256Hex(util.RandToken(24)))
	s.ports.set(sid, []proto.ListenPort{{Proto: "udp", Port: 443, Proc: "nginx"}, {Proto: "tcp", Port: 443, Proc: "nginx"}})
	if got := s.defaultPort(sid, []string{"udp"}, 0); got != 8443 {
		t.Fatalf("want 8443, got %d", got)
	}
	s.ports.set(sid, []proto.ListenPort{{Proto: "tcp", Port: 443, Proc: "nginx"}})
	if got := s.defaultPort(sid, []string{"udp"}, 0); got != 443 { // udp 443 is free when only tcp is held
		t.Fatalf("want 443, got %d", got)
	}
}

func TestIPChecksOneRowPerIP(t *testing.T) {
	s, err := New(Options{DataDir: t.TempDir(), AdminPass: "test-pass-123"})
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := s.st.CreateServer(&store.Server{Name: "AWS-US", Host: "13.58.3.202", PublicIPv4: "13.58.3.202", Enabled: true, TrafficResetDay: 1}, util.SHA256Hex(util.RandToken(24)))
	for i, p := range []string{"vless", "hysteria2"} {
		n := &store.Node{ServerID: sid, Name: "n-" + p, Protocol: p, Port: 4443 + i, Enabled: true}
		if err := s.normalizeNode(n); err != nil {
			t.Fatal(err)
		}
		if _, err := s.st.CreateNode(n); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	s.handleListIPChecks(w, httptest.NewRequest("GET", "/api/ipchecks", nil), nil)
	var res struct {
		Data struct {
			Items []ipRow `json:"items"`
		} `json:"data"`
		Items []ipRow `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err, w.Body.String())
	}
	items := res.Items
	if len(items) == 0 {
		items = res.Data.Items
	}
	if len(items) != 1 || items[0].NodeName != "AWS-US" || len(items[0].Nodes) != 2 {
		t.Fatalf("want 1 row titled by server with 2 nodes, got %+v", items)
	}
}

func TestSamePortDifferentTransport(t *testing.T) {
	s, err := New(Options{DataDir: t.TempDir(), AdminPass: "test-pass-123"})
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := s.st.CreateServer(&store.Server{Name: "s1", Enabled: true, TrafficResetDay: 1}, util.SHA256Hex(util.RandToken(24)))
	vl := &store.Node{ServerID: sid, Name: "vl", Protocol: "vless", Port: 443, Enabled: true}
	if err := s.normalizeNode(vl); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.CreateNode(vl); err != nil {
		t.Fatal(err)
	}
	hy := &store.Node{ServerID: sid, Name: "hy", Protocol: "hysteria2", Port: 443, Enabled: true}
	if err := s.normalizeNode(hy); err != nil {
		t.Fatalf("udp 443 must coexist with tcp 443: %v", err)
	}
	if _, err := s.st.CreateNode(hy); err != nil {
		t.Fatal(err)
	}
	tr := &store.Node{ServerID: sid, Name: "tr", Protocol: "trojan", Port: 443, Enabled: true}
	if err := s.normalizeNode(tr); err == nil || !strings.Contains(err.Error(), "vl") {
		t.Fatalf("second tcp 443 must be refused naming the node, got %v", err)
	}
}

func TestUniqueNames(t *testing.T) {
	mk := func(name, proto string) subNode { return subNode{Name: name, Node: &store.Node{Protocol: proto}} }
	l := []subNode{mk("US", "vless"), mk("US", "hysteria2"), mk("JP", "vless"), mk("DE", "vless"), mk("DE", "vless")}
	uniqueNames(l)
	got := []string{}
	seen := map[string]bool{}
	for _, n := range l {
		got = append(got, n.Name)
		if seen[n.Name] {
			t.Fatalf("duplicate name %q in %v", n.Name, got)
		}
		seen[n.Name] = true
	}
	if l[0].Name != "US VLESS" || l[1].Name != "US Hysteria2" || l[2].Name != "JP" {
		t.Fatalf("unexpected names %v", got)
	}
}

func TestScriptNode(t *testing.T) {
	s, err := New(Options{DataDir: t.TempDir(), AdminPass: "test-pass-123"})
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := s.st.CreateServer(&store.Server{Name: "AWS-US", Host: "13.58.3.202", PublicIPv4: "13.58.3.202", Enabled: true, TrafficResetDay: 1}, util.SHA256Hex(util.RandToken(24)))
	cid, _ := s.st.QueueCommand(sid, "install_hy2", "{}")
	res := `{"scan":{"kind":"hysteria2-installer","port":16305,"domain":"13.58.3.202","cert_mode":"file","insecure":true,"obfs_password":"obfspw","hop_ports":"20000-40000","auth_password":"ownerpw","up_mbps":1000,"down_mbps":1000,"version":"v2.6"},"log":"ok"}`
	s.st.FinishCommand(sid, proto.CommandResult{ID: cid, OK: true, Output: res})

	body, _ := json.Marshal(map[string]any{"command_id": cid})
	req := httptest.NewRequest("POST", "/api/servers/1/script-node/finish", bytes.NewReader(body))
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()
	s.handleScriptNodeFinish(w, req, nil)
	if w.Code != 200 {
		t.Fatalf("finish: %d %s", w.Code, w.Body.String())
	}
	// a second finish is idempotent and must not create another node
	req2 := httptest.NewRequest("POST", "/api/servers/1/script-node/finish", bytes.NewReader(body))
	req2.SetPathValue("id", "1")
	w2 := httptest.NewRecorder()
	s.handleScriptNodeFinish(w2, req2, nil)
	if w2.Code != 200 {
		t.Fatalf("second finish: %d %s", w2.Code, w2.Body.String())
	}

	srv, _ := s.st.GetServer(sid)
	cfg, err := s.buildAgentConfig(srv)
	if err != nil || len(cfg.Nodes) != 0 {
		t.Fatalf("agent must not run script nodes: %v %+v", err, cfg)
	}
	nodes, _ := s.st.NodesByServer(sid)
	if len(nodes) != 1 || nodes[0].Core != "script" || nodes[0].Settings.CertMode != "self" {
		t.Fatalf("node: %+v", nodes)
	}
	u := &store.User{Username: "u", Password: "userpw", UUID: "uuid-1"}
	link := shareLink(subNode{Node: nodes[0], Name: "x", Addr: "13.58.3.202"}, u)
	for _, want := range []string{"hysteria2://ownerpw@13.58.3.202:16305", "obfs=salamander", "obfs-password=obfspw", "mport=20000-40000", "insecure=1"} {
		if !strings.Contains(link, want) {
			t.Errorf("link %q lacks %q", link, want)
		}
	}
}

func TestIPChecksListNodelessServers(t *testing.T) {
	s, err := New(Options{DataDir: t.TempDir(), AdminPass: "test-pass-123"})
	if err != nil {
		t.Fatal(err)
	}
	s.st.CreateServer(&store.Server{Name: "with-node", PublicIPv4: "1.1.1.1", Enabled: true, TrafficResetDay: 1}, util.SHA256Hex(util.RandToken(24)))
	s2, _ := s.st.CreateServer(&store.Server{Name: "empty", PublicIPv4: "2.2.2.2", Enabled: true, TrafficResetDay: 1}, util.SHA256Hex(util.RandToken(24)))
	n := &store.Node{ServerID: 1, Name: "n", Protocol: "vless", Port: 443, Enabled: true}
	if err := s.normalizeNode(n); err != nil {
		t.Fatal(err)
	}
	s.st.CreateNode(n)
	s.st.SaveIPCheck(&store.IPCheck{ServerID: s2, IP: "2.2.2.2", FraudScore: 7, CheckedAt: time.Now().Unix()})
	w := httptest.NewRecorder()
	s.handleListIPChecks(w, httptest.NewRequest("GET", "/api/ipchecks", nil), nil)
	var res struct {
		Items []ipRow `json:"items"`
	}
	json.Unmarshal(w.Body.Bytes(), &res)
	if len(res.Items) != 2 || res.Items[1].NodeName != "empty" || res.Items[1].ServerID != s2 || res.Items[1].Check == nil || res.Items[1].Check.FraudScore != 7 {
		t.Fatalf("want node-less server row with its check, got %s", w.Body.String())
	}
}

func TestScriptNodeAutoCreate(t *testing.T) {
	s, err := New(Options{DataDir: t.TempDir(), AdminPass: "test-pass-123"})
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := s.st.CreateServer(&store.Server{Name: "servercheap", PublicIPv4: "172.82.74.159", Enabled: true, TrafficResetDay: 1}, util.SHA256Hex(util.RandToken(24)))
	cid, _ := s.st.QueueCommand(sid, "install_hy2", `{"port":443,"cert_type":3,"domain":"sc.example.com","name":"SC","groups":""}`)
	out := `{"scan":{"kind":"hysteria2-installer","port":443,"domain":"sc.example.com","cert_mode":"acme","obfs_password":"o","hop_ports":"20000-40000","auth_password":"pw"},"log":""}`
	s.st.FinishCommand(sid, proto.CommandResult{ID: cid, OK: true, Output: out})
	srv, _ := s.st.GetServer(sid)
	s.afterScriptInstall(srv, cid)
	s.afterScriptInstall(srv, cid) // repeated reports must not duplicate the node
	nodes, _ := s.st.NodesByServer(sid)
	if len(nodes) != 1 || nodes[0].Name != "SC" || nodes[0].Core != "script" || nodes[0].Settings.CertMode != "acme" {
		t.Fatalf("auto-created node: %+v", nodes)
	}
}

func TestClashRuleModes(t *testing.T) {
	g := renderClash(nil, &store.User{}, "x", false)
	if strings.Contains(g, "GEOSITE,CN") || strings.Contains(g, "GEOIP,CN") || !strings.Contains(g, "MATCH,") {
		t.Fatalf("global mode must not send China sites direct:\n%s", g)
	}
	sm := renderClash(nil, &store.User{}, "x", true)
	if !strings.Contains(sm, "GEOSITE,CN,DIRECT") || !strings.Contains(sm, "GEOIP,CN,DIRECT,no-resolve") {
		t.Fatalf("smart mode rules missing:\n%s", sm)
	}
}
