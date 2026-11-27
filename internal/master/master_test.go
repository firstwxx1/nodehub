package master

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	sid, _ := s.st.CreateServer(&store.Server{Name: "servercheap", PublicIPv4: "198.51.100.159", Enabled: true, TrafficResetDay: 1}, util.SHA256Hex(util.RandToken(24)))
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
	g := renderClash(nil, &store.User{}, "x", false, false)
	if strings.Contains(g, "GEOSITE,CN") || strings.Contains(g, "GEOIP,CN") || !strings.Contains(g, "MATCH,") {
		t.Fatalf("global mode must not send China sites direct:\n%s", g)
	}
	sm := renderClash(nil, &store.User{}, "x", true, false)
	for _, want := range []string{
		"GEOSITE,CN,DIRECT",
		"GEOIP,CN,DIRECT,no-resolve",
		"GEOSITE,steam@cn,DIRECT",
		"GEOSITE,apple-cn,DIRECT",
		"GEOSITE,microsoft@cn,DIRECT",
		"GEOSITE,github,GitHub",
		"DOMAIN-SUFFIX,antigravity.google,AI",
		"DOMAIN-SUFFIX,claude.ai,AI",
		"DOMAIN-SUFFIX,copilot.microsoft.com,AI",
	} {
		if !strings.Contains(sm, want) {
			t.Fatalf("smart mode missing rule %q:\n%s", want, sm)
		}
	}
	if strings.Index(sm, "DOMAIN-SUFFIX,antigravity.google,AI") >= strings.Index(sm, "GEOSITE,google,Google") {
		t.Fatalf("AI rules must precede GEOSITE,google")
	}
	if strings.Index(sm, "DOMAIN-SUFFIX,copilot.microsoft.com,AI") >= strings.Index(sm, "GEOSITE,microsoft,Microsoft") {
		t.Fatalf("AI Copilot rule must precede GEOSITE,microsoft")
	}
}

func TestOptimizedRoutingGroups(t *testing.T) {
	mk := func(srvID int64, name, proto, cc string) subNode {
		n := &store.Node{ServerID: srvID, Name: name, Protocol: proto, Port: 44443}
		n.Settings.SNI = "a.example.com"
		if proto == "vless" {
			n.Settings.Security = "reality"
			n.Settings.RealityPublicKey = "pub"
			n.Settings.RealityShortID = "1234"
		} else if proto == "hysteria2" {
			n.Settings.HopPorts = "20000-40000"
		}
		return subNode{Node: n, Name: name, Addr: "1.2.3.4", Country: cc}
	}
	nodes := []subNode{
		mk(1, "🇯🇵 阿里云日本", "hysteria2", "JP"),
		mk(1, "🇯🇵 阿里云日本-TCP", "vless", "JP"),
		mk(2, "🇺🇸 洛杉矶", "hysteria2", "US"),
		mk(2, "🇺🇸 洛杉矶-TCP", "vless", "US"),
		mk(3, "🇸🇪 AWS-瑞典EC2", "hysteria2", "SE"),
		mk(3, "🇸🇪 AWS-瑞典EC2-TCP", "vless", "SE"),
	}
	// Verify region detection trusts Country code over vendor name (阿里云新加坡 -> SG, not JP)
	if got := detectRegionKey(mk(4, "🇸🇬 阿里云新加坡", "hysteria2", "SG")); got != "SG" {
		t.Fatalf("expected SG for 阿里云新加坡, got %q", got)
	}
	clash := renderClash(nodes, &store.User{UUID: "u1", Password: "p1"}, "NodeHub", true, true)
	for _, want := range []string{
		`"name":"⚡ 高速 UDP"`,
		`"name":"🛡️ 稳定 TCP"`,
		`"name":"故障转移","proxies":["⚡ 高速 UDP","🛡️ 稳定 TCP"]`,
		`"name":"🌏 亚洲中转"`,
		`"name":"🚀 欧美中转"`,
		`"name":"🚀 中转·🇺🇸 洛杉矶"`,
		`"name":"🚀 中转·🇸🇪 AWS-瑞典EC2"`,
		`"dialer-proxy":"🌏 亚洲中转"`,
		`"name":"日本"`,
		`"name":"美国"`,
		`"name":"欧洲"`,
	} {
		if !strings.Contains(clash, want) {
			t.Fatalf("clash config missing %q:\n%s", want, clash)
		}
	}
	// Ensure 🌏 亚洲中转 only contains direct Asia nodes (no proxy loop!)
	for _, ln := range strings.Split(clash, "\n") {
		if strings.Contains(ln, `"name":"🌏 亚洲中转"`) && strings.Contains(ln, "中转·") {
			t.Fatalf("asia relay group must never contain relayed nodes: %s", ln)
		}
	}
	for _, forbid := range []string{`"name":"新加坡"`, `"name":"香港"`, `"name":"台湾"`, `"name":"其他地区"`} {
		if strings.Contains(clash, forbid) {
			t.Fatalf("clash config must omit empty region group %s", forbid)
		}
	}
	// Verify relay=false cleanly disables auto relays
	clashOff := renderClash(nodes, &store.User{UUID: "u1", Password: "p1"}, "NodeHub", true, false)
	if strings.Contains(clashOff, "🌏 亚洲中转") || strings.Contains(clashOff, "🚀 中转·") {
		t.Fatalf("clash with relay=false must not emit relay groups:\n%s", clashOff)
	}

	sbSmart := renderSingbox(nodes, &store.User{UUID: "u1", Password: "p1"}, true, true)
	for _, want := range []string{"geosite-cn", `"tag": "🌏 亚洲中转"`, `"tag": "🚀 欧美中转"`, `"tag": "🚀 中转·🇺🇸 洛杉矶"`, `"detour": "🌏 亚洲中转"`} {
		if !strings.Contains(sbSmart, want) {
			t.Fatalf("sing-box smart+relay missing %q:\n%s", want, sbSmart)
		}
	}
	if strings.Contains(sbSmart, `"tag": "新加坡"`) {
		t.Fatalf("sing-box smart config unexpected:\n%s", sbSmart)
	}
	sbGlobal := renderSingbox(nodes, &store.User{UUID: "u1", Password: "p1"}, false, false)
	if strings.Contains(sbGlobal, "geosite-cn") || strings.Contains(sbGlobal, "🌏 亚洲中转") {
		t.Fatalf("sing-box global/no-relay unexpected:\n%s", sbGlobal)
	}

	// Surge drops VLESS so auto-relay falls back to Hy2 with underlying-proxy and NO port-hopping
	surge := renderSurge(nodes, &store.User{UUID: "u1", Password: "p1"}, "https://example.com/sub/x", true, true)
	if !strings.Contains(surge, "🚀 中转·🇺🇸 洛杉矶 = hysteria2,") || !strings.Contains(surge, "underlying-proxy=🌏 亚洲中转") || !strings.Contains(surge, "🌏 亚洲中转 = url-test,") {
		t.Fatalf("surge auto-relay unexpected:\n%s", surge)
	}
	for _, ln := range strings.Split(surge, "\n") {
		if strings.HasPrefix(ln, "🚀 中转·🇺🇸 洛杉矶 =") && strings.Contains(ln, "port-hopping=") {
			t.Fatalf("relayed surge hysteria2 must strip port-hopping: %s", ln)
		}
	}
}

func TestHy2ClientBandwidth(t *testing.T) {
	n := &store.Node{Name: "h", Protocol: "hysteria2", Core: "script", Port: 443}
	n.Settings.SNI, n.Settings.SharedPassword = "a.example.com", "pw"
	sn := subNode{Node: n, Name: "h", Addr: "1.2.3.4", UpMbps: 50, DownMbps: 200}
	p := clashProxy(sn, &store.User{})
	if p["up"] != "50 Mbps" || p["down"] != "200 Mbps" {
		t.Fatalf("clash bandwidth: %v", p)
	}
	o := singboxOutbound(sn, &store.User{})
	if o["up_mbps"] != 50 || o["down_mbps"] != 200 {
		t.Fatalf("sing-box bandwidth: %v", o)
	}
	link := shareLink(sn, &store.User{})
	if !strings.Contains(link, "upmbps=50") || !strings.Contains(link, "downmbps=200") {
		t.Fatalf("hysteria2 shareLink must emit upmbps/downmbps for Shadowrocket/v2rayNG: %s", link)
	}
	sn.UpMbps, sn.DownMbps = 0, 0
	p0 := clashProxy(sn, &store.User{})
	if _, ok := p0["down"]; ok {
		t.Fatal("no bandwidth must be written when unset")
	}
	if link0 := shareLink(sn, &store.User{}); strings.Contains(link0, "upmbps=") || strings.Contains(link0, "downmbps=") {
		t.Fatalf("shareLink must not emit upmbps/downmbps when unset: %s", link0)
	}
	if p0["disable-mtu-discovery"] != true {
		t.Fatalf("clash hysteria2 must set disable-mtu-discovery=true, got %v", p0)
	}
	n.Settings.HopPorts = "20000-40000"
	pHop := clashProxy(sn, &store.User{})
	if pHop["hop-interval"] != 60 {
		t.Fatalf("clash hysteria2 hop-interval want 60, got %v", pHop["hop-interval"])
	}
	if oHop := singboxOutbound(sn, &store.User{}); oHop["hop_interval"] != "60s" {
		t.Fatalf("singbox hysteria2 hop_interval want 60s, got %v", oHop["hop_interval"])
	}
	// Relayed Hy2 must attach dialer-proxy/detour and strip port hopping
	snRelay := sn
	snRelay.DialerProxy = "🌏 亚洲中转"
	pRel := clashProxy(snRelay, &store.User{})
	if pRel["dialer-proxy"] != "🌏 亚洲中转" || pRel["ports"] != nil {
		t.Fatalf("relayed clash hy2 mismatch: %v", pRel)
	}
	oRel := singboxOutbound(snRelay, &store.User{})
	if oRel["detour"] != "🌏 亚洲中转" || oRel["server_ports"] != nil {
		t.Fatalf("relayed sing-box hy2 mismatch: %v", oRel)
	}
	clashYAML := renderClash([]subNode{sn}, &store.User{}, "x", false, true)
	if strings.Contains(clashYAML, "cloudflare-dns.com") || strings.Contains(clashYAML, "dns.google") {
		t.Fatalf("renderClash must not configure direct blocked foreign DoH:\n%s", clashYAML)
	}
	// No Asia nodes -> no auto relay groups emitted
	if strings.Contains(clashYAML, "🌏 亚洲中转") {
		t.Fatalf("renderClash must omit relay groups when no Asia nodes exist:\n%s", clashYAML)
	}
}

func TestScriptAdoptWhenAlreadyInstalled(t *testing.T) {
	s, err := New(Options{DataDir: t.TempDir(), AdminPass: "test-pass-123"})
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := s.st.CreateServer(&store.Server{Name: "kamatera", PublicIPv4: "203.0.113.10", Enabled: true, TrafficResetDay: 1}, util.SHA256Hex(util.RandToken(24)))
	cid, _ := s.st.QueueCommand(sid, "scan_import", "adopt:kamatera")
	s.st.FinishCommand(sid, proto.CommandResult{ID: cid, OK: true, Output: `{"kind":"hysteria2-installer","port":28443,"domain":"k.example.com","cert_mode":"acme","obfs_password":"o","hop_ports":"20000-40000","auth_password":"pw","users":[]}`})
	srv, _ := s.st.GetServer(sid)
	s.afterScriptInstall(srv, cid)
	s.afterScriptInstall(srv, cid)
	nodes, _ := s.st.NodesByServer(sid)
	if len(nodes) != 1 || nodes[0].Name != "kamatera" || nodes[0].Core != "script" {
		t.Fatalf("adopted node: %+v", nodes)
	}
}

func TestPortalSyncSwitchesToPerUser(t *testing.T) {
	s, err := New(Options{DataDir: t.TempDir(), AdminPass: "test-pass-123"})
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := s.st.CreateServer(&store.Server{Name: "JP", PublicIPv4: "8.8.8.8", Enabled: true, TrafficResetDay: 1}, util.SHA256Hex(util.RandToken(24)))
	n := &store.Node{ServerID: sid, Name: "JP", Core: "script", Protocol: "hysteria2", Port: 443, Enabled: true}
	n.Settings.SharedPassword = "owner"
	if err := s.normalizeNode(n); err != nil {
		t.Fatal(err)
	}
	nid, _ := s.st.CreateNode(n)
	name, pw := "buyer", "buyerpw-123"
	u, err := s.createUser(&UserInput{Username: &name, Password: &pw})
	if err != nil {
		t.Fatal(err)
	}
	node, _ := s.st.GetNode(nid)
	if got := (subNode{Node: node}).pw(u); got != "owner" {
		t.Fatalf("before sync: %s", got)
	}
	want := s.portalDesired(node, []*store.User{u})
	if len(want) != 1 || want[0].ID != fmt.Sprintf("nh-%d", u.ID) || want[0].Password != "buyerpw-123" {
		t.Fatalf("desired %+v", want)
	}
	srv, _ := s.st.GetServer(sid)
	sync := func(used int64) {
		cid, _ := s.st.QueueCommand(sid, "portal_sync", "{}")
		out, _ := json.Marshal(map[string]any{"created": 1, "usage": []map[string]any{{"id": fmt.Sprintf("nh-%d", u.ID), "used": used}}})
		s.st.FinishCommand(sid, proto.CommandResult{ID: cid, OK: true, Output: string(out)})
		s.afterScriptInstall(srv, cid)
	}
	sync(1000) // first sample: baseline only
	sync(5000) // +4000
	sync(200)  // portal counter reset: +200
	got, _ := s.st.GetUser(u.ID)
	if got.Up+got.Down != 4200 {
		t.Fatalf("usage booked %d", got.Up+got.Down)
	}
	node, _ = s.st.GetNode(nid)
	if !node.Settings.PortalUsers || (subNode{Node: node}).pw(u) != "buyerpw-123" {
		t.Fatal("after a clean sync the subscription must use the user's own password")
	}
	if versionLess("1.3.10", "1.3.2") || !versionLess("1.3.1", "1.3.2") {
		t.Fatal("versionLess")
	}
}

func TestDualStackProvisionWithCloudflare(t *testing.T) {
	// Mock Cloudflare API v4
	records := map[string]cfDNSRecord{}
	cfMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cf-test-tok" {
			http.Error(w, `{"success":false,"errors":[{"code":1000,"message":"bad auth"}]}`, 403)
			return
		}
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/zones") && !strings.Contains(r.URL.Path, "/dns_records"):
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []cfZone{{ID: "z1", Name: "example.com", Status: "active"}}})
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/dns_records"):
			name := r.URL.Query().Get("name")
			var out []cfDNSRecord
			if rec, ok := records[name]; ok {
				out = append(out, rec)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": out})
		case r.Method == "POST" && strings.Contains(r.URL.Path, "/dns_records"):
			var rec cfDNSRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			rec.ID = "rec-1"
			records[rec.Name] = rec
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rec})
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/dns_records/"):
			var rec cfDNSRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			rec.ID = "rec-1"
			records[rec.Name] = rec
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rec})
		default:
			http.NotFound(w, r)
		}
	}))
	defer cfMock.Close()
	origBase := cfAPIBase
	cfAPIBase = cfMock.URL
	defer func() { cfAPIBase = origBase }()

	s, err := New(Options{DataDir: t.TempDir(), AdminPass: "test-pass-123"})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.st.SetSetting("cf_api_token", "cf-test-tok")
	_ = s.st.SetSetting("acme_email", "ops@example.com")
	ts := httptest.NewServer(s.middleware(s.mux))
	defer ts.Close()
	c := &client{t: t, srv: ts}

	// Verify /dual-stack.sh renders with master URL
	resp, err := http.Get(ts.URL + "/dual-stack.sh")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("dual-stack.sh: %v %v", err, resp)
	}
	scriptBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(scriptBody), ts.URL) || strings.Contains(string(scriptBody), "__MASTER_URL__") {
		t.Fatalf("dual-stack.sh did not substitute master URL")
	}
	if strings.Contains(string(scriptBody), "$GROUPS") || strings.Contains(string(scriptBody), "\r") || !strings.Contains(string(scriptBody), "NODE_GROUPS") {
		t.Fatalf("dual-stack.sh must avoid bash built-in $GROUPS and CRLF")
	}

	raw := "nhk_" + util.RandToken(30)
	_, _ = s.st.CreateAPIKey("prov", raw[:10], util.SHA256Hex(raw), "read,write", "")
	auth := "Bearer " + raw

	// First call: creates server + CF DNS A record (bare prefix -> jp2.example.com) + Hy2(acme_dns) + VLESS-Reality(tcp)
	code, out := c.do("POST", "/api/open/v1/provision", auth, map[string]any{
		"name": "jp2", "region": "JP", "ip": "203.0.113.55", "domain": "jp2",
	})
	if code != 200 {
		t.Fatalf("provision failed %d: %v", code, out)
	}
	if out["domain"] != "jp2.example.com" || out["dns_action"] != "created" || out["cert_mode"] != "acme_dns" {
		t.Fatalf("unexpected domain/dns/cert: %v", out)
	}
	if rec := records["jp2.example.com"]; rec.Content != "203.0.113.55" || rec.Proxied {
		t.Fatalf("CF record mismatch: %+v", rec)
	}
	if out["token"] == "" || out["install_command"] == "" {
		t.Fatalf("missing agent token/install_command: %v", out)
	}
	hy2 := out["hy2_node"].(map[string]any)
	vl := out["vless_node"].(map[string]any)
	if hy2["protocol"] != "hysteria2" || hy2["core"] != "singbox" || vl["protocol"] != "vless" || vl["core"] != "xray" {
		t.Fatalf("unexpected nodes: hy2=%v vl=%v", hy2, vl)
	}

	// Second call for same IP: idempotent, does not duplicate nodes, CF record unchanged
	code2, out2 := c.do("POST", "/api/open/v1/provision", auth, map[string]any{
		"name": "jp2", "region": "JP", "ip": "203.0.113.55", "domain": "jp2.example.com",
	})
	if code2 != 200 || out2["created_server"] != false || out2["dns_action"] != "unchanged" {
		t.Fatalf("second provision mismatch %d: %v", code2, out2)
	}
}

func TestDownloadGzipAndChecksumCache(t *testing.T) {
	dist := t.TempDir()
	raw := bytes.Repeat([]byte("nodehub-fast-binary-payload-"), 512)
	binPath := filepath.Join(dist, "sing-box-linux-amd64")
	if err := os.WriteFile(binPath, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write(raw)
	_ = gw.Close()
	if err := os.WriteFile(binPath+".gz", gzBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := New(Options{DataDir: t.TempDir(), DistDir: dist, AdminPass: "test-pass-123"})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.middleware(s.mux))
	defer ts.Close()

	// Explicit Accept-Encoding: gzip should serve pre-compressed .gz + raw SHA256 header
	req, _ := http.NewRequest("GET", ts.URL+"/dl/sing-box-linux-amd64", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	cl := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("want 200 gzip, got %d encoding=%q", resp.StatusCode, resp.Header.Get("Content-Encoding"))
	}
	if len(body) >= len(raw) {
		t.Fatalf("gzip body (%d) should be smaller than raw (%d)", len(body), len(raw))
	}
	wantSum := util.SHA256Hex(string(raw))
	if got := resp.Header.Get("X-Checksum-Sha256"); got != wantSum {
		t.Fatalf("X-Checksum-Sha256 mismatch: want %s got %s", wantSum, got)
	}
	// Verify decompressed bytes equal raw payload
	gr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(gr)
	_ = gr.Close()
	if !bytes.Equal(plain, raw) {
		t.Fatalf("decompressed payload mismatch")
	}

	// HEAD request returns checksum without body
	headReq, _ := http.NewRequest("HEAD", ts.URL+"/dl/sing-box-linux-amd64", nil)
	headResp, err := cl.Do(headReq)
	if err != nil {
		t.Fatal(err)
	}
	headResp.Body.Close()
	if headResp.StatusCode != 200 || headResp.Header.Get("X-Checksum-Sha256") != wantSum {
		t.Fatalf("HEAD mismatch: %d sha=%q", headResp.StatusCode, headResp.Header.Get("X-Checksum-Sha256"))
	}

	// Verify install.sh has parallel downloads, --compressed, LF endings, and no redundant apt-get unzip
	instResp, err := http.Get(ts.URL + "/install.sh")
	if err != nil || instResp.StatusCode != 200 {
		t.Fatalf("install.sh: %v %v", err, instResp)
	}
	instBody, _ := io.ReadAll(instResp.Body)
	instResp.Body.Close()
	for _, want := range []string{"--compressed", "PID_A=$!", "PID_X=$!", "PID_S=$!", "extract_zip_member"} {
		if !strings.Contains(string(instBody), want) {
			t.Fatalf("install.sh missing %q", want)
		}
	}
	if strings.Contains(string(instBody), "\r") || strings.Contains(string(instBody), "IGNORECASE") || strings.Contains(string(instBody), "version 2>/dev/null | head") {
		t.Fatalf("install.sh must use LF endings, mawk-safe tolower(), and avoid pipefail SIGPIPE")
	}
}
