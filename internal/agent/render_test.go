package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"nodehub/internal/proto"
	"nodehub/internal/util"
)

// Validates generated configs with the real binaries. Set XRAY_BIN and SINGBOX_BIN to run.
func TestRenderValidates(t *testing.T) {
	xbin, sbin := os.Getenv("XRAY_BIN"), os.Getenv("SINGBOX_BIN")
	if xbin == "" || sbin == "" {
		t.Skip("XRAY_BIN / SINGBOX_BIN not set")
	}
	dir := t.TempDir()
	opt := RenderOptions{
		XrayAPIPort: 10085, SingboxAPIPort: 10086, BlockPrivate: true, BlockBT: true, CertDir: dir, ACMEDir: dir + "/acme", IPv4Only: true,
		WARP: &WARPCred{PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", PeerPubKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", Endpoint: "162.159.192.1:2408", AddressV4: "172.16.0.2", AddressV6: "2606:4700:110::1", Reserved: []int{1, 2, 3}},
	}
	priv, pub, _ := util.RealityKeyPair()
	uid := util.UUID()
	mk := func(id int64, core, proto_ string, s proto.NodeSettings) proto.NodeConfig {
		pw := uid
		if proto_ == "shadowsocks" {
			pw = util.SSUserKey(s.Cipher, uid)
		}
		return proto.NodeConfig{ID: id, Core: core, Protocol: proto_, Port: int(20000 + id), Settings: s,
			Users: []proto.NodeUser{{Key: fmt.Sprintf("n%d.u1", id), UUID: uid, Password: pw}}}
	}
	reality := proto.NodeSettings{Security: "reality", Flow: "xtls-rprx-vision", RealityDest: "www.microsoft.com:443", RealityServerName: "www.microsoft.com", RealityPrivateKey: priv, RealityShortID: "abcd1234"}
	nodes := []proto.NodeConfig{
		mk(1, "xray", "vless", reality),
		mk(2, "xray", "vless", proto.NodeSettings{Network: "ws", Path: "/ws", Security: "tls", SNI: "a.example.com"}),
		mk(3, "xray", "vless", proto.NodeSettings{Network: "xhttp", Path: "/x", Security: "reality", RealityDest: "www.apple.com", RealityPrivateKey: priv, RealityShortID: "ab"}),
		mk(4, "xray", "vmess", proto.NodeSettings{Network: "ws", Path: "/vm"}),
		mk(5, "xray", "vmess", proto.NodeSettings{Network: "grpc", ServiceName: "grpc", Security: "tls", SNI: "b.example.com"}),
		mk(6, "xray", "trojan", proto.NodeSettings{Security: "tls", SNI: "c.example.com"}),
		mk(7, "xray", "shadowsocks", proto.NodeSettings{Cipher: "2022-blake3-aes-128-gcm", ServerKey: util.SSServerKey("2022-blake3-aes-128-gcm")}),
		mk(8, "xray", "shadowsocks", proto.NodeSettings{Cipher: "aes-128-gcm"}),
		mk(9, "xray", "vless", proto.NodeSettings{Network: "httpupgrade", Path: "/hu"}),
		mk(11, "singbox", "hysteria2", proto.NodeSettings{SNI: "d.example.com", UpMbps: 100, DownMbps: 100, Obfs: "salamander", ObfsPassword: "x"}),
		mk(12, "singbox", "tuic", proto.NodeSettings{SNI: "e.example.com"}),
		mk(13, "singbox", "anytls", proto.NodeSettings{SNI: "f.example.com", Outbound: "warp"}),
		mk(14, "singbox", "vless", reality),
		mk(15, "singbox", "shadowsocks", proto.NodeSettings{Cipher: "2022-blake3-aes-256-gcm", ServerKey: util.SSServerKey("2022-blake3-aes-256-gcm")}),
		mk(16, "singbox", "trojan", proto.NodeSettings{Network: "ws", Path: "/t", Security: "tls", SNI: "g.example.com"}),
		mk(17, "singbox", "vmess", proto.NodeSettings{Network: "grpc", ServiceName: "g"}),
		mk(18, "singbox", "hysteria2", proto.NodeSettings{SNI: "hy.example.com", CertMode: "acme", ACMEEmail: "a@example.com", UpMbps: 1000, DownMbps: 1000,
			Obfs: "salamander", ObfsPassword: "x", HopPorts: "30000-40000", Masquerade: "https://www.bing.com"}),
		mk(19, "singbox", "hysteria2", proto.NodeSettings{SNI: "us.example.com", CertMode: "acme_dns", ACMEDNSProvider: "cloudflare", ACMEDNSToken: "tok", ACMEEmail: "a@example.com"}),
		mk(20, "singbox", "vless", proto.NodeSettings{Network: "ws", Path: "/ws-cdn", Host: "cdn.example.com", Security: "tls", SNI: "cdn.example.com", ALPN: "http/1.1", CertMode: "acme_dns", ACMEDNSProvider: "cloudflare", ACMEDNSToken: "tok", ACMEEmail: "a@example.com"}),
	}
	relays := []proto.RelayOutbound{{
		Tag: "relay-n50", Protocol: "vless", Address: "192.3.173.122", Port: 44443, UUID: uid,
		Flow: "xtls-rprx-vision", Network: "tcp", Security: "reality", SNI: "www.apple.com",
		Fingerprint: "chrome", RealityPublicKey: pub, RealityShortID: "abcd1234",
		UserKeys: []string{"n1.u1", "n11.u1"},
	}}
	for _, n := range nodes {
		if NeedsCert(n) {
			c, k := certPaths(n, opt)
			if err := EnsureSelfSigned(c, k, n.Settings.SNI); err != nil {
				t.Fatal(err)
			}
		}
	}
	xb, err := RenderXray(nodes, opt, relays...)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := RenderSingbox(nodes, opt, relays...)
	if err != nil {
		t.Fatal(err)
	}
	xp, sp := filepath.Join(dir, "x.json"), filepath.Join(dir, "s.json")
	os.WriteFile(xp, xb, 0o600)
	os.WriteFile(sp, sb, 0o600)
	if err := (&Core{Name: "xray", Bin: xbin}).Test(xp); err != nil {
		t.Fatalf("xray: %v\n%s", err, xb)
	}
	if err := (&Core{Name: "singbox", Bin: sbin}).Test(sp); err != nil {
		t.Fatalf("singbox: %v\n%s", err, sb)
	}
}

func TestHopRules(t *testing.T) {
	nodes := []proto.NodeConfig{
		{Protocol: "hysteria2", Port: 16305, Settings: proto.NodeSettings{HopPorts: "20000-40000"}, Users: []proto.NodeUser{{Key: "a"}}},
		{Protocol: "hysteria2", Port: 25000, Settings: proto.NodeSettings{HopPorts: "20000-40000"}, Users: []proto.NodeUser{{Key: "a"}}}, // port inside own range: ignored
		{Protocol: "tuic", Port: 1, Settings: proto.NodeSettings{HopPorts: "2000-3000"}, Users: []proto.NodeUser{{Key: "a"}}},            // not hysteria2: ignored
		{Protocol: "hysteria2", Port: 2, Settings: proto.NodeSettings{HopPorts: "5000-6000"}},                                            // no users: ignored
	}
	r := hopRules(nodes)
	if len(r) != 1 || r[0] != (hopRule{20000, 40000, 16305}) {
		t.Fatalf("%+v", r)
	}
}

func TestACMEDNSNeedsToken(t *testing.T) {
	n := proto.NodeConfig{ID: 1, Name: "x", Core: "singbox", Protocol: "hysteria2", Port: 443, Users: []proto.NodeUser{{Key: "k", UUID: "u", Password: "p"}},
		Settings: proto.NodeSettings{SNI: "us.example.com", CertMode: "acme_dns"}}
	if _, err := RenderSingbox([]proto.NodeConfig{n}, RenderOptions{CertDir: t.TempDir(), ACMEDir: t.TempDir()}); err == nil {
		t.Fatal("expected error without a DNS token")
	}
}

// A Hysteria2 client waits for the server before sending on a TCP stream, so
// sniffing its TCP would stall each new connection for the sniff timeout.
func TestSingboxSniffSkipsHysteria2TCP(t *testing.T) {
	u := []proto.NodeUser{{Key: "k", UUID: "u", Password: "p"}}
	nodes := []proto.NodeConfig{
		{ID: 1, Core: "singbox", Protocol: "hysteria2", Port: 443, Users: u, Settings: proto.NodeSettings{SNI: "a.example.com"}},
		{ID: 2, Core: "singbox", Protocol: "tuic", Port: 444, Users: u, Settings: proto.NodeSettings{SNI: "b.example.com"}},
	}
	dir := t.TempDir()
	b, err := RenderSingbox(nodes, RenderOptions{CertDir: dir, ACMEDir: dir, BlockBT: true})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	sniff := map[string]string{} // inbound tag -> network restriction ("" = all)
	for _, r := range cfg.Route.Rules {
		if r["action"] != "sniff" {
			continue
		}
		network, _ := r["network"].(string)
		for _, tag := range r["inbound"].([]any) {
			sniff[tag.(string)] = network
		}
	}
	if net, ok := sniff["n1"]; !ok || net != "udp" {
		t.Fatalf("hysteria2 inbound should sniff UDP only, got %q (present=%v)", net, ok)
	}
	if net, ok := sniff["n2"]; !ok || net != "" {
		t.Fatalf("tuic inbound should sniff everything, got %q (present=%v)", net, ok)
	}
}

func TestEnsureHy2StableQUIC(t *testing.T) {
	dir := t.TempDir()
	// Case 1: existing quic section with disablePathMTUDiscovery: false and maxIdleTimeout: 30s
	p1 := filepath.Join(dir, "c1.yaml")
	in1 := "listen: :44443\nquic:\n  maxIdleTimeout: 30s\n  disablePathMTUDiscovery: false\n"
	if err := os.WriteFile(p1, []byte(in1), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := EnsureHy2StableQUIC(p1)
	if err != nil || !changed {
		t.Fatalf("expected change, got changed=%v err=%v", changed, err)
	}
	b1, _ := os.ReadFile(p1)
	s1 := string(b1)
	if !containsAll(s1, "maxIdleTimeout: 60s", "disablePathMTUDiscovery: true") {
		t.Fatalf("unexpected patched config:\n%s", s1)
	}
	// Idempotent second call
	changed2, err := EnsureHy2StableQUIC(p1)
	if err != nil || changed2 {
		t.Fatalf("second call should be no-op, got changed=%v err=%v", changed2, err)
	}

	// Case 2: no quic section at all
	p2 := filepath.Join(dir, "c2.yaml")
	if err := os.WriteFile(p2, []byte("listen: :44443\nbandwidth:\n  up: 1 gbps\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed3, err := EnsureHy2StableQUIC(p2)
	if err != nil || !changed3 {
		t.Fatalf("expected append, got changed=%v err=%v", changed3, err)
	}
	b2, _ := os.ReadFile(p2)
	if !containsAll(string(b2), "quic:", "maxIdleTimeout: 60s", "disablePathMTUDiscovery: true") {
		t.Fatalf("unexpected appended config:\n%s", string(b2))
	}
}

func TestRenderServerRelays(t *testing.T) {
	priv, pub, _ := util.RealityKeyPair()
	uDirect := util.UUID()
	uRelay := util.UUID()
	uLanding := util.UUID()
	dir := t.TempDir()
	opt := RenderOptions{XrayAPIPort: 10085, SingboxAPIPort: 10086, BlockPrivate: true, BlockBT: true, CertDir: dir, ACMEDir: dir + "/acme"}

	xNodes := []proto.NodeConfig{{
		ID: 39, Core: "xray", Protocol: "vless", Port: 44443,
		Settings: proto.NodeSettings{Network: "tcp", Security: "reality", Flow: "xtls-rprx-vision", RealityDest: "www.apple.com:443", RealityPrivateKey: priv, RealityShortID: "abcd"},
		Users: []proto.NodeUser{
			{Key: "n39.u1", UUID: uDirect},
			{Key: "n39.u1.r50", UUID: uRelay},
		},
	}}
	relays := []proto.RelayOutbound{
		{
			Tag: "relay-n50", Protocol: "vless", Address: "192.3.173.122", Port: 44443, UUID: uLanding,
			Flow: "xtls-rprx-vision", Network: "tcp", Security: "reality", SNI: "www.apple.com",
			Fingerprint: "chrome", RealityPublicKey: pub, RealityShortID: "1234",
			UserKeys: []string{"n39.u1.r50", "n999.u1.r50"},
		},
		{
			Tag: "relay-unused", Protocol: "vless", Address: "1.2.3.4", Port: 443, UUID: uLanding,
			UserKeys: []string{"n888.u1.r99"},
		},
	}
	xb, err := RenderXray(xNodes, opt, relays...)
	if err != nil {
		t.Fatal(err)
	}
	xs := string(xb)
	if !containsAll(xs, `"tag": "relay-n50"`, `"address": "192.3.173.122"`, `"outboundTag": "relay-n50"`, `"n39.u1.r50"`) {
		t.Fatalf("xray relay missing expected entries:\n%s", xs)
	}
	if containsAll(xs, "relay-unused") || containsAll(xs, "n999.u1.r50") {
		t.Fatalf("xray relay leaked unmatched outbound/user:\n%s", xs)
	}

	sNodes := []proto.NodeConfig{{
		ID: 35, Core: "singbox", Protocol: "hysteria2", Port: 44443,
		Settings: proto.NodeSettings{SNI: "jp.example.com"},
		Users: []proto.NodeUser{
			{Key: "n35.u1", Password: "p1"},
			{Key: "n35.u1.r50", Password: "p2"},
		},
	}}
	relays[0].UserKeys = []string{"n35.u1.r50"}
	sb, err := RenderSingbox(sNodes, opt, relays...)
	if err != nil {
		t.Fatal(err)
	}
	ss := string(sb)
	if !containsAll(ss, `"tag": "relay-n50"`, `"server": "192.3.173.122"`, `"auth_user"`, `"n35.u1.r50"`) {
		t.Fatalf("sing-box relay missing expected entries:\n%s", ss)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
