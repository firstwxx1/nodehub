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
	opt := RenderOptions{XrayAPIPort: 10085, SingboxAPIPort: 10086, BlockPrivate: true, BlockBT: true, CertDir: dir, ACMEDir: dir + "/acme", IPv4Only: true}
	priv, _, _ := util.RealityKeyPair()
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
		mk(13, "singbox", "anytls", proto.NodeSettings{SNI: "f.example.com"}),
		mk(14, "singbox", "vless", reality),
		mk(15, "singbox", "shadowsocks", proto.NodeSettings{Cipher: "2022-blake3-aes-256-gcm", ServerKey: util.SSServerKey("2022-blake3-aes-256-gcm")}),
		mk(16, "singbox", "trojan", proto.NodeSettings{Network: "ws", Path: "/t", Security: "tls", SNI: "g.example.com"}),
		mk(17, "singbox", "vmess", proto.NodeSettings{Network: "grpc", ServiceName: "g"}),
		mk(18, "singbox", "hysteria2", proto.NodeSettings{SNI: "hy.example.com", CertMode: "acme", ACMEEmail: "a@example.com", UpMbps: 1000, DownMbps: 1000,
			Obfs: "salamander", ObfsPassword: "x", HopPorts: "30000-40000", Masquerade: "https://www.bing.com"}),
		mk(19, "singbox", "hysteria2", proto.NodeSettings{SNI: "us.example.com", CertMode: "acme_dns", ACMEDNSProvider: "cloudflare", ACMEDNSToken: "tok", ACMEEmail: "a@example.com"}),
	}
	for _, n := range nodes {
		if NeedsCert(n) {
			c, k := certPaths(n, opt)
			if err := EnsureSelfSigned(c, k, n.Settings.SNI); err != nil {
				t.Fatal(err)
			}
		}
	}
	xb, err := RenderXray(nodes, opt)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := RenderSingbox(nodes, opt)
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
