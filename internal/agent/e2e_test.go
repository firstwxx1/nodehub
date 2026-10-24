package agent

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nodehub/internal/proto"
	"nodehub/internal/util"
)

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestRealityE2E renders a VLESS+Reality node, runs real Xray with it, and connects through it with a
// sing-box client configured exactly like the exported share link (public key / short id / sni / flow).
func TestRealityE2E(t *testing.T) {
	xbin, sbin := os.Getenv("XRAY_BIN"), os.Getenv("SINGBOX_BIN")
	if xbin == "" || sbin == "" {
		t.Skip("XRAY_BIN / SINGBOX_BIN not set")
	}
	dir := t.TempDir()
	// "dest": a local TLS 1.3 site standing in for www.microsoft.com
	destSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "dest") }))
	destSrv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
	destSrv.StartTLS()
	defer destSrv.Close()
	destAddr := strings.TrimPrefix(destSrv.URL, "https://")
	// target the client wants to reach through the proxy
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello-through-reality") }))
	defer target.Close()

	priv, pub, err := util.RealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	uid := util.UUID()
	port := freePort(t)
	sn := "localhost"
	n := proto.NodeConfig{ID: 2, Core: "xray", Protocol: "vless", Port: port, Listen: "127.0.0.1",
		Settings: proto.NodeSettings{Network: "tcp", Security: "reality", Flow: "xtls-rprx-vision", Fingerprint: "chrome",
			RealityDest: destAddr, RealityServerName: sn, RealityPrivateKey: priv, RealityShortID: "c5e2d6ee"},
		Users: []proto.NodeUser{{Key: "n2.u1", UUID: uid, Password: uid}}}
	opt := RenderOptions{XrayAPIPort: freePort(t), CertDir: dir, ACMEDir: dir, IPv4Only: true}
	xb, err := RenderXray([]proto.NodeConfig{n}, opt)
	if err != nil {
		t.Fatal(err)
	}
	xp := filepath.Join(dir, "x.json")
	os.WriteFile(xp, xb, 0o600)
	xr := exec.Command(xbin, "run", "-c", xp)
	var xlog strings.Builder
	xr.Stdout, xr.Stderr = &xlog, &xlog
	if err := xr.Start(); err != nil {
		t.Fatal(err)
	}
	defer xr.Process.Kill()

	socks := freePort(t)
	cfg := map[string]any{"log": map[string]any{"level": "debug"},
		"inbounds": []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": socks}},
		"outbounds": []any{map[string]any{"type": "vless", "server": "127.0.0.1", "server_port": port, "uuid": uid, "flow": "xtls-rprx-vision",
			"tls": map[string]any{"enabled": true, "server_name": sn, "utls": map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{"enabled": true, "public_key": pub, "short_id": "c5e2d6ee"}}}}}
	cb, _ := json.Marshal(cfg)
	cp := filepath.Join(dir, "c.json")
	os.WriteFile(cp, cb, 0o600)
	sr := exec.Command(sbin, "run", "-c", cp)
	var slog strings.Builder
	sr.Stdout, sr.Stderr = &slog, &slog
	if err := sr.Start(); err != nil {
		t.Fatal(err)
	}
	defer sr.Process.Kill()
	time.Sleep(2500 * time.Millisecond)

	pu, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socks))
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	resp, err := cl.Get(target.URL)
	if err != nil {
		t.Fatalf("through reality: %v\n--- xray ---\n%s\n--- client ---\n%s", err, lastN(xlog.String()), lastN(slog.String()))
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "hello-through-reality" {
		t.Fatalf("got %q", b)
	}
}

func lastN(s string) string {
	if len(s) > 3000 {
		return s[len(s)-3000:]
	}
	return s
}
