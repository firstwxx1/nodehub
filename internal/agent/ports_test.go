package agent

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestScanPortsSeesForeignListener(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	tp := l.Addr().(*net.TCPAddr).Port
	up := pc.LocalAddr().(*net.UDPAddr).Port
	// this test process is "self", so its own sockets are filtered out like the agent's cores
	for _, p := range scanPorts("/proc") {
		if (p.Proto == "tcp" && p.Port == tp) || (p.Proto == "udp" && p.Port == up) {
			t.Fatalf("own socket must be excluded: %+v", p)
		}
	}
	if got := scanPorts("/nonexistent"); got == nil {
		t.Fatal("must return non-nil slice")
	}
}

func TestScanPortsFindsOrphanProcess(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	// a double-forked listener is not our child, like nginx on a real VPS
	code := `import socket,time
s=socket.socket();s.bind(("127.0.0.1",0));s.listen()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(("127.0.0.1",0))
print(s.getsockname()[1],u.getsockname()[1],flush=True);time.sleep(4)`
	out := filepath.Join(t.TempDir(), "o2")
	cmd := exec.Command("sh", "-c", `(`+py+` -c '`+code+`' > `+out+` &)`)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	var tp, up int
	for i := 0; i < 50 && tp == 0; i++ {
		time.Sleep(100 * time.Millisecond)
		if b, _ := os.ReadFile(out); len(b) > 0 {
			fmt.Sscan(string(b), &tp, &up)
		}
	}
	if tp == 0 {
		t.Fatal("helper did not start")
	}
	var gotT, gotU bool
	for _, p := range scanPorts("/proc") {
		gotT = gotT || (p.Proto == "tcp" && p.Port == tp && p.Proc != "")
		gotU = gotU || (p.Proto == "udp" && p.Port == up)
	}
	if !gotT || !gotU {
		t.Fatalf("tcp=%v udp=%v (ports %d/%d)", gotT, gotU, tp, up)
	}
}
