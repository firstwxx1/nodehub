package agent

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodehub/internal/proto"
)

// Port scanner: lists the host's listening TCP ports and bound UDP ports together with the owning process,
// leaving out sockets owned by the agent's own child processes (Xray / sing-box). The master uses this to
// refuse a node port that another program already holds and to suggest a free one.

var (
	portsMu      sync.Mutex
	portsCache   []proto.ListenPort
	portsScanned time.Time
)

// ListeningPorts returns a cached scan (refreshed at most every 45 seconds).
func ListeningPorts() []proto.ListenPort {
	portsMu.Lock()
	defer portsMu.Unlock()
	if time.Since(portsScanned) < 45*time.Second && portsCache != nil {
		return portsCache
	}
	portsCache = scanPorts("/proc")
	portsScanned = time.Now()
	return portsCache
}

type sockEntry struct {
	proto string
	port  int
}

// readSockets parses /proc/net/{tcp,tcp6,udp,udp6}: inode -> proto/port, only LISTEN tcp and bound udp.
func readSockets(proc string) map[string]sockEntry {
	out := map[string]sockEntry{}
	for _, f := range []struct{ name, proto string }{{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"}} {
		fh, err := os.Open(filepath.Join(proc, "net", f.name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Scan() // header
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) < 10 {
				continue
			}
			if f.proto == "tcp" && fs[3] != "0A" { // LISTEN
				continue
			}
			i := strings.LastIndex(fs[1], ":")
			if i < 0 {
				continue
			}
			port, err := strconv.ParseInt(fs[1][i+1:], 16, 32)
			if err != nil || port == 0 {
				continue
			}
			if f.proto == "udp" && fs[3] != "07" { // unconnected, bound
				continue
			}
			out[fs[9]] = sockEntry{f.proto, int(port)}
		}
		fh.Close()
	}
	return out
}

func ppidOf(proc, pid string) int {
	b, err := os.ReadFile(filepath.Join(proc, pid, "stat"))
	if err != nil {
		return -1
	}
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return -1
	}
	fs := strings.Fields(s[i+1:])
	if len(fs) < 2 {
		return -1
	}
	n, _ := strconv.Atoi(fs[1])
	return n
}

func scanPorts(proc string) []proto.ListenPort {
	socks := readSockets(proc)
	if len(socks) == 0 {
		return []proto.ListenPort{}
	}
	self := os.Getpid()
	seen := map[string]proto.ListenPort{}
	ents, _ := os.ReadDir(proc)
	for _, e := range ents {
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(proc, pid, "fd"))
		if err != nil {
			continue
		}
		var mine []sockEntry
		for _, fd := range fds {
			l, err := os.Readlink(filepath.Join(proc, pid, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(l, "socket:[") {
				continue
			}
			if se, ok := socks[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")]; ok {
				mine = append(mine, se)
			}
		}
		if len(mine) == 0 {
			continue
		}
		if p, _ := strconv.Atoi(pid); p == self || ppidOf(proc, pid) == self {
			continue // our own cores
		}
		name := "?"
		if b, err := os.ReadFile(filepath.Join(proc, pid, "comm")); err == nil {
			name = strings.TrimSpace(string(b))
		}
		for _, se := range mine {
			seen[se.proto+":"+strconv.Itoa(se.port)] = proto.ListenPort{Proto: se.proto, Port: se.port, Proc: name}
		}
	}
	out := make([]proto.ListenPort, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	if len(out) > 3000 {
		out = out[:3000]
	}
	return out
}
