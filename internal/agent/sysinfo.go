package agent

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodehub/internal/proto"
)

// SysCollector samples /proc. CPU usage and network rates are computed between calls.
type SysCollector struct {
	mu                sync.Mutex
	lastIdle, lastAll uint64
	lastRx, lastTx    uint64
	lastAt            time.Time
	staticOnce        sync.Once
	cpuModel, kernel  string
	osName            string
}

func (c *SysCollector) Collect(hb *proto.Heartbeat) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.staticOnce.Do(func() {
		c.cpuModel = readCPUModel()
		c.kernel = strings.TrimSpace(readFile("/proc/sys/kernel/osrelease"))
		c.osName = readOSName()
	})
	hb.OS = c.osName
	hb.Arch = runtime.GOARCH
	hb.Kernel = c.kernel
	hb.CPUModel = c.cpuModel
	hb.CPUCores = runtime.NumCPU()
	hb.Hostname, _ = os.Hostname()

	// cpu
	idle, all := readCPU()
	if c.lastAll > 0 && all > c.lastAll {
		hb.CPUUsage = round1(100 * (1 - float64(idle-c.lastIdle)/float64(all-c.lastAll)))
	}
	c.lastIdle, c.lastAll = idle, all

	// load
	if f := strings.Fields(readFile("/proc/loadavg")); len(f) >= 3 {
		hb.Load1, _ = strconv.ParseFloat(f[0], 64)
		hb.Load5, _ = strconv.ParseFloat(f[1], 64)
		hb.Load15, _ = strconv.ParseFloat(f[2], 64)
	}

	// memory
	mem := readKV("/proc/meminfo")
	hb.MemTotal = mem["MemTotal"] * 1024
	avail := mem["MemAvailable"]
	if avail == 0 {
		avail = mem["MemFree"] + mem["Buffers"] + mem["Cached"]
	}
	hb.MemUsed = hb.MemTotal - avail*1024
	hb.SwapTotal = mem["SwapTotal"] * 1024
	hb.SwapUsed = hb.SwapTotal - mem["SwapFree"]*1024

	hb.DiskTotal, hb.DiskUsed = diskUsage("/")

	// network
	rx, tx := readNet()
	now := time.Now()
	hb.NetRxTotal, hb.NetTxTotal = rx, tx
	if !c.lastAt.IsZero() && rx >= c.lastRx && tx >= c.lastTx {
		sec := now.Sub(c.lastAt).Seconds()
		if sec > 0 {
			hb.NetRxRate = uint64(float64(rx-c.lastRx) / sec)
			hb.NetTxRate = uint64(float64(tx-c.lastTx) / sec)
		}
	}
	c.lastRx, c.lastTx, c.lastAt = rx, tx, now

	hb.TCPConns = countLines("/proc/net/tcp") + countLines("/proc/net/tcp6")
	hb.UDPConns = countLines("/proc/net/udp") + countLines("/proc/net/udp6")
	if f := strings.Fields(readFile("/proc/uptime")); len(f) > 0 {
		up, _ := strconv.ParseFloat(f[0], 64)
		hb.Uptime = uint64(up)
	}
}

func round1(f float64) float64 {
	if f < 0 {
		f = 0
	}
	return float64(int(f*10+0.5)) / 10
}

func readFile(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

func readCPU() (idle, all uint64) {
	line := strings.SplitN(readFile("/proc/stat"), "\n", 2)[0]
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0
	}
	for i, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		if i < 8 { // user nice system idle iowait irq softirq steal (guest is counted in user)
			all += n
		}
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return
}

func readKV(p string) map[string]uint64 {
	out := map[string]uint64{}
	f, err := os.Open(p)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) >= 2 {
			n, _ := strconv.ParseUint(parts[1], 10, 64)
			out[strings.TrimSuffix(parts[0], ":")] = n
		}
	}
	return out
}

func readNet() (rx, tx uint64) {
	lines := strings.Split(readFile("/proc/net/dev"), "\n")
	for _, l := range lines[min(2, len(lines)):] {
		i := strings.Index(l, ":")
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(l[:i])
		if name == "lo" || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "wg") || strings.HasPrefix(name, "virbr") {
			continue
		}
		f := strings.Fields(l[i+1:])
		if len(f) >= 9 {
			r, _ := strconv.ParseUint(f[0], 10, 64)
			t, _ := strconv.ParseUint(f[8], 10, 64)
			rx += r
			tx += t
		}
	}
	return
}

func countLines(p string) int {
	s := readFile(p)
	if s == "" {
		return 0
	}
	n := strings.Count(s, "\n") - 1
	if n < 0 {
		return 0
	}
	return n
}

func readCPUModel() string {
	for _, l := range strings.Split(readFile("/proc/cpuinfo"), "\n") {
		if strings.HasPrefix(l, "model name") {
			if i := strings.Index(l, ":"); i > 0 {
				return strings.TrimSpace(l[i+1:])
			}
		}
	}
	return runtime.GOARCH
}

func readOSName() string {
	for _, l := range strings.Split(readFile("/etc/os-release"), "\n") {
		if strings.HasPrefix(l, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
		}
	}
	return runtime.GOOS
}
