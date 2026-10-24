// Package agent runs on each VPS: it reports system status, applies node configs to
// Xray / sing-box, and reports per-user traffic back to the master.
package agent

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodehub/internal/proto"
)

type Config struct {
	Master         string `json:"master"`
	Token          string `json:"token"`
	DataDir        string `json:"data_dir"`
	XrayBin        string `json:"xray_bin"`
	SingboxBin     string `json:"singbox_bin"`
	XrayAPIPort    int    `json:"xray_api_port"`
	SingboxAPIPort int    `json:"singbox_api_port"`
	BlockPrivate   *bool  `json:"block_private"`
	BlockBT        *bool  `json:"block_bt"`
	HeartbeatSec   int    `json:"heartbeat_sec"`
	InsecureTLS    bool   `json:"insecure_tls"`
}

func (c *Config) Defaults() {
	if c.DataDir == "" {
		c.DataDir = "/etc/nodehub"
	}
	if c.XrayBin == "" {
		c.XrayBin = "/usr/local/nodehub/xray"
	}
	if c.SingboxBin == "" {
		c.SingboxBin = "/usr/local/nodehub/sing-box"
	}
	if c.XrayAPIPort == 0 {
		c.XrayAPIPort = 10085
	}
	if c.SingboxAPIPort == 0 {
		c.SingboxAPIPort = 10086
	}
	if c.HeartbeatSec <= 0 {
		c.HeartbeatSec = 10
	}
	t := true
	if c.BlockPrivate == nil {
		c.BlockPrivate = &t
	}
	if c.BlockBT == nil {
		c.BlockBT = &t
	}
	c.Master = strings.TrimRight(c.Master, "/")
}

type trafficKey struct {
	node int64
	key  string
}

type Agent struct {
	cfg    Config
	http   *http.Client
	sys    SysCollector
	cores  map[string]*Core
	stats  map[string]*StatsClient
	applyM sync.Mutex

	appliedVersion string
	applyError     string
	appliedFiles   map[string][]byte

	mu           sync.Mutex
	pending      map[trafficKey][2]int64
	pendingNode  map[int64][2]int64
	online       map[trafficKey]map[string]bool
	results      []proto.CommandResult
	unlock       *proto.UnlockResult
	reportEvery  time.Duration
	lastReport   time.Time
	pubV4, pubV6 string
	pubCheckedAt time.Time
	lastCounters map[string]int64 // xray user counters seen by sampleOnline (reset with the stats)
}

func New(cfg Config) *Agent {
	cfg.Defaults()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.InsecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	a := &Agent{
		cfg:          cfg,
		http:         &http.Client{Timeout: 20 * time.Second, Transport: tr},
		pending:      map[trafficKey][2]int64{},
		pendingNode:  map[int64][2]int64{},
		online:       map[trafficKey]map[string]bool{},
		appliedFiles: map[string][]byte{},
		lastCounters: map[string]int64{},
		reportEvery:  60 * time.Second,
	}
	a.cores = map[string]*Core{
		"xray":    {Name: "xray", Bin: cfg.XrayBin, ConfigPath: filepath.Join(cfg.DataDir, "xray.json"), LogPath: filepath.Join(cfg.DataDir, "xray.log")},
		"singbox": {Name: "singbox", Bin: cfg.SingboxBin, ConfigPath: filepath.Join(cfg.DataDir, "sing-box.json"), LogPath: filepath.Join(cfg.DataDir, "sing-box.log")},
	}
	a.stats = map[string]*StatsClient{}
	if c, err := NewStatsClient("127.0.0.1:"+strconv.Itoa(cfg.XrayAPIPort), XrayStatsService); err == nil {
		a.stats["xray"] = c
	}
	if c, err := NewStatsClient("127.0.0.1:"+strconv.Itoa(cfg.SingboxAPIPort), SingboxStatsService); err == nil {
		a.stats["singbox"] = c
	}
	return a
}

func (a *Agent) Run(stop <-chan struct{}) {
	_ = os.MkdirAll(filepath.Join(a.cfg.DataDir, "certs"), 0o755)
	a.restoreLastConfig()
	tick := time.NewTicker(time.Duration(a.cfg.HeartbeatSec) * time.Second)
	defer tick.Stop()
	a.lastReport = time.Now()
	a.loop()
	for {
		select {
		case <-stop:
			a.collectTraffic()
			_ = a.report()
			for _, c := range a.cores {
				c.Stop()
			}
			return
		case <-tick.C:
			a.loop()
		}
	}
}

func (a *Agent) loop() {
	resp, err := a.heartbeat()
	if err != nil {
		log.Printf("heartbeat: %v", err)
	} else {
		if resp.ReportEvery > 0 {
			a.reportEvery = time.Duration(resp.ReportEvery) * time.Second
		}
		// takeover / rollback must run before the config sync: they free (or reclaim) the ports the new config uses
		var async []proto.Command
		for _, c := range resp.Commands {
			if c.Type == "takeover" || c.Type == "rollback_takeover" {
				a.runCommand(c)
			} else {
				async = append(async, c)
			}
		}
		if resp.ConfigVersion != "" && resp.ConfigVersion != a.appliedVersion {
			if err := a.syncConfig(); err != nil {
				log.Printf("apply config: %v", err)
			}
		}
		for _, c := range async {
			go a.runCommand(c)
		}
	}
	a.sampleOnline()
	if time.Since(a.lastReport) >= a.reportEvery {
		a.lastReport = time.Now()
		a.collectTraffic()
		if err := a.report(); err != nil {
			log.Printf("report: %v", err)
		}
	}
}

// ---------------- master API ----------------

func (a *Agent) do(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, a.cfg.Master+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "nodehub-agent/"+proto.AgentVersion)
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s %s: HTTP %d %s", method, path, resp.StatusCode, tail(string(b), 200))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (a *Agent) heartbeat() (*proto.HeartbeatResp, error) {
	hb := &proto.Heartbeat{AgentVersion: proto.AgentVersion, CoreVersions: map[string]string{}, CoreRunning: map[string]bool{}}
	a.sys.Collect(hb)
	hb.Ports = ListeningPorts()
	a.refreshPublicIP()
	a.mu.Lock()
	hb.PublicIPv4, hb.PublicIPv6 = a.pubV4, a.pubV6
	a.mu.Unlock()
	for name, c := range a.cores {
		if c.Installed() {
			hb.CoreVersions[name] = c.Version()
		}
		hb.CoreRunning[name] = c.Running()
	}
	a.applyM.Lock()
	hb.ConfigVersion = a.appliedVersion
	hb.ApplyError = a.applyError
	a.applyM.Unlock()
	for _, c := range a.cores {
		if e := c.LastError(); e != "" && hb.ApplyError == "" && c.Installed() {
			hb.ApplyError = e
		}
	}
	var resp proto.HeartbeatResp
	return &resp, a.do("POST", "/agent/v1/heartbeat", hb, &resp)
}

func (a *Agent) refreshPublicIP() {
	a.mu.Lock()
	fresh := time.Since(a.pubCheckedAt) < 30*time.Minute && a.pubV4 != ""
	a.mu.Unlock()
	if fresh {
		return
	}
	v4 := fetchIP("https://api.ipify.org", "https://ipv4.icanhazip.com", "https://4.ipw.cn")
	v6 := fetchIP("https://api6.ipify.org", "https://ipv6.icanhazip.com")
	a.mu.Lock()
	a.pubV4, a.pubV6, a.pubCheckedAt = v4, v6, time.Now()
	a.mu.Unlock()
}

func fetchIP(urls ...string) string {
	c := &http.Client{Timeout: 5 * time.Second}
	for _, u := range urls {
		resp, err := c.Get(u)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 100))
		resp.Body.Close()
		if s := strings.TrimSpace(string(b)); resp.StatusCode == 200 && s != "" && len(s) < 50 {
			return s
		}
	}
	return ""
}

// ---------------- config apply ----------------

func (a *Agent) syncConfig() error {
	var cfg proto.AgentConfig
	if err := a.do("GET", "/agent/v1/config", nil, &cfg); err != nil {
		return err
	}
	return a.apply(&cfg, true)
}

func (a *Agent) cachePath() string { return filepath.Join(a.cfg.DataDir, "last-config.json") }

// restoreLastConfig starts the cores from the last good config so nodes keep serving if the master is down.
func (a *Agent) restoreLastConfig() {
	b, err := os.ReadFile(a.cachePath())
	if err != nil {
		return
	}
	var cfg proto.AgentConfig
	if json.Unmarshal(b, &cfg) == nil {
		if err := a.apply(&cfg, false); err != nil {
			log.Printf("restore last config: %v", err)
		}
	}
}

func (a *Agent) apply(cfg *proto.AgentConfig, save bool) error {
	a.applyM.Lock()
	defer a.applyM.Unlock()
	err := a.applyLocked(cfg)
	if err != nil {
		a.applyError = err.Error()
		// keep the version so we do not retry in a tight loop; a new version from the master retries
		a.appliedVersion = cfg.Version
		return err
	}
	a.applyError = ""
	a.appliedVersion = cfg.Version
	if save {
		if b, err := json.Marshal(cfg); err == nil {
			_ = os.WriteFile(a.cachePath(), b, 0o600)
		}
	}
	log.Printf("applied config %s (%d nodes)", cfg.Version, len(cfg.Nodes))
	return nil
}

func (a *Agent) applyLocked(cfg *proto.AgentConfig) error {
	opt := RenderOptions{
		XrayAPIPort: a.cfg.XrayAPIPort, SingboxAPIPort: a.cfg.SingboxAPIPort,
		BlockPrivate: *a.cfg.BlockPrivate, BlockBT: *a.cfg.BlockBT,
		CertDir:  filepath.Join(a.cfg.DataDir, "certs"),
		ACMEDir:  filepath.Join(a.cfg.DataDir, "acme"),
		IPv4Only: !hasIPv6Route(),
	}
	_ = os.MkdirAll(opt.ACMEDir, 0o700)
	byCore := map[string][]proto.NodeConfig{}
	for _, n := range cfg.Nodes {
		byCore[n.Core] = append(byCore[n.Core], n)
		if NeedsCert(n) {
			cert, key := certPaths(n, opt)
			if err := EnsureSelfSigned(cert, key, n.Settings.SNI); err != nil {
				return fmt.Errorf("生成证书失败 node %d: %w", n.ID, err)
			}
		}
	}
	var errs []string
	for name, core := range a.cores {
		nodes := byCore[name]
		active := 0
		for _, n := range nodes {
			if len(n.Users) > 0 {
				active++
			}
		}
		if active == 0 {
			if core.Running() {
				a.collectCore(name)
				core.Stop()
			}
			delete(a.appliedFiles, name)
			continue
		}
		if !core.Installed() {
			errs = append(errs, fmt.Sprintf("%s 未安装（%s），有 %d 个节点无法启动", name, core.Bin, active))
			continue
		}
		var data []byte
		var err error
		if name == "xray" {
			data, err = RenderXray(nodes, opt)
		} else {
			data, err = RenderSingbox(nodes, opt)
		}
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if bytes.Equal(data, a.appliedFiles[name]) && core.Running() {
			continue
		}
		tmp := strings.TrimSuffix(core.ConfigPath, ".json") + ".new.json" // xray infers the format from the extension
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if err := core.Test(tmp); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		var oldData []byte
		oldData, _ = os.ReadFile(core.ConfigPath)
		if err := os.Rename(tmp, core.ConfigPath); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if core.Running() {
			a.collectCore(name) // counters reset on restart; save them first
		}
		if err := core.Restart(); err != nil {
			errs = append(errs, err.Error())
			// roll back to the previous config so existing nodes keep working
			if len(oldData) > 0 {
				_ = os.WriteFile(core.ConfigPath, oldData, 0o600)
				_ = core.Restart()
			}
			continue
		}
		a.appliedFiles[name] = data
	}
	if err := applyHopRules(cfg.Nodes); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// ---------------- traffic ----------------

func parseKey(key string) (int64, bool) {
	// keys look like n12.u34 or n12.p56
	if !strings.HasPrefix(key, "n") {
		return 0, false
	}
	i := strings.Index(key, ".")
	if i < 2 {
		return 0, false
	}
	id, err := strconv.ParseInt(key[1:i], 10, 64)
	return id, err == nil
}

func (a *Agent) collectTraffic() {
	for name, c := range a.cores {
		if c.Running() {
			a.collectCore(name)
		}
	}
}

func (a *Agent) collectCore(name string) {
	sc := a.stats[name]
	if sc == nil {
		return
	}
	userStats, err := sc.Query("user>>>", true)
	if err != nil {
		log.Printf("[%s] stats: %v", name, err)
		return
	}
	inbStats, _ := sc.Query("inbound>>>", true)
	a.mu.Lock()
	defer a.mu.Unlock()
	if name == "xray" {
		a.lastCounters = map[string]int64{}
	}
	active := map[trafficKey]bool{}
	for k, v := range userStats {
		p := strings.Split(k, ">>>")
		if len(p) != 4 || p[2] != "traffic" || v == 0 {
			continue
		}
		nodeID, ok := parseKey(p[1])
		if !ok {
			continue
		}
		tk := trafficKey{nodeID, p[1]}
		cur := a.pending[tk]
		if p[3] == "uplink" {
			cur[0] += v
		} else {
			cur[1] += v
		}
		a.pending[tk] = cur
		active[tk] = true
	}
	for k, v := range inbStats {
		p := strings.Split(k, ">>>")
		if len(p) != 4 || !strings.HasPrefix(p[1], "n") || v == 0 {
			continue
		}
		id, err := strconv.ParseInt(p[1][1:], 10, 64)
		if err != nil {
			continue
		}
		cur := a.pendingNode[id]
		if p[3] == "uplink" {
			cur[0] += v
		} else {
			cur[1] += v
		}
		a.pendingNode[id] = cur
	}
	for tk := range active {
		if a.online[tk] == nil {
			a.online[tk] = map[string]bool{}
		}
		if name == "xray" {
			if ips, err := sc.OnlineIPs(tk.key); err == nil {
				for ip := range ips {
					a.online[tk][ip] = true
				}
			}
		}
	}
}

// sampleOnline records the client IPs of Xray users whose counters moved since the last sample.
// Xray only keeps IPs while connections are open, so this runs on every heartbeat, not just at report time.
func (a *Agent) sampleOnline() {
	c := a.cores["xray"]
	sc := a.stats["xray"]
	if c == nil || sc == nil || !c.Running() {
		return
	}
	cur, err := sc.Query("user>>>", false)
	if err != nil {
		return
	}
	totals := map[string]int64{}
	for k, v := range cur {
		if p := strings.Split(k, ">>>"); len(p) == 4 && p[2] == "traffic" {
			totals[p[1]] += v
		}
	}
	a.mu.Lock()
	var moved []string
	for key, v := range totals {
		if v > a.lastCounters[key] {
			moved = append(moved, key)
		}
		a.lastCounters[key] = v
	}
	a.mu.Unlock()
	for _, key := range moved {
		nodeID, ok := parseKey(key)
		if !ok {
			continue
		}
		ips, err := sc.OnlineIPs(key)
		if err != nil || len(ips) == 0 {
			continue
		}
		tk := trafficKey{nodeID, key}
		a.mu.Lock()
		if a.online[tk] == nil {
			a.online[tk] = map[string]bool{}
		}
		for ip := range ips {
			a.online[tk][ip] = true
		}
		a.mu.Unlock()
	}
}

func (a *Agent) report() error {
	a.mu.Lock()
	r := proto.Report{Results: a.results, Unlock: a.unlock}
	for k, v := range a.pending {
		r.Traffic = append(r.Traffic, proto.TrafficDelta{NodeID: k.node, Key: k.key, Up: v[0], Down: v[1]})
	}
	for id, v := range a.pendingNode {
		r.NodeStats = append(r.NodeStats, proto.NodeTraffic{NodeID: id, Up: v[0], Down: v[1]})
	}
	for k, ips := range a.online {
		e := proto.OnlineEntry{NodeID: k.node, Key: k.key}
		for ip := range ips {
			e.IPs = append(e.IPs, ip)
		}
		r.Online = append(r.Online, e)
	}
	a.mu.Unlock()

	if err := a.do("POST", "/agent/v1/report", r, nil); err != nil {
		return err // keep pending, retry next round
	}
	a.mu.Lock()
	// subtract what we sent; anything collected meanwhile stays
	for _, t := range r.Traffic {
		k := trafficKey{t.NodeID, t.Key}
		cur := a.pending[k]
		cur[0] -= t.Up
		cur[1] -= t.Down
		if cur[0] <= 0 && cur[1] <= 0 {
			delete(a.pending, k)
		} else {
			a.pending[k] = cur
		}
	}
	for _, t := range r.NodeStats {
		cur := a.pendingNode[t.NodeID]
		cur[0] -= t.Up
		cur[1] -= t.Down
		if cur[0] <= 0 && cur[1] <= 0 {
			delete(a.pendingNode, t.NodeID)
		} else {
			a.pendingNode[t.NodeID] = cur
		}
	}
	a.online = map[trafficKey]map[string]bool{}
	a.results = a.results[len(r.Results):]
	if r.Unlock != nil && a.unlock == r.Unlock {
		a.unlock = nil
	}
	a.mu.Unlock()
	return nil
}

// ---------------- commands ----------------

func (a *Agent) runCommand(c proto.Command) {
	res := proto.CommandResult{ID: c.ID, OK: true}
	switch c.Type {
	case "restart_core":
		var outs []string
		for name, core := range a.cores {
			if c.Arg != "" && c.Arg != name {
				continue
			}
			if core.Running() || a.appliedFiles[name] != nil {
				a.collectCore(name)
				if err := core.Restart(); err != nil {
					res.OK = false
					outs = append(outs, err.Error())
				} else {
					outs = append(outs, name+" restarted")
				}
			}
		}
		res.Output = strings.Join(outs, "\n")
	case "reload":
		a.applyM.Lock()
		a.appliedVersion = ""
		a.appliedFiles = map[string][]byte{}
		a.applyM.Unlock()
		if err := a.syncConfig(); err != nil {
			res.OK, res.Output = false, err.Error()
		} else {
			res.Output = "config reloaded"
		}
	case "unlock_test":
		items := RunUnlockTests()
		a.mu.Lock()
		a.unlock = &proto.UnlockResult{CheckedAt: time.Now().Unix(), Items: items}
		a.mu.Unlock()
		b, _ := json.Marshal(items)
		res.Output = string(b)
	case "scan_import":
		scan, err := ScanHysteria2Installer()
		if err != nil {
			res.OK, res.Output = false, err.Error()
		} else {
			b, _ := json.Marshal(scan)
			res.Output = string(b)
		}
	case "takeover":
		out, err := TakeoverHysteria2Installer(a.cfg.DataDir)
		if err != nil {
			res.OK, res.Output = false, err.Error()
			break
		}
		a.applyM.Lock()
		a.appliedVersion, a.appliedFiles = "", map[string][]byte{}
		a.applyM.Unlock()
		if err := a.syncConfig(); err != nil {
			res.OK, res.Output = false, out+"\n应用 NodeHub 配置失败: "+err.Error()
		} else {
			res.Output = out + "\nNodeHub 已接管"
		}
	case "rollback_takeover":
		// the master has already disabled the imported node: release its port first
		a.applyM.Lock()
		a.appliedVersion, a.appliedFiles = "", map[string][]byte{}
		a.applyM.Unlock()
		if err := a.syncConfig(); err != nil {
			res.OK, res.Output = false, "释放端口失败: "+err.Error()
			break
		}
		out, err := RollbackHysteria2Installer()
		if err != nil {
			res.OK = false
			out += "\n" + err.Error()
		}
		res.Output = out
	case "install_hy2":
		out, err := InstallHy2(c.Arg)
		if err != nil {
			res.OK, res.Output = false, err.Error()
		} else {
			res.Output = out
		}
	case "uninstall_hy2":
		out, err := UninstallHy2(c.Arg)
		res.Output = out
		if err != nil {
			res.OK = false
			res.Output += "\n" + err.Error()
		}
	case "upgrade_agent":
		if err := a.upgradeSelf(); err != nil {
			res.OK, res.Output = false, err.Error()
		} else {
			res.Output = "upgraded, restarting"
			a.mu.Lock()
			a.results = append(a.results, res)
			a.mu.Unlock()
			_ = a.report()
			log.Printf("agent upgraded, exiting for restart")
			os.Exit(0)
		}
	default:
		res.OK, res.Output = false, "unknown command "+c.Type
	}
	a.mu.Lock()
	a.results = append(a.results, res)
	a.mu.Unlock()
	a.lastReport = time.Time{} // report results soon
}

func (a *Agent) upgradeSelf() error {
	req, _ := http.NewRequest("GET", a.cfg.Master+"/dl/agent?arch="+runtime.GOARCH, nil)
	req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	resp, err := (&http.Client{Timeout: 5 * time.Minute, Transport: a.http.Transport}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download agent: HTTP %d", resp.StatusCode)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tmp := exe + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if want := resp.Header.Get("X-Checksum-Sha256"); want != "" && want != hex.EncodeToString(h.Sum(nil)) {
		os.Remove(tmp)
		return errors.New("checksum mismatch")
	}
	return os.Rename(tmp, exe)
}
