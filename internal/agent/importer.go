package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Importer for nodes created by the hysteria2-installer script (github.com/yys9253462-gif/hysteria2-installer).
// scan reads its config + user database and reports them to the master; takeover stops the script's
// services so NodeHub can serve the same port, password, obfs key and certificate. Nothing in
// /etc/hysteria is deleted, so a rollback can simply start the old services again.

var hy2Dir = "/etc/hysteria" // var for tests

// legacyUnits are the script's units that must stop before NodeHub binds the same port.
var legacyUnits = []string{"hysteria-server.service", "hysteria-portal.service", "hy2-iptables.service",
	"hy2-cert-selfheal.timer", "hy2-cert-selfheal.path", "hy2-cert-selfheal.service"}

type ImportUser struct {
	ID         string `json:"id"`
	Password   string `json:"password"`
	ExpiresAt  int64  `json:"expires_at"`
	LimitBytes int64  `json:"limit_bytes"`
	UsedBytes  int64  `json:"used_bytes"`
	Status     string `json:"status"`
	IPLimit    int    `json:"ip_limit"`
	Note       string `json:"note"`
}

type ImportScan struct {
	Kind         string       `json:"kind"`
	Port         int          `json:"port"`
	Domain       string       `json:"domain"`
	CertMode     string       `json:"cert_mode"` // acme | file | self
	ACMEEmail    string       `json:"acme_email"`
	ACMEDir      string       `json:"acme_dir"`
	CertFile     string       `json:"cert_file"`
	KeyFile      string       `json:"key_file"`
	ObfsPassword string       `json:"obfs_password"`
	UpMbps       int          `json:"up_mbps"`
	DownMbps     int          `json:"down_mbps"`
	HopPorts     string       `json:"hop_ports"`
	Insecure     bool         `json:"insecure"`
	AuthMode     string       `json:"auth_mode"` // http (portal users) | password (single user)
	Users        []ImportUser `json:"users"`
	Version      string       `json:"version"`
	Running      []string     `json:"running"`
	Warnings     []string     `json:"warnings"`
}

var bwRe = regexp.MustCompile(`(?i)^\s*([\d.]+)\s*([kmgt]?)(bps|b)?\s*$`)

// parseMbps converts "1 gbps" / "500 mbps" / "100" into Mbps.
func parseMbps(s string) int {
	m := bwRe.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	switch strings.ToLower(m[2]) {
	case "k":
		v /= 1000
	case "g":
		v *= 1000
	case "t":
		v *= 1000000
	case "":
		if strings.ToLower(m[3]) == "" { // bare number = bytes per second in hysteria
			v = v * 8 / 1e6
		}
	}
	return int(v)
}

func ScanHysteria2Installer() (*ImportScan, error) {
	raw, err := os.ReadFile(filepath.Join(hy2Dir, "config.yaml"))
	if err != nil {
		return nil, errors.New("没有找到 hysteria2-installer 的配置（/etc/hysteria/config.yaml）")
	}
	var c struct {
		Listen string `yaml:"listen"`
		ACME   *struct {
			Domains []string `yaml:"domains"`
			Email   string   `yaml:"email"`
			Dir     string   `yaml:"dir"`
		} `yaml:"acme"`
		TLS *struct {
			Cert string `yaml:"cert"`
			Key  string `yaml:"key"`
		} `yaml:"tls"`
		Auth struct {
			Type     string `yaml:"type"`
			Password string `yaml:"password"`
		} `yaml:"auth"`
		Obfs struct {
			Type       string `yaml:"type"`
			Salamander struct {
				Password string `yaml:"password"`
			} `yaml:"salamander"`
		} `yaml:"obfs"`
		Bandwidth struct {
			Up   string `yaml:"up"`
			Down string `yaml:"down"`
		} `yaml:"bandwidth"`
	}
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("解析 config.yaml 失败: %w", err)
	}
	s := &ImportScan{Kind: "hysteria2-installer", Users: []ImportUser{}, Running: []string{}, Warnings: []string{}}
	if i := strings.LastIndex(c.Listen, ":"); i >= 0 {
		s.Port, _ = strconv.Atoi(c.Listen[i+1:])
	}
	if s.Port == 0 {
		return nil, fmt.Errorf("无法识别监听端口: %q", c.Listen)
	}
	switch {
	case c.ACME != nil && len(c.ACME.Domains) > 0:
		s.CertMode, s.Domain, s.ACMEEmail = "acme", c.ACME.Domains[0], c.ACME.Email
		s.ACMEDir = c.ACME.Dir
		if s.ACMEDir == "" {
			s.ACMEDir = filepath.Join(hy2Dir, "acme") // hysteria default: "acme" under its working directory
		}
		if !strings.HasPrefix(s.ACMEDir, "/") {
			s.ACMEDir = filepath.Join(hy2Dir, s.ACMEDir)
		}
	case c.TLS != nil:
		s.CertMode, s.CertFile, s.KeyFile = "file", c.TLS.Cert, c.TLS.Key
	}
	if c.Obfs.Type == "salamander" {
		s.ObfsPassword = c.Obfs.Salamander.Password
	}
	s.UpMbps, s.DownMbps = parseMbps(c.Bandwidth.Up), parseMbps(c.Bandwidth.Down)

	var meta struct {
		ServerName   string `json:"server_name"`
		HopPortRange string `json:"hop_port_range"`
		IsInsecure   any    `json:"is_insecure"`
		AuthPassword string `json:"auth_password"`
	}
	if b, err := os.ReadFile(filepath.Join(hy2Dir, "client_meta.json")); err == nil {
		_ = json.Unmarshal(b, &meta)
	}
	if s.Domain == "" {
		s.Domain = meta.ServerName
	}
	s.HopPorts = strings.ReplaceAll(meta.HopPortRange, ":", "-")
	s.Insecure = fmt.Sprint(meta.IsInsecure) == "true" || fmt.Sprint(meta.IsInsecure) == "1"
	if s.CertMode == "file" && s.Insecure {
		s.CertMode = "self" // self-signed by the script: clients already skip verification
	}

	s.AuthMode = c.Auth.Type
	if c.Auth.Type == "password" {
		pw := c.Auth.Password
		if pw == "" {
			pw = meta.AuthPassword
		}
		s.Users = append(s.Users, ImportUser{ID: "owner", Password: pw, Status: "active", Note: "single-password mode"})
	} else {
		var portal struct {
			Users map[string]ImportUser `json:"users"`
		}
		b, err := os.ReadFile(filepath.Join(hy2Dir, "portal.json"))
		if err != nil {
			return nil, errors.New("HTTP 认证模式但读不到 portal.json")
		}
		if err := json.Unmarshal(b, &portal); err != nil {
			return nil, fmt.Errorf("解析 portal.json 失败: %w", err)
		}
		for id, u := range portal.Users {
			u.ID = id
			if u.Status == "" {
				u.Status = "active"
			}
			s.Users = append(s.Users, u)
		}
	}
	if out, err := exec.Command("/usr/local/bin/hysteria", "version").Output(); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(l, "Version:") {
				s.Version = strings.TrimSpace(strings.TrimPrefix(l, "Version:"))
			}
		}
	}
	for _, u := range append(legacyUnits, "xray.service", "gost.service", "wireproxy.service", "amneziawg-server.service") {
		if exec.Command("systemctl", "is-active", "--quiet", u).Run() == nil {
			s.Running = append(s.Running, u)
		}
	}
	for _, u := range []string{"xray.service", "gost.service", "amneziawg-server.service"} {
		for _, r := range s.Running {
			if r == u {
				s.Warnings = append(s.Warnings, u+" 也在运行，导入只接管 Hysteria2，它会保持原样")
			}
		}
	}
	if s.CertMode == "acme" {
		if _, err := os.Stat(s.ACMEDir); err != nil {
			s.Warnings = append(s.Warnings, "没找到原 ACME 证书目录，接管后会重新申请证书（需要 80 端口可访问）")
		}
	}
	return s, nil
}

// TakeoverHysteria2Installer stops the script's services, removes its port-hopping rules and copies its
// ACME data into dataDir/acme so the existing certificate keeps being used and renewed.
func TakeoverHysteria2Installer(dataDir string) (string, error) {
	scan, err := ScanHysteria2Installer()
	if err != nil {
		return "", err
	}
	var log []string
	if scan.CertMode == "acme" {
		if _, err := os.Stat(scan.ACMEDir); err == nil {
			dst := filepath.Join(dataDir, "acme")
			_ = os.MkdirAll(dst, 0o700)
			if out, err := exec.Command("cp", "-a", scan.ACMEDir+"/.", dst+"/").CombinedOutput(); err != nil {
				return "", fmt.Errorf("复制 ACME 证书失败: %v %s", err, out)
			}
			log = append(log, "已复制原 ACME 证书与账户到 "+dst)
		}
	}
	for _, u := range legacyUnits {
		if exec.Command("systemctl", "cat", u).Run() == nil {
			_ = exec.Command("systemctl", "disable", "--now", u).Run()
			log = append(log, "已停用 "+u)
		}
	}
	// remove the script's REDIRECT rules for this port (NodeHub manages hopping in its own chain)
	for _, bin := range []string{"iptables", "ip6tables"} {
		out, err := exec.Command(bin, "-t", "nat", "-S").Output()
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(out), "\n") {
			if (strings.HasPrefix(l, "-A PREROUTING ") || strings.HasPrefix(l, "-A OUTPUT ")) &&
				strings.Contains(l, "REDIRECT") && strings.Contains(l, "--to-ports "+strconv.Itoa(scan.Port)) {
				args := append([]string{"-t", "nat", "-D"}, strings.Fields(strings.TrimPrefix(l, "-A "))...)
				if err := exec.Command(bin, args...).Run(); err == nil {
					log = append(log, bin+" 删除旧规则: "+strings.TrimPrefix(l, "-A "))
				}
			}
		}
	}
	return strings.Join(log, "\n"), nil
}

// RollbackHysteria2Installer re-enables the script's services (after NodeHub released the port).
func RollbackHysteria2Installer() (string, error) {
	var log []string
	for _, u := range []string{"hy2-iptables.service", "hysteria-portal.service", "hysteria-server.service", "hy2-cert-selfheal.timer", "hy2-cert-selfheal.path"} {
		if exec.Command("systemctl", "cat", u).Run() == nil {
			if out, err := exec.Command("systemctl", "enable", "--now", u).CombinedOutput(); err != nil {
				return strings.Join(log, "\n"), fmt.Errorf("启动 %s 失败: %v %s", u, err, out)
			}
			log = append(log, "已恢复 "+u)
		}
	}
	return strings.Join(log, "\n"), nil
}
