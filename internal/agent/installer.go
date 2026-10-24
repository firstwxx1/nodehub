package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultInstallerURL is the hysteria2-installer script used to create "script nodes".
const DefaultInstallerURL = "https://raw.githubusercontent.com/firstwxx1/hysteria2-installer/main/install.sh"

// InstallReq is the argument of the "install_hy2" command.
type InstallReq struct {
	URL      string `json:"url"`
	Port     int    `json:"port"`
	CertType int    `json:"cert_type"` // 1 self-signed, 3 ACME for Domain
	Domain   string `json:"domain"`
	Email    string `json:"email"`
	CFToken  string `json:"cf_token"`
	CFEmail  string `json:"cf_email"`
	Name     string `json:"name,omitempty"`   // used by the master only
	Groups   string `json:"groups,omitempty"` // used by the master only
}

// InstallResult is returned (as JSON) by install_hy2.
type InstallResult struct {
	Scan *ImportScan `json:"scan"`
	Log  string      `json:"log"`
}

var (
	ansiRe   = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	domainRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
)

func tailLog(b []byte, n int) string {
	s := strings.TrimSpace(ansiRe.ReplaceAllString(strings.ReplaceAll(string(b), "\r", "\n"), ""))
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}

func fetchInstaller(url string) (string, error) {
	cl := &http.Client{Timeout: 90 * time.Second}
	resp, err := cl.Get(url)
	if err != nil {
		return "", fmt.Errorf("下载安装脚本失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("下载安装脚本失败: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(string(b), "#!") || !strings.Contains(string(b), "hysteria") {
		return "", errors.New("下载到的内容不像 hysteria2 安装脚本")
	}
	f, err := os.CreateTemp("", "nodehub-hy2-*.sh")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// runInstaller executes `bash install.sh <sub>` non-interactively and returns its output.
func runInstaller(script, sub string, env []string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", script, sub)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return out, fmt.Errorf("脚本运行超过 %v 被终止", timeout)
	}
	return out, err
}

// InstallHy2 runs the hysteria2-installer script unattended and reports what it set up.
func InstallHy2(arg string) (string, error) {
	var req InstallReq
	if err := json.Unmarshal([]byte(arg), &req); err != nil {
		return "", fmt.Errorf("参数错误: %w", err)
	}
	if req.URL == "" {
		req.URL = DefaultInstallerURL
	}
	if !strings.HasPrefix(req.URL, "https://") {
		return "", errors.New("安装脚本地址必须是 https")
	}
	if req.Port < 1 || req.Port > 65535 {
		return "", errors.New("端口不合法")
	}
	if req.CertType != 1 && req.CertType != 3 {
		return "", errors.New("证书方式只支持 自签名(1) 或 域名 ACME(3)")
	}
	if req.CertType == 3 && !domainRe.MatchString(req.Domain) {
		return "", errors.New("ACME 需要有效的域名")
	}
	if _, err := os.Stat(hy2Dir + "/config.yaml"); err == nil {
		return "", errors.New("这台服务器上已经安装了 hysteria2-installer（/etc/hysteria/config.yaml 已存在），请在服务器菜单里用「接入原版脚本节点」把它收进面板；如要按新参数重装，先删除/卸载旧的")
	}
	script, err := fetchInstaller(req.URL)
	if err != nil {
		return "", err
	}
	defer os.Remove(script)

	env := []string{"HY2_NODE_MODE=2", "HY2_PORT=" + strconv.Itoa(req.Port), "HY2_CERT_TYPE=" + strconv.Itoa(req.CertType),
		"DEBIAN_FRONTEND=noninteractive"}
	if req.CertType == 3 {
		env = append(env, "HY2_DOMAIN="+req.Domain)
		if req.Email != "" {
			env = append(env, "HY2_EMAIL="+req.Email)
		}
	}
	pre := ""
	// With a Cloudflare token the certificate is issued by DNS-01 first (acme.sh), so it works even when TCP 80/443
	// are taken by nginx & co.; the script then reuses that certificate. Without a token, or if it fails, the
	// script's own ACME (HTTP-01) runs as before.
	if req.CertType == 3 && req.CFToken != "" {
		cert, key, l, err := issueCertDNS(req.Domain, req.Email, req.CFToken)
		pre = l
		if err == nil {
			env = append(env, "HY2_CUSTOM_CERT_FILE="+cert, "HY2_CUSTOM_KEY_FILE="+key, "HY2_CUSTOM_INSECURE=false")
		} else {
			pre += "\nDNS 验证签发失败，改用脚本自带的 HTTP 验证: " + err.Error()
		}
	}
	out, runErr := runInstaller(script, "install", env, 20*time.Minute)
	log := tailLog(append([]byte(pre+"\n"), out...), 3500)
	if runErr != nil {
		return "", fmt.Errorf("安装脚本失败: %v\n%s", runErr, log)
	}
	if exec.Command("systemctl", "is-active", "--quiet", "hysteria-server.service").Run() != nil {
		return "", fmt.Errorf("脚本执行完了，但 hysteria-server 没有在运行\n%s", log)
	}
	scan, err := ScanHysteria2Installer()
	if err != nil {
		return "", fmt.Errorf("安装完成但读取结果失败: %v\n%s", err, log)
	}
	b, _ := json.Marshal(InstallResult{Scan: scan, Log: log})
	return string(b), nil
}

// UninstallHy2 runs `install.sh uninstall` (with every confirmation answered yes).
func UninstallHy2(url string) (string, error) {
	if url == "" {
		url = DefaultInstallerURL
	}
	script, err := fetchInstaller(url)
	if err != nil {
		return "", err
	}
	defer os.Remove(script)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", "printf 'y\\nn\\n' | bash "+script+" uninstall")
	cmd.Env = append(os.Environ(), "HY2_NODE_MODE=2")
	out, err := cmd.CombinedOutput()
	log := tailLog(out, 2000)
	if err != nil {
		return log, fmt.Errorf("卸载脚本失败: %v", err)
	}
	return log, nil
}

// issueCertDNS gets a Let's Encrypt certificate for domain through Cloudflare DNS-01 with acme.sh and installs it
// to /etc/hy2-cert (acme.sh renews it by cron and restarts hysteria-server afterwards).
func issueCertDNS(domain, email, cfToken string) (cert, key, log string, err error) {
	acme := "/root/.acme.sh/acme.sh"
	var buf strings.Builder
	run := func(timeout time.Duration, env []string, name string, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		c := exec.CommandContext(ctx, name, args...)
		c.Env = append(os.Environ(), env...)
		out, err := c.CombinedOutput()
		buf.WriteString(tailLog(out, 600) + "\n")
		return err
	}
	if _, e := os.Stat(acme); e != nil {
		if email == "" {
			email = "admin@" + domain
		}
		if e := run(3*time.Minute, nil, "sh", "-c", "curl -fsSL https://get.acme.sh | sh -s email="+email); e != nil {
			return "", "", buf.String(), fmt.Errorf("安装 acme.sh 失败: %v", e)
		}
	}
	env := []string{"CF_Token=" + cfToken, "HOME=/root"}
	// exit code 2 = cert exists and is not due for renewal: fine
	if e := run(5*time.Minute, env, acme, "--issue", "--dns", "dns_cf", "-d", domain, "--server", "letsencrypt", "--keylength", "ec-256"); e != nil {
		if ee, ok := e.(*exec.ExitError); !ok || ee.ExitCode() != 2 {
			return "", "", buf.String(), fmt.Errorf("acme.sh 签发失败: %v", e)
		}
	}
	if e := os.MkdirAll("/etc/hy2-cert", 0o700); e != nil {
		return "", "", buf.String(), e
	}
	cert, key = "/etc/hy2-cert/fullchain.pem", "/etc/hy2-cert/privkey.pem"
	if e := run(time.Minute, env, acme, "--install-cert", "-d", domain, "--ecc", "--fullchain-file", cert, "--key-file", key,
		"--reloadcmd", "systemctl restart hysteria-server 2>/dev/null || true"); e != nil {
		return "", "", buf.String(), fmt.Errorf("安装证书失败: %v", e)
	}
	return cert, key, "已通过 Cloudflare DNS 验证签发证书 " + domain, nil
}
