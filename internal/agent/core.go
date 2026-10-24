package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Core supervises one proxy core process (xray or sing-box).
type Core struct {
	Name       string // xray | singbox
	Bin        string
	ConfigPath string
	LogPath    string

	mu       sync.Mutex
	cmd      *exec.Cmd
	want     bool
	exited   chan struct{}
	lastErr  string
	restarts int
}

func (c *Core) args() []string {
	if c.Name == "xray" {
		return []string{"run", "-c", c.ConfigPath}
	}
	return []string{"run", "-c", c.ConfigPath}
}

// Test validates a config file without starting the core.
func (c *Core) Test(path string) error {
	var cmd *exec.Cmd
	if c.Name == "xray" {
		cmd = exec.Command(c.Bin, "run", "-test", "-c", path)
	} else {
		cmd = exec.Command(c.Bin, "check", "-c", path)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s 配置校验失败: %s", c.Name, tail(string(out), 600))
	}
	return nil
}

func (c *Core) Version() string {
	if c.Bin == "" {
		return ""
	}
	if _, err := os.Stat(c.Bin); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, c.Bin, "version").Output()
	if err != nil {
		return ""
	}
	line := strings.SplitN(string(out), "\n", 2)[0]
	f := strings.Fields(line) // "Xray 25.10.15 (...)" or "sing-box version 1.12.12"
	for _, w := range f[1:] {
		if w != "version" {
			return w
		}
	}
	return strings.TrimSpace(line)
}

func (c *Core) Installed() bool {
	_, err := os.Stat(c.Bin)
	return c.Bin != "" && err == nil
}

func (c *Core) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cmd != nil
}

func (c *Core) LastError() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastErr
}

// Start launches the core and keeps it running until Stop is called.
func (c *Core) Start() error {
	c.mu.Lock()
	c.want = true
	c.mu.Unlock()
	return c.spawn()
}

func (c *Core) spawn() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd != nil {
		return nil
	}
	var logw io.Writer = io.Discard
	if c.LogPath != "" {
		if f, err := os.OpenFile(c.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			logw = f
		}
	}
	errBuf := &ringBuffer{max: 4096}
	cmd := exec.Command(c.Bin, c.args()...)
	cmd.Stdout = io.MultiWriter(logw, errBuf)
	cmd.Stderr = io.MultiWriter(logw, errBuf)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+dirOf(c.Bin), "ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true")
	if err := cmd.Start(); err != nil {
		c.lastErr = err.Error()
		return err
	}
	c.cmd = cmd
	exited := make(chan struct{})
	c.exited = exited
	started := time.Now()
	go func() {
		err := cmd.Wait()
		if f, ok := logw.(*os.File); ok {
			f.Close()
		}
		c.mu.Lock()
		c.cmd = nil
		want := c.want
		if err != nil || want {
			c.lastErr = fmt.Sprintf("%s 退出: %v %s", c.Name, err, tail(errBuf.String(), 400))
		}
		c.mu.Unlock()
		close(exited)
		if want {
			c.restarts++
			wait := time.Second
			if time.Since(started) < 10*time.Second {
				wait = 5 * time.Second // crash loop protection
			}
			log.Printf("[%s] exited unexpectedly (%v), restarting in %s", c.Name, err, wait)
			time.Sleep(wait)
			c.mu.Lock()
			stillWant := c.want
			c.mu.Unlock()
			if stillWant {
				_ = c.spawn()
			}
		}
	}()
	return nil
}

func (c *Core) Stop() {
	c.mu.Lock()
	c.want = false
	cmd, exited := c.cmd, c.exited
	c.mu.Unlock()
	if cmd == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-exited
	}
}

func (c *Core) Restart() error {
	c.Stop()
	c.mu.Lock()
	c.lastErr = ""
	c.mu.Unlock()
	if err := c.Start(); err != nil {
		return err
	}
	// a broken config makes the core exit right away; surface that as an error
	time.Sleep(1500 * time.Millisecond)
	if !c.Running() {
		return fmt.Errorf("%s 启动失败: %s", c.Name, c.LastError())
	}
	return nil
}

func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i > 0 {
		return p[:i]
	}
	return "."
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

type ringBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (r *ringBuffer) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf.Write(p)
	if r.buf.Len() > r.max {
		b := r.buf.Bytes()
		keep := append([]byte(nil), b[len(b)-r.max:]...)
		r.buf.Reset()
		r.buf.Write(keep)
	}
	return len(p), nil
}

func (r *ringBuffer) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}
