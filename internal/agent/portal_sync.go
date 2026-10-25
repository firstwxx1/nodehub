package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Per-user sync into the hysteria2-installer portal: every NodeHub user becomes a portal user ("nh-<id>") with
// their own password, expiry, traffic cap and device limit, so the script itself authenticates and cuts off
// each customer. Users with the prefix that NodeHub no longer wants are deleted. The agent reports each synced
// user's byte counter so the master can add the growth to the NodeHub user.

type PortalUser struct {
	ID        string  `json:"id"`
	Password  string  `json:"password"`
	ExpiresAt int64   `json:"expires_at"` // unix; 0 = never
	TrafficGB float64 `json:"traffic_gb"` // 0 = unlimited
	IPLimit   int     `json:"ip_limit"`   // 0 = unlimited
}

type PortalSyncReq struct {
	Prefix string       `json:"prefix"`
	Users  []PortalUser `json:"users"`
}

type PortalUsage struct {
	ID   string `json:"id"`
	Used int64  `json:"used"`
}

type PortalSyncResult struct {
	Created int           `json:"created"`
	Updated int           `json:"updated"`
	Deleted int           `json:"deleted"`
	Usage   []PortalUsage `json:"usage"`
	Errors  []string      `json:"errors,omitempty"`
}

type portalAPI struct {
	base, key string
	hc        *http.Client
}

func newPortalAPI() (*portalAPI, error) {
	var acc struct {
		APIKey string `json:"api_key"`
	}
	b, err := os.ReadFile(filepath.Join(hy2Dir, "portal-access.json"))
	if err != nil {
		return nil, errors.New("没有原版脚本的门户（portal-access.json）")
	}
	if json.Unmarshal(b, &acc) != nil || acc.APIKey == "" {
		return nil, errors.New("portal-access.json 里没有 api_key")
	}
	var pj struct {
		Port int `json:"port"`
	}
	b, err = os.ReadFile(filepath.Join(hy2Dir, "portal.json"))
	if err != nil || json.Unmarshal(b, &pj) != nil || pj.Port == 0 {
		return nil, errors.New("portal.json 无法读取")
	}
	return &portalAPI{base: fmt.Sprintf("http://127.0.0.1:%d/api/v1/", pj.Port), key: acc.APIKey,
		hc: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (p *portalAPI) do(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, p.base+path, rd)
	req.Header.Set("Authorization", "Bearer "+p.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var env struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(b, &env)
	if resp.StatusCode != 200 || !env.OK {
		msg := env.Error
		if msg == "" {
			msg = strings.TrimSpace(string(b))
			if len(msg) > 200 {
				msg = msg[:200]
			}
		}
		return fmt.Errorf("portal %s: HTTP %d %s", path, resp.StatusCode, msg)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// portalState remembers what was last pushed for each user (a hash), because users/list never returns passwords.
func portalStatePath(dataDir string) string { return filepath.Join(dataDir, "portal-sync.json") }

func userHash(u PortalUser) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%g|%d", u.Password, u.ExpiresAt, u.TrafficGB, u.IPLimit)))
	return hex.EncodeToString(h[:8])
}

// SyncPortalUsers reconciles the portal's prefix users with the desired list.
func SyncPortalUsers(arg, dataDir string) (string, error) {
	var req PortalSyncReq
	if err := json.Unmarshal([]byte(arg), &req); err != nil {
		return "", fmt.Errorf("参数错误: %w", err)
	}
	if !strings.HasPrefix(req.Prefix, "nh") || len(req.Prefix) < 3 {
		return "", errors.New("prefix 必须以 nh 开头")
	}
	api, err := newPortalAPI()
	if err != nil {
		return "", err
	}
	var list struct {
		Users []struct {
			UserID  string `json:"user_id"`
			Status  string `json:"status"`
			Used    int64  `json:"traffic_used_bytes"`
			Expires int64  `json:"expires_at"`
		} `json:"users"`
	}
	if err := api.do("GET", "users/list", nil, &list); err != nil {
		return "", err
	}
	have := map[string]bool{}
	status := map[string]string{}
	res := PortalSyncResult{Usage: []PortalUsage{}}
	for _, u := range list.Users {
		if strings.HasPrefix(u.UserID, req.Prefix) {
			have[u.UserID] = true
			status[u.UserID] = u.Status
			res.Usage = append(res.Usage, PortalUsage{ID: u.UserID, Used: u.Used})
		}
	}
	state := map[string]string{}
	if b, err := os.ReadFile(portalStatePath(dataDir)); err == nil {
		_ = json.Unmarshal(b, &state)
	}
	want := map[string]bool{}
	far := time.Now().AddDate(20, 0, 0).Unix()
	for _, u := range req.Users {
		if !strings.HasPrefix(u.ID, req.Prefix) || u.Password == "" {
			continue
		}
		want[u.ID] = true
		h := userHash(u)
		if have[u.ID] && state[u.ID] == h && status[u.ID] != "disabled" {
			continue
		}
		exp := u.ExpiresAt
		if exp <= 0 {
			exp = far
		}
		body := map[string]any{"user_id": u.ID, "password": u.Password, "expires_at": exp, "traffic_gb": u.TrafficGB,
			"ip_limit": u.IPLimit, "note": "NodeHub"}
		if err := api.do("POST", "users/create", body, nil); err != nil {
			res.Errors = append(res.Errors, u.ID+": "+err.Error())
			continue
		}
		if status[u.ID] == "disabled" { // users/create keeps the old status: switch it back on
			if err := api.do("POST", "users/update", map[string]any{"user_id": u.ID, "status": "active"}, nil); err != nil {
				res.Errors = append(res.Errors, u.ID+": "+err.Error())
			}
		}
		if have[u.ID] {
			res.Updated++
		} else {
			res.Created++
		}
		state[u.ID] = h
	}
	for id := range have {
		if want[id] {
			continue
		}
		if err := api.do("POST", "users/delete", map[string]any{"user_id": id}, nil); err != nil {
			res.Errors = append(res.Errors, id+": "+err.Error())
			continue
		}
		delete(state, id)
		res.Deleted++
	}
	if b, err := json.Marshal(state); err == nil {
		_ = os.WriteFile(portalStatePath(dataDir), b, 0o600)
	}
	b, _ := json.Marshal(res)
	if len(res.Errors) > 0 && res.Created+res.Updated+res.Deleted == 0 && len(req.Users) > 0 {
		return string(b), fmt.Errorf("同步失败: %s", strings.Join(res.Errors, "; "))
	}
	return string(b), nil
}
