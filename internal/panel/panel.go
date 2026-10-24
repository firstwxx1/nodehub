// Package panel lets NodeHub act as the node backend for existing shop panels
// (Xboard / V2Board UniProxy API and SSPanel-UIM mod_mu API).
package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodehub/internal/proto"
	"nodehub/internal/store"
	"nodehub/internal/util"
)

// RemoteConfig is the node definition reported by the panel (used when panel_sync_config is on).
type RemoteConfig struct {
	Port     int
	Protocol string
	Settings proto.NodeSettings
}

type Client interface {
	FetchUsers(ctx context.Context, n *store.Node) (users []store.PanelUser, notModified bool, err error)
	FetchConfig(ctx context.Context, n *store.Node) (*RemoteConfig, error)
	PushTraffic(ctx context.Context, n *store.Node, items []store.PendingTraffic) error
	PushAlive(ctx context.Context, n *store.Node, alive map[int64][]string) error
	PushStatus(ctx context.Context, n *store.Node, st Status) error
}

type Status struct {
	CPU      float64
	MemTotal uint64
	MemUsed  uint64
	Disk     uint64
	DiskUsed uint64
	Uptime   uint64
	Load     [3]float64
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

func New(p *store.Panel) (Client, error) {
	switch p.Type {
	case "xboard", "v2board":
		return &xboard{p: p}, nil
	case "sspanel":
		return &sspanel{p: p}, nil
	}
	return nil, fmt.Errorf("unknown panel type %q", p.Type)
}

// DefaultNodeType maps our protocol name to the panel's node_type.
func DefaultNodeType(panelType, protocol string) string {
	if panelType == "sspanel" {
		return ""
	}
	switch protocol {
	case "hysteria2":
		return "hysteria"
	}
	return protocol
}

func doJSON(ctx context.Context, method, u string, body any, hdr map[string]string, out any) (int, http.Header, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "NodeHub/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode == http.StatusNotModified {
		return resp.StatusCode, resp.Header, nil
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, resp.Header, fmt.Errorf("HTTP %d: %s", resp.StatusCode, trunc(string(b), 200))
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.StatusCode, resp.Header, fmt.Errorf("decode response: %w (%s)", err, trunc(string(b), 120))
		}
	}
	return resp.StatusCode, resp.Header, nil
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ======================= Xboard / V2Board =======================

type xboard struct {
	p     *store.Panel
	mu    sync.Mutex
	etags map[int64]string
}

func (x *xboard) url(path string, n *store.Node) string {
	q := url.Values{}
	q.Set("token", x.p.Token)
	q.Set("node_id", strconv.FormatInt(n.PanelNodeID, 10))
	nt := n.PanelNodeType
	if nt == "" {
		nt = DefaultNodeType(x.p.Type, n.Protocol)
	}
	q.Set("node_type", nt)
	return x.p.BaseURL + "/api/v1/server/UniProxy/" + path + "?" + q.Encode()
}

func (x *xboard) FetchUsers(ctx context.Context, n *store.Node) ([]store.PanelUser, bool, error) {
	var r struct {
		Users []struct {
			ID          int64  `json:"id"`
			UUID        string `json:"uuid"`
			SpeedLimit  *int   `json:"speed_limit"`
			DeviceLimit *int   `json:"device_limit"`
		} `json:"users"`
	}
	hdr := map[string]string{}
	x.mu.Lock()
	if x.etags == nil {
		x.etags = map[int64]string{}
	}
	if e := x.etags[n.ID]; e != "" {
		hdr["If-None-Match"] = e
	}
	x.mu.Unlock()
	code, h, err := doJSON(ctx, "GET", x.url("user", n), nil, hdr, &r)
	if err != nil {
		return nil, false, err
	}
	if code == http.StatusNotModified {
		return nil, true, nil
	}
	x.mu.Lock()
	x.etags[n.ID] = h.Get("ETag")
	x.mu.Unlock()
	out := make([]store.PanelUser, 0, len(r.Users))
	for _, u := range r.Users {
		pu := store.PanelUser{RemoteID: u.ID, UUID: u.UUID, Password: u.UUID}
		if u.SpeedLimit != nil {
			pu.SpeedLimit = *u.SpeedLimit
		}
		if u.DeviceLimit != nil {
			pu.DeviceLimit = *u.DeviceLimit
		}
		out = append(out, pu)
	}
	return out, false, nil
}

// ResetETag forces a full user fetch next time (used after the local user table is cleared).
func ResetETag(c Client, nodeID int64) {
	if x, ok := c.(*xboard); ok {
		x.mu.Lock()
		delete(x.etags, nodeID)
		x.mu.Unlock()
	}
}

func (x *xboard) FetchConfig(ctx context.Context, n *store.Node) (*RemoteConfig, error) {
	var r map[string]any
	if _, _, err := doJSON(ctx, "GET", x.url("config", n), nil, nil, &r); err != nil {
		return nil, err
	}
	return parseXboardConfig(n, r)
}

func num(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		i, _ := strconv.Atoi(t)
		return i
	}
	return 0
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return ""
}

func obj(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func parseXboardConfig(n *store.Node, r map[string]any) (*RemoteConfig, error) {
	rc := &RemoteConfig{Protocol: n.Protocol, Settings: n.Settings}
	rc.Port = num(r["server_port"])
	if rc.Port == 0 {
		return nil, errors.New("panel config has no server_port")
	}
	s := &rc.Settings
	nt := n.PanelNodeType
	if nt == "" {
		nt = DefaultNodeType("xboard", n.Protocol)
	}
	netSettings := obj(r["networkSettings"])
	if len(netSettings) == 0 {
		netSettings = obj(r["network_settings"])
	}
	applyNetwork := func() {
		if nw := str(r["network"]); nw != "" {
			s.Network = nw
		}
		s.Path = str(netSettings["path"])
		s.Host = str(obj(netSettings["headers"])["Host"])
		if s.Host == "" {
			s.Host = str(netSettings["host"])
		}
		s.ServiceName = str(netSettings["serviceName"])
	}
	tlsSettings := obj(r["tls_settings"])
	switch nt {
	case "vless":
		rc.Protocol = "vless"
		applyNetwork()
		s.Flow = str(r["flow"])
		switch num(r["tls"]) {
		case 2:
			s.Security = "reality"
			s.RealityServerName = str(tlsSettings["server_name"])
			dport := str(tlsSettings["server_port"])
			if dport == "" {
				dport = "443"
			}
			if s.RealityServerName != "" {
				s.RealityDest = s.RealityServerName + ":" + dport
			}
			s.RealityPrivateKey = str(tlsSettings["private_key"])
			s.RealityPublicKey = str(tlsSettings["public_key"])
			if s.RealityPublicKey == "" && s.RealityPrivateKey != "" {
				s.RealityPublicKey, _ = util.RealityPublicKey(s.RealityPrivateKey)
			}
			s.RealityShortID = str(tlsSettings["short_id"])
		case 1:
			s.Security = "tls"
			s.SNI = str(tlsSettings["server_name"])
		default:
			s.Security = "none"
		}
	case "vmess":
		rc.Protocol = "vmess"
		applyNetwork()
		if num(r["tls"]) == 1 {
			s.Security = "tls"
			if sn := str(obj(r["tlsSettings"])["serverName"]); sn != "" {
				s.SNI = sn
			}
		} else {
			s.Security = "none"
		}
	case "trojan":
		rc.Protocol = "trojan"
		applyNetwork()
		s.Security = "tls"
		if sn := str(r["server_name"]); sn != "" {
			s.SNI = sn
		}
	case "shadowsocks":
		rc.Protocol = "shadowsocks"
		s.Cipher = str(r["cipher"])
		s.ServerKey = str(r["server_key"])
	case "hysteria", "hysteria2":
		rc.Protocol = "hysteria2"
		s.UpMbps = num(r["up_mbps"])
		s.DownMbps = num(r["down_mbps"])
		if sn := str(r["server_name"]); sn != "" {
			s.SNI = sn
		}
		if o := str(r["obfs"]); o != "" {
			s.Obfs = "salamander"
			s.ObfsPassword = str(r["obfs-password"])
			if s.ObfsPassword == "" {
				s.ObfsPassword = str(r["obfs_password"])
			}
			if s.ObfsPassword == "" {
				s.ObfsPassword = o
			}
		}
	case "tuic":
		rc.Protocol = "tuic"
		if sn := str(r["server_name"]); sn != "" {
			s.SNI = sn
		}
		if cc := str(r["congestion_control"]); cc != "" {
			s.Congestion = cc
		}
	case "anytls":
		rc.Protocol = "anytls"
		if sn := str(r["server_name"]); sn != "" {
			s.SNI = sn
		}
	}
	return rc, nil
}

func (x *xboard) PushTraffic(ctx context.Context, n *store.Node, items []store.PendingTraffic) error {
	body := map[string][2]int64{}
	for _, it := range items {
		body[strconv.FormatInt(it.RemoteID, 10)] = [2]int64{it.Up, it.Down}
	}
	_, _, err := doJSON(ctx, "POST", x.url("push", n), body, nil, nil)
	return err
}

func (x *xboard) PushAlive(ctx context.Context, n *store.Node, alive map[int64][]string) error {
	body := map[string][]string{}
	for uid, ips := range alive {
		var tagged []string
		for _, ip := range ips {
			tagged = append(tagged, ip+"_"+strconv.FormatInt(n.PanelNodeID, 10))
		}
		body[strconv.FormatInt(uid, 10)] = tagged
	}
	_, _, err := doJSON(ctx, "POST", x.url("alive", n), body, nil, nil)
	return err
}

// PushStatus uses Xboard's node status endpoint when available; V2Board has none, so errors are ignored by callers.
func (x *xboard) PushStatus(ctx context.Context, n *store.Node, st Status) error {
	if x.p.Type != "xboard" {
		return nil
	}
	body := map[string]any{
		"cpu":    st.CPU,
		"mem":    map[string]any{"total": st.MemTotal, "used": st.MemUsed},
		"swap":   map[string]any{"total": 0, "used": 0},
		"disk":   map[string]any{"total": st.Disk, "used": st.DiskUsed},
		"uptime": st.Uptime,
	}
	_, _, err := doJSON(ctx, "POST", x.url("status", n), body, nil, nil)
	return err
}

// ======================= SSPanel-UIM =======================

type sspanel struct{ p *store.Panel }

func (s *sspanel) url(path string, n *store.Node) string {
	q := url.Values{}
	q.Set("key", s.p.Token)
	q.Set("node_id", strconv.FormatInt(n.PanelNodeID, 10))
	return s.p.BaseURL + "/mod_mu/" + path + "?" + q.Encode()
}

type ssResp struct {
	Ret  int             `json:"ret"`
	Data json.RawMessage `json:"data"`
	Msg  string          `json:"msg"`
}

func (s *sspanel) FetchUsers(ctx context.Context, n *store.Node) ([]store.PanelUser, bool, error) {
	var r ssResp
	if _, _, err := doJSON(ctx, "GET", s.url("users", n), nil, nil, &r); err != nil {
		return nil, false, err
	}
	if r.Ret != 1 {
		return nil, false, fmt.Errorf("sspanel: %s", r.Msg)
	}
	var users []map[string]any
	if err := json.Unmarshal(r.Data, &users); err != nil {
		return nil, false, err
	}
	out := make([]store.PanelUser, 0, len(users))
	for _, u := range users {
		id := int64(num(u["id"]))
		uuid := str(u["uuid"])
		pw := str(u["passwd"])
		if pw == "" {
			pw = uuid
		}
		pu := store.PanelUser{RemoteID: id, UUID: uuid, Password: pw,
			SpeedLimit: num(u["node_speedlimit"]), DeviceLimit: num(u["node_iplimit"])}
		if n.Protocol == "shadowsocks" && util.SSKeyLen(n.Settings.Cipher) > 0 {
			pu.Password = util.SSUserKey(n.Settings.Cipher, uuid)
		}
		out = append(out, pu)
	}
	return out, false, nil
}

func (s *sspanel) FetchConfig(ctx context.Context, n *store.Node) (*RemoteConfig, error) {
	return nil, errors.New("SSPanel 不提供结构化节点配置，请在 NodeHub 中手动配置协议参数")
}

func (s *sspanel) PushTraffic(ctx context.Context, n *store.Node, items []store.PendingTraffic) error {
	var data []map[string]int64
	for _, it := range items {
		data = append(data, map[string]int64{"user_id": it.RemoteID, "u": it.Up, "d": it.Down})
	}
	var r ssResp
	if _, _, err := doJSON(ctx, "POST", s.url("users/traffic", n), map[string]any{"data": data}, nil, &r); err != nil {
		return err
	}
	if r.Ret != 1 {
		return fmt.Errorf("sspanel: %s", r.Msg)
	}
	return nil
}

func (s *sspanel) PushAlive(ctx context.Context, n *store.Node, alive map[int64][]string) error {
	var data []map[string]any
	for uid, ips := range alive {
		for _, ip := range ips {
			data = append(data, map[string]any{"ip": ip, "user_id": uid})
		}
	}
	_, _, err := doJSON(ctx, "POST", s.url("users/aliveip", n), map[string]any{"data": data}, nil, nil)
	return err
}

func (s *sspanel) PushStatus(ctx context.Context, n *store.Node, st Status) error {
	u := s.p.BaseURL + "/mod_mu/nodes/" + strconv.FormatInt(n.PanelNodeID, 10) + "/info?key=" + url.QueryEscape(s.p.Token)
	load := strings.TrimSpace(fmt.Sprintf("%.2f %.2f %.2f", st.Load[0], st.Load[1], st.Load[2]))
	_, _, err := doJSON(ctx, "POST", u, map[string]any{"uptime": st.Uptime, "load": load}, nil, nil)
	return err
}
