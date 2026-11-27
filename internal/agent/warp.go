package agent

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
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

// WARPCred holds cached Cloudflare WARP WireGuard credentials registered locally on the VPS.
type WARPCred struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	PeerPubKey string `json:"peer_public_key"`
	Endpoint   string `json:"endpoint"` // e.g. "162.159.192.1:2408"
	AddressV4  string `json:"address_v4"`
	AddressV6  string `json:"address_v6"`
	Reserved   []int  `json:"reserved"`
	ClientID   string `json:"client_id"`
}

var warpRegURL = "https://api.cloudflareclient.com/v0a2158/reg"

const defaultWARPEndpoint = "162.159.192.1:2408"

// EnsureWARPCred loads cached WARP credentials from path, or registers a fresh free WARP device
// with Cloudflare using pure-Go X25519 keys (no external wgcf binary needed) and caches them.
func EnsureWARPCred(path string) (*WARPCred, error) {
	if b, err := os.ReadFile(path); err == nil {
		var c WARPCred
		if json.Unmarshal(b, &c) == nil && c.PrivateKey != "" && c.PeerPubKey != "" && c.AddressV4 != "" {
			if c.Endpoint == "" {
				c.Endpoint = defaultWARPEndpoint
			}
			return &c, nil
		}
	}
	c, err := registerWARP()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if b, err := json.MarshalIndent(c, "", "  "); err == nil {
		_ = os.WriteFile(path, b, 0o600)
	}
	return c, nil
}

func registerWARP() (*WARPCred, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成 WARP X25519 密钥失败: %w", err)
	}
	privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())
	pubB64 := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())

	body, _ := json.Marshal(map[string]any{
		"key":        pubB64,
		"install_id": "",
		"fcm_token":  "",
		"tos":        time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"model":      "PC",
		"type":       "Android",
		"locale":     "en_US",
	})
	req, err := http.NewRequest("POST", warpRegURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", "a-6.11-2223")

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 Cloudflare WARP 注册接口失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Cloudflare WARP 注册失败 (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var parsed struct {
		Config struct {
			ClientID  string `json:"client_id"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
			Peers []struct {
				PublicKey string `json:"public_key"`
			} `json:"peers"`
		} `json:"config"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("解析 WARP 响应失败: %w", err)
	}
	if parsed.Config.Interface.Addresses.V4 == "" || len(parsed.Config.Peers) == 0 || parsed.Config.Peers[0].PublicKey == "" {
		return nil, errors.New("WARP 响应缺少有效地址或 peer 公钥")
	}
	reserved := []int{0, 0, 0}
	if cid, err := base64.StdEncoding.DecodeString(parsed.Config.ClientID); err == nil && len(cid) >= 3 {
		reserved = []int{int(cid[0]), int(cid[1]), int(cid[2])}
	}
	return &WARPCred{
		PrivateKey: privB64,
		PublicKey:  pubB64,
		PeerPubKey: parsed.Config.Peers[0].PublicKey,
		Endpoint:   defaultWARPEndpoint,
		AddressV4:  parsed.Config.Interface.Addresses.V4,
		AddressV6:  parsed.Config.Interface.Addresses.V6,
		Reserved:   reserved,
		ClientID:   parsed.Config.ClientID,
	}, nil
}
