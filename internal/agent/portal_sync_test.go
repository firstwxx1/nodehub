package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// a tiny stand-in for the hysteria2-installer portal API
type fakePortal struct {
	mu    sync.Mutex
	users map[string]map[string]any
	calls []string
}

func (f *fakePortal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer k1" {
		w.WriteHeader(401)
		fmt.Fprint(w, `{"ok":false,"error":"bad key"}`)
		return
	}
	sub := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	f.calls = append(f.calls, sub)
	var p map[string]any
	_ = json.NewDecoder(r.Body).Decode(&p)
	switch sub {
	case "users/list":
		var out []map[string]any
		for id, u := range f.users {
			out = append(out, map[string]any{"user_id": id, "status": u["status"], "traffic_used_bytes": u["used"]})
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "users": out})
	case "users/create":
		id := p["user_id"].(string)
		old := f.users[id]
		u := map[string]any{"password": p["password"], "status": "active", "used": float64(0)}
		if old != nil {
			u["status"], u["used"] = old["status"], old["used"]
		}
		f.users[id] = u
		fmt.Fprint(w, `{"ok":true}`)
	case "users/update":
		f.users[p["user_id"].(string)]["status"] = p["status"]
		fmt.Fprint(w, `{"ok":true}`)
	case "users/delete":
		delete(f.users, p["user_id"].(string))
		fmt.Fprint(w, `{"ok":true}`)
	default:
		w.WriteHeader(404)
	}
}

func TestSyncPortalUsers(t *testing.T) {
	fp := &fakePortal{users: map[string]map[string]any{
		"admin_master": {"status": "active", "used": float64(5)},
		"nh-9":         {"status": "active", "used": float64(100)}, // no longer wanted
		"nh-2":         {"status": "disabled", "used": float64(7)}, // wanted again
	}}
	srv := httptest.NewServer(fp)
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	dir := t.TempDir()
	old := hy2Dir
	hy2Dir = dir
	defer func() { hy2Dir = old }()
	os.WriteFile(filepath.Join(dir, "portal-access.json"), []byte(`{"api_key":"k1"}`), 0o600)
	os.WriteFile(filepath.Join(dir, "portal.json"), []byte(`{"port":`+port+`}`), 0o600)
	data := t.TempDir()

	req := PortalSyncReq{Prefix: "nh-", Users: []PortalUser{
		{ID: "nh-1", Password: "pw1", TrafficGB: 50, IPLimit: 2},
		{ID: "nh-2", Password: "pw2"},
	}}
	b, _ := json.Marshal(req)
	out, err := SyncPortalUsers(string(b), data)
	if err != nil {
		t.Fatal(err, out)
	}
	var res PortalSyncResult
	json.Unmarshal([]byte(out), &res)
	if res.Created != 1 || res.Updated != 1 || res.Deleted != 1 {
		t.Fatalf("result %+v", res)
	}
	if _, ok := fp.users["nh-9"]; ok {
		t.Fatal("nh-9 should be deleted")
	}
	if fp.users["admin_master"] == nil {
		t.Fatal("non-prefix users must be left alone")
	}
	if fp.users["nh-2"]["status"] != "active" {
		t.Fatal("re-wanted disabled user must be switched on")
	}
	if len(res.Usage) != 2 { // nh-9 and nh-2 were seen before the changes
		t.Fatalf("usage %+v", res.Usage)
	}
	// unchanged second run touches nothing
	fp.calls = nil
	out, err = SyncPortalUsers(string(b), data)
	json.Unmarshal([]byte(out), &res)
	if err != nil || res.Created+res.Updated+res.Deleted != 0 || len(fp.calls) != 1 {
		t.Fatalf("second run should only list: %+v %v", res, fp.calls)
	}
}
