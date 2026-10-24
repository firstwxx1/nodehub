// Package master is the control plane: admin UI/API, agent API, shop open API,
// subscriptions, panel sync, IP checks and notifications.
package master

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nodehub/internal/panel"
	"nodehub/internal/store"
	"nodehub/internal/util"
)

type Options struct {
	Listen    string
	DataDir   string
	PublicURL string
	DistDir   string // directory with agent binaries / cores to serve under /dl
	WebFS     fs.FS
	AdminUser string
	AdminPass string
}

type Server struct {
	opt   Options
	st    *store.Store
	mux   *http.ServeMux
	start time.Time

	// configGen is bumped whenever nodes, users or panel users change; agents compare versions.
	configGen   atomic.Int64
	verMu       sync.Mutex
	verCache    map[int64]verEntry
	panelMu     sync.Mutex
	panelCli    map[int64]panel.Client
	loginMu     sync.Mutex
	loginFails  map[string][]time.Time
	ipcheckBusy atomic.Bool
	notifyQ     chan notifyJob
	ports       portBook
}

type verEntry struct {
	gen int64
	ver string
}

//go:embed install.sh
var installScript string

var _ embed.FS

func New(opt Options) (*Server, error) {
	if err := os.MkdirAll(opt.DataDir, 0o755); err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(opt.DataDir, "nodehub.db"))
	if err != nil {
		return nil, err
	}
	s := &Server{opt: opt, st: st, start: time.Now(), verCache: map[int64]verEntry{}, panelCli: map[int64]panel.Client{},
		loginFails: map[string][]time.Time{}, notifyQ: make(chan notifyJob, 1000)}
	s.configGen.Store(time.Now().UnixNano())
	if err := s.bootstrap(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

func (s *Server) bootstrap() error {
	if s.st.Setting("secret") == "" {
		if err := s.st.SetSetting("secret", util.RandHex(32)); err != nil {
			return err
		}
	}
	defaults := map[string]string{
		"site_name":              "NodeHub",
		"sub_name_template":      "{flag} {name}",
		"ipcheck_interval_hours": "24",
		"unlock_interval_hours":  "24",
		"report_interval":        "60",
		"offline_after":          "60",
		"traffic_retention_days": "90",
		"notify_events":          "server.offline,server.online,server.expiring,user.exhausted,user.expired,ipcheck.risk_changed,panel.error",
	}
	for k, v := range defaults {
		if s.st.Setting(k) == "" {
			_ = s.st.SetSetting(k, v)
		}
	}
	if s.opt.PublicURL != "" {
		_ = s.st.SetSetting("public_url", strings.TrimRight(s.opt.PublicURL, "/"))
	}
	if s.st.AdminCount() == 0 {
		user, pass := s.opt.AdminUser, s.opt.AdminPass
		if user == "" {
			user = "admin"
		}
		if pass == "" {
			pass = util.RandToken(12)
			log.Printf("==========================================================")
			log.Printf(" 初始管理员账号: %s   密码: %s", user, pass)
			log.Printf(" 请登录后立即修改密码")
			log.Printf("==========================================================")
			_ = os.WriteFile(filepath.Join(s.opt.DataDir, "initial-admin.txt"), []byte(user+" / "+pass+"\n"), 0o600)
		}
		h, err := hashPassword(pass)
		if err != nil {
			return err
		}
		if err := s.st.CreateAdmin(user, h); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) Run(ctx context.Context) error {
	go s.scheduler(ctx)
	go s.notifyWorker(ctx)
	srv := &http.Server{Addr: s.opt.Listen, Handler: s.middleware(s.mux), ReadHeaderTimeout: 15 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("NodeHub master listening on %s", s.opt.Listen)
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) bump() { s.configGen.Add(1) }

func (s *Server) publicURL(r *http.Request) string {
	if u := s.st.Setting("public_url"); u != "" {
		return u
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (s *Server) subURL(r *http.Request) string {
	if u := s.st.Setting("sub_url"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return s.publicURL(r)
}

// ---------------- routing ----------------

func (s *Server) routes() {
	m := http.NewServeMux()
	s.mux = m

	// health
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	// agent
	m.HandleFunc("POST /agent/v1/heartbeat", s.agentAuth(s.agentHeartbeat))
	m.HandleFunc("GET /agent/v1/config", s.agentAuth(s.agentConfig))
	m.HandleFunc("POST /agent/v1/report", s.agentAuth(s.agentReport))
	m.HandleFunc("GET /install.sh", s.handleInstallScript)
	m.HandleFunc("GET /dl/{name}", s.handleDownload)

	// subscription
	m.HandleFunc("GET /sub/{token}", s.handleSub)
	m.HandleFunc("GET /sub/{token}/info", s.handleSubInfo)

	// auth
	m.HandleFunc("POST /api/auth/login", s.handleLogin)
	m.HandleFunc("POST /api/auth/logout", s.handleLogout)
	m.HandleFunc("GET /api/auth/me", s.admin(s.handleMe))
	m.HandleFunc("POST /api/auth/password", s.admin(s.handleChangePassword))
	m.HandleFunc("POST /api/auth/totp/setup", s.admin(s.handleTOTPSetup))
	m.HandleFunc("POST /api/auth/totp/enable", s.admin(s.handleTOTPEnable))
	m.HandleFunc("POST /api/auth/totp/disable", s.admin(s.handleTOTPDisable))

	// admin: dashboard
	m.HandleFunc("GET /api/dashboard", s.admin(s.handleDashboard))
	m.HandleFunc("GET /api/traffic", s.admin(s.handleTrafficSeries))
	m.HandleFunc("GET /api/events", s.admin(s.handleEvents))
	m.HandleFunc("GET /api/audit", s.admin(s.handleAudit))

	// admin: servers
	m.HandleFunc("GET /api/servers", s.admin(s.handleListServers))
	m.HandleFunc("POST /api/servers", s.admin(s.handleCreateServer))
	m.HandleFunc("GET /api/servers/{id}", s.admin(s.handleGetServer))
	m.HandleFunc("PUT /api/servers/{id}", s.admin(s.handleUpdateServer))
	m.HandleFunc("DELETE /api/servers/{id}", s.admin(s.handleDeleteServer))
	m.HandleFunc("GET /api/servers/{id}/ports", s.admin(s.handleServerPorts))
	m.HandleFunc("POST /api/servers/{id}/token", s.admin(s.handleResetServerToken))
	m.HandleFunc("POST /api/servers/{id}/command", s.admin(s.handleServerCommand))
	m.HandleFunc("GET /api/servers/{id}/commands", s.admin(s.handleServerCommands))
	m.HandleFunc("POST /api/servers/{id}/reset-traffic", s.admin(s.handleServerResetTraffic))
	m.HandleFunc("POST /api/servers/{id}/script-node", s.admin(s.handleScriptNodeInstall))
	m.HandleFunc("POST /api/servers/{id}/script-node/adopt", s.admin(s.handleScriptNodeAdopt))
	m.HandleFunc("POST /api/servers/{id}/script-node/finish", s.admin(s.handleScriptNodeFinish))
	m.HandleFunc("POST /api/servers/{id}/import/scan", s.admin(s.handleImportScan))
	m.HandleFunc("GET /api/servers/{id}/import/preview", s.admin(s.handleImportPreview))
	m.HandleFunc("POST /api/servers/{id}/import", s.admin(s.handleImport))
	m.HandleFunc("POST /api/servers/{id}/import/rollback", s.admin(s.handleImportRollback))

	// admin: nodes
	m.HandleFunc("GET /api/nodes", s.admin(s.handleListNodes))
	m.HandleFunc("POST /api/nodes", s.admin(s.handleCreateNode))
	m.HandleFunc("GET /api/nodes/{id}", s.admin(s.handleGetNode))
	m.HandleFunc("PUT /api/nodes/{id}", s.admin(s.handleUpdateNode))
	m.HandleFunc("DELETE /api/nodes/{id}", s.admin(s.handleDeleteNode))
	m.HandleFunc("POST /api/nodes/{id}/toggle", s.admin(s.handleToggleNode))
	m.HandleFunc("POST /api/nodes/{id}/copy", s.admin(s.handleCopyNode))
	m.HandleFunc("GET /api/nodes/{id}/online", s.admin(s.handleNodeOnline))
	m.HandleFunc("POST /api/nodes/{id}/panel-sync", s.admin(s.handleNodePanelSync))
	m.HandleFunc("POST /api/tools/reality-keypair", s.admin(s.handleRealityKeypair))
	m.HandleFunc("POST /api/tools/ss-key", s.admin(s.handleSSKey))

	// admin: ip quality
	m.HandleFunc("GET /api/ipchecks", s.admin(s.handleListIPChecks))
	m.HandleFunc("POST /api/ipchecks/run", s.admin(s.handleRunIPChecks))
	m.HandleFunc("POST /api/nodes/{id}/ipcheck", s.admin(s.handleNodeIPCheck))
	m.HandleFunc("POST /api/servers/{id}/ipcheck", s.admin(s.handleServerIPCheck))
	m.HandleFunc("GET /api/servers/{id}/ipcheck", s.admin(s.handleServerIPCheckDetail))
	m.HandleFunc("GET /api/nodes/{id}/ipcheck", s.admin(s.handleNodeIPCheckDetail))

	// admin: users
	m.HandleFunc("GET /api/users", s.admin(s.handleListUsers))
	m.HandleFunc("POST /api/users", s.admin(s.handleCreateUser))
	m.HandleFunc("POST /api/users/batch", s.admin(s.handleBatchUsers))
	m.HandleFunc("GET /api/users/{id}", s.admin(s.handleGetUser))
	m.HandleFunc("PUT /api/users/{id}", s.admin(s.handleUpdateUser))
	m.HandleFunc("DELETE /api/users/{id}", s.admin(s.handleDeleteUser))
	m.HandleFunc("POST /api/users/{id}/reset-traffic", s.admin(s.handleResetUserTraffic))
	m.HandleFunc("POST /api/users/{id}/reset-credentials", s.admin(s.handleResetUserCreds))
	m.HandleFunc("GET /api/users/{id}/traffic", s.admin(s.handleUserTraffic))

	// admin: panels
	m.HandleFunc("GET /api/panels", s.admin(s.handleListPanels))
	m.HandleFunc("POST /api/panels", s.admin(s.handleCreatePanel))
	m.HandleFunc("PUT /api/panels/{id}", s.admin(s.handleUpdatePanel))
	m.HandleFunc("DELETE /api/panels/{id}", s.admin(s.handleDeletePanel))
	m.HandleFunc("POST /api/panels/{id}/sync", s.admin(s.handleSyncPanel))

	// admin: api keys, webhooks, settings
	m.HandleFunc("GET /api/apikeys", s.admin(s.handleListAPIKeys))
	m.HandleFunc("POST /api/apikeys", s.admin(s.handleCreateAPIKey))
	m.HandleFunc("PUT /api/apikeys/{id}", s.admin(s.handleUpdateAPIKey))
	m.HandleFunc("DELETE /api/apikeys/{id}", s.admin(s.handleDeleteAPIKey))
	m.HandleFunc("GET /api/webhooks", s.admin(s.handleListWebhooks))
	m.HandleFunc("POST /api/webhooks", s.admin(s.handleCreateWebhook))
	m.HandleFunc("PUT /api/webhooks/{id}", s.admin(s.handleUpdateWebhook))
	m.HandleFunc("DELETE /api/webhooks/{id}", s.admin(s.handleDeleteWebhook))
	m.HandleFunc("POST /api/webhooks/{id}/test", s.admin(s.handleTestWebhook))
	m.HandleFunc("GET /api/settings", s.admin(s.handleGetSettings))
	m.HandleFunc("PUT /api/settings", s.admin(s.handlePutSettings))
	m.HandleFunc("POST /api/settings/test-telegram", s.admin(s.handleTestTelegram))
	m.HandleFunc("GET /api/backup", s.admin(s.handleBackup))

	// open API for the shop
	s.openRoutes(m)

	// web UI
	if s.opt.WebFS != nil {
		fsrv := http.FileServer(http.FS(s.opt.WebFS))
		m.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" && !strings.Contains(r.URL.Path, ".") {
				r.URL.Path = "/"
			}
			w.Header().Set("Cache-Control", "no-cache")
			fsrv.ServeHTTP(w, r)
		}))
	}
}

func (s *Server) middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !strings.HasPrefix(r.URL.Path, "/sub/") {
			w.Header().Set("X-Frame-Options", "DENY")
		}
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic %s %s: %v", r.Method, r.URL.Path, rec)
				writeErr(w, 500, "internal error")
			}
		}()
		h.ServeHTTP(w, r)
	})
}

// ---------------- helpers ----------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func ok(w http.ResponseWriter, v any) { writeJSON(w, 200, v) }

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 8<<20))
	if err := dec.Decode(v); err != nil {
		return errors.New("请求体不是有效的 JSON: " + err.Error())
	}
	return nil
}

func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" && trustProxy() {
		return strings.TrimSpace(strings.Split(xf, ",")[0])
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" && trustProxy() {
		return xr
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// trustProxy is opt-in: only honour X-Forwarded-For / X-Real-IP when NodeHub sits behind a reverse
// proxy, otherwise clients could spoof their IP past rate limits and API-key IP whitelists.
func trustProxy() bool { return os.Getenv("NODEHUB_TRUST_PROXY") == "1" }

func qInt(r *http.Request, k string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(k)); err == nil {
		return v
	}
	return def
}

func notFoundOr500(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, 404, "not found")
		return
	}
	writeErr(w, 500, err.Error())
}
