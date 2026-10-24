// Package store is the SQLite persistence layer.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	DB *sql.DB

	settingsMu sync.RWMutex
	settings   map[string]string
}

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer; a single connection avoids SQLITE_BUSY under load.
	db.SetMaxOpenConns(1)
	s := &Store{DB: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := s.loadSettings(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	if _, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS schema_version (v INTEGER NOT NULL)`); err != nil {
		return err
	}
	var v int
	_ = s.DB.QueryRow(`SELECT COALESCE(MAX(v),0) FROM schema_version`).Scan(&v)
	for i := v; i < len(migrations); i++ {
		tx, err := s.DB.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version(v) VALUES (?)`, i+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func Now() int64 { return time.Now().Unix() }

// ---------- settings ----------

func (s *Store) loadSettings() error {
	rows, err := s.DB.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		m[k] = v
	}
	s.settingsMu.Lock()
	s.settings = m
	s.settingsMu.Unlock()
	return rows.Err()
}

func (s *Store) Setting(key string) string {
	s.settingsMu.RLock()
	defer s.settingsMu.RUnlock()
	return s.settings[key]
}

func (s *Store) SettingOr(key, def string) string {
	if v := s.Setting(key); v != "" {
		return v
	}
	return def
}

func (s *Store) AllSettings() map[string]string {
	s.settingsMu.RLock()
	defer s.settingsMu.RUnlock()
	out := make(map[string]string, len(s.settings))
	for k, v := range s.settings {
		out[k] = v
	}
	return out
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.DB.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	if err != nil {
		return err
	}
	s.settingsMu.Lock()
	s.settings[key] = value
	s.settingsMu.Unlock()
	return nil
}

// ---------- helpers ----------

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func SplitTags(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '，' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Audit writes an audit log row; errors are ignored on purpose (auditing must not break requests).
func (s *Store) Audit(actor, action, target, detail, ip string) {
	_, _ = s.DB.Exec(`INSERT INTO audit_logs(actor,action,target,detail,ip,created_at) VALUES(?,?,?,?,?,?)`,
		actor, action, target, detail, ip, Now())
}

type AuditLog struct {
	ID        int64  `json:"id"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Detail    string `json:"detail"`
	IP        string `json:"ip"`
	CreatedAt int64  `json:"created_at"`
}

func (s *Store) ListAudit(limit int) ([]AuditLog, error) {
	rows, err := s.DB.Query(`SELECT id,actor,action,target,detail,ip,created_at FROM audit_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditLog
	for rows.Next() {
		var a AuditLog
		if err := rows.Scan(&a.ID, &a.Actor, &a.Action, &a.Target, &a.Detail, &a.IP, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------- events ----------

type Event struct {
	ID        int64           `json:"id"`
	Type      string          `json:"type"`
	Level     string          `json:"level"`
	Message   string          `json:"message"`
	Data      json.RawMessage `json:"data"`
	CreatedAt int64           `json:"created_at"`
}

func (s *Store) AddEvent(typ, level, msg string, data any) (Event, error) {
	d := mustJSON(data)
	now := Now()
	res, err := s.DB.Exec(`INSERT INTO events(type,level,message,data_json,created_at) VALUES(?,?,?,?,?)`, typ, level, msg, d, now)
	if err != nil {
		return Event{}, err
	}
	id, _ := res.LastInsertId()
	return Event{ID: id, Type: typ, Level: level, Message: msg, Data: json.RawMessage(d), CreatedAt: now}, nil
}

func (s *Store) ListEvents(limit int) ([]Event, error) {
	rows, err := s.DB.Query(`SELECT id,type,level,message,data_json,created_at FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var d string
		if err := rows.Scan(&e.ID, &e.Type, &e.Level, &e.Message, &d, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Data = json.RawMessage(d)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Prune removes old time-series rows.
func (s *Store) Prune(trafficDays, eventDays int) {
	now := Now()
	_, _ = s.DB.Exec(`DELETE FROM traffic_hourly WHERE hour < ?`, now-int64(trafficDays)*86400)
	_, _ = s.DB.Exec(`DELETE FROM events WHERE created_at < ?`, now-int64(eventDays)*86400)
	_, _ = s.DB.Exec(`DELETE FROM audit_logs WHERE created_at < ?`, now-180*86400)
	_, _ = s.DB.Exec(`DELETE FROM online_ips WHERE last_seen < ?`, now-600)
	_, _ = s.DB.Exec(`DELETE FROM idempotency WHERE created_at < ?`, now-7*86400) // keys live 7 days
	_, _ = s.DB.Exec(`DELETE FROM commands WHERE created_at < ? AND status IN ('done','failed')`, now-7*86400)
	// keep last 50 ip checks per node
	_, _ = s.DB.Exec(`DELETE FROM ip_checks WHERE id IN (
	  SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY node_id, server_id, ip ORDER BY checked_at DESC) rn FROM ip_checks) WHERE rn > 50)`)
}
