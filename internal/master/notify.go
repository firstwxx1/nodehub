package master

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"nodehub/internal/store"
	"nodehub/internal/util"
)

type notifyJob struct{ ev store.Event }

// emit records an event and queues webhook / Telegram delivery.
func (s *Server) emit(typ, level, msg string, data any) {
	ev, err := s.st.AddEvent(typ, level, msg, data)
	if err != nil {
		log.Printf("event %s: %v", typ, err)
		return
	}
	log.Printf("[event] %s: %s", typ, msg)
	select {
	case s.notifyQ <- notifyJob{ev}:
	default:
		log.Printf("notify queue full, dropping %s", typ)
	}
}

func (s *Server) notifyWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-s.notifyQ:
			hooks, _ := s.st.ListWebhooks()
			for _, h := range hooks {
				if h.Enabled && eventMatches(h.Events, j.ev.Type) {
					s.deliverWebhook(h, j.ev)
				}
			}
			if eventMatches(s.st.Setting("notify_events"), j.ev.Type) {
				icon := map[string]string{"warn": "⚠️", "error": "🔴", "info": "ℹ️"}[j.ev.Level]
				if err := s.sendTelegram(fmt.Sprintf("%s [%s] %s", icon, s.st.SettingOr("site_name", "NodeHub"), j.ev.Message)); err != nil && err != errTGOff {
					log.Printf("telegram: %v", err)
				}
			}
		}
	}
}

func eventMatches(list, typ string) bool {
	for _, e := range store.SplitTags(list) {
		if e == "*" || e == typ || (strings.HasSuffix(e, ".*") && strings.HasPrefix(typ, strings.TrimSuffix(e, "*"))) {
			return true
		}
	}
	return false
}

var hookClient = &http.Client{Timeout: 10 * time.Second}

// deliverWebhook POSTs the event with an HMAC signature: hex(HMAC-SHA256(secret, timestamp + "." + body)).
func (s *Server) deliverWebhook(h *store.Webhook, ev store.Event) string {
	body, _ := json.Marshal(map[string]any{"id": ev.ID, "type": ev.Type, "level": ev.Level, "message": ev.Message, "data": ev.Data, "created_at": ev.CreatedAt})
	var status string
	for attempt := 0; attempt < 3; attempt++ {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req, _ := http.NewRequest("POST", h.URL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "NodeHub-Webhook/1.0")
		req.Header.Set("X-NodeHub-Event", ev.Type)
		req.Header.Set("X-NodeHub-Timestamp", ts)
		req.Header.Set("X-NodeHub-Signature", "sha256="+util.HMACHex(h.Secret, ts+"."+string(body)))
		resp, err := hookClient.Do(req)
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			status = fmt.Sprintf("%s HTTP %d", time.Now().Format("01-02 15:04:05"), resp.StatusCode)
			if resp.StatusCode < 300 {
				break
			}
		} else {
			status = time.Now().Format("01-02 15:04:05") + " " + err.Error()
		}
		time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
	}
	s.st.SetWebhookStatus(h.ID, status)
	return status
}

var errTGOff = fmt.Errorf("telegram not configured")

func (s *Server) sendTelegram(text string) error {
	token, chat := s.st.Setting("tg_bot_token"), s.st.Setting("tg_chat_id")
	if token == "" || chat == "" {
		return errTGOff
	}
	api := s.st.SettingOr("tg_api_base", "https://api.telegram.org")
	resp, err := hookClient.PostForm(api+"/bot"+token+"/sendMessage", url.Values{"chat_id": {chat}, "text": {text}, "disable_web_page_preview": {"true"}})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("telegram HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}
