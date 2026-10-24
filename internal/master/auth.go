package master

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"nodehub/internal/store"
	"nodehub/internal/util"
)

const sessionCookie = "nh_session"
const sessionTTL = 7 * 24 * time.Hour

type ctxKey string

func hashPassword(p string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	return string(b), err
}

func checkPassword(hash, p string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(p)) == nil
}

// session token: base64(username).expiry.hmac — the password hash is part of the MAC,
// so changing the password invalidates every existing session.
func (s *Server) makeSession(a *store.Admin) string {
	exp := time.Now().Add(sessionTTL).Unix()
	payload := a.Username + "|" + strconv.FormatInt(exp, 10)
	mac := util.HMACHex(s.st.Setting("secret")+a.PassHash, payload)
	return payload + "|" + mac
}

func (s *Server) parseSession(tok string) (*store.Admin, bool) {
	parts := strings.Split(tok, "|")
	if len(parts) != 3 {
		return nil, false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return nil, false
	}
	a, err := s.st.AdminByName(parts[0])
	if err != nil {
		return nil, false
	}
	want := util.HMACHex(s.st.Setting("secret")+a.PassHash, parts[0]+"|"+parts[1])
	if !hmac.Equal([]byte(want), []byte(parts[2])) {
		return nil, false
	}
	return a, true
}

func (s *Server) admin(h func(http.ResponseWriter, *http.Request, *store.Admin)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := ""
		if c, err := r.Cookie(sessionCookie); err == nil {
			tok = c.Value
		}
		if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Session ") {
			tok = strings.TrimPrefix(a, "Session ")
		}
		ad, okk := s.parseSession(tok)
		if !okk {
			writeErr(w, 401, "未登录或登录已过期")
			return
		}
		// CSRF: state-changing requests from the browser must carry the custom header
		if r.Method != "GET" && r.Header.Get("X-Requested-With") != "nodehub" {
			writeErr(w, 403, "missing X-Requested-With header")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey("admin"), ad.Username)), ad)
	}
}

func (s *Server) audit(r *http.Request, a *store.Admin, action, target, detail string) {
	actor := "system"
	if a != nil {
		actor = a.Username
	}
	s.st.Audit(actor, action, target, detail, clientIP(r))
}

// ---------------- login rate limiting ----------------

func (s *Server) tooManyFails(ip string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	cut := time.Now().Add(-15 * time.Minute)
	var keep []time.Time
	for _, t := range s.loginFails[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	s.loginFails[ip] = keep
	return len(keep) >= 8
}

func (s *Server) recordFail(ip string) {
	s.loginMu.Lock()
	s.loginFails[ip] = append(s.loginFails[ip], time.Now())
	s.loginMu.Unlock()
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.tooManyFails(ip) {
		writeErr(w, 429, "失败次数过多，请 15 分钟后再试")
		return
	}
	var req struct{ Username, Password, Code string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	a, err := s.st.AdminByName(req.Username)
	if err != nil || !checkPassword(a.PassHash, req.Password) {
		s.recordFail(ip)
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	if a.TOTPSecret != "" {
		if req.Code == "" {
			writeJSON(w, 401, map[string]any{"error": "需要两步验证码", "need_totp": true})
			return
		}
		if !verifyTOTP(a.TOTPSecret, req.Code) {
			s.recordFail(ip)
			writeErr(w, 401, "验证码错误")
			return
		}
	}
	tok := s.makeSession(a)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", MaxAge: int(sessionTTL.Seconds())})
	s.st.Audit(a.Username, "login", "", "", ip)
	ok(w, map[string]any{"ok": true, "username": a.Username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	ok(w, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	ok(w, map[string]any{"username": a.Username, "totp": a.TOTPSecret != "", "site_name": s.st.Setting("site_name")})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	var req struct{ Old, New string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !checkPassword(a.PassHash, req.Old) {
		writeErr(w, 400, "原密码错误")
		return
	}
	if len(req.New) < 8 {
		writeErr(w, 400, "新密码至少 8 位")
		return
	}
	h, err := hashPassword(req.New)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := s.st.UpdateAdminPassword(a.ID, h); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "password.change", "", "")
	ok(w, map[string]any{"ok": true})
}

// ---------------- TOTP (RFC 6238) ----------------

func totpCode(secret string, t int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t/30))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}

func verifyTOTP(secret, code string) bool {
	now := time.Now().Unix()
	for _, d := range []int64{-30, 0, 30} {
		if hmac.Equal([]byte(totpCode(secret, now+d)), []byte(strings.TrimSpace(code))) {
			return true
		}
	}
	return false
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	uri := fmt.Sprintf("otpauth://totp/NodeHub:%s?secret=%s&issuer=NodeHub", a.Username, secret)
	ok(w, map[string]any{"secret": secret, "uri": uri})
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	var req struct{ Secret, Code string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !verifyTOTP(req.Secret, req.Code) {
		writeErr(w, 400, "验证码不正确")
		return
	}
	if err := s.st.SetAdminTOTP(a.ID, req.Secret); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "totp.enable", "", "")
	ok(w, map[string]any{"ok": true})
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	var req struct{ Password string }
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if !checkPassword(a.PassHash, req.Password) {
		writeErr(w, 400, "密码错误")
		return
	}
	_ = s.st.SetAdminTOTP(a.ID, "")
	s.audit(r, a, "totp.disable", "", "")
	ok(w, map[string]any{"ok": true})
}
