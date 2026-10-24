package master

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"nodehub/internal/store"
	"nodehub/internal/util"
)

const GB = int64(1 << 30)

// UserInput supports partial updates: nil fields are left unchanged.
type UserInput struct {
	Username       *string  `json:"username"`
	ExternalID     *string  `json:"external_id"`
	UUID           *string  `json:"uuid"`
	Password       *string  `json:"password"`         // trojan/hysteria2/tuic/anytls password; "" = use the UUID
	TrafficLimit   *int64   `json:"traffic_limit"`    // bytes
	TrafficLimitGB *float64 `json:"traffic_limit_gb"` // convenience
	AddTrafficGB   *float64 `json:"add_traffic_gb"`   // add to the current limit (top-up)
	ExpireAt       *int64   `json:"expire_at"`        // unix seconds, 0 = never
	ExtendDays     *int     `json:"extend_days"`      // extend from max(now, expire_at)
	SpeedLimit     *int     `json:"speed_limit"`
	DeviceLimit    *int     `json:"device_limit"`
	Groups         *string  `json:"groups"`
	ResetStrategy  *string  `json:"reset_strategy"` // none | monthly | day_of_month
	ResetDay       *int     `json:"reset_day"`
	Enabled        *bool    `json:"enabled"`
	Note           *string  `json:"note"`
	ResetTraffic   bool     `json:"reset_traffic"`
}

func (s *Server) applyUserInput(u *store.User, in *UserInput, creating bool) error {
	if in.Username != nil {
		u.Username = strings.TrimSpace(*in.Username)
	}
	if in.ExternalID != nil {
		ext := strings.TrimSpace(*in.ExternalID)
		if ext != "" && ext != u.ExternalID {
			if o, err := s.st.UserByExternal(ext); err == nil && o.ID != u.ID {
				return fmt.Errorf("external_id %q 已被用户 %d 使用", ext, o.ID)
			}
		}
		u.ExternalID = ext
	}
	if in.UUID != nil && *in.UUID != "" {
		id := strings.ToLower(strings.TrimSpace(*in.UUID))
		if !util.ValidUUID(id) {
			return errors.New("uuid 格式错误")
		}
		if o, err := s.st.UserByUUID(id); err == nil && o.ID != u.ID {
			return errors.New("uuid 已存在")
		}
		u.UUID = id
	}
	if in.Password != nil {
		pw := strings.TrimSpace(*in.Password)
		if pw != "" {
			if len(pw) < 8 || len(pw) > 128 || strings.ContainsAny(pw, " \t\r\n") {
				return errors.New("连接密码需为 8-128 位且不含空白")
			}
			// hysteria2 / trojan identify a user by password alone, so it must be unique
			if o, err := s.st.UserByPassword(pw); err == nil && o.ID != u.ID {
				return errors.New("连接密码已被其他用户使用")
			}
			if o, err := s.st.UserByUUID(pw); err == nil && o.ID != u.ID {
				return errors.New("连接密码与其他用户的 UUID 相同")
			}
		}
		u.Password = pw
	}
	if in.TrafficLimit != nil {
		u.TrafficLimit = *in.TrafficLimit
	}
	if in.TrafficLimitGB != nil {
		u.TrafficLimit = int64(math.Round(*in.TrafficLimitGB * float64(GB)))
	}
	if in.AddTrafficGB != nil {
		u.TrafficLimit += int64(math.Round(*in.AddTrafficGB * float64(GB)))
	}
	if u.TrafficLimit < 0 {
		u.TrafficLimit = 0
	}
	if in.ExpireAt != nil {
		u.ExpireAt = *in.ExpireAt
	}
	if in.ExtendDays != nil {
		base := time.Now().Unix()
		if u.ExpireAt > base {
			base = u.ExpireAt
		}
		u.ExpireAt = base + int64(*in.ExtendDays)*86400
	}
	if in.SpeedLimit != nil {
		u.SpeedLimit = max(0, *in.SpeedLimit)
	}
	if in.DeviceLimit != nil {
		u.DeviceLimit = max(0, *in.DeviceLimit)
	}
	if in.Groups != nil {
		u.Groups = strings.Join(store.SplitTags(*in.Groups), ",")
	}
	if in.ResetStrategy != nil {
		switch *in.ResetStrategy {
		case "none", "monthly", "day_of_month":
			u.ResetStrategy = *in.ResetStrategy
		default:
			return errors.New("reset_strategy 只能是 none / monthly / day_of_month")
		}
	}
	if in.ResetDay != nil {
		if *in.ResetDay < 1 || *in.ResetDay > 28 {
			return errors.New("reset_day 必须在 1-28 之间")
		}
		u.ResetDay = *in.ResetDay
	}
	if in.Enabled != nil {
		u.Enabled = *in.Enabled
	}
	if in.Note != nil {
		u.Note = *in.Note
	}
	if in.ResetTraffic {
		u.Up, u.Down = 0, 0
		u.LastResetAt = time.Now().Unix()
	}
	if creating && u.Username != "" {
		if o, err := s.st.UserByUsername(u.Username); err == nil && o.ID != u.ID {
			return fmt.Errorf("用户名 %q 已存在", u.Username)
		}
	}
	return nil
}

func (s *Server) createUser(in *UserInput) (*store.User, error) {
	u := &store.User{UUID: util.UUID(), SubToken: util.RandToken(18), Enabled: true, ResetStrategy: "none", ResetDay: 1, Status: "active"}
	if err := s.applyUserInput(u, in, true); err != nil {
		return nil, err
	}
	u.Status = u.ComputeStatus(time.Now().Unix())
	id, err := s.st.CreateUser(u)
	if err != nil {
		return nil, err
	}
	u.ID = id
	s.bump()
	s.emit("user.created", "info", fmt.Sprintf("创建用户 %s", displayUser(u)), map[string]any{"user_id": u.ID, "external_id": u.ExternalID})
	return u, nil
}

func (s *Server) updateUser(u *store.User, in *UserInput) error {
	oldStatus := u.Status
	if err := s.applyUserInput(u, in, false); err != nil {
		return err
	}
	if err := s.st.UpdateUser(u); err != nil {
		return err
	}
	s.bump()
	// status transitions (and their events) go through one place
	u.Status = oldStatus
	_ = s.st.UpdateUser(u)
	s.refreshUserStatus(u.ID)
	nu, err := s.st.GetUser(u.ID)
	if err == nil {
		*u = *nu
	}
	return nil
}

type userView struct {
	*store.User
	Used       int64  `json:"used"`
	Remaining  int64  `json:"remaining"` // -1 = unlimited
	SubURL     string `json:"sub_url"`
	OnlineIPs  int    `json:"online_ips"`
	ExpireDays int    `json:"expire_days"` // -1 = never
}

func (s *Server) viewUser(r *http.Request, u *store.User) userView {
	v := userView{User: u, Used: u.Up + u.Down, Remaining: -1, ExpireDays: -1}
	if u.TrafficLimit > 0 {
		v.Remaining = max(0, u.TrafficLimit-v.Used)
	}
	if u.ExpireAt > 0 {
		v.ExpireDays = int(math.Ceil(float64(u.ExpireAt-time.Now().Unix()) / 86400))
		if v.ExpireDays < 0 {
			v.ExpireDays = 0
		}
	}
	v.SubURL = s.subURL(r) + "/sub/" + u.SubToken
	return v
}

func (s *Server) resetUserCredentials(u *store.User, uuid, token bool) error {
	if uuid {
		u.UUID = util.UUID()
		if u.Password != "" { // a custom password is a credential too: rotate it with the UUID
			u.Password = util.RandHex(16)
		}
	}
	if token {
		u.SubToken = util.RandToken(18)
	}
	if err := s.st.UpdateUser(u); err != nil {
		return err
	}
	s.bump()
	return nil
}

// ---------------- admin handlers ----------------

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	limit := qInt(r, "limit", 50)
	if limit > 500 {
		limit = 500
	}
	list, total, err := s.st.ListUsers(r.URL.Query().Get("q"), r.URL.Query().Get("status"), qInt(r, "offset", 0), limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	online := s.onlineCounts()
	out := make([]userView, 0, len(list))
	for _, u := range list {
		v := s.viewUser(r, u)
		v.OnlineIPs = online[u.ID]
		out = append(out, v)
	}
	ok(w, map[string]any{"items": out, "total": total})
}

// onlineCounts maps local user id -> distinct online IPs in the last 3 minutes.
func (s *Server) onlineCounts() map[int64]int {
	list, _ := s.st.OnlineIPs(0, time.Now().Unix()-180)
	seen := map[int64]map[string]bool{}
	for _, o := range list {
		kind, id, okk := parseUserKey(o.UserKey)
		if !okk || kind != 'u' {
			continue
		}
		if seen[id] == nil {
			seen[id] = map[string]bool{}
		}
		seen[id][o.IP] = true
	}
	out := map[int64]int{}
	for id, m := range seen {
		n := len(m)
		if m["-"] && n > 1 { // "-" only means online without a known IP
			n--
		}
		out[id] = n
	}
	return out
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	u, err := s.st.GetUser(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	ok(w, s.viewUser(r, u))
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	var in UserInput
	if err := readJSON(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	u, err := s.createUser(&in)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.audit(r, a, "user.create", fmt.Sprint(u.ID), u.Username)
	ok(w, s.viewUser(r, u))
}

func (s *Server) handleBatchUsers(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	var req struct {
		Count  int       `json:"count"`
		Prefix string    `json:"prefix"`
		Input  UserInput `json:"input"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Count < 1 || req.Count > 1000 {
		writeErr(w, 400, "数量需在 1-1000 之间")
		return
	}
	var out []userView
	for i := 0; i < req.Count; i++ {
		in := req.Input
		if req.Prefix != "" {
			name := fmt.Sprintf("%s%s", req.Prefix, util.RandHex(3))
			in.Username = &name
		}
		u, err := s.createUser(&in)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		out = append(out, s.viewUser(r, u))
	}
	s.audit(r, a, "user.batch_create", "", fmt.Sprint(req.Count))
	ok(w, out)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	u, err := s.st.GetUser(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	var in UserInput
	if err := readJSON(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.updateUser(u, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.audit(r, a, "user.update", fmt.Sprint(u.ID), "")
	ok(w, s.viewUser(r, u))
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	if err := s.st.DeleteUser(pathID(r)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.bump()
	s.audit(r, a, "user.delete", fmt.Sprint(pathID(r)), "")
	ok(w, map[string]any{"ok": true})
}

func (s *Server) handleResetUserTraffic(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	u, err := s.st.GetUser(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	if err := s.updateUser(u, &UserInput{ResetTraffic: true}); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "user.reset_traffic", fmt.Sprint(u.ID), "")
	ok(w, s.viewUser(r, u))
}

func (s *Server) handleResetUserCreds(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	u, err := s.st.GetUser(pathID(r))
	if err != nil {
		notFoundOr500(w, err)
		return
	}
	var req struct {
		UUID  bool `json:"uuid"`
		Token bool `json:"token"`
	}
	_ = readJSON(r, &req)
	if !req.UUID && !req.Token {
		req.UUID, req.Token = true, true
	}
	if err := s.resetUserCredentials(u, req.UUID, req.Token); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r, a, "user.reset_credentials", fmt.Sprint(u.ID), "")
	ok(w, s.viewUser(r, u))
}

func (s *Server) handleUserTraffic(w http.ResponseWriter, r *http.Request, a *store.Admin) {
	days := qInt(r, "days", 30)
	pts, err := s.st.TrafficSeries("user", pathID(r), time.Now().Unix()-int64(days)*86400, 86400, tzOffset())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ok(w, pts)
}

func tzOffset() int64 {
	_, off := time.Now().Zone()
	return int64(off)
}
