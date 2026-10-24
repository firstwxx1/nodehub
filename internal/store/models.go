package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"nodehub/internal/proto"
)

// ======================= admins =======================

type Admin struct {
	ID         int64
	Username   string
	PassHash   string
	TOTPSecret string
}

func (s *Store) AdminByName(name string) (*Admin, error) {
	a := &Admin{}
	err := s.DB.QueryRow(`SELECT id,username,pass_hash,totp_secret FROM admins WHERE username=?`, name).
		Scan(&a.ID, &a.Username, &a.PassHash, &a.TOTPSecret)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (s *Store) AdminCount() int {
	var n int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM admins`).Scan(&n)
	return n
}

func (s *Store) CreateAdmin(name, hash string) error {
	_, err := s.DB.Exec(`INSERT INTO admins(username,pass_hash,created_at) VALUES(?,?,?)`, name, hash, Now())
	return err
}

func (s *Store) UpdateAdminPassword(id int64, hash string) error {
	_, err := s.DB.Exec(`UPDATE admins SET pass_hash=? WHERE id=?`, hash, id)
	return err
}

func (s *Store) SetAdminTOTP(id int64, secret string) error {
	_, err := s.DB.Exec(`UPDATE admins SET totp_secret=? WHERE id=?`, secret, id)
	return err
}

// ======================= api keys =======================

type APIKey struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Prefix      string `json:"prefix"`
	Scopes      string `json:"scopes"`
	IPWhitelist string `json:"ip_whitelist"`
	Enabled     bool   `json:"enabled"`
	LastUsedAt  int64  `json:"last_used_at"`
	CreatedAt   int64  `json:"created_at"`
}

func (s *Store) CreateAPIKey(name, prefix, hash, scopes, ips string) (int64, error) {
	res, err := s.DB.Exec(`INSERT INTO api_keys(name,prefix,key_hash,scopes,ip_whitelist,created_at) VALUES(?,?,?,?,?,?)`,
		name, prefix, hash, scopes, ips, Now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) APIKeyByHash(hash string) (*APIKey, error) {
	k := &APIKey{}
	var en int
	err := s.DB.QueryRow(`SELECT id,name,prefix,scopes,ip_whitelist,enabled,last_used_at,created_at FROM api_keys WHERE key_hash=?`, hash).
		Scan(&k.ID, &k.Name, &k.Prefix, &k.Scopes, &k.IPWhitelist, &en, &k.LastUsedAt, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	k.Enabled = en == 1
	return k, err
}

func (s *Store) TouchAPIKey(id int64) {
	_, _ = s.DB.Exec(`UPDATE api_keys SET last_used_at=? WHERE id=?`, Now(), id)
}

func (s *Store) ListAPIKeys() ([]APIKey, error) {
	rows, err := s.DB.Query(`SELECT id,name,prefix,scopes,ip_whitelist,enabled,last_used_at,created_at FROM api_keys ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		var k APIKey
		var en int
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.Scopes, &k.IPWhitelist, &en, &k.LastUsedAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		k.Enabled = en == 1
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) UpdateAPIKey(id int64, name, scopes, ips string, enabled bool) error {
	_, err := s.DB.Exec(`UPDATE api_keys SET name=?,scopes=?,ip_whitelist=?,enabled=? WHERE id=?`, name, scopes, ips, b2i(enabled), id)
	return err
}

func (s *Store) DeleteAPIKey(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM api_keys WHERE id=?`, id)
	return err
}

// ======================= servers =======================

type Server struct {
	ID              int64           `json:"id"`
	Name            string          `json:"name"`
	Host            string          `json:"host"`
	Region          string          `json:"region"`
	Tags            string          `json:"tags"`
	Provider        string          `json:"provider"`
	Price           string          `json:"price"`
	ExpireAt        int64           `json:"expire_at"`
	TrafficLimit    int64           `json:"traffic_limit"`
	TrafficResetDay int             `json:"traffic_reset_day"`
	Note            string          `json:"note"`
	Enabled         bool            `json:"enabled"`
	LastSeen        int64           `json:"last_seen"`
	Status          json.RawMessage `json:"status"`
	PublicIPv4      string          `json:"public_ipv4"`
	PublicIPv6      string          `json:"public_ipv6"`
	AgentVersion    string          `json:"agent_version"`
	AppliedVersion  string          `json:"applied_version"`
	ApplyError      string          `json:"apply_error"`
	MonthRx         int64           `json:"month_rx"`
	MonthTx         int64           `json:"month_tx"`
	LastRxTotal     int64           `json:"-"`
	LastTxTotal     int64           `json:"-"`
	Unlock          json.RawMessage `json:"unlock"`
	Online          bool            `json:"online"`
	CreatedAt       int64           `json:"created_at"`
	NodeCount       int             `json:"node_count"`
}

const serverCols = `id,name,host,region,tags,provider,price,expire_at,traffic_limit,traffic_reset_day,note,enabled,last_seen,status_json,public_ipv4,public_ipv6,agent_version,applied_version,apply_error,month_rx,month_tx,last_rx_total,last_tx_total,unlock_json,online,created_at,
 (SELECT COUNT(*) FROM nodes n WHERE n.server_id=servers.id)`

func scanServer(sc interface{ Scan(...any) error }) (*Server, error) {
	v := &Server{}
	var en, on int
	var st, ul string
	err := sc.Scan(&v.ID, &v.Name, &v.Host, &v.Region, &v.Tags, &v.Provider, &v.Price, &v.ExpireAt, &v.TrafficLimit, &v.TrafficResetDay, &v.Note, &en,
		&v.LastSeen, &st, &v.PublicIPv4, &v.PublicIPv6, &v.AgentVersion, &v.AppliedVersion, &v.ApplyError, &v.MonthRx, &v.MonthTx,
		&v.LastRxTotal, &v.LastTxTotal, &ul, &on, &v.CreatedAt, &v.NodeCount)
	if err != nil {
		return nil, err
	}
	v.Enabled, v.Online = en == 1, on == 1
	v.Status = json.RawMessage(st)
	if ul == "" {
		ul = "null"
	}
	v.Unlock = json.RawMessage(ul)
	return v, nil
}

func (s *Store) ListServers() ([]*Server, error) {
	rows, err := s.DB.Query(`SELECT ` + serverCols + ` FROM servers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Server{}
	for rows.Next() {
		v, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetServer(id int64) (*Server, error) {
	v, err := scanServer(s.DB.QueryRow(`SELECT `+serverCols+` FROM servers WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

func (s *Store) ServerByToken(hash string) (*Server, error) {
	v, err := scanServer(s.DB.QueryRow(`SELECT `+serverCols+` FROM servers WHERE token_hash=?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

func (s *Store) CreateServer(v *Server, tokenHash string) (int64, error) {
	res, err := s.DB.Exec(`INSERT INTO servers(name,host,region,tags,provider,price,expire_at,traffic_limit,traffic_reset_day,note,token_hash,enabled,created_at)
	 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, v.Name, v.Host, v.Region, v.Tags, v.Provider, v.Price, v.ExpireAt, v.TrafficLimit, v.TrafficResetDay, v.Note, tokenHash, b2i(v.Enabled), Now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateServer(v *Server) error {
	_, err := s.DB.Exec(`UPDATE servers SET name=?,host=?,region=?,tags=?,provider=?,price=?,expire_at=?,traffic_limit=?,traffic_reset_day=?,note=?,enabled=? WHERE id=?`,
		v.Name, v.Host, v.Region, v.Tags, v.Provider, v.Price, v.ExpireAt, v.TrafficLimit, v.TrafficResetDay, v.Note, b2i(v.Enabled), v.ID)
	return err
}

func (s *Store) SetServerToken(id int64, hash string) error {
	_, err := s.DB.Exec(`UPDATE servers SET token_hash=? WHERE id=?`, hash, id)
	return err
}

func (s *Store) DeleteServer(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM servers WHERE id=?`, id)
	return err
}

// UpdateServerHeartbeat stores runtime data and accumulates monthly traffic from the NIC counters.
func (s *Store) UpdateServerHeartbeat(id int64, hb *proto.Heartbeat) error {
	srv, err := s.GetServer(id)
	if err != nil {
		return err
	}
	rx, tx := int64(hb.NetRxTotal), int64(hb.NetTxTotal)
	dRx, dTx := rx-srv.LastRxTotal, tx-srv.LastTxTotal
	if dRx < 0 || srv.LastRxTotal == 0 { // reboot / counter reset / first beat
		dRx = 0
	}
	if dTx < 0 || srv.LastTxTotal == 0 {
		dTx = 0
	}
	st := mustJSON(hb)
	_, err = s.DB.Exec(`UPDATE servers SET last_seen=?,status_json=?,public_ipv4=CASE WHEN ?<>'' THEN ? ELSE public_ipv4 END,public_ipv6=?,agent_version=?,applied_version=?,apply_error=?,
	 month_rx=month_rx+?,month_tx=month_tx+?,last_rx_total=?,last_tx_total=?,online=1 WHERE id=?`,
		Now(), st, hb.PublicIPv4, hb.PublicIPv4, hb.PublicIPv6, hb.AgentVersion, hb.ConfigVersion, hb.ApplyError, dRx, dTx, rx, tx, id)
	return err
}

func (s *Store) SetServerOnline(id int64, online bool) error {
	_, err := s.DB.Exec(`UPDATE servers SET online=? WHERE id=?`, b2i(online), id)
	return err
}

func (s *Store) SetServerUnlock(id int64, data string) error {
	_, err := s.DB.Exec(`UPDATE servers SET unlock_json=? WHERE id=?`, data, id)
	return err
}

func (s *Store) ResetServerMonthTraffic(id int64) error {
	_, err := s.DB.Exec(`UPDATE servers SET month_rx=0,month_tx=0 WHERE id=?`, id)
	return err
}

// ======================= nodes =======================

type Node struct {
	ID              int64              `json:"id"`
	ServerID        int64              `json:"server_id"`
	Name            string             `json:"name"`
	Core            string             `json:"core"`
	Protocol        string             `json:"protocol"`
	Listen          string             `json:"listen"`
	Port            int                `json:"port"`
	Address         string             `json:"address"`
	EgressIP        string             `json:"egress_ip"`
	Settings        proto.NodeSettings `json:"settings"`
	Rate            float64            `json:"rate"`
	Groups          string             `json:"groups"`
	Sort            int                `json:"sort"`
	Enabled         bool               `json:"enabled"`
	Source          string             `json:"source"`
	PanelID         int64              `json:"panel_id"`
	PanelNodeID     int64              `json:"panel_node_id"`
	PanelNodeType   string             `json:"panel_node_type"`
	PanelSyncConfig bool               `json:"panel_sync_config"`
	SpeedLimit      int                `json:"speed_limit"`
	DeviceLimit     int                `json:"device_limit"`
	OnlineUsers     int                `json:"online_users"`
	UpTotal         int64              `json:"up_total"`
	DownTotal       int64              `json:"down_total"`
	Note            string             `json:"note"`
	CreatedAt       int64              `json:"created_at"`
	UpdatedAt       int64              `json:"updated_at"`
}

const nodeCols = `id,server_id,name,core,protocol,listen,port,address,egress_ip,settings_json,rate,groups,sort,enabled,source,panel_id,panel_node_id,panel_node_type,panel_sync_config,speed_limit,device_limit,online_users,up_total,down_total,note,created_at,updated_at`

func scanNode(sc interface{ Scan(...any) error }) (*Node, error) {
	n := &Node{}
	var st string
	var en, psc int
	err := sc.Scan(&n.ID, &n.ServerID, &n.Name, &n.Core, &n.Protocol, &n.Listen, &n.Port, &n.Address, &n.EgressIP, &st, &n.Rate, &n.Groups, &n.Sort, &en,
		&n.Source, &n.PanelID, &n.PanelNodeID, &n.PanelNodeType, &psc, &n.SpeedLimit, &n.DeviceLimit, &n.OnlineUsers, &n.UpTotal, &n.DownTotal, &n.Note, &n.CreatedAt, &n.UpdatedAt)
	if err != nil {
		return nil, err
	}
	n.Enabled, n.PanelSyncConfig = en == 1, psc == 1
	_ = json.Unmarshal([]byte(st), &n.Settings)
	return n, nil
}

func (s *Store) queryNodes(where string, args ...any) ([]*Node, error) {
	rows, err := s.DB.Query(`SELECT `+nodeCols+` FROM nodes `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Node{}
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) ListNodes() ([]*Node, error) { return s.queryNodes(`ORDER BY sort, id`) }
func (s *Store) NodesByServer(id int64) ([]*Node, error) {
	return s.queryNodes(`WHERE server_id=? ORDER BY sort, id`, id)
}
func (s *Store) PanelNodes(panelID int64) ([]*Node, error) {
	return s.queryNodes(`WHERE source='panel' AND panel_id=? ORDER BY id`, panelID)
}

func (s *Store) GetNode(id int64) (*Node, error) {
	n, err := scanNode(s.DB.QueryRow(`SELECT `+nodeCols+` FROM nodes WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return n, err
}

func (s *Store) CreateNode(n *Node) (int64, error) {
	now := Now()
	res, err := s.DB.Exec(`INSERT INTO nodes(server_id,name,core,protocol,listen,port,address,egress_ip,settings_json,rate,groups,sort,enabled,source,panel_id,panel_node_id,panel_node_type,panel_sync_config,speed_limit,device_limit,note,created_at,updated_at)
	 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		n.ServerID, n.Name, n.Core, n.Protocol, n.Listen, n.Port, n.Address, n.EgressIP, mustJSON(n.Settings), n.Rate, n.Groups, n.Sort, b2i(n.Enabled),
		n.Source, n.PanelID, n.PanelNodeID, n.PanelNodeType, b2i(n.PanelSyncConfig), n.SpeedLimit, n.DeviceLimit, n.Note, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateNode(n *Node) error {
	_, err := s.DB.Exec(`UPDATE nodes SET server_id=?,name=?,core=?,protocol=?,listen=?,port=?,address=?,egress_ip=?,settings_json=?,rate=?,groups=?,sort=?,enabled=?,source=?,panel_id=?,panel_node_id=?,panel_node_type=?,panel_sync_config=?,speed_limit=?,device_limit=?,note=?,updated_at=? WHERE id=?`,
		n.ServerID, n.Name, n.Core, n.Protocol, n.Listen, n.Port, n.Address, n.EgressIP, mustJSON(n.Settings), n.Rate, n.Groups, n.Sort, b2i(n.Enabled),
		n.Source, n.PanelID, n.PanelNodeID, n.PanelNodeType, b2i(n.PanelSyncConfig), n.SpeedLimit, n.DeviceLimit, n.Note, Now(), n.ID)
	return err
}

func (s *Store) DeleteNode(id int64) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	for _, q := range []string{`DELETE FROM nodes WHERE id=?`, `DELETE FROM panel_users WHERE node_id=?`, `DELETE FROM panel_traffic_pending WHERE node_id=?`, `DELETE FROM online_ips WHERE node_id=?`} {
		if _, err := tx.Exec(q, id); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) TouchServerNodes(serverID int64) {
	_, _ = s.DB.Exec(`UPDATE nodes SET updated_at=? WHERE server_id=?`, Now(), serverID)
}

func (s *Store) PortInUse(serverID int64, port int, exceptNode int64) bool {
	var n int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM nodes WHERE server_id=? AND port=? AND id<>?`, serverID, port, exceptNode).Scan(&n)
	return n > 0
}

// ======================= users =======================

type User struct {
	ID            int64  `json:"id"`
	UUID          string `json:"uuid"`
	Password      string `json:"password"` // optional; empty = UUID is the password
	Username      string `json:"username"`
	ExternalID    string `json:"external_id"`
	SubToken      string `json:"sub_token"`
	TrafficLimit  int64  `json:"traffic_limit"`
	Up            int64  `json:"up"`
	Down          int64  `json:"down"`
	ExpireAt      int64  `json:"expire_at"`
	SpeedLimit    int    `json:"speed_limit"`
	DeviceLimit   int    `json:"device_limit"`
	Groups        string `json:"groups"`
	ResetStrategy string `json:"reset_strategy"`
	ResetDay      int    `json:"reset_day"`
	LastResetAt   int64  `json:"last_reset_at"`
	Enabled       bool   `json:"enabled"`
	Status        string `json:"status"`
	Note          string `json:"note"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
}

const userCols = `id,uuid,password,username,external_id,sub_token,traffic_limit,up,down,expire_at,speed_limit,device_limit,groups,reset_strategy,reset_day,last_reset_at,enabled,status,note,created_at,updated_at`

func scanUser(sc interface{ Scan(...any) error }) (*User, error) {
	u := &User{}
	var en int
	err := sc.Scan(&u.ID, &u.UUID, &u.Password, &u.Username, &u.ExternalID, &u.SubToken, &u.TrafficLimit, &u.Up, &u.Down, &u.ExpireAt, &u.SpeedLimit, &u.DeviceLimit,
		&u.Groups, &u.ResetStrategy, &u.ResetDay, &u.LastResetAt, &en, &u.Status, &u.Note, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.Enabled = en == 1
	return u, nil
}

func (s *Store) queryUsers(where string, args ...any) ([]*User, error) {
	rows, err := s.DB.Query(`SELECT `+userCols+` FROM users `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) ListUsers(q string, status string, offset, limit int) ([]*User, int, error) {
	where := `WHERE 1=1`
	var args []any
	if q != "" {
		where += ` AND (username LIKE ? OR uuid LIKE ? OR external_id LIKE ? OR note LIKE ?)`
		like := "%" + q + "%"
		args = append(args, like, like, like, like)
	}
	if status != "" {
		where += ` AND status=?`
		args = append(args, status)
	}
	var total int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM users `+where, args...).Scan(&total)
	args = append(args, limit, offset)
	us, err := s.queryUsers(where+` ORDER BY id DESC LIMIT ? OFFSET ?`, args...)
	return us, total, err
}

func (s *Store) ActiveUsers() ([]*User, error) {
	return s.queryUsers(`WHERE status='active' AND enabled=1`)
}
func (s *Store) AllUsers() ([]*User, error) { return s.queryUsers(``) }

func (s *Store) getUser(where string, arg any) (*User, error) {
	u, err := scanUser(s.DB.QueryRow(`SELECT `+userCols+` FROM users WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) GetUser(id int64) (*User, error)     { return s.getUser(`id=?`, id) }
func (s *Store) UserByToken(t string) (*User, error) { return s.getUser(`sub_token=?`, t) }
func (s *Store) UserByExternal(ext string) (*User, error) {
	return s.getUser(`external_id=? AND external_id<>''`, ext)
}
func (s *Store) UserByUUID(uuid string) (*User, error)  { return s.getUser(`uuid=?`, uuid) }
func (s *Store) UserByUsername(n string) (*User, error) { return s.getUser(`username=?`, n) }

func (s *Store) CreateUser(u *User) (int64, error) {
	now := Now()
	res, err := s.DB.Exec(`INSERT INTO users(uuid,password,username,external_id,sub_token,traffic_limit,up,down,expire_at,speed_limit,device_limit,groups,reset_strategy,reset_day,last_reset_at,enabled,status,note,created_at,updated_at)
	 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.UUID, u.Password, u.Username, u.ExternalID, u.SubToken, u.TrafficLimit, u.Up, u.Down, u.ExpireAt, u.SpeedLimit, u.DeviceLimit, u.Groups, u.ResetStrategy, u.ResetDay, now, b2i(u.Enabled), u.Status, u.Note, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateUser(u *User) error {
	_, err := s.DB.Exec(`UPDATE users SET uuid=?,password=?,username=?,external_id=?,sub_token=?,traffic_limit=?,up=?,down=?,expire_at=?,speed_limit=?,device_limit=?,groups=?,reset_strategy=?,reset_day=?,last_reset_at=?,enabled=?,status=?,note=?,updated_at=? WHERE id=?`,
		u.UUID, u.Password, u.Username, u.ExternalID, u.SubToken, u.TrafficLimit, u.Up, u.Down, u.ExpireAt, u.SpeedLimit, u.DeviceLimit, u.Groups, u.ResetStrategy, u.ResetDay, u.LastResetAt, b2i(u.Enabled), u.Status, u.Note, Now(), u.ID)
	return err
}

func (s *Store) DeleteUser(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

func (s *Store) AddUserTraffic(id, up, down int64) error {
	_, err := s.DB.Exec(`UPDATE users SET up=up+?,down=down+? WHERE id=?`, up, down, id)
	return err
}

// ComputeStatus derives the user status from limits.
func (u *User) ComputeStatus(now int64) string {
	switch {
	case !u.Enabled:
		return "disabled"
	case u.ExpireAt > 0 && u.ExpireAt <= now:
		return "expired"
	case u.TrafficLimit > 0 && u.Up+u.Down >= u.TrafficLimit:
		return "exhausted"
	}
	return "active"
}

// ======================= panel users =======================

type PanelUser struct {
	NodeID      int64
	RemoteID    int64
	UUID        string
	Password    string
	SpeedLimit  int
	DeviceLimit int
}

func (s *Store) ReplacePanelUsers(nodeID int64, users []PanelUser) (changed bool, err error) {
	old, err := s.PanelUsers(nodeID)
	if err != nil {
		return false, err
	}
	if samePanelUsers(old, users) {
		return false, nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(`DELETE FROM panel_users WHERE node_id=?`, nodeID); err != nil {
		tx.Rollback()
		return false, err
	}
	st, err := tx.Prepare(`INSERT OR REPLACE INTO panel_users(node_id,remote_id,uuid,password,speed_limit,device_limit) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return false, err
	}
	for _, u := range users {
		if _, err := st.Exec(nodeID, u.RemoteID, u.UUID, u.Password, u.SpeedLimit, u.DeviceLimit); err != nil {
			st.Close()
			tx.Rollback()
			return false, err
		}
	}
	st.Close()
	if _, err := tx.Exec(`UPDATE nodes SET updated_at=? WHERE id=?`, Now(), nodeID); err != nil {
		tx.Rollback()
		return false, err
	}
	return true, tx.Commit()
}

func samePanelUsers(a, b []PanelUser) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[int64]PanelUser, len(a))
	for _, u := range a {
		m[u.RemoteID] = u
	}
	for _, u := range b {
		o, ok := m[u.RemoteID]
		if !ok || o.UUID != u.UUID || o.Password != u.Password || o.SpeedLimit != u.SpeedLimit || o.DeviceLimit != u.DeviceLimit {
			return false
		}
	}
	return true
}

func (s *Store) PanelUsers(nodeID int64) ([]PanelUser, error) {
	rows, err := s.DB.Query(`SELECT node_id,remote_id,uuid,password,speed_limit,device_limit FROM panel_users WHERE node_id=? ORDER BY remote_id`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PanelUser
	for rows.Next() {
		var u PanelUser
		if err := rows.Scan(&u.NodeID, &u.RemoteID, &u.UUID, &u.Password, &u.SpeedLimit, &u.DeviceLimit); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) PanelUserCount(nodeID int64) int {
	var n int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM panel_users WHERE node_id=?`, nodeID).Scan(&n)
	return n
}

func (s *Store) AddPanelTraffic(nodeID, remoteID, up, down int64) error {
	_, err := s.DB.Exec(`INSERT INTO panel_traffic_pending(node_id,remote_id,up,down) VALUES(?,?,?,?)
	 ON CONFLICT(node_id,remote_id) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`, nodeID, remoteID, up, down)
	return err
}

type PendingTraffic struct {
	RemoteID int64
	Up, Down int64
}

func (s *Store) PendingPanelTraffic(nodeID int64) ([]PendingTraffic, error) {
	rows, err := s.DB.Query(`SELECT remote_id,up,down FROM panel_traffic_pending WHERE node_id=? AND (up>0 OR down>0)`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingTraffic
	for rows.Next() {
		var p PendingTraffic
		if err := rows.Scan(&p.RemoteID, &p.Up, &p.Down); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SubtractPanelTraffic removes exactly what was pushed, so traffic that arrived during the push is kept.
func (s *Store) SubtractPanelTraffic(nodeID int64, items []PendingTraffic) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	for _, p := range items {
		if _, err := tx.Exec(`UPDATE panel_traffic_pending SET up=up-?, down=down-? WHERE node_id=? AND remote_id=?`, p.Up, p.Down, nodeID, p.RemoteID); err != nil {
			tx.Rollback()
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM panel_traffic_pending WHERE node_id=? AND up<=0 AND down<=0`, nodeID); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ======================= panels =======================

type Panel struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	BaseURL      string `json:"base_url"`
	Token        string `json:"token"`
	Enabled      bool   `json:"enabled"`
	SyncInterval int    `json:"sync_interval"`
	LastSyncAt   int64  `json:"last_sync_at"`
	LastError    string `json:"last_error"`
	CreatedAt    int64  `json:"created_at"`
}

func (s *Store) ListPanels() ([]*Panel, error) {
	rows, err := s.DB.Query(`SELECT id,name,type,base_url,token,enabled,sync_interval,last_sync_at,last_error,created_at FROM panels ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Panel{}
	for rows.Next() {
		p := &Panel{}
		var en int
		if err := rows.Scan(&p.ID, &p.Name, &p.Type, &p.BaseURL, &p.Token, &en, &p.SyncInterval, &p.LastSyncAt, &p.LastError, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.Enabled = en == 1
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetPanel(id int64) (*Panel, error) {
	ps, err := s.ListPanels()
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) CreatePanel(p *Panel) (int64, error) {
	res, err := s.DB.Exec(`INSERT INTO panels(name,type,base_url,token,enabled,sync_interval,created_at) VALUES(?,?,?,?,?,?,?)`,
		p.Name, p.Type, strings.TrimRight(p.BaseURL, "/"), p.Token, b2i(p.Enabled), p.SyncInterval, Now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdatePanel(p *Panel) error {
	_, err := s.DB.Exec(`UPDATE panels SET name=?,type=?,base_url=?,token=?,enabled=?,sync_interval=? WHERE id=?`,
		p.Name, p.Type, strings.TrimRight(p.BaseURL, "/"), p.Token, b2i(p.Enabled), p.SyncInterval, p.ID)
	return err
}

func (s *Store) SetPanelSync(id int64, errMsg string) {
	_, _ = s.DB.Exec(`UPDATE panels SET last_sync_at=?, last_error=? WHERE id=?`, Now(), errMsg, id)
}

func (s *Store) DeletePanel(id int64) error {
	var n int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM nodes WHERE panel_id=? AND source='panel'`, id).Scan(&n)
	if n > 0 {
		return errors.New("还有节点绑定到这个面板，请先解绑")
	}
	_, err := s.DB.Exec(`DELETE FROM panels WHERE id=?`, id)
	return err
}

// ======================= traffic =======================

func (s *Store) AddHourly(hour, nodeID, userID, up, down int64) error {
	_, err := s.DB.Exec(`INSERT INTO traffic_hourly(hour,node_id,user_id,up,down) VALUES(?,?,?,?,?)
	 ON CONFLICT(hour,node_id,user_id) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`, hour, nodeID, userID, up, down)
	return err
}

func (s *Store) AddNodeTotals(nodeID, up, down int64) error {
	_, err := s.DB.Exec(`UPDATE nodes SET up_total=up_total+?, down_total=down_total+? WHERE id=?`, up, down, nodeID)
	return err
}

type TrafficPoint struct {
	T    int64 `json:"t"`
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// TrafficSeries returns traffic grouped by bucket seconds (3600 or 86400). tzOffset shifts day buckets to local time.
func (s *Store) TrafficSeries(filterCol string, filterVal int64, since int64, bucket int64, tzOffset int64) ([]TrafficPoint, error) {
	q := `SELECT ((hour+?)/?)*?-? AS b, SUM(up), SUM(down) FROM traffic_hourly WHERE hour>=?`
	args := []any{tzOffset, bucket, bucket, tzOffset, since}
	switch filterCol {
	case "node":
		q += ` AND node_id=? AND user_id=0`
		args = append(args, filterVal)
	case "user":
		q += ` AND user_id=?`
		args = append(args, filterVal)
	case "server":
		q += ` AND user_id=0 AND node_id IN (SELECT id FROM nodes WHERE server_id=?)`
		args = append(args, filterVal)
	default:
		q += ` AND user_id=0`
	}
	q += ` GROUP BY b ORDER BY b`
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrafficPoint{}
	for rows.Next() {
		var p TrafficPoint
		if err := rows.Scan(&p.T, &p.Up, &p.Down); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type RankRow struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

func (s *Store) TopUsers(since int64, limit int) ([]RankRow, error) {
	rows, err := s.DB.Query(`SELECT t.user_id, COALESCE(u.username, u.uuid, ''), SUM(t.up), SUM(t.down) FROM traffic_hourly t LEFT JOIN users u ON u.id=t.user_id
	 WHERE t.hour>=? AND t.user_id>0 GROUP BY t.user_id ORDER BY SUM(t.up+t.down) DESC LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RankRow{}
	for rows.Next() {
		var r RankRow
		var name sql.NullString
		if err := rows.Scan(&r.ID, &name, &r.Up, &r.Down); err != nil {
			return nil, err
		}
		r.Name = name.String
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) TopNodes(since int64, limit int) ([]RankRow, error) {
	rows, err := s.DB.Query(`SELECT t.node_id, COALESCE(n.name,''), SUM(t.up), SUM(t.down) FROM traffic_hourly t LEFT JOIN nodes n ON n.id=t.node_id
	 WHERE t.hour>=? AND t.user_id=0 GROUP BY t.node_id ORDER BY SUM(t.up+t.down) DESC LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RankRow{}
	for rows.Next() {
		var r RankRow
		var name sql.NullString
		if err := rows.Scan(&r.ID, &name, &r.Up, &r.Down); err != nil {
			return nil, err
		}
		r.Name = name.String
		out = append(out, r)
	}
	return out, rows.Err()
}

// ======================= online ips =======================

func (s *Store) TouchOnline(nodeID int64, key, ip string, now int64) error {
	_, err := s.DB.Exec(`INSERT INTO online_ips(node_id,user_key,ip,last_seen) VALUES(?,?,?,?) ON CONFLICT(node_id,user_key,ip) DO UPDATE SET last_seen=excluded.last_seen`,
		nodeID, key, ip, now)
	return err
}

type OnlineIP struct {
	NodeID   int64  `json:"node_id"`
	UserKey  string `json:"user_key"`
	IP       string `json:"ip"`
	LastSeen int64  `json:"last_seen"`
}

func (s *Store) OnlineIPs(nodeID int64, since int64) ([]OnlineIP, error) {
	q := `SELECT node_id,user_key,ip,last_seen FROM online_ips WHERE last_seen>=?`
	args := []any{since}
	if nodeID > 0 {
		q += ` AND node_id=?`
		args = append(args, nodeID)
	}
	rows, err := s.DB.Query(q+` ORDER BY node_id,user_key`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OnlineIP{}
	for rows.Next() {
		var o OnlineIP
		if err := rows.Scan(&o.NodeID, &o.UserKey, &o.IP, &o.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) RefreshNodeOnlineCounts(since int64) {
	_, _ = s.DB.Exec(`UPDATE nodes SET online_users=(SELECT COUNT(DISTINCT user_key) FROM online_ips o WHERE o.node_id=nodes.id AND o.last_seen>=?)`, since)
}

// ======================= commands =======================

func (s *Store) QueueCommand(serverID int64, typ, arg string) (int64, error) {
	now := Now()
	res, err := s.DB.Exec(`INSERT INTO commands(server_id,type,arg,created_at,updated_at) VALUES(?,?,?,?,?)`, serverID, typ, arg, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) TakeCommands(serverID int64) ([]proto.Command, error) {
	rows, err := s.DB.Query(`SELECT id,type,arg FROM commands WHERE server_id=? AND status='pending' ORDER BY id`, serverID)
	if err != nil {
		return nil, err
	}
	var out []proto.Command
	for rows.Next() {
		var c proto.Command
		if err := rows.Scan(&c.ID, &c.Type, &c.Arg); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, c)
	}
	rows.Close()
	for _, c := range out {
		_, _ = s.DB.Exec(`UPDATE commands SET status='sent', updated_at=? WHERE id=?`, Now(), c.ID)
	}
	return out, nil
}

func (s *Store) FinishCommand(serverID int64, r proto.CommandResult) {
	st := "done"
	if !r.OK {
		st = "failed"
	}
	_, _ = s.DB.Exec(`UPDATE commands SET status=?, output=?, updated_at=? WHERE id=? AND server_id=?`, st, r.Output, Now(), r.ID, serverID)
}

type CommandRow struct {
	ID        int64  `json:"id"`
	ServerID  int64  `json:"server_id"`
	Type      string `json:"type"`
	Arg       string `json:"arg"`
	Status    string `json:"status"`
	Output    string `json:"output"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

func (s *Store) ListCommands(serverID int64, limit int) ([]CommandRow, error) {
	rows, err := s.DB.Query(`SELECT id,server_id,type,arg,status,output,created_at,updated_at FROM commands WHERE server_id=? ORDER BY id DESC LIMIT ?`, serverID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CommandRow{}
	for rows.Next() {
		var c CommandRow
		if err := rows.Scan(&c.ID, &c.ServerID, &c.Type, &c.Arg, &c.Status, &c.Output, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ======================= webhooks =======================

type Webhook struct {
	ID         int64  `json:"id"`
	URL        string `json:"url"`
	Secret     string `json:"secret"`
	Events     string `json:"events"`
	Enabled    bool   `json:"enabled"`
	LastStatus string `json:"last_status"`
	CreatedAt  int64  `json:"created_at"`
}

func (s *Store) ListWebhooks() ([]*Webhook, error) {
	rows, err := s.DB.Query(`SELECT id,url,secret,events,enabled,last_status,created_at FROM webhooks ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Webhook{}
	for rows.Next() {
		w := &Webhook{}
		var en int
		if err := rows.Scan(&w.ID, &w.URL, &w.Secret, &w.Events, &en, &w.LastStatus, &w.CreatedAt); err != nil {
			return nil, err
		}
		w.Enabled = en == 1
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) CreateWebhook(w *Webhook) (int64, error) {
	res, err := s.DB.Exec(`INSERT INTO webhooks(url,secret,events,enabled,created_at) VALUES(?,?,?,?,?)`, w.URL, w.Secret, w.Events, b2i(w.Enabled), Now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateWebhook(w *Webhook) error {
	_, err := s.DB.Exec(`UPDATE webhooks SET url=?,events=?,enabled=? WHERE id=?`, w.URL, w.Events, b2i(w.Enabled), w.ID)
	return err
}

func (s *Store) SetWebhookStatus(id int64, st string) {
	_, _ = s.DB.Exec(`UPDATE webhooks SET last_status=? WHERE id=?`, st, id)
}

func (s *Store) DeleteWebhook(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM webhooks WHERE id=?`, id)
	return err
}

// ======================= idempotency =======================

type IdemRecord struct {
	Request   string
	Response  string
	Status    int
	CreatedAt int64
}

func (s *Store) IdemGet(key string) (*IdemRecord, bool) {
	r := &IdemRecord{}
	err := s.DB.QueryRow(`SELECT request,response,status,created_at FROM idempotency WHERE key=?`, key).Scan(&r.Request, &r.Response, &r.Status, &r.CreatedAt)
	return r, err == nil
}

func (s *Store) IdemPut(key, request, resp string, status int) {
	_, _ = s.DB.Exec(`INSERT OR IGNORE INTO idempotency(key,request,response,status,created_at) VALUES(?,?,?,?,?)`, key, request, resp, status, Now())
}

// UserByPassword finds the user with a custom connection password.
func (s *Store) UserByPassword(pw string) (*User, error) {
	return s.getUser(`password=? AND password<>''`, pw)
}

func (s *Store) GetCommand(id int64) (*CommandRow, error) {
	c := &CommandRow{}
	err := s.DB.QueryRow(`SELECT id,server_id,type,arg,status,output,created_at,updated_at FROM commands WHERE id=?`, id).
		Scan(&c.ID, &c.ServerID, &c.Type, &c.Arg, &c.Status, &c.Output, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}
