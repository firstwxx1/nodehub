package store

import (
	"database/sql"
	"encoding/json"
	"errors"
)

type IPCheck struct {
	ID          int64           `json:"id"`
	NodeID      int64           `json:"node_id"`
	ServerID    int64           `json:"server_id"`
	IP          string          `json:"ip"`
	Native      bool            `json:"native"`
	RegCountry  string          `json:"reg_country"`
	GeoCountry  string          `json:"geo_country"`
	GeoCity     string          `json:"geo_city"`
	ConnType    string          `json:"conn_type"`
	DualISP     bool            `json:"dual_isp"`
	IsProxy     bool            `json:"is_proxy"`
	IsVPN       bool            `json:"is_vpn"`
	IsTor       bool            `json:"is_tor"`
	IsAbuse     bool            `json:"is_abuse"`
	IsHosting   bool            `json:"is_hosting"`
	FraudScore  int             `json:"fraud_score"`
	FraudSource string          `json:"fraud_source"`
	ASN         string          `json:"asn"`
	Org         string          `json:"org"`
	Raw         json.RawMessage `json:"raw,omitempty"`
	Error       string          `json:"error"`
	CheckedAt   int64           `json:"checked_at"`
}

func (c *IPCheck) Risky() bool {
	return c.IsProxy || c.IsVPN || c.IsTor || c.IsAbuse || c.FraudScore >= 70
}

func (s *Store) SaveIPCheck(c *IPCheck) (int64, error) {
	raw := string(c.Raw)
	if raw == "" {
		raw = "{}"
	}
	res, err := s.DB.Exec(`INSERT INTO ip_checks(node_id,server_id,ip,native,reg_country,geo_country,geo_city,conn_type,dual_isp,is_proxy,is_vpn,is_tor,is_abuse,is_hosting,fraud_score,fraud_source,asn,org,raw_json,error,checked_at)
	 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.NodeID, c.ServerID, c.IP, b2i(c.Native), c.RegCountry, c.GeoCountry, c.GeoCity, c.ConnType, b2i(c.DualISP), b2i(c.IsProxy), b2i(c.IsVPN), b2i(c.IsTor),
		b2i(c.IsAbuse), b2i(c.IsHosting), c.FraudScore, c.FraudSource, c.ASN, c.Org, raw, c.Error, c.CheckedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

const ipCols = `id,node_id,server_id,ip,native,reg_country,geo_country,geo_city,conn_type,dual_isp,is_proxy,is_vpn,is_tor,is_abuse,is_hosting,fraud_score,fraud_source,asn,org,raw_json,error,checked_at`

func scanIP(sc interface{ Scan(...any) error }, withRaw bool) (*IPCheck, error) {
	c := &IPCheck{}
	var nat, dual, px, vpn, tor, ab, host int
	var raw string
	err := sc.Scan(&c.ID, &c.NodeID, &c.ServerID, &c.IP, &nat, &c.RegCountry, &c.GeoCountry, &c.GeoCity, &c.ConnType, &dual, &px, &vpn, &tor, &ab, &host,
		&c.FraudScore, &c.FraudSource, &c.ASN, &c.Org, &raw, &c.Error, &c.CheckedAt)
	if err != nil {
		return nil, err
	}
	c.Native, c.DualISP, c.IsProxy, c.IsVPN, c.IsTor, c.IsAbuse, c.IsHosting = nat == 1, dual == 1, px == 1, vpn == 1, tor == 1, ab == 1, host == 1
	if withRaw {
		c.Raw = json.RawMessage(raw)
	}
	return c, nil
}

// LatestIPChecks returns the newest check per node.
func (s *Store) LatestIPChecks() (map[int64]*IPCheck, error) {
	rows, err := s.DB.Query(`SELECT ` + ipCols + ` FROM ip_checks WHERE id IN (SELECT MAX(id) FROM ip_checks WHERE node_id>0 GROUP BY node_id)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]*IPCheck{}
	for rows.Next() {
		c, err := scanIP(rows, false)
		if err != nil {
			return nil, err
		}
		out[c.NodeID] = c
	}
	return out, rows.Err()
}

func (s *Store) LatestIPCheck(nodeID int64) (*IPCheck, error) {
	c, err := scanIP(s.DB.QueryRow(`SELECT `+ipCols+` FROM ip_checks WHERE node_id=? ORDER BY id DESC LIMIT 1`, nodeID), true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func (s *Store) IPCheckHistory(nodeID int64, limit int) ([]*IPCheck, error) {
	rows, err := s.DB.Query(`SELECT `+ipCols+` FROM ip_checks WHERE node_id=? ORDER BY id DESC LIMIT ?`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*IPCheck{}
	for rows.Next() {
		c, err := scanIP(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Server-level checks (node_id = 0) cover servers that have no nodes yet.

func (s *Store) LatestServerIPChecks() (map[int64]*IPCheck, error) {
	rows, err := s.DB.Query(`SELECT ` + ipCols + ` FROM ip_checks WHERE id IN (SELECT MAX(id) FROM ip_checks WHERE node_id=0 GROUP BY server_id)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]*IPCheck{}
	for rows.Next() {
		c, err := scanIP(rows, false)
		if err != nil {
			return nil, err
		}
		out[c.ServerID] = c
	}
	return out, rows.Err()
}

func (s *Store) LatestServerIPCheck(serverID int64) (*IPCheck, error) {
	c, err := scanIP(s.DB.QueryRow(`SELECT `+ipCols+` FROM ip_checks WHERE node_id=0 AND server_id=? ORDER BY id DESC LIMIT 1`, serverID), true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func (s *Store) ServerIPCheckHistory(serverID int64, limit int) ([]*IPCheck, error) {
	rows, err := s.DB.Query(`SELECT `+ipCols+` FROM ip_checks WHERE node_id=0 AND server_id=? ORDER BY id DESC LIMIT ?`, serverID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*IPCheck
	for rows.Next() {
		c, err := scanIP(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
