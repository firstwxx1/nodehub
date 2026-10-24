// Package ipcheck aggregates several IP intelligence sources into one verdict:
// native vs. broadcast IP, connection type, dual-ISP, risk flags and a fraud score.
package ipcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Keys holds optional API credentials; empty keys disable the paid sources.
type Keys struct {
	IPQS           string
	IPInfo         string
	IPAPIIs        string
	ScamalyticsURL string // e.g. https://api12.scamalytics.com/v3/youruser/
	ScamalyticsKey string
	AbuseIPDB      string
}

type Result struct {
	IP          string                     `json:"ip"`
	Native      bool                       `json:"native"`
	RegCountry  string                     `json:"reg_country"`
	GeoCountry  string                     `json:"geo_country"`
	GeoCity     string                     `json:"geo_city"`
	ConnType    string                     `json:"conn_type"`
	DualISP     bool                       `json:"dual_isp"`
	IsProxy     bool                       `json:"is_proxy"`
	IsVPN       bool                       `json:"is_vpn"`
	IsTor       bool                       `json:"is_tor"`
	IsAbuse     bool                       `json:"is_abuse"`
	IsHosting   bool                       `json:"is_hosting"`
	FraudScore  int                        `json:"fraud_score"`
	FraudSource string                     `json:"fraud_source"`
	ASN         string                     `json:"asn"`
	Org         string                     `json:"org"`
	Sources     map[string]json.RawMessage `json:"sources"`
	Errors      map[string]string          `json:"errors"`
}

type partial struct {
	name       string
	geo        string
	city       string
	reg        string
	conn       string // datacenter residential mobile business
	connWeak   bool
	ipType     string // ipapi.is company.type
	asnType    string // ipapi.is asn.type
	proxy, vpn bool
	tor, abuse bool
	hosting    bool
	score      int // -1 = none
	asn, org   string
	raw        json.RawMessage
}

var client = &http.Client{Timeout: 15 * time.Second}

func fetchJSON(ctx context.Context, u string, hdr map[string]string, out any) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "nodehub-ipcheck/1.0")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(b), 160))
	}
	if err := json.Unmarshal(b, out); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return json.RawMessage(b), nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ---------------- sources ----------------

func srcRDAP(ctx context.Context, ip string, _ Keys) (*partial, error) {
	var r struct {
		Country    string `json:"country"`
		Name       string `json:"name"`
		Port43     string `json:"port43"`
		Entities   []json.RawMessage
		Handle     string `json:"handle"`
		StartAddr  string `json:"startAddress"`
		EndAddress string `json:"endAddress"`
	}
	raw, err := fetchJSON(ctx, "https://rdap.org/ip/"+url.PathEscape(ip), nil, &r)
	if err != nil {
		return nil, err
	}
	reg := strings.ToUpper(r.Country)
	if reg == "" && strings.Contains(r.Port43, "arin") {
		reg = "US"
		if strings.Contains(strings.ToLower(string(raw)), "canada") {
			reg = "CA"
		}
	}
	// keep only the useful part of a large RDAP document
	small, _ := json.Marshal(map[string]string{"country": reg, "name": r.Name, "handle": r.Handle, "range": r.StartAddr + " - " + r.EndAddress, "whois": r.Port43})
	return &partial{name: "rdap", reg: reg, score: -1, raw: small}, nil
}

func srcIPAPI(ctx context.Context, ip string, _ Keys) (*partial, error) {
	var r struct {
		Status, Message, CountryCode, City, ISP, Org, AS string
		Mobile, Proxy, Hosting                           bool
	}
	raw, err := fetchJSON(ctx, "http://ip-api.com/json/"+url.PathEscape(ip)+"?fields=status,message,countryCode,city,isp,org,as,mobile,proxy,hosting", nil, &r)
	if err != nil {
		return nil, err
	}
	if r.Status != "success" {
		return nil, fmt.Errorf("ip-api: %s", r.Message)
	}
	p := &partial{name: "ip-api", geo: r.CountryCode, city: r.City, proxy: r.Proxy, hosting: r.Hosting, score: -1, raw: raw, org: r.ISP}
	if f := strings.Fields(r.AS); len(f) > 0 {
		p.asn = f[0]
	}
	switch {
	case r.Mobile:
		p.conn = "mobile"
	case r.Hosting:
		p.conn = "datacenter"
	default:
		p.conn, p.connWeak = "residential", true
	}
	return p, nil
}

func srcIPAPIIs(ctx context.Context, ip string, k Keys) (*partial, error) {
	type company struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		AbuserScore string `json:"abuser_score"`
	}
	type asnT struct {
		ASN         int    `json:"asn"`
		Org         string `json:"org"`
		Type        string `json:"type"`
		Country     string `json:"country"`
		AbuserScore string `json:"abuser_score"`
	}
	var r struct {
		IsDatacenter bool            `json:"is_datacenter"`
		IsProxy      bool            `json:"is_proxy"`
		IsVPN        bool            `json:"is_vpn"`
		IsTor        bool            `json:"is_tor"`
		IsAbuser     bool            `json:"is_abuser"`
		IsMobile     bool            `json:"is_mobile"`
		CompanyRaw   json.RawMessage `json:"company"`
		ASNRaw       json.RawMessage `json:"asn"`
		Location     struct {
			CountryCode string `json:"country_code"`
			City        string `json:"city"`
		} `json:"location"`
		City  string `json:"city"`
		Error string `json:"error"`
	}
	u := "https://api.ipapi.is/?q=" + url.QueryEscape(ip)
	if k.IPAPIIs != "" {
		u += "&key=" + url.QueryEscape(k.IPAPIIs)
	}
	raw, err := fetchJSON(ctx, u, nil, &r)
	if err != nil {
		return nil, err
	}
	if r.Error != "" {
		return nil, fmt.Errorf("ipapi.is: %s", r.Error)
	}
	var c company
	var a asnT
	if json.Unmarshal(r.CompanyRaw, &c) != nil || json.Unmarshal(r.ASNRaw, &a) != nil {
		// reduced keyless response: company/asn are plain strings and there are no risk flags
		var asnStr string
		_ = json.Unmarshal(r.ASNRaw, &asnStr)
		p := &partial{name: "ipapi.is", city: r.City, score: -1, raw: raw}
		if f := strings.SplitN(asnStr, " ", 2); len(f) == 2 {
			p.asn, p.org = f[0], f[1]
		}
		return p, nil
	}
	r2 := struct {
		Company company
		ASN     asnT
	}{c, a}
	p := &partial{name: "ipapi.is", geo: strings.ToUpper(r.Location.CountryCode), city: r.Location.City,
		proxy: r.IsProxy, vpn: r.IsVPN, tor: r.IsTor, abuse: r.IsAbuser, hosting: r.IsDatacenter, score: -1, raw: raw,
		ipType: r2.Company.Type, asnType: r2.ASN.Type, org: r2.ASN.Org}
	if r2.ASN.ASN > 0 {
		p.asn = fmt.Sprintf("AS%d", r2.ASN.ASN)
	}
	switch {
	case r.IsMobile:
		p.conn = "mobile"
	case r.IsDatacenter || r2.Company.Type == "hosting":
		p.conn = "datacenter"
	case r2.Company.Type == "isp":
		p.conn = "residential"
	case r2.Company.Type == "business" || r2.Company.Type == "education" || r2.Company.Type == "government":
		p.conn = "business"
	}
	return p, nil
}

func srcIPInfo(ctx context.Context, ip string, k Keys) (*partial, error) {
	if k.IPInfo == "" {
		return nil, nil
	}
	var r struct {
		Country, City, Org string
		Privacy            *struct{ VPN, Proxy, Tor, Relay, Hosting bool }
	}
	raw, err := fetchJSON(ctx, "https://ipinfo.io/"+url.PathEscape(ip)+"?token="+url.QueryEscape(k.IPInfo), nil, &r)
	if err != nil {
		return nil, err
	}
	p := &partial{name: "ipinfo", geo: r.Country, city: r.City, score: -1, raw: raw}
	if f := strings.SplitN(r.Org, " ", 2); len(f) == 2 && strings.HasPrefix(f[0], "AS") {
		p.asn, p.org = f[0], f[1]
	}
	if r.Privacy != nil {
		p.vpn, p.proxy, p.tor, p.hosting = r.Privacy.VPN, r.Privacy.Proxy, r.Privacy.Tor, r.Privacy.Hosting
	}
	return p, nil
}

func srcIPQS(ctx context.Context, ip string, k Keys) (*partial, error) {
	if k.IPQS == "" {
		return nil, nil
	}
	var r struct {
		Success        bool   `json:"success"`
		Message        string `json:"message"`
		FraudScore     int    `json:"fraud_score"`
		CountryCode    string `json:"country_code"`
		City           string `json:"city"`
		ISP            string `json:"ISP"`
		ASN            int    `json:"ASN"`
		Proxy          bool   `json:"proxy"`
		VPN            bool   `json:"vpn"`
		Tor            bool   `json:"tor"`
		RecentAbuse    bool   `json:"recent_abuse"`
		ConnectionType string `json:"connection_type"`
	}
	raw, err := fetchJSON(ctx, fmt.Sprintf("https://ipqualityscore.com/api/json/ip/%s/%s?strictness=1&allow_public_access_points=true", url.PathEscape(k.IPQS), url.PathEscape(ip)), nil, &r)
	if err != nil {
		return nil, err
	}
	if !r.Success {
		return nil, fmt.Errorf("ipqs: %s", r.Message)
	}
	p := &partial{name: "ipqs", geo: r.CountryCode, city: r.City, proxy: r.Proxy, vpn: r.VPN, tor: r.Tor, abuse: r.RecentAbuse, score: r.FraudScore, raw: raw, org: r.ISP}
	if r.ASN > 0 {
		p.asn = fmt.Sprintf("AS%d", r.ASN)
	}
	switch r.ConnectionType {
	case "Data Center":
		p.conn, p.hosting = "datacenter", true
	case "Residential":
		p.conn = "residential"
	case "Mobile":
		p.conn = "mobile"
	case "Corporate", "Education":
		p.conn = "business"
	}
	return p, nil
}

func srcScamalytics(ctx context.Context, ip string, k Keys) (*partial, error) {
	if k.ScamalyticsURL == "" || k.ScamalyticsKey == "" {
		return nil, nil
	}
	var r struct {
		Scamalytics struct {
			Status string `json:"status"`
			Error  string `json:"error"`
			Score  int    `json:"scamalytics_score"`
			Risk   string `json:"scamalytics_risk"`
			Proxy  struct {
				IsDatacenter bool `json:"is_datacenter"`
				IsVPN        bool `json:"is_vpn"`
				IsTor        bool `json:"is_tor"`
			} `json:"scamalytics_proxy"`
		} `json:"scamalytics"`
	}
	u := strings.TrimRight(k.ScamalyticsURL, "/") + "/?key=" + url.QueryEscape(k.ScamalyticsKey) + "&ip=" + url.QueryEscape(ip)
	raw, err := fetchJSON(ctx, u, nil, &r)
	if err != nil {
		return nil, err
	}
	if r.Scamalytics.Status != "ok" {
		return nil, fmt.Errorf("scamalytics: %s", r.Scamalytics.Error)
	}
	return &partial{name: "scamalytics", score: r.Scamalytics.Score, vpn: r.Scamalytics.Proxy.IsVPN, tor: r.Scamalytics.Proxy.IsTor,
		hosting: r.Scamalytics.Proxy.IsDatacenter, raw: raw}, nil
}

func srcAbuseIPDB(ctx context.Context, ip string, k Keys) (*partial, error) {
	if k.AbuseIPDB == "" {
		return nil, nil
	}
	var r struct {
		Data struct {
			Score       int    `json:"abuseConfidenceScore"`
			CountryCode string `json:"countryCode"`
			UsageType   string `json:"usageType"`
			ISP         string `json:"isp"`
			IsTor       bool   `json:"isTor"`
		} `json:"data"`
	}
	raw, err := fetchJSON(ctx, "https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress="+url.QueryEscape(ip), map[string]string{"Key": k.AbuseIPDB}, &r)
	if err != nil {
		return nil, err
	}
	p := &partial{name: "abuseipdb", geo: r.Data.CountryCode, tor: r.Data.IsTor, abuse: r.Data.Score >= 25, score: -1, raw: raw}
	switch {
	case strings.Contains(r.Data.UsageType, "Data Center"):
		p.conn, p.hosting = "datacenter", true
	case strings.Contains(r.Data.UsageType, "Mobile"):
		p.conn = "mobile"
	case strings.Contains(r.Data.UsageType, "Fixed Line ISP"):
		p.conn = "residential"
	case r.Data.UsageType != "":
		p.conn = "business"
	}
	return p, nil
}

// ---------------- aggregation ----------------

type source struct {
	name string
	fn   func(context.Context, string, Keys) (*partial, error)
}

var sources = []source{
	{"rdap", srcRDAP}, {"ip-api", srcIPAPI}, {"ipapi.is", srcIPAPIIs}, {"ipinfo", srcIPInfo},
	{"ipqs", srcIPQS}, {"scamalytics", srcScamalytics}, {"abuseipdb", srcAbuseIPDB},
}

// Check queries every configured source in parallel and merges the answers.
func Check(ctx context.Context, ip string, keys Keys) *Result {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	res := &Result{IP: ip, Sources: map[string]json.RawMessage{}, Errors: map[string]string{}, FraudScore: -1}
	var mu sync.Mutex
	var parts []*partial
	var wg sync.WaitGroup
	for _, s := range sources {
		wg.Add(1)
		go func(s source) {
			defer wg.Done()
			p, err := s.fn(ctx, ip, keys)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Errors[s.name] = err.Error()
				return
			}
			if p != nil {
				parts = append(parts, p)
				res.Sources[s.name] = p.raw
			}
		}(s)
	}
	wg.Wait()
	merge(res, parts)
	return res
}

func vote(vals []string) string {
	count := map[string]int{}
	order := []string{}
	for _, v := range vals {
		if v == "" {
			continue
		}
		if count[v] == 0 {
			order = append(order, v)
		}
		count[v]++
	}
	sort.SliceStable(order, func(i, j int) bool { return count[order[i]] > count[order[j]] })
	if len(order) == 0 {
		return ""
	}
	return order[0]
}

// hostingWords flags well-known cloud / hosting organisations so free-tier lookups don't
// mislabel a datacenter IP as residential.
var hostingWords = []string{"amazon", "aws", "google", "microsoft", "azure", "alibaba", "aliyun", "tencent", "huawei cloud", "oracle",
	"digitalocean", "linode", "akamai", "vultr", "choopa", "constant company", "hetzner", "ovh", "contabo", "leaseweb", "m247",
	"datacamp", "cloudflare", "fastly", "scaleway", "online s.a.s", "kamatera", "racknerd", "colocrossing", "buyvm", "frantech",
	"bandwagon", "it7", "dmit", "greencloud", "hostinger", "hostwinds", "ionos", "godaddy", "zenlayer", "cogent", "psychz", "quadranet",
	"ucloud", "kingsoft", "byteplus", "volcengine", "baidu", "cloud", "hosting", "host", "data center", "datacenter", "server", "vps", "idc", "colo"}

func looksHosting(org string) bool {
	o := strings.ToLower(org)
	for _, w := range hostingWords {
		if strings.Contains(o, w) {
			return true
		}
	}
	return false
}

func merge(res *Result, parts []*partial) {
	sort.Slice(parts, func(i, j int) bool { return parts[i].name < parts[j].name })
	var geos, cities, strong, weak []string
	for _, p := range parts {
		if p.reg != "" {
			res.RegCountry = p.reg
		}
		geos = append(geos, strings.ToUpper(p.geo))
		cities = append(cities, p.city)
		if p.conn != "" {
			if p.connWeak {
				weak = append(weak, p.conn)
			} else {
				strong = append(strong, p.conn)
			}
		}
		res.IsProxy = res.IsProxy || p.proxy
		res.IsVPN = res.IsVPN || p.vpn
		res.IsTor = res.IsTor || p.tor
		res.IsAbuse = res.IsAbuse || p.abuse
		res.IsHosting = res.IsHosting || p.hosting
		if p.name == "ipapi.is" {
			res.DualISP = p.ipType == "isp" && p.asnType == "isp"
			if p.asn != "" {
				res.ASN, res.Org = p.asn, p.org
			}
		}
	}
	for _, p := range parts { // fill ASN/org from any source if ipapi.is failed
		if res.ASN == "" && p.asn != "" {
			res.ASN = p.asn
		}
		if res.Org == "" && p.org != "" {
			res.Org = p.org
		}
	}
	orgHosting := looksHosting(res.Org)
	for _, p := range parts {
		orgHosting = orgHosting || looksHosting(p.org)
	}
	if orgHosting {
		strong = append(strong, "datacenter")
		res.IsHosting = true
	}
	res.GeoCountry = vote(geos)
	res.GeoCity = vote(cities)
	if res.RegCountry == "" {
		res.RegCountry = res.GeoCountry
	}
	res.Native = res.RegCountry != "" && res.RegCountry == res.GeoCountry
	res.ConnType = vote(strong)
	if res.ConnType == "" {
		res.ConnType = vote(weak)
	}
	if res.ConnType == "" {
		res.ConnType = "unknown"
	}
	// fraud score preference: IPQS > Scamalytics > estimate
	for _, name := range []string{"ipqs", "scamalytics"} {
		for _, p := range parts {
			if p.name == name && p.score >= 0 && res.FraudScore < 0 {
				res.FraudScore, res.FraudSource = p.score, name
			}
		}
	}
	if res.FraudScore < 0 && len(parts) > 0 {
		s := 0
		if res.IsHosting || res.ConnType == "datacenter" {
			s += 35
		}
		if res.IsProxy {
			s += 25
		}
		if res.IsVPN {
			s += 20
		}
		if res.IsAbuse {
			s += 25
		}
		if res.IsTor {
			s += 50
		}
		if s > 100 {
			s = 100
		}
		res.FraudScore, res.FraudSource = s, "estimate"
	}
}
