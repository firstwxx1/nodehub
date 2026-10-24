package agent

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Unlock tests run from the VPS itself, so they reflect what clients see through the node.
// They are heuristics against public pages and can break when services change their sites.

const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

var unlockClient = &http.Client{
	Timeout: 12 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func get(url string) (*http.Response, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := unlockClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return resp, string(b), nil
}

func traceLoc(base string) string {
	_, body, err := get(base + "/cdn-cgi/trace")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "loc=") {
			return strings.TrimPrefix(l, "loc=")
		}
	}
	return ""
}

func checkChatGPT() string {
	resp, body, err := get("https://ios.chat.openai.com/")
	if err != nil {
		return "error: " + shortErr(err)
	}
	loc := traceLoc("https://chatgpt.com")
	if strings.Contains(body, "unsupported_country") || strings.Contains(body, "VPN") && resp.StatusCode == 403 {
		return "no (" + loc + ")"
	}
	if resp.StatusCode == 403 && strings.Contains(body, "cf-") {
		return "blocked by Cloudflare (" + loc + ")"
	}
	return "yes (" + loc + ")"
}

func checkClaude() string {
	resp, _, err := get("https://claude.ai/")
	if err != nil {
		return "error: " + shortErr(err)
	}
	loc := traceLoc("https://claude.ai")
	if l := resp.Header.Get("Location"); strings.Contains(l, "app-unavailable-in-region") {
		return "no (" + loc + ")"
	}
	if resp.StatusCode == 403 {
		return "blocked (" + loc + ")"
	}
	return "yes (" + loc + ")"
}

func checkGemini() string {
	_, body, err := get("https://gemini.google.com/")
	if err != nil {
		return "error: " + shortErr(err)
	}
	if strings.Contains(body, "45631641,null,true") {
		return "yes"
	}
	return "no"
}

var nfRegion = regexp.MustCompile(`"currentCountry":"([A-Z]{2})"|"requestCountry":\{"id":"([A-Z]{2})"`)

func checkNetflix() string {
	// 81280792 is a Netflix original (LEGO Ninjago); 70143836 is licensed (Breaking Bad).
	r1, b1, err := get("https://www.netflix.com/title/81280792")
	if err != nil {
		return "error: " + shortErr(err)
	}
	r2, _, err := get("https://www.netflix.com/title/70143836")
	if err != nil {
		return "error: " + shortErr(err)
	}
	region := ""
	if m := nfRegion.FindStringSubmatch(b1); m != nil {
		region = m[1] + m[2]
	}
	if region == "" {
		if l := r1.Header.Get("Location"); l != "" {
			if p := strings.Split(strings.TrimPrefix(l, "https://www.netflix.com/"), "/"); len(p) > 0 && len(p[0]) <= 5 {
				region = strings.ToUpper(strings.Split(p[0], "-")[0])
			}
		}
	}
	ok1 := r1.StatusCode == 200 || r1.StatusCode == 301 || r1.StatusCode == 302
	ok2 := r2.StatusCode == 200 || r2.StatusCode == 301 || r2.StatusCode == 302
	switch {
	case r1.StatusCode == 403 || r2.StatusCode == 403:
		return "no"
	case ok1 && ok2:
		return "yes (" + orDefault(region, "US") + ")"
	case ok1:
		return "originals only (" + orDefault(region, "?") + ")"
	}
	return "no"
}

var ytRegion = regexp.MustCompile(`"countryCode":"([A-Z]{2})"`)

func checkYouTube() string {
	_, body, err := get("https://www.youtube.com/premium")
	if err != nil {
		return "error: " + shortErr(err)
	}
	if strings.Contains(body, "www.google.cn") {
		return "no (CN)"
	}
	region := ""
	if m := ytRegion.FindStringSubmatch(body); m != nil {
		region = m[1]
	}
	if strings.Contains(body, "Premium is not available in your country") {
		return "no (" + region + ")"
	}
	return "yes (" + orDefault(region, "?") + ")"
}

func checkDisney() string {
	resp, _, err := get("https://www.disneyplus.com/")
	if err != nil {
		return "error: " + shortErr(err)
	}
	l := resp.Header.Get("Location")
	if strings.Contains(l, "unavailable") || resp.StatusCode == 403 {
		return "no"
	}
	return "likely yes"
}

func checkTikTok() string {
	_, body, err := get("https://www.tiktok.com/")
	if err != nil {
		return "error: " + shortErr(err)
	}
	if m := regexp.MustCompile(`"region":"([A-Z]{2})"`).FindStringSubmatch(body); m != nil {
		return "yes (" + m[1] + ")"
	}
	return "unknown"
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 80 {
		s = s[len(s)-80:]
	}
	return s
}

// RunUnlockTests runs all checks in parallel.
func RunUnlockTests() map[string]string {
	checks := map[string]func() string{
		"ChatGPT": checkChatGPT, "Claude": checkClaude, "Gemini": checkGemini, "Netflix": checkNetflix,
		"YouTube Premium": checkYouTube, "Disney+": checkDisney, "TikTok": checkTikTok,
	}
	out := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for name, fn := range checks {
		wg.Add(1)
		go func(name string, fn func() string) {
			defer wg.Done()
			r := fn()
			mu.Lock()
			out[name] = r
			mu.Unlock()
		}(name, fn)
	}
	wg.Wait()
	return out
}
