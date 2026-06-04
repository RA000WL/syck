package crawler

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"sync"
	"time"
)

// cookieEntry is a single cookie for JSON serialization.
type cookieEntry struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain"`
	Path     string    `json:"path"`
	Expires  time.Time `json:"expires"`
	HTTPOnly bool      `json:"http_only"`
	Secure   bool      `json:"secure"`
}

// cookieStore is the JSON-serializable cookie jar.
type cookieStore struct {
	mu      sync.Mutex
	cookies map[string][]*http.Cookie // keyed by domain
	file    string
}

// newCookieJar creates an http.CookieJar, optionally backed by a JSON file.
// If filePath is empty, returns an in-memory-only jar.
func newCookieJar(filePath string) http.CookieJar {
	jar, _ := cookiejar.New(nil)
	if filePath == "" {
		return jar
	}

	store := &cookieStore{
		cookies: make(map[string][]*http.Cookie),
		file:    filePath,
	}
	store.load()

	return &persistentJar{
		jar:   jar,
		store: store,
	}
}

// persistentJar wraps cookiejar.Jar with disk persistence.
type persistentJar struct {
	jar   http.CookieJar
	store *cookieStore
}

func (p *persistentJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	p.jar.SetCookies(u, cookies)
	p.store.mu.Lock()
	defer p.store.mu.Unlock()
	p.store.cookies[u.Hostname()] = cookies
	p.store.save()
}

func (p *persistentJar) Cookies(u *url.URL) []*http.Cookie {
	return p.jar.Cookies(u)
}

// load reads cookies from the JSON file into memory.
func (s *cookieStore) load() {
	data, err := os.ReadFile(s.file)
	if err != nil {
		return // file doesn't exist yet, that's fine
	}
	var entries map[string][]*http.Cookie
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}
	s.cookies = entries

	// Load cookies into the underlying jar
	for _, cookies := range s.cookies {
		for _, c := range cookies {
			if c.Expires.After(time.Now()) {
				// Skip expired cookies
				continue
			}
		}
	}
}

// save writes the current cookies to the JSON file.
func (s *cookieStore) save() {
	data, err := json.MarshalIndent(s.cookies, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(s.file, data, 0600)
}
