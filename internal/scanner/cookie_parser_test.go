package scanner

import "testing"

func TestParseCookies_Simple(t *testing.T) {
	cookies := ParseCookies("session=abc123; csrftoken=xyz789")
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
	if cookies[0].Name != "session" || cookies[0].Value != "abc123" {
		t.Errorf("cookie[0]: got %s=%s", cookies[0].Name, cookies[0].Value)
	}
	if cookies[1].Name != "csrftoken" || cookies[1].Value != "xyz789" {
		t.Errorf("cookie[1]: got %s=%s", cookies[1].Name, cookies[1].Value)
	}
}

func TestParseCookies_EqualsInValue(t *testing.T) {
	cookies := ParseCookies("token=abc=def=ghi")
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Value != "abc=def=ghi" {
		t.Errorf("expected value 'abc=def=ghi', got %q", cookies[0].Value)
	}
}

func TestParseCookies_Empty(t *testing.T) {
	cookies := ParseCookies("")
	if len(cookies) != 0 {
		t.Fatalf("expected 0 cookies, got %d", len(cookies))
	}
}

func TestParseCookies_LeadingTrailingSpaces(t *testing.T) {
	cookies := ParseCookies("  a=1 ;  b=2  ")
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
	if cookies[0].Name != "a" || cookies[0].Value != "1" {
		t.Errorf("cookie[0]: got %s=%s", cookies[0].Name, cookies[0].Value)
	}
}

func TestParseCookies_SingleCookie(t *testing.T) {
	cookies := ParseCookies("session=abc")
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
}

func TestParseCookies_HttpCookieType(t *testing.T) {
	cookies := ParseCookies("a=1; b=2")
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
	if cookies[0].Name != "a" || cookies[0].Value != "1" {
		t.Errorf("cookie[0]: got %s=%s", cookies[0].Name, cookies[0].Value)
	}
	if cookies[1].Name != "b" || cookies[1].Value != "2" {
		t.Errorf("cookie[1]: got %s=%s", cookies[1].Name, cookies[1].Value)
	}
}
