package echobasicauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestClientIP(t *testing.T) {
	newEcho := func(extractor echo.IPExtractor) *echo.Echo {
		e := echo.New()
		e.IPExtractor = extractor
		e.GET("/", func(c echo.Context) error { return c.String(http.StatusOK, ClientIP(c)) })
		return e
	}

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set(echo.HeaderXForwardedFor, "10.9.9.9")

	rec := httptest.NewRecorder()
	newEcho(nil).ServeHTTP(rec, req)
	if got := rec.Body.String(); got != "127.0.0.1" {
		t.Errorf("expected transport peer without an extractor, got %q", got)
	}

	rec = httptest.NewRecorder()
	newEcho(echo.ExtractIPFromXFFHeader()).ServeHTTP(rec, req)
	if got := rec.Body.String(); got != "10.9.9.9" {
		t.Errorf("expected configured extractor to be honored, got %q", got)
	}

	req.RemoteAddr = "not-a-peer"
	rec = httptest.NewRecorder()
	newEcho(nil).ServeHTTP(rec, req)
	if got := rec.Body.String(); got != "" {
		t.Errorf("expected unparseable peer to resolve to an empty IP, got %q", got)
	}
}

func TestClientIPCanonicalizesIP(t *testing.T) {
	// non-canonical (uppercase) IPv6 coming from the extractor is normalized to canonical form
	e := echo.New()
	e.IPExtractor = echo.ExtractIPFromXFFHeader()
	e.GET("/", func(c echo.Context) error { return c.String(http.StatusOK, ClientIP(c)) })

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set(echo.HeaderXForwardedFor, "2001:DB8::1")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if got := rec.Body.String(); got != "2001:db8::1" {
		t.Errorf("expected extractor IP to be canonicalized, got %q", got)
	}
}

func TestClientIPRejectsNonIP(t *testing.T) {
	// without an extractor, an unparseable remote address resolves to an empty IP so the allowlist denies it
	e := echo.New()
	e.GET("/", func(c echo.Context) error { return c.String(http.StatusOK, ClientIP(c)) })
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "evil.com:1234"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if got := rec.Body.String(); got != "" {
		t.Errorf("expected non-IP remote address to resolve to an empty IP, got %q", got)
	}
}

func TestAnonymizeIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"not-an-ip", "invalid"},
		{"1.2.3.4 - FAIL [01/Jan/2020:00:00:00 +0000]", "invalid"},
		{"10.9.9.0/24", "invalid"},
		{"192.168.1.100", "192.168.1.0"},
		{"10.0.0.1", "10.0.0.0"},
		{"::1", "::"},
		{"2001:db8::1", "2001:db8::"},
	}

	for _, test := range tests {
		result := anonymizeIP(test.input)
		if result != test.expected {
			t.Errorf("anonymizeIP(%q) = %q, expected %q", test.input, result, test.expected)
		}
	}
}
