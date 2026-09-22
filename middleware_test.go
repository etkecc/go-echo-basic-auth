package echobasicauth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	gommonlog "github.com/labstack/gommon/log"
)

func TestNewValidatorNil(t *testing.T) {
	if NewValidator() != nil {
		t.Error("expected nil validator for no auths")
	}
	if NewValidator(nil) != nil {
		t.Error("expected nil validator for single nil auth")
	}
	if NewValidator(nil, nil) != nil {
		t.Error("expected nil validator for all nil auths")
	}
}

func TestNewValidatorNilFiltering(t *testing.T) {
	auth := &Auth{Login: "user", Password: "pass"}
	validator := NewValidator(nil, auth, nil)
	if validator == nil {
		t.Fatal("expected non-nil validator when valid auth is present among nils")
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if valid, _ := validator("user", "pass", c); !valid {
		t.Error("expected valid credentials to pass with nil-filtered auths")
	}
}

func TestNewValidatorMultipleAuths(t *testing.T) {
	auths := []*Auth{
		{Login: "admin", Password: "admin123"},
		{Login: "user", Password: "user456"},
	}

	validator := NewValidator(auths...)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if valid, _ := validator("admin", "admin123", c); !valid {
		t.Error("expected first auth to pass")
	}
	if valid, _ := validator("user", "user456", c); !valid {
		t.Error("expected second auth to pass")
	}
	if valid, _ := validator("admin", "user456", c); valid {
		t.Error("expected mismatched credentials to fail")
	}
}

func TestNewValidatorSetsContextLogin(t *testing.T) {
	auth := &Auth{Login: "myuser", Password: "mypass"}
	validator := NewValidator(auth)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	_, _ = validator("myuser", "mypass", c)
	login, ok := c.Get(ContextLoginKey).(string)
	if !ok || login != "myuser" {
		t.Errorf("expected context login to be 'myuser', got %q", login)
	}
}

func TestNewMiddleware(t *testing.T) {
	auth := &Auth{Login: "user", Password: "pass"}
	mw := NewMiddleware(auth)
	if mw == nil {
		t.Fatal("expected non-nil middleware")
	}
}

func TestNewValidator(t *testing.T) {
	auths := []*Auth{
		{Login: "user1", Password: "pass1", IPs: []string{"127.0.0.1"}},
	}

	validator := NewValidator(auths...)
	if validator == nil {
		t.Fatal("expected non-nil validator")
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Valid credentials and IP
	c.Request().RemoteAddr = "127.0.0.1:12345"
	if valid, _ := validator("user1", "pass1", c); !valid {
		t.Error("Expected valid credentials to pass")
	}

	// Invalid IP
	c.Request().RemoteAddr = "192.168.1.2:12345"
	if valid, _ := validator("user1", "pass1", c); valid {
		t.Error("Expected invalid IP to fail")
	}

	// Invalid credentials
	c.Request().RemoteAddr = "127.0.0.1:12345"
	if valid, _ := validator("user1", "wrongpass", c); valid {
		t.Error("Expected invalid credentials to fail")
	}
}

func TestNewValidatorEmptyConfiguredCredsNeverMatch(t *testing.T) {
	// Empty configured creds must reject even empty presented creds, else a dropped secret degrades to IP-only auth.
	validator := NewValidator(&Auth{Login: "", Password: ""})
	if validator == nil {
		t.Fatal("expected non-nil validator")
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if valid, _ := validator("", "", c); valid {
		t.Error("empty configured creds matched empty presented creds")
	}
	if valid, _ := validator("anything", "anything", c); valid {
		t.Error("empty configured creds matched presented creds")
	}
}

func TestNewValidatorBcrypt(t *testing.T) {
	auths := []*Auth{
		{Login: "admin", Password: bcryptPassword(t, "s3cr3t"), IPs: []string{"127.0.0.1"}},
	}
	validator := NewValidator(auths...)
	if validator == nil {
		t.Fatal("expected non-nil validator")
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	c.Request().RemoteAddr = "127.0.0.1:12345"
	if valid, _ := validator("admin", "s3cr3t", c); !valid {
		t.Error("expected bcrypt password to match from an allowed IP")
	}

	c.Request().RemoteAddr = "127.0.0.1:12345"
	if valid, _ := validator("admin", "nope", c); valid {
		t.Error("expected wrong password to fail")
	}

	c.Request().RemoteAddr = "10.9.9.9:12345"
	if valid, _ := validator("admin", "s3cr3t", c); valid {
		t.Error("expected disallowed IP to fail even with valid bcrypt creds")
	}
}

func TestNewValidatorRejectsForwardedHeaderSpoof(t *testing.T) {
	auth := &Auth{Login: "admin", Password: "s3cr3t", IPs: []string{"10.9.9.9"}}

	e := echo.New()
	e.Use(NewMiddleware(auth))
	e.GET("/admin", func(c echo.Context) error { return c.NoContent(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set(echo.HeaderXForwardedFor, "10.9.9.9")
	req.Header.Set(echo.HeaderXRealIP, "10.9.9.9")
	req.SetBasicAuth("admin", "s3cr3t")

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected forwarded headers to be ignored, got status %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
	req.RemoteAddr = "10.9.9.9:1234"
	req.SetBasicAuth("admin", "s3cr3t")

	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected whitelisted peer to pass, got status %d", rec.Code)
	}
}

func TestNewMiddlewareEmptyAuthsDenies(t *testing.T) {
	// an empty or all-nil auth list must yield a working deny-all middleware at wiring time
	mws := map[string]echo.MiddlewareFunc{
		"no args": NewMiddleware(),
		"all nil": NewMiddleware(nil, nil),
	}
	for label, mw := range mws {
		if mw == nil {
			t.Fatalf("%s: expected non-nil middleware", label)
		}

		e := echo.New()
		e.Use(mw)
		e.GET("/admin", func(c echo.Context) error { return c.NoContent(http.StatusOK) })

		req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
		req.SetBasicAuth("admin", "s3cr3t")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: expected 401 from the empty-auth middleware, got %d", label, rec.Code)
		}
	}
}

func TestLogAttemptVisibleAtWarnLevel(t *testing.T) {
	auth := &Auth{Login: "admin", Password: "s3cr3t"}

	e := echo.New()
	sink := &bytes.Buffer{}
	e.Logger.SetOutput(sink)
	e.Logger.SetLevel(gommonlog.WARN)
	e.Use(NewMiddleware(auth))
	e.GET("/admin", func(c echo.Context) error { return c.NoContent(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
	req.RemoteAddr = "203.0.113.7:1234"
	req.SetBasicAuth("admin", "wrong")
	e.ServeHTTP(httptest.NewRecorder(), req)

	if !strings.Contains(sink.String(), "FAIL") {
		t.Errorf("expected failed attempt to be logged at WARN level, got %q", sink.String())
	}
}

func TestLogAttemptDropsUnparsedPeerInput(t *testing.T) {
	auth := &Auth{Login: "admin", Password: "s3cr3t"}

	e := echo.New()
	sink := &bytes.Buffer{}
	e.Logger.SetOutput(sink)
	e.Logger.SetLevel(gommonlog.WARN)
	e.Use(NewMiddleware(auth))
	e.GET("/admin", func(c echo.Context) error { return c.NoContent(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
	req.RemoteAddr = "1.2.3.4 - FAIL [01/Jan/2020:00:00:00 +0000]"
	req.SetBasicAuth("admin", "wrong")
	e.ServeHTTP(httptest.NewRecorder(), req)

	if strings.Contains(sink.String(), "01/Jan/2020") {
		t.Errorf("expected log to drop unparsed peer input, got %q", sink.String())
	}
	if strings.Contains(sink.String(), "1.2.3.4") {
		t.Errorf("expected log to drop the raw peer, got %q", sink.String())
	}
	// unparseable peers resolve to an empty client IP, so the line starts with an empty address
	if !strings.Contains(sink.String(), " - FAIL") {
		t.Errorf("expected empty client IP in the log, got %q", sink.String())
	}
}
