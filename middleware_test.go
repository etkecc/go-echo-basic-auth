package echobasicauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
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
