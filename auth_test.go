package echobasicauth

import (
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/labstack/echo/v4"
	// This is just for the echo context setup, not for assertions in the test itself
)

func TestIsIPAllowed(t *testing.T) {
	validIPs := []string{"192.168.1.1", "10.0.0.1"}
	_, validCIDR1, _ := net.ParseCIDR("192.168.1.0/24")
	validCIDRs := []*net.IPNet{validCIDR1}

	tests := []struct {
		ip         string
		shouldPass bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"192.168.1.15", true}, // Inside CIDR
		{"192.168.2.1", false},
	}

	for _, test := range tests {
		result := isIPAllowed(validIPs, validCIDRs, test.ip)
		if result != test.shouldPass {
			t.Errorf("expected isIPAllowed for %s to be %v, got %v", test.ip, test.shouldPass, result)
		}
	}
}

func TestParseIPs(t *testing.T) {
	auths := []*Auth{
		{IPs: []string{"192.168.1.1", "10.0.0.0/24"}},
		{IPs: []string{"8.8.8.8"}},
	}

	validIPs, validCIDRs := parseIPs(auths...)

	if len(validIPs) != 2 || len(validCIDRs) != 2 {
		t.Fatalf("unexpected parse result count")
	}

	if !slices.Contains(validIPs[0], "192.168.1.1") || len(validCIDRs[0]) != 1 {
		t.Errorf("unexpected parsing for auth 0")
	}

	if !slices.Contains(validIPs[1], "8.8.8.8") || len(validCIDRs[1]) != 0 {
		t.Errorf("unexpected parsing for auth 1")
	}
}

func TestEquals(t *testing.T) {
	tests := []struct {
		a, b        string
		shouldEqual bool
	}{
		{"password", "password", true},
		{"pass", "word", false},
		{"same", "same", true},
		{"", "", true},
	}

	for _, test := range tests {
		if Equals(test.a, test.b) != test.shouldEqual {
			t.Errorf("Equals(%q, %q) expected %v", test.a, test.b, test.shouldEqual)
		}
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
