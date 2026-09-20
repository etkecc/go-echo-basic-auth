package echobasicauth

import (
	"strings"
	"sync"
	"testing"
)

func TestParseIPs(t *testing.T) {
	auth0 := &Auth{IPs: []string{"192.168.1.1", "10.0.0.0/24"}}
	auth1 := &Auth{IPs: []string{"8.8.8.8"}}

	// trigger lazy parsing via AllowedIP
	auth0.AllowedIP("0.0.0.0")
	auth1.AllowedIP("0.0.0.0")

	if len(auth0.parsedIPs) != 1 || auth0.parsedIPs[0] != "192.168.1.1" {
		t.Errorf("unexpected parsed IPs for auth0: %v", auth0.parsedIPs)
	}
	if len(auth0.parsedCIDRs) != 1 {
		t.Errorf("unexpected parsed CIDRs for auth0: %v", auth0.parsedCIDRs)
	}

	if len(auth1.parsedIPs) != 1 || auth1.parsedIPs[0] != "8.8.8.8" {
		t.Errorf("unexpected parsed IPs for auth1: %v", auth1.parsedIPs)
	}
	if len(auth1.parsedCIDRs) != 0 {
		t.Errorf("unexpected parsed CIDRs for auth1: %v", auth1.parsedCIDRs)
	}
}

func TestAllowedIP(t *testing.T) {
	auth := &Auth{IPs: []string{"192.168.1.1", "10.0.0.1", "192.168.1.0/24"}}

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
		result := auth.AllowedIP(test.ip)
		if result != test.shouldPass {
			t.Errorf("expected AllowedIP for %s to be %v, got %v", test.ip, test.shouldPass, result)
		}
	}
}

func TestAllowedIPNoRestrictions(t *testing.T) {
	auth := &Auth{}

	if !auth.AllowedIP("1.2.3.4") {
		t.Error("expected any IP to be allowed when no IPs configured")
	}
}

func TestAllowedIPCIDROnly(t *testing.T) {
	auth := &Auth{IPs: []string{"10.0.0.0/8"}}

	tests := []struct {
		ip         string
		shouldPass bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"192.168.1.1", false},
	}

	for _, test := range tests {
		result := auth.AllowedIP(test.ip)
		if result != test.shouldPass {
			t.Errorf("expected AllowedIP for %s to be %v, got %v", test.ip, test.shouldPass, result)
		}
	}
}

func TestParseIPsInvalidEntries(t *testing.T) {
	auth := &Auth{IPs: []string{"not-an-ip", "192.168.1.1", "also-invalid"}}
	auth.AllowedIP("0.0.0.0")

	if len(auth.parsedIPs) != 1 || auth.parsedIPs[0] != "192.168.1.1" {
		t.Errorf("expected only valid IPs, got: %v", auth.parsedIPs)
	}
	if len(auth.parsedCIDRs) != 0 {
		t.Errorf("expected no CIDRs, got: %v", auth.parsedCIDRs)
	}
}

func TestAllowedIPFollowsChangedIPs(t *testing.T) {
	auth := &Auth{IPs: []string{"127.0.0.1"}}
	if !auth.AllowedIP("127.0.0.1") {
		t.Fatal("expected configured IP to be allowed")
	}

	auth.IPs = []string{"10.0.0.1"}
	if auth.AllowedIP("127.0.0.1") {
		t.Error("expected revoked IP to be denied once IPs changed")
	}
	if !auth.AllowedIP("10.0.0.1") {
		t.Error("expected added IP to be allowed once IPs changed")
	}
}

func TestAllowedIPUnparseableEntriesDeny(t *testing.T) {
	tests := []struct {
		name string
		ips  []string
	}{
		{"out of range prefix", []string{"10.0.0.0/33"}},
		{"unsupported range syntax", []string{"10.0.0.1-10.0.0.9"}},
		{"unsupported wildcard", []string{"10.0.0.*"}},
		{"empty entry", []string{""}},
	}

	for _, test := range tests {
		auth := &Auth{IPs: test.ips}
		if auth.AllowedIP("203.0.113.7") {
			t.Errorf("%s: expected %v to deny everyone, got an open allowlist", test.name, test.ips)
		}
	}
}

func TestAllowedIPValidEntryGovernsUnparseableOne(t *testing.T) {
	auth := &Auth{IPs: []string{"10.0.0.0/8", "10.0.0.0/33"}}

	if !auth.AllowedIP("10.1.2.3") {
		t.Error("expected valid CIDR to allow its range")
	}
	if auth.AllowedIP("203.0.113.7") {
		t.Error("expected outside IP to stay denied")
	}
}

func TestValidate(t *testing.T) {
	valid := &Auth{IPs: []string{"127.0.0.1", "10.0.0.0/24", "::1", "2001:db8::/32"}}
	if err := valid.Validate(); err != nil {
		t.Errorf("expected valid entries to pass, got %v", err)
	}
	if err := (&Auth{}).Validate(); err != nil {
		t.Errorf("expected no entries to pass, got %v", err)
	}

	invalid := &Auth{IPs: []string{"10.0.0.0/33", "10.0.0.1-10.0.0.9"}}
	err := invalid.Validate()
	if err == nil {
		t.Fatal("expected unparseable entries to be reported")
	}
	if !strings.Contains(err.Error(), "10.0.0.0/33") || !strings.Contains(err.Error(), "10.0.0.1-10.0.0.9") {
		t.Errorf("expected every invalid entry in the error, got %v", err)
	}
}

func TestAllowedIPConcurrent(_ *testing.T) {
	auth := &Auth{IPs: []string{"192.168.1.1", "10.0.0.0/24"}}

	wg := sync.WaitGroup{}
	for range 100 {
		wg.Go(func() {
			auth.AllowedIP("192.168.1.1")
			auth.AllowedIP("10.0.0.5")
			auth.AllowedIP("8.8.8.8")
		})
	}
	wg.Wait()
}
