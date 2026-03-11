package echobasicauth

import (
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

func TestParseIPsCalledOnce(t *testing.T) {
	auth := &Auth{IPs: []string{"192.168.1.1"}}
	auth.AllowedIP("0.0.0.0")

	// mutate IPs after first parse
	auth.IPs = append(auth.IPs, "10.0.0.1")
	auth.AllowedIP("0.0.0.0")

	// should still have only the original IP since sync.Once prevents re-parsing
	if len(auth.parsedIPs) != 1 {
		t.Errorf("expected parseIPs to run only once, got parsedIPs: %v", auth.parsedIPs)
	}
}

func TestAllowedIPConcurrent(_ *testing.T) {
	auth := &Auth{IPs: []string{"192.168.1.1", "10.0.0.0/24"}}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			auth.AllowedIP("192.168.1.1")
			auth.AllowedIP("10.0.0.5")
			auth.AllowedIP("8.8.8.8")
		}()
	}
	wg.Wait()
}
