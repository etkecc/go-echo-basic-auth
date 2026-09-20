package echobasicauth

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
)

// Auth model
type Auth struct {
	Login    string   `json:"login" yaml:"login"` // Basic auth login
	Password string   `json:"password" yaml:"password"`
	IPs      []string `json:"ips" yaml:"ips"` // Allowed IPs and CIDRs

	mu          sync.RWMutex // guards the parsed rules below
	parsed      bool         // whether parsedIPs and parsedCIDRs match the current IPs field
	parsedFrom  []string     // copy of the IPs field the parsed rules were built from
	parsedIPs   []string     // parsed plain IPs from the IPs field, used by AllowedIP
	parsedCIDRs []*net.IPNet // parsed CIDRs from the IPs field, used by AllowedIP
}

// parseEntry classifies an allowlist entry as a CIDR or a plain IP, returning both as nil when it is neither
func parseEntry(entry string) (*net.IPNet, net.IP) {
	if _, ipnet, err := net.ParseCIDR(entry); err == nil {
		return ipnet, nil
	}
	return nil, net.ParseIP(entry)
}

// rules returns the parsed allowlist, rebuilt whenever the IPs field changed since the last call
func (a *Auth) rules() ([]string, []*net.IPNet) {
	a.mu.RLock()
	current := a.parsed && slices.Equal(a.parsedFrom, a.IPs)
	parsedIPs, parsedCIDRs := a.parsedIPs, a.parsedCIDRs
	a.mu.RUnlock()
	if current {
		return parsedIPs, parsedCIDRs
	}

	parsedIPs = []string{}
	parsedCIDRs = []*net.IPNet{}
	for _, entry := range a.IPs {
		ipnet, ip := parseEntry(entry)
		if ipnet != nil {
			parsedCIDRs = append(parsedCIDRs, ipnet)
		} else if ip != nil {
			parsedIPs = append(parsedIPs, entry)
		}
	}

	a.mu.Lock()
	a.parsed = true
	a.parsedFrom = slices.Clone(a.IPs)
	a.parsedIPs = parsedIPs
	a.parsedCIDRs = parsedCIDRs
	a.mu.Unlock()
	return parsedIPs, parsedCIDRs
}

// AllowedIP checks if the given IP is allowed by this Auth's IP rules
func (a *Auth) AllowedIP(ip string) bool {
	parsedIPs, parsedCIDRs := a.rules()
	if len(parsedIPs) == 0 && len(parsedCIDRs) == 0 {
		// No configured entries mean no IP restriction, unparseable entries deny everyone
		return len(a.IPs) == 0
	}

	if len(parsedIPs) != 0 && slices.Contains(parsedIPs, ip) {
		return true
	}

	if len(parsedCIDRs) != 0 {
		parsed := net.ParseIP(ip)
		for _, ipnet := range parsedCIDRs {
			if ipnet.Contains(parsed) {
				return true
			}
		}
	}

	return false
}

// Validate reports allowlist entries that are neither an IP nor a CIDR, so a typo fails the boot
func (a *Auth) Validate() error {
	errs := make([]error, 0, len(a.IPs))
	for _, entry := range a.IPs {
		ipnet, ip := parseEntry(entry)
		if ipnet == nil && ip == nil {
			errs = append(errs, fmt.Errorf("invalid IP or CIDR %q", entry))
		}
	}
	return errors.Join(errs...)
}
