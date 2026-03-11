package echobasicauth

import "testing"

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
		if equals(test.a, test.b) != test.shouldEqual {
			t.Errorf("equals(%q, %q) expected %v", test.a, test.b, test.shouldEqual)
		}
	}
}

func TestAnonymizeIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"not-an-ip", "not-an-ip"},
		{"192.168.1.100", "192.168.1.0"},
		{"10.0.0.1", "10.0.0.0"},
		{"::1", "::0"},
		{"2001:db8::1", "2001:db8::0"},
	}

	for _, test := range tests {
		result := anonymizeIP(test.input)
		if result != test.expected {
			t.Errorf("anonymizeIP(%q) = %q, expected %q", test.input, result, test.expected)
		}
	}
}
