package echobasicauth

import (
	"testing"
)

func TestNewValidator(t *testing.T) {
	auth := &Auth{Login: "test", Password: "test", IPs: []string{"127.0.0.1"}}
	validator := NewValidator(auth)
	if validator == nil {
		t.Error("NewValidator() should not return nil")
	}
}

func TestNewValidator_NoArgs(t *testing.T) {
	validator := NewValidator()
	if validator != nil {
		t.Error("NewValidator() should return nil")
	}
}

func TestNewValidator_Nil(t *testing.T) {
	validator := NewValidator(nil)
	if validator != nil {
		t.Error("NewValidator() should return nil")
	}
}

func TestNewMiddleware(t *testing.T) {
	auth := &Auth{Login: "test", Password: "test", IPs: []string{"127.0.0.1"}}
	middleware := NewMiddleware(auth)
	if middleware == nil {
		t.Error("NewMiddleware() should not return nil")
	}
}

func TestEquals(t *testing.T) {
	if !Equals("test", "test") {
		t.Error("Equals() should return true")
	}
}
