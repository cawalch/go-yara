// Package testutils provides common utilities and patterns for compiler testing
package testutils

import (
	"testing"
)

// AssertNoError is a helper to assert no error occurred
func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// AssertError is a helper to assert an error occurred
func AssertError(t *testing.T, err error, expectedMsg string) {
	t.Helper()
	if err == nil {
		t.Fatal("Expected error but got none")
	}
	if expectedMsg != "" && err.Error() != expectedMsg {
		t.Fatalf("Expected error message %q, got %q", expectedMsg, err.Error())
	}
}

// AssertEqual is a helper to assert two values are equal
func AssertEqual[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Fatalf("Expected %v, got %v", want, got)
	}
}

// AssertNotEqual is a helper to assert two values are not equal
func AssertNotEqual[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got == want {
		t.Fatalf("Expected values to be different, but both are %v", got)
	}
}

// AssertTrue is a helper to assert a condition is true
func AssertTrue(t *testing.T, condition bool, msg string) {
	t.Helper()
	if !condition {
		t.Fatalf("Expected true, got false. %s", msg)
	}
}

// AssertFalse is a helper to assert a condition is false
func AssertFalse(t *testing.T, condition bool, msg string) {
	t.Helper()
	if condition {
		t.Fatalf("Expected false, got true. %s", msg)
	}
}
