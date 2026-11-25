package parser

import (
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/lexer"
)

func TestGlobalIntegerOverflowRejected(t *testing.T) {
	source := `global threshold = 999999999999999999999999 rule r { condition: threshold == 0 }`
	p := New(lexer.New(source))
	if _, err := p.ParseRules(); err == nil || !strings.Contains(err.Error(), "invalid integer literal") {
		t.Fatalf("ParseRules() error = %v, want invalid integer literal", err)
	}
}
