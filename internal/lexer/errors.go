package lexer

import (
	"fmt"

	"github.com/cawalch/go-yara/token"
)

// Error represents a recoverable lexical error with precise position information.
// Note: Errors are surfaced to consumers via ILLEGAL tokens today. This structured type
// is provided for future use in higher-level APIs that may stream tokens alongside errors.
type Error struct {
	Position token.Position
	Message  string
}

func (e *Error) Error() string {
	return fmt.Sprintf("lexical error at L%d:C%d: %s", e.Position.Line, e.Position.Column, e.Message)
}
