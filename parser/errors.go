package parser

import (
	"errors"
	"fmt"

	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/token"
)

// SyntaxError describes a single parser diagnostic with source position and
// optional enclosing rule name.
type SyntaxError struct {
	Rule     string
	Position token.Position
	Message  string
	Err      error
}

// Error implements the error interface.
func (e *SyntaxError) Error() string {
	switch {
	case e.Rule != "" && e.Position.Line > 0:
		return fmt.Sprintf("rule %q %s: %s", e.Rule, e.Position.String(), e.Message)
	case e.Rule != "":
		return fmt.Sprintf("rule %q: %s", e.Rule, e.Message)
	case e.Position.Line > 0:
		return fmt.Sprintf("%s: %s", e.Position.String(), e.Message)
	default:
		return e.Message
	}
}

// Unwrap returns the underlying error if any.
func (e *SyntaxError) Unwrap() error {
	return e.Err
}

// ParseError reports the collected diagnostics when strict parsing fails.
type ParseError struct {
	Errors []error
}

// Error implements the error interface.
func (pe *ParseError) Error() string {
	return formatErrorSummary("parsing failed", pe.Errors)
}

// Unwrap returns the underlying parser errors.
func (pe *ParseError) Unwrap() []error {
	return pe.Errors
}

func formatErrorSummary(prefix string, errs []error) string {
	if len(errs) == 0 {
		return prefix
	}
	if len(errs) == 1 {
		return fmt.Sprintf("%s with 1 error: %v", prefix, errs[0])
	}
	return fmt.Sprintf("%s with %d errors, first error: %v", prefix, len(errs), errs[0])
}

func newSyntaxError(pos token.Position, format string, args ...any) *SyntaxError {
	return &SyntaxError{
		Position: pos,
		Message:  fmt.Sprintf(format, args...),
	}
}

func unexpectedTokenError(tok token.Token) *SyntaxError {
	return &SyntaxError{
		Position: tok.Pos,
		Message:  "syntax error, unexpected " + tok.Display(),
	}
}

func expectedTokenError(want token.Type, got token.Token) *SyntaxError {
	return &SyntaxError{
		Position: got.Pos,
		Message:  fmt.Sprintf("expected %s, got %s", want.Display(), got.Display()),
	}
}

func withRuleContext(rule string, fallbackPos token.Position, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*lexer.Error](err); ok {
		return err
	}
	if synErr, ok := errors.AsType[*SyntaxError](err); ok {
		copyErr := *synErr
		if copyErr.Rule == "" && rule != "" {
			copyErr.Rule = rule
		}
		if copyErr.Position.Line == 0 && fallbackPos.Line > 0 {
			copyErr.Position = fallbackPos
		}
		return &copyErr
	}
	return &SyntaxError{
		Rule:     rule,
		Position: fallbackPos,
		Message:  err.Error(),
		Err:      err,
	}
}

func (p *RuleParser) wrapSectionError(section string, err error) error {
	if err == nil {
		return nil
	}
	rule := p.currentRule
	pos := p.current.Pos
	msg := err.Error()
	if synErr, ok := errors.AsType[*SyntaxError](err); ok {
		if synErr.Position.Line > 0 {
			pos = synErr.Position
		}
		if synErr.Rule != "" && rule == "" {
			rule = synErr.Rule
		}
		msg = synErr.Message
		return &SyntaxError{
			Rule:     rule,
			Position: pos,
			Message:  section + " section error: " + msg,
			Err:      err,
		}
	}
	if lexErr, ok := errors.AsType[*lexer.Error](err); ok {
		if lexErr.Position.Line > 0 {
			pos = lexErr.Position
		}
		msg = lexErr.Message
	}
	return &SyntaxError{
		Rule:     rule,
		Position: pos,
		Message:  section + " section error: " + msg,
		Err:      err,
	}
}
