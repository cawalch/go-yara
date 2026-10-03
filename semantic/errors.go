package semantic

import (
	"fmt"
	"strings"

	"github.com/cawalch/go-yara/token"
)

// ErrorCode represents a machine-readable diagnostic error code.
type ErrorCode = string

// Diagnostic error codes for semantic analysis.
const (
	ErrCodeUndefinedIdentifier  ErrorCode = "undefined-identifier"
	ErrCodeTypeMismatch         ErrorCode = "type-mismatch"
	ErrCodeCircularDependency   ErrorCode = "circular-dependency"
	ErrCodeDuplicateRule        ErrorCode = "duplicate-rule"
	ErrCodeDuplicateString      ErrorCode = "duplicate-string"
	ErrCodeDuplicateVariable    ErrorCode = "duplicate-variable"
	ErrCodeDuplicateMeta        ErrorCode = "duplicate-meta"
	ErrCodeUnsupportedModule    ErrorCode = "unsupported-module"
	ErrCodeInvalidCondition     ErrorCode = "invalid-condition"
	ErrCodeInvalidFunction      ErrorCode = "invalid-function"
	ErrCodeInvalidArgumentCount ErrorCode = "invalid-argument-count"
	ErrCodeInvalidArgumentType  ErrorCode = "invalid-argument-type"
	ErrCodeInvalidModifier      ErrorCode = "invalid-modifier"
	ErrCodeInvalidEvidence      ErrorCode = "invalid-evidence"
	ErrCodeInvalidLoop          ErrorCode = "invalid-loop"
	ErrCodeInvalidOperation     ErrorCode = "invalid-operation"
	ErrCodeInvalidStringOp      ErrorCode = "invalid-string-operation"
	ErrCodeInvalidVariable      ErrorCode = "invalid-variable"
)

// Error represents a semantic analysis error with structured diagnostic details.
type Error struct {
	Code       ErrorCode      // Machine-readable diagnostic error code
	Message    string         // Human-readable error message
	Position   token.Position // Source position where the error occurred
	Rule       string         // Name of the enclosing rule (if applicable)
	Suggestion string         // Optional suggested correction (e.g. "did you mean ...?")
}

// Error formats the semantic error as a human-readable string including line, column,
// message, and any available suggestion.
func (e *Error) Error() string {
	msg := e.Message
	if e.Suggestion != "" && !strings.Contains(msg, e.Suggestion) {
		msg = fmt.Sprintf("%s; did you mean %s?", msg, e.Suggestion)
	}
	return fmt.Sprintf("semantic error at %d:%d: %s",
		e.Position.Line, e.Position.Column, msg)
}

// NewError creates a new semantic Error with the given code, message, and position.
func NewError(code, message string, pos token.Position) *Error {
	return &Error{
		Code:     code,
		Message:  message,
		Position: pos,
	}
}

// WithRule sets the rule name on the error and returns it for chaining.
func (e *Error) WithRule(rule string) *Error {
	e.Rule = rule
	return e
}

// WithSuggestion sets the suggestion on the error and returns it for chaining.
func (e *Error) WithSuggestion(suggestion string) *Error {
	e.Suggestion = suggestion
	return e
}

// WithCode sets the error code on the error and returns it for chaining.
func (e *Error) WithCode(code string) *Error {
	e.Code = code
	return e
}

// IsUndefinedIdentifier reports whether the error represents an undefined identifier.
func (e *Error) IsUndefinedIdentifier() bool {
	return e.Code == ErrCodeUndefinedIdentifier
}

// IsTypeMismatch reports whether the error represents a type mismatch.
func (e *Error) IsTypeMismatch() bool {
	return e.Code == ErrCodeTypeMismatch
}

// IsCircularDependency reports whether the error represents a circular rule dependency.
func (e *Error) IsCircularDependency() bool {
	return e.Code == ErrCodeCircularDependency
}

// IsDuplicate reports whether the error represents any duplicate definition.
func (e *Error) IsDuplicate() bool {
	return e.Code == ErrCodeDuplicateRule ||
		e.Code == ErrCodeDuplicateString ||
		e.Code == ErrCodeDuplicateVariable ||
		e.Code == ErrCodeDuplicateMeta
}
