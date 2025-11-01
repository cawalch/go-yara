package semantic

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

const themKeyword = "them"

// StringValidator handles validation of string references and patterns
type StringValidator struct {
	symbolTable *SymbolTable
	errors      []error
}

// NewStringValidator creates a new string validator
func NewStringValidator(symbolTable *SymbolTable) *StringValidator {
	return &StringValidator{
		symbolTable: symbolTable,
		errors:      make([]error, 0),
	}
}

// ValidateStringReferences validates all string references in expressions
func (sv *StringValidator) ValidateStringReferences(expr ast.Expression) []error {
	sv.errors = sv.errors[:0] // Clear previous errors
	sv.collectStringReferences(expr)
	return sv.errors
}

// collectStringReferences recursively collects string references from expressions
func (sv *StringValidator) collectStringReferences(expr ast.Expression) {
	switch e := expr.(type) {
	case *ast.Identifier:
		// Check if this is a string reference ($s1, $a*, etc.)
		if sv.isStringReference(e.Name) {
			sv.validateStringReference(e.Name, e.Position())
		}

	case *ast.BinaryOp:
		// Handle quantifier expressions like "all of them", "any of ($a*)"
		if e.Op == token.OF {
			sv.validateQuantifierExpression(e, e.Position())
		} else {
			sv.collectStringReferences(e.Left)
			sv.collectStringReferences(e.Right)
		}

	case *ast.UnaryOp:
		sv.collectStringReferences(e.Right)

	default:
		// For other expression types, no string references to collect
	}
}

// isStringReference checks if an identifier is a string reference
func (sv *StringValidator) isStringReference(name string) bool {
	return strings.HasPrefix(name, "$") && len(name) > 1
}

// validateStringReference validates a single string reference
func (sv *StringValidator) validateStringReference(ref string, pos token.Position) {
	// Handle wildcard patterns like $a*, $s?, $*
	if sv.containsWildcard(ref) {
		sv.validateWildcardReference(ref, pos)
		return
	}

	// Handle specific string references like $s1, $mz
	if symbol, exists := sv.symbolTable.Lookup(ref); exists {
		if symbol.Type == SymbolString {
			symbol.Used = true
		} else {
			sv.addError(&Error{
				Message:  fmt.Sprintf("identifier %q is not a string", ref),
				Position: pos,
			})
		}
	} else {
		sv.addError(&Error{
			Message:  fmt.Sprintf("undefined string %q", ref),
			Position: pos,
		})
	}
}

// validateWildcardReference validates wildcard string references
func (sv *StringValidator) validateWildcardReference(ref string, pos token.Position) {
	// Check if this is a "them" reference
	if sv.isThemReference(ref) {
		return // "them" refers to all strings in the current rule, always valid
	}

	// For specific patterns like $a*, check if any strings match
	if !sv.findMatchingString(ref, pos) {
		sv.addError(&Error{
			Message:  fmt.Sprintf("no strings match pattern %q", ref),
			Position: pos,
		})
	}
}

// isThemReference checks if the reference is a "them" reference
func (sv *StringValidator) isThemReference(ref string) bool {
	return ref == "$*" || ref == "$"
}

// findMatchingString searches for strings matching the given pattern
func (sv *StringValidator) findMatchingString(ref string, _ token.Position) bool {
	base := strings.TrimPrefix(ref, "$")
	scope := sv.symbolTable.Current

	for scope != nil {
		for _, symbol := range scope.Symbols {
			if symbol.Type == SymbolString && sv.matchesPattern(symbol.Name, base) {
				symbol.Used = true
				return true
			}
		}
		scope = scope.Parent
	}

	return false
}

// validateQuantifierExpression validates quantifier expressions like "all of them"
func (sv *StringValidator) validateQuantifierExpression(expr *ast.BinaryOp, pos token.Position) {
	left := expr.Left
	right := expr.Right

	// Left side should be a quantifier (all, any, none) or number
	var err error

	switch l := left.(type) {
	case *ast.Identifier:
		// Quantifier is valid (all, any, none, or number)
		_ = l.Name
	case *ast.Literal:
		if l.Type != token.INTEGER_LIT {
			err = errors.New("invalid quantifier type")
		}
	default:
		err = errors.New("invalid quantifier expression")
	}

	if err != nil {
		sv.addError(&Error{
			Message:  err.Error(),
			Position: pos,
		})
		return
	}

	// Right side should be "them" or a string pattern
	switch r := right.(type) {
	case *ast.Identifier:
		switch {
		case r.Name == themKeyword:
			// "all of them" - validate that we have strings in current rule
			sv.validateThemReference(r.Position())
		case sv.isStringReference(r.Name):
			// "all of ($a*)" - validate the string pattern
			sv.validateStringReference(r.Name, r.Position())
		default:
			sv.addError(&Error{
				Message:  "invalid quantifier target: " + r.Name,
				Position: r.Position(),
			})
		}

	default:
		sv.addError(&Error{
			Message:  fmt.Sprintf("quantifier requires '%s' or string pattern", themKeyword),
			Position: pos,
		})
	}
}

// validateThemReference validates a "them" reference
func (sv *StringValidator) validateThemReference(pos token.Position) {
	// Check if we have any strings in the current rule scope
	scope := sv.symbolTable.Current
	hasStrings := false

	for scope != nil {
		for _, symbol := range scope.Symbols {
			if symbol.Type == SymbolString {
				symbol.Used = true
				hasStrings = true
			}
		}
		if hasStrings {
			break
		}
		scope = scope.Parent
	}

	if !hasStrings {
		sv.addError(&Error{
			Message:  fmt.Sprintf("'%s' refers to no strings in this rule", themKeyword),
			Position: pos,
		})
	}
}

// containsWildcard checks if a string reference contains wildcards
func (sv *StringValidator) containsWildcard(ref string) bool {
	return strings.Contains(ref, "*") || strings.Contains(ref, "?")
}

// matchesPattern checks if a string name matches a wildcard pattern
func (sv *StringValidator) matchesPattern(name, pattern string) bool {
	// Simple pattern matching for wildcards
	// In a full implementation, this would use proper regex or glob matching

	// Handle "*" wildcard (matches anything after)
	if before, ok := strings.CutSuffix(pattern, "*"); ok {
		prefix := before
		return strings.HasPrefix(name, prefix)
	}

	// Handle "?" wildcard (matches single character)
	if strings.Contains(pattern, "?") {
		// Simple implementation - in practice, use regex
		regexPattern := strings.ReplaceAll(pattern, "?", ".")
		matched, err := regexp.MatchString("^"+regexPattern+"$", name)
		if err != nil {
			// Invalid regex pattern, treat as no match
			return false
		}
		return matched
	}

	// Exact match
	return name == pattern
}

// addError adds a validation error
func (sv *StringValidator) addError(err error) {
	sv.errors = append(sv.errors, err)
}

// GetErrors returns all validation errors
func (sv *StringValidator) GetErrors() []error {
	return sv.errors
}

// HasErrors returns true if there are validation errors
func (sv *StringValidator) HasErrors() bool {
	return len(sv.errors) > 0
}
