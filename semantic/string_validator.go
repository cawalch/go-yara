// Package semantic implements semantic analysis and validation for YARA rules.
package semantic

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

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
			sv.addError(&SemanticError{
				Message:  fmt.Sprintf("identifier %q is not a string", ref),
				Position: pos,
			})
		}
	} else {
		sv.addError(&SemanticError{
			Message:  fmt.Sprintf("undefined string %q", ref),
			Position: pos,
		})
	}
}

// validateWildcardReference validates wildcard string references
func (sv *StringValidator) validateWildcardReference(ref string, pos token.Position) {
	// Extract the base pattern (e.g., "a" from "$a*", "s" from "$s?")
	base := strings.TrimPrefix(ref, "$")

	// For now, we'll validate that at least one string matches the pattern
	// In a full implementation, this would check against all defined strings
	found := false

	// Check if this is a "them" reference
	if ref == "$*" || ref == "$" {
		// "them" refers to all strings in the current rule
		// This is always valid if we're in a rule context
		found = true
	} else {
		// For specific patterns like $a*, check if any strings match
		// This is a simplified implementation
		scope := sv.symbolTable.Current
		for scope != nil {
			for _, symbol := range scope.Symbols {
				if symbol.Type == SymbolString {
					if sv.matchesPattern(symbol.Name, base) {
						symbol.Used = true
						found = true
						break
					}
				}
			}
			if found {
				break
			}
			scope = scope.Parent
		}
	}

	if !found {
		sv.addError(&SemanticError{
			Message:  fmt.Sprintf("no strings match pattern %q", ref),
			Position: pos,
		})
	}
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
			err = fmt.Errorf("invalid quantifier type")
		}
	default:
		err = fmt.Errorf("invalid quantifier expression")
	}

	if err != nil {
		sv.addError(&SemanticError{
			Message:  err.Error(),
			Position: pos,
		})
		return
	}

	// Right side should be "them" or a string pattern
	switch r := right.(type) {
	case *ast.Identifier:
		if r.Name == "them" {
			// "all of them" - validate that we have strings in current rule
			sv.validateThemReference(r.Position())
		} else if sv.isStringReference(r.Name) {
			// "all of ($a*)" - validate the string pattern
			sv.validateStringReference(r.Name, r.Position())
		} else {
			sv.addError(&SemanticError{
				Message:  fmt.Sprintf("invalid quantifier target: %s", r.Name),
				Position: r.Position(),
			})
		}

	default:
		sv.addError(&SemanticError{
			Message:  "quantifier requires 'them' or string pattern",
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
		sv.addError(&SemanticError{
			Message:  "'them' refers to no strings in this rule",
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
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
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