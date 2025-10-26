// Package semantic implements semantic analysis and validation for YARA rules.
// It provides symbol table management, type checking, and semantic validation.
package semantic

import (
	"fmt"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// SymbolType represents the type of a symbol in the symbol table
type SymbolType int

const (
	// SymbolRule represents a rule symbol
	SymbolRule SymbolType = iota
	// SymbolString represents a string symbol
	SymbolString
	// SymbolVariable represents a variable symbol
	SymbolVariable
	// SymbolFunction represents a function symbol
	SymbolFunction
)

// Symbol represents a symbol in the symbol table
type Symbol struct {
	Name     string
	Type     SymbolType
	Position token.Position
	Node     interface{} // Reference to AST node
	Scope    *Scope
	IsGlobal bool
	Used     bool // Track if symbol is referenced
}

// Scope represents a scope in the symbol table (global, rule, etc.)
type Scope struct {
	Name     string
	Parent   *Scope
	Symbols  map[string]*Symbol
	Children []*Scope
	Level    int // Nesting level (0 = global)
}

// SymbolTable manages all symbols across different scopes
type SymbolTable struct {
	Root    *Scope
	Current *Scope
	Errors  []error
}

// NewSymbolTable creates a new symbol table
func NewSymbolTable() *SymbolTable {
	root := &Scope{
		Name:     "global",
		Parent:   nil,
		Symbols:  make(map[string]*Symbol),
		Children: make([]*Scope, 0),
		Level:    0,
	}

	return &SymbolTable{
		Root:    root,
		Current: root,
		Errors:  make([]error, 0),
	}
}

// EnterScope creates a new scope and makes it current
func (st *SymbolTable) EnterScope(name string) {
	scope := &Scope{
		Name:     name,
		Parent:   st.Current,
		Symbols:  make(map[string]*Symbol),
		Children: make([]*Scope, 0),
		Level:    st.Current.Level + 1,
	}

	st.Current.Children = append(st.Current.Children, scope)
	st.Current = scope
}

// ExitScope exits the current scope and returns to parent
func (st *SymbolTable) ExitScope() {
	if st.Current.Parent != nil {
		st.Current = st.Current.Parent
	}
}

// DefineRule adds a rule symbol to the current scope
func (st *SymbolTable) DefineRule(name string, pos token.Position, rule *ast.Rule) error {
	if existing, exists := st.Current.Symbols[name]; exists {
		return fmt.Errorf("rule %q already defined at %v (previously at %v)",
			name, pos, existing.Position)
	}

	symbol := &Symbol{
		Name:     name,
		Type:     SymbolRule,
		Position: pos,
		Node:     rule,
		Scope:    st.Current,
		IsGlobal: st.Current.Level == 0,
		Used:     false,
	}

	st.Current.Symbols[name] = symbol
	return nil
}

// DefineString adds a string symbol to the current scope
func (st *SymbolTable) DefineString(name string, pos token.Position, str *ast.String) error {
	if existing, exists := st.Current.Symbols[name]; exists {
		return fmt.Errorf("string %q already defined at %v (previously at %v)",
			name, pos, existing.Position)
	}

	symbol := &Symbol{
		Name:     name,
		Type:     SymbolString,
		Position: pos,
		Node:     str,
		Scope:    st.Current,
		IsGlobal: st.Current.Level == 0,
		Used:     false,
	}

	st.Current.Symbols[name] = symbol
	return nil
}

// DefineVariable adds a variable symbol to the current scope
func (st *SymbolTable) DefineVariable(name string, pos token.Position, varType SymbolType) error {
	if existing, exists := st.Current.Symbols[name]; exists {
		return fmt.Errorf("variable %q already defined at %v (previously at %v)",
			name, pos, existing.Position)
	}

	symbol := &Symbol{
		Name:     name,
		Type:     varType,
		Position: pos,
		Node:     nil,
		Scope:    st.Current,
		IsGlobal: st.Current.Level == 0,
		Used:     false,
	}

	st.Current.Symbols[name] = symbol
	return nil
}

// Lookup searches for a symbol by name, starting from current scope
func (st *SymbolTable) Lookup(name string) (*Symbol, bool) {
	scope := st.Current
	for scope != nil {
		if symbol, exists := scope.Symbols[name]; exists {
			return symbol, true
		}
		scope = scope.Parent
	}
	return nil, false
}

// LookupInCurrentScope searches for a symbol only in the current scope
func (st *SymbolTable) LookupInCurrentScope(name string) (*Symbol, bool) {
	symbol, exists := st.Current.Symbols[name]
	return symbol, exists
}

// LookupInGlobalScope searches for a symbol only in the global scope
func (st *SymbolTable) LookupInGlobalScope(name string) (*Symbol, bool) {
	symbol, exists := st.Root.Symbols[name]
	return symbol, exists
}

// MarkUsed marks a symbol as used (referenced)
func (st *SymbolTable) MarkUsed(name string) {
	if symbol, exists := st.Lookup(name); exists {
		symbol.Used = true
	}
}

// GetUnusedSymbols returns all symbols that are defined but never used
func (st *SymbolTable) GetUnusedSymbols() []*Symbol {
	var unused []*Symbol
	st.collectUnusedSymbols(st.Root, &unused)
	return unused
}

// collectUnusedSymbols recursively collects unused symbols
func (st *SymbolTable) collectUnusedSymbols(scope *Scope, unused *[]*Symbol) {
	for _, symbol := range scope.Symbols {
		if !symbol.Used {
			*unused = append(*unused, symbol)
		}
	}

	for _, child := range scope.Children {
		st.collectUnusedSymbols(child, unused)
	}
}

// AddError adds a semantic error to the error list
func (st *SymbolTable) AddError(err error) {
	st.Errors = append(st.Errors, err)
}

// GetErrors returns all semantic errors
func (st *SymbolTable) GetErrors() []error {
	return st.Errors
}

// HasErrors returns true if there are semantic errors
func (st *SymbolTable) HasErrors() bool {
	return len(st.Errors) > 0
}

// Reset clears all errors
func (st *SymbolTable) Reset() {
	st.Errors = st.Errors[:0]
}
