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
	// SymbolExternal represents an external variable symbol
	SymbolExternal
	// SymbolGlobal represents a global variable symbol
	SymbolGlobal
	// SymbolFunction represents a function symbol
	SymbolFunction
)

// Symbol represents a symbol in the symbol table
type Symbol struct {
	Name     string
	Type     SymbolType
	Position token.Position
	Node     any // Reference to AST node
	Scope    *Scope
	IsGlobal bool
	Used     bool // Track if symbol is referenced
	TypeInfo *TypeInfo
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
}

// NewSymbolTable creates a new symbol table
func NewSymbolTable() *SymbolTable {
	root := &Scope{
		Name:     "global",
		Parent:   nil,
		Symbols:  make(map[string]*Symbol, 64), // Pre-allocate for typical symbol count
		Children: make([]*Scope, 0, 8),         // Pre-allocate for child scopes
		Level:    0,
	}

	return &SymbolTable{
		Root:    root,
		Current: root,
	}
}

// EnterScope creates a new scope and makes it current
func (st *SymbolTable) EnterScope(name string) {
	st.EnterScopeWithCapacity(name, 0)
}

// EnterScopeWithCapacity creates a new scope with pre-sized symbol map and makes it current
func (st *SymbolTable) EnterScopeWithCapacity(name string, symbolCap int) {
	scope := &Scope{
		Name:    name,
		Parent:  st.Current,
		Symbols: make(map[string]*Symbol, symbolCap),
		Level:   st.Current.Level + 1,
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
	if name == "$" {
		return nil
	}
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

type globalVariableDefinition struct {
	name     string
	pos      token.Position
	global   *ast.GlobalVariable
	typeInfo *TypeInfo
}

func (st *SymbolTable) defineGlobalVariable(def globalVariableDefinition) error {
	current := st.Current
	st.Current = st.Root
	defer func() { st.Current = current }()

	if existing, exists := st.Current.Symbols[def.name]; exists {
		return fmt.Errorf("global variable %q already defined at %v (previously at %v)",
			def.name, def.pos, existing.Position)
	}

	st.Current.Symbols[def.name] = &Symbol{
		Name:     def.name,
		Type:     SymbolGlobal,
		Position: def.pos,
		Node:     def.global,
		Scope:    st.Current,
		IsGlobal: true,
		Used:     false,
		TypeInfo: def.typeInfo,
	}
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

// Reset clears all scopes and resets the symbol table
func (st *SymbolTable) Reset() {
	st.ResetWithCapacity(64)
}

// ResetWithCapacity clears all scopes and resets the symbol table with expected rule capacity
func (st *SymbolTable) ResetWithCapacity(ruleCount int) {
	if ruleCount < 64 {
		ruleCount = 64
	}
	root := &Scope{
		Name:     "global",
		Symbols:  make(map[string]*Symbol, ruleCount),
		Children: make([]*Scope, 0, ruleCount),
		Level:    0,
	}
	st.Root = root
	st.Current = root
}
