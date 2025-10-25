package semantic

import (
	"errors"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func TestSymbolTableScopes(t *testing.T) {
	st := NewSymbolTable()

	// Test entering and exiting scopes
	st.EnterScope("outer")
	pos := token.Position{Line: 1, Column: 1}

	// Define a variable in outer scope
	err := st.DefineVariable("x", pos, SymbolVariable)
	if err != nil {
		t.Errorf("DefineVariable() unexpected error: %v", err)
	}

	// Enter inner scope
	st.EnterScope("inner")

	// Variable should be visible in inner scope
	symbol, exists := st.Lookup("x")
	if !exists {
		t.Error("Lookup() should find variable from outer scope")
	}
	if symbol.Type != SymbolVariable {
		t.Errorf("Symbol type = %v, want %v", symbol.Type, SymbolVariable)
	}

	// Define a variable with same name in inner scope (shadowing)
	err = st.DefineVariable("x", pos, SymbolVariable)
	if err != nil {
		t.Errorf("DefineVariable() unexpected error for shadowing: %v", err)
	}

	// Should find the inner scope variable
	_, exists = st.Lookup("x")
	if !exists {
		t.Error("Lookup() should find inner scope variable")
	}

	// Exit inner scope
	st.ExitScope()

	// Should now find outer scope variable again
	_, exists = st.Lookup("x")
	if !exists {
		t.Error("Lookup() should find outer scope variable after exiting inner scope")
	}

	st.ExitScope()
}

func TestSymbolTableDefineErrors(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	pos := token.Position{Line: 1, Column: 1}

	// Define a string
	str := &ast.String{Identifier: "$s1", Pos: pos}
	err := st.DefineString("$s1", pos, str)
	if err != nil {
		t.Errorf("DefineString() unexpected error: %v", err)
	}

	// Try to define it again - should error
	err = st.DefineString("$s1", pos, str)
	if err == nil {
		t.Error("DefineString() should error when redefining symbol")
	}

	// Define a rule
	rule := &ast.Rule{Name: "test_rule", Pos: pos}
	err = st.DefineRule("test_rule", pos, rule)
	if err != nil {
		t.Errorf("DefineRule() unexpected error: %v", err)
	}

	// Try to define it again - should error
	err = st.DefineRule("test_rule", pos, rule)
	if err == nil {
		t.Error("DefineRule() should error when redefining symbol")
	}

	// Define a variable
	err = st.DefineVariable("var1", pos, SymbolVariable)
	if err != nil {
		t.Errorf("DefineVariable() unexpected error: %v", err)
	}

	// Try to define it again - should error
	err = st.DefineVariable("var1", pos, SymbolVariable)
	if err == nil {
		t.Error("DefineVariable() should error when redefining symbol")
	}
}

func TestSymbolTableLookupInCurrentScope(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("outer")
	pos := token.Position{Line: 1, Column: 1}

	// Define a string in outer scope
	str := &ast.String{Identifier: "$s1", Pos: pos}
	st.DefineString("$s1", pos, str)

	// Enter inner scope
	st.EnterScope("inner")

	// LookupInCurrentScope should NOT find outer scope symbol
	_, exists := st.LookupInCurrentScope("$s1")
	if exists {
		t.Error("LookupInCurrentScope() should not find symbol from outer scope")
	}

	// Define a string in inner scope
	str2 := &ast.String{Identifier: "$s2", Pos: pos}
	st.DefineString("$s2", pos, str2)

	// LookupInCurrentScope should find inner scope symbol
	symbol, exists := st.LookupInCurrentScope("$s2")
	if !exists {
		t.Error("LookupInCurrentScope() should find symbol in current scope")
	}
	if symbol.Name != "$s2" {
		t.Errorf("Symbol name = %s, want $s2", symbol.Name)
	}
}

func TestSymbolTableMarkUsed(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	pos := token.Position{Line: 1, Column: 1}

	// Define a string
	str := &ast.String{Identifier: "$s1", Pos: pos}
	st.DefineString("$s1", pos, str)

	// Initially should not be marked as used
	symbol, _ := st.Lookup("$s1")
	if symbol.Used {
		t.Error("Symbol should not be marked as used initially")
	}

	// Mark as used
	st.MarkUsed("$s1")

	// Should now be marked as used
	symbol, _ = st.Lookup("$s1")
	if !symbol.Used {
		t.Error("Symbol should be marked as used after MarkUsed()")
	}

	// Marking non-existent symbol should not error
	st.MarkUsed("$nonexistent")
}

func TestSymbolTableGetUnusedSymbols(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	pos := token.Position{Line: 1, Column: 1}

	// Define multiple strings
	str1 := &ast.String{Identifier: "$s1", Pos: pos}
	st.DefineString("$s1", pos, str1)

	str2 := &ast.String{Identifier: "$s2", Pos: pos}
	st.DefineString("$s2", pos, str2)

	str3 := &ast.String{Identifier: "$s3", Pos: pos}
	st.DefineString("$s3", pos, str3)

	// Mark some as used
	st.MarkUsed("$s1")
	st.MarkUsed("$s3")

	// Get unused symbols
	unused := st.GetUnusedSymbols()

	// Should have one unused symbol ($s2)
	if len(unused) != 1 {
		t.Errorf("GetUnusedSymbols() returned %d symbols, want 1", len(unused))
	}

	if len(unused) > 0 && unused[0].Name != "$s2" {
		t.Errorf("Unused symbol name = %s, want $s2", unused[0].Name)
	}
}

func TestSymbolTableErrors(t *testing.T) {
	st := NewSymbolTable()

	// Test adding errors
	if st.HasErrors() {
		t.Error("HasErrors() should return false initially")
	}

	st.AddError(errors.New("error 1"))
	if !st.HasErrors() {
		t.Error("HasErrors() should return true after adding error")
	}

	st.AddError(errors.New("error 2"))
	errs := st.GetErrors()
	if len(errs) != 2 {
		t.Errorf("GetErrors() returned %d errors, want 2", len(errs))
	}

	if errs[0].Error() != "error 1" || errs[1].Error() != "error 2" {
		t.Errorf("GetErrors() returned %v, want [error 1, error 2]", errs)
	}
}

func TestSymbolTableReset(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	pos := token.Position{Line: 1, Column: 1}

	// Define a string and add error
	str := &ast.String{Identifier: "$s1", Pos: pos}
	st.DefineString("$s1", pos, str)
	st.AddError(errors.New("test error"))

	// Reset
	st.Reset()

	// Should have no errors
	if st.HasErrors() {
		t.Error("HasErrors() should return false after Reset()")
	}

	// Should still be able to use symbol table
	st.EnterScope("new_test")
	err := st.DefineString("$s2", pos, str)
	if err != nil {
		t.Errorf("DefineString() unexpected error after Reset(): %v", err)
	}
}

func TestSymbolTypes(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	pos := token.Position{Line: 1, Column: 1}

	// Test SymbolRule
	rule := &ast.Rule{Name: "test_rule", Pos: pos}
	st.DefineRule("test_rule", pos, rule)
	symbol, _ := st.Lookup("test_rule")
	if symbol.Type != SymbolRule {
		t.Errorf("Symbol type = %v, want %v", symbol.Type, SymbolRule)
	}
	if symbol.Node != rule {
		t.Error("Node should be set to rule")
	}

	// Test SymbolString
	str := &ast.String{Identifier: "$s1", Pos: pos}
	st.DefineString("$s1", pos, str)
	symbol, _ = st.Lookup("$s1")
	if symbol.Type != SymbolString {
		t.Errorf("Symbol type = %v, want %v", symbol.Type, SymbolString)
	}
	if symbol.Node != str {
		t.Error("Node should be set to string")
	}

	// Test SymbolVariable
	st.DefineVariable("var1", pos, SymbolVariable)
	symbol, _ = st.Lookup("var1")
	if symbol.Type != SymbolVariable {
		t.Errorf("Symbol type = %v, want %v", symbol.Type, SymbolVariable)
	}
}

func TestSymbolPosition(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	pos := token.Position{Line: 10, Column: 5}

	str := &ast.String{Identifier: "$s1", Pos: pos}
	st.DefineString("$s1", pos, str)

	symbol, _ := st.Lookup("$s1")
	if symbol.Position.Line != 10 || symbol.Position.Column != 5 {
		t.Errorf("Symbol position = %v, want %v", symbol.Position, pos)
	}
}

func TestSymbolIsGlobal(t *testing.T) {
	st := NewSymbolTable()
	pos := token.Position{Line: 1, Column: 1}

	// Define in global scope
	rule1 := &ast.Rule{Name: "global_rule", Pos: pos}
	st.DefineRule("global_rule", pos, rule1)

	symbol, _ := st.Lookup("global_rule")
	if !symbol.IsGlobal {
		t.Error("Symbol defined at root should be global")
	}

	// Define in nested scope
	st.EnterScope("test")
	rule2 := &ast.Rule{Name: "local_rule", Pos: pos}
	st.DefineRule("local_rule", pos, rule2)

	symbol, _ = st.Lookup("local_rule")
	if symbol.IsGlobal {
		t.Error("Symbol defined in nested scope should not be global")
	}
}
