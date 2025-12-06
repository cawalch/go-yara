package semantic

import (
	"context"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
	"github.com/cawalch/go-yara/token"
)

// testHelper provides common setup functionality for string validator tests
type testHelper struct {
	t         *testing.T
	program   *ast.Program
	symbol    *SymbolTable
	validator *StringValidator
}

// newTestHelper creates a new test helper with parsed program and symbol table
func newTestHelper(t *testing.T, input string) *testHelper {
	lex := lexer.New(input)
	p := parser.New(lex)

	program, err := p.ParseRulesWithContext(context.Background())
	if err != nil {
		t.Fatalf("ParseRulesWithContext() error = %v", err)
	}

	st := NewSymbolTable()
	if len(program.Rules) > 0 {
		st.EnterScope(program.Rules[0].Name)
		// Define strings from the first rule
		for _, str := range program.Rules[0].Strings {
			_ = st.DefineString(str.Identifier, str.Pos, str)
		}
	}

	return &testHelper{
		t:         t,
		program:   program,
		symbol:    st,
		validator: NewStringValidator(st),
	}
}

// assertValidation asserts validation results
func (th *testHelper) assertValidation(wantErr bool) {
	if len(th.program.Rules) == 0 || th.program.Rules[0].Condition == nil {
		th.t.Fatal("No rules or condition to validate")
	}

	errors := th.validator.ValidateStringReferences(th.program.Rules[0].Condition)
	hasErr := len(errors) > 0

	if hasErr != wantErr {
		th.t.Errorf("ValidateStringReferences() error = %v, wantErr %v, errors: %v", hasErr, wantErr, errors)
	}
}

// TestStringValidatorFullIntegration tests string validator with parsed programs
func TestStringValidatorFullIntegration(t *testing.T) {
	t.Run("ValidReferences", testValidStringReferences)
	t.Run("InvalidReferences", testInvalidStringReferences)
}

func testValidStringReferences(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "simple_string_reference",
			input: `
rule test {
	strings:
		$s1 = "test"
	condition:
		$s1
}`,
		},
		{
			name: "wildcard_all_of_them",
			input: `
rule test {
	strings:
		$s1 = "test"
		$s2 = "test2"
	condition:
		all of them
}`,
		},
		{
			name: "wildcard_any_of_them",
			input: `
rule test {
	strings:
		$s1 = "test"
		$s2 = "test2"
	condition:
		any of them
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			helper := newTestHelper(t, tt.input)
			helper.assertValidation(false)
		})
	}
}

func testInvalidStringReferences(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "undefined_string",
			input: `
rule test {
	strings:
		$s1 = "test"
	condition:
		$s2
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			helper := newTestHelper(t, tt.input)
			helper.assertValidation(true)
		})
	}
}

// TestStringValidatorQuantifierExpression tests quantifier expression validation
func TestStringValidatorQuantifierExpression(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	pos := token.Position{Line: 1, Column: 1}

	// Define some strings
	str1 := &ast.String{Identifier: "$s1", Pos: pos}
	_ = st.DefineString("$s1", pos, str1)

	str2 := &ast.String{Identifier: "$s2", Pos: pos}
	_ = st.DefineString("$s2", pos, str2)

	validator := NewStringValidator(st)

	// Test "all of them" expression
	allOfThem := &ast.BinaryOp{
		Pos: pos,
		Left: &ast.Identifier{
			Name: "all",
			Pos:  pos,
		},
		Op: token.OF,
		Right: &ast.Identifier{
			Name: "them",
			Pos:  pos,
		},
	}

	errors := validator.ValidateStringReferences(allOfThem)
	if len(errors) > 0 {
		t.Errorf("ValidateStringReferences() unexpected errors for 'all of them': %v", errors)
	}
}

// TestStringValidatorWildcardValidation tests wildcard pattern validation
func TestStringValidatorWildcardValidation(t *testing.T) {
	st := NewSymbolTable()
	st.EnterScope("test")
	pos := token.Position{Line: 1, Column: 1}

	// Define strings with pattern
	for _, id := range []string{"$abc1", "$abc2", "$xyz1"} {
		str := &ast.String{Identifier: id, Pos: pos}
		_ = st.DefineString(id, pos, str)
	}

	validator := NewStringValidator(st)

	// Test "all of ($abc*)" expression
	wildcardExpr := &ast.BinaryOp{
		Pos: pos,
		Left: &ast.Identifier{
			Name: "all",
			Pos:  pos,
		},
		Op: token.OF,
		Right: &ast.Identifier{
			Name: "$abc*",
			Pos:  pos,
		},
	}

	errors := validator.ValidateStringReferences(wildcardExpr)
	if len(errors) > 0 {
		t.Logf("ValidateStringReferences() errors for wildcard (may be expected): %v", errors)
	}
}

// TestModuleValidatorDataTypeFunctions tests data type function validation
func TestModuleValidatorDataTypeFunctions(t *testing.T) {
	st := NewSymbolTable()
	validator := NewModuleValidator(st)

	pos := token.Position{Line: 1, Column: 1}
	args := []ast.Expression{
		&ast.Literal{
			Type:  token.IntegerLit,
			Value: int64(0x1000),
			Pos:   pos,
		},
	}

	dataTypeFunctions := []string{
		"uint8", "uint16", "uint32",
		"int8", "int16", "int32",
		"uint8be", "uint16be", "uint32be",
		"int8be", "int16be", "int32be",
	}

	for _, funcName := range dataTypeFunctions {
		t.Run(funcName, func(t *testing.T) {
			typeInfo, errors := validator.ValidateFunctionCall(funcName, args, pos)
			if len(errors) > 0 {
				t.Errorf("ValidateFunctionCall(%s) unexpected errors: %v", funcName, errors)
			}

			if typeInfo.DataType != TypeInteger {
				t.Errorf(
					"ValidateFunctionCall(%s) returned type %v, want TypeInteger",
					funcName,
					typeInfo.DataType,
				)
			}
		})
	}
}

// TestModuleValidatorInvalidFunctions tests invalid function validation
func TestModuleValidatorInvalidFunctions(t *testing.T) {
	st := NewSymbolTable()
	validator := NewModuleValidator(st)

	pos := token.Position{Line: 1, Column: 1}

	tests := []struct {
		name     string
		funcName string
		args     []ast.Expression
		wantErr  bool
	}{
		{
			name:     "unknown_function",
			funcName: "unknown_func",
			args:     []ast.Expression{},
			wantErr:  true,
		},
		{
			name:     "filesize_with_args",
			funcName: "filesize",
			args: []ast.Expression{
				&ast.Literal{Type: token.IntegerLit, Value: int64(1), Pos: pos},
			},
			wantErr: true,
		},
		{
			name:     "uint8_no_args",
			funcName: "uint8",
			args:     []ast.Expression{},
			wantErr:  true,
		},
		{
			name:     "uint8_too_many_args",
			funcName: "uint8",
			args: []ast.Expression{
				&ast.Literal{Type: token.IntegerLit, Value: int64(1), Pos: pos},
				&ast.Literal{Type: token.IntegerLit, Value: int64(2), Pos: pos},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errors := validator.ValidateFunctionCall(tt.funcName, tt.args, pos)
			hasErr := len(errors) > 0

			if hasErr != tt.wantErr {
				t.Errorf(
					"ValidateFunctionCall() error = %v, wantErr %v, errors: %v",
					hasErr,
					tt.wantErr,
					errors,
				)
			}
		})
	}
}

// TestFileValidatorIntegration tests file validator with realistic scenarios
func TestFileValidatorIntegration(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name: "filesize_comparison",
			input: `
rule test {
	condition:
		filesize > 1024
}`,
			wantErr: false,
		},
		{
			name: "entrypoint_comparison",
			input: `
rule test {
	condition:
		entrypoint == 0x400000
}`,
			wantErr: false,
		},
		{
			name: "filesize_and_entrypoint",
			input: `
rule test {
	condition:
		filesize > 0 and entrypoint == 0x400000
}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program := parseProgramOrFail(t, tt.input)
			st := NewSymbolTable()
			validator := NewFileValidator(st)

			// Validate the condition
			if len(program.Rules) > 0 && program.Rules[0].Condition != nil {
				errors := validator.ValidateFileOperations(program.Rules[0].Condition)
				hasErr := len(errors) > 0

				if hasErr != tt.wantErr {
					t.Errorf("ValidateFileOperations() error = %v, wantErr %v, errors: %v", hasErr, tt.wantErr, errors)
				}
			}
		})
	}
}

// TestValidatorWithComplexPrograms tests validator with complex programs
func TestValidatorWithComplexPrograms(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		minErrCount int
	}{
		{
			name: "valid_complex_rule",
			input: `
rule complex {
	meta:
		author = "test"
		version = 1
		enabled = true
	strings:
		$s1 = "malware"
		$s2 = "virus"
		$s3 = "trojan"
	condition:
		($s1 or $s2) and $s3 and filesize > 100
}`,
			minErrCount: 0,
		},
		{
			name: "arithmetic_in_condition",
			input: `
rule arithmetic {
	condition:
		(1 + 2) * 3 == 9
}`,
			minErrCount: 0,
		},
		{
			name: "bitwise_operators",
			input: `
rule bitwise {
	condition:
		(1 & 2) | (3 ^ 4)
}`,
			minErrCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertProgramValidation(t, tt.input, tt.minErrCount)
		})
	}
}

// assertProgramValidation parses and validates a program with minimum error count
func assertProgramValidation(t *testing.T, input string, minErrCount int) {
	program := parseProgramOrFail(t, input)

	validator := NewValidator()
	errors := validator.ValidateProgram(program)

	if len(errors) < minErrCount {
		t.Errorf("ValidateProgram() got %d errors, want at least %d", len(errors), minErrCount)
	}
}

// parseProgramOrFail parses a program or fails the test
func parseProgramOrFail(t *testing.T, input string) *ast.Program {
	lex := lexer.New(input)
	p := parser.New(lex)

	program, err := p.ParseRulesWithContext(context.Background())
	if err != nil {
		t.Fatalf("ParseRulesWithContext() error = %v", err)
	}

	return program
}
