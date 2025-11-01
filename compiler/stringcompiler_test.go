package compiler

import (
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

// TestStringCompilerTextString tests text string compilation
func TestStringCompilerTextString(t *testing.T) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	tests := []struct {
		name      string
		text      string
		modifiers []ast.StringModifier
		wantErr   bool
	}{
		{
			name:      "simple_text",
			text:      "hello",
			modifiers: []ast.StringModifier{},
			wantErr:   false,
		},
		{
			name: "text_with_nocase",
			text: "hello",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierNocase},
			},
			wantErr: false,
		},
		{
			name: "text_with_wide",
			text: "hello",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierWide},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			textPattern := &ast.TextString{
				Value: tt.text,
				Pos:   token.Position{Line: 1, Column: 1},
			}
			err := sc.compileTextString("$test", textPattern, tt.modifiers)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileTextString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestStringCompilerValidateModifiers tests string modifier validation
func TestStringCompilerValidateModifiers(t *testing.T) {
	emitter := NewEmitter()
	sc := NewStringCompiler(emitter)

	tests := []struct {
		name      string
		modifiers []ast.StringModifier
		wantErr   bool
	}{
		{
			name:      "no_modifiers",
			modifiers: []ast.StringModifier{},
			wantErr:   false,
		},
		{
			name: "single_modifier",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierNocase},
			},
			wantErr: false,
		},
		{
			name: "wide_and_ascii_conflict",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierWide},
				{Type: ast.StringModifierASCII},
			},
			wantErr: true,
		},
		{
			name: "base64_and_base64wide_conflict",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierBase64},
				{Type: ast.StringModifierBase64Wide},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sc.ValidateStringModifiers(tt.modifiers)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateStringModifiers() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
