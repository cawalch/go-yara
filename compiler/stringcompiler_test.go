package compiler

import (
	"bytes"
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

func TestStringCompilerBase64Modifier(t *testing.T) {
	sc := NewStringCompiler(nil)

	tests := []struct {
		name      string
		input     []byte
		modifier  ast.StringModifier
		want      []byte
		wantError bool
	}{
		{
			name:     "standard_base64_decoding",
			input:    []byte("SGVsbG8gV29ybGQ="),
			modifier: ast.StringModifier{Type: ast.StringModifierBase64},
			want:     []byte("Hello World"),
		},
		{
			name:     "base64wide_decoding",
			input:    []byte("SGVsbG8gV29ybGQ="),
			modifier: ast.StringModifier{Type: ast.StringModifierBase64Wide},
			want:     []byte{0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x20, 0x00, 0x57, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x6C, 0x00, 0x64, 0x00},
		},
		{
			name:      "invalid_base64_should_not_panic",
			input:     []byte("Invalid!Base64@@"),
			modifier:  ast.StringModifier{Type: ast.StringModifierBase64},
			wantError: true,
		},
		{
			name:     "empty_base64_string",
			input:    []byte(""),
			modifier: ast.StringModifier{Type: ast.StringModifierBase64},
			want:     []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sc.applyBase64Modifier(tt.input, tt.modifier)

			if tt.wantError {
				if err == nil {
					t.Errorf("applyBase64Modifier() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("applyBase64Modifier() unexpected error: %v", err)
				return
			}

			if !bytes.Equal(result, tt.want) {
				t.Errorf("applyBase64Modifier() = %v, want %v", result, tt.want)
			}
		})
	}
}

func TestStringCompilerEncodeToWideBytes(t *testing.T) {
	sc := NewStringCompiler(nil)

	tests := []struct {
		name  string
		input string
		want  []byte
	}{
		{
			name:  "simple_ascii",
			input: "Hi",
			want:  []byte{0x48, 0x00, 0x69, 0x00},
		},
		{
			name:  "empty_string",
			input: "",
			want:  []byte{},
		},
		{
			name:  "unicode_character",
			input: "é",
			want:  []byte{0xE9, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sc.encodeToWideBytes(tt.input)
			if !bytes.Equal(result, tt.want) {
				t.Errorf("encodeToWideBytes() = %v, want %v", result, tt.want)
			}
		})
	}
}
