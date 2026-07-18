package compiler

import (
	"bytes"
	"testing"

	"github.com/cawalch/go-yara/ast"
)

// TestStringCompilerValidateModifiers tests string modifier validation
func TestStringCompilerValidateModifiers(t *testing.T) {
	sc := NewStringCompiler()

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
			wantErr: false,
		},
		{
			name: "base64_and_base64wide_conflict",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierBase64},
				{Type: ast.StringModifierBase64Wide},
			},
			wantErr: true,
		},
		{
			name: "base64_with_wide",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierBase64},
				{Type: ast.StringModifierWide},
			},
			wantErr: true,
		},
		{
			name: "base64wide_with_ascii",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierBase64Wide},
				{Type: ast.StringModifierASCII},
			},
			wantErr: true,
		},
		{
			name: "base64_with_nocase",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierBase64},
				{Type: ast.StringModifierNocase},
			},
			wantErr: true,
		},
		{
			name: "base64_with_fullword",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierBase64},
				{Type: ast.StringModifierFullword},
			},
			wantErr: true,
		},
		{
			name: "base64_with_xor",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierBase64},
				{Type: ast.StringModifierXor, Value: ast.XorRange{Min: 1, Max: 1}},
			},
			wantErr: true,
		},
		{
			name: "xor_out_of_range",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierXor, Value: ast.XorRange{Min: 0, Max: 300}},
			},
			wantErr: true,
		},
		{
			name: "base64_duplicate_alphabet",
			modifiers: []ast.StringModifier{
				{Type: ast.StringModifierBase64, Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
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

func TestBase64AlignmentVariants(t *testing.T) {
	sc := NewStringCompiler()
	input := []byte("This program cannot")
	variants, err := sc.base64AlignedPatterns(input, "", false)
	if err != nil {
		t.Fatalf("base64AlignedPatterns: %v", err)
	}

	want := []string{
		"VGhpcyBwcm9ncmFtIGNhbm5vd",
		"RoaXMgcHJvZ3JhbSBjYW5ub3",
		"UaGlzIHByb2dyYW0gY2Fubm90",
	}
	if len(variants) != len(want) {
		t.Fatalf("variants=%d, want %d", len(variants), len(want))
	}

	got := make([]string, 0, len(variants))
	for _, v := range variants {
		got = append(got, string(v))
	}

	for i, expected := range want {
		if got[i] != expected {
			t.Fatalf("variant[%d]=%q, want %q", i, got[i], expected)
		}
	}
}

func TestBase64WideAlignmentVariants(t *testing.T) {
	sc := NewStringCompiler()
	input := []byte("This program cannot")
	variants, err := sc.base64AlignedPatterns(input, "", true)
	if err != nil {
		t.Fatalf("base64AlignedPatterns: %v", err)
	}

	want := []string{
		"VGhpcyBwcm9ncmFtIGNhbm5vd",
		"RoaXMgcHJvZ3JhbSBjYW5ub3",
		"UaGlzIHByb2dyYW0gY2Fubm90",
	}
	if len(variants) != len(want) {
		t.Fatalf("variants=%d, want %d", len(variants), len(want))
	}

	for i, expected := range want {
		expectedWide := sc.encodeToWideBytes(expected)
		if !bytes.Equal(variants[i], expectedWide) {
			t.Fatalf("variant[%d]=%v, want %v", i, variants[i], expectedWide)
		}
	}
}

func TestStringCompilerEncodeToWideBytes(t *testing.T) {
	sc := NewStringCompiler()

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
