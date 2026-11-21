package semantic

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/token"
)

func TestModifierDuplicateTracking(t *testing.T) {
	types := []ast.StringModifierType{-1, 64, 1 << 30}
	for modifier := ast.StringModifierNocase; modifier <= ast.StringModifierCapture; modifier++ {
		types = append(types, modifier)
	}
	for _, modifier := range types {
		t.Run(fmt.Sprint(modifier), func(t *testing.T) {
			pos := token.Position{Line: 7, Column: 3}
			str := &ast.String{Identifier: "$a", Pos: pos, Pattern: &ast.TextString{Value: "abcdef"},
				Modifiers: []ast.StringModifier{{Type: modifier}, {Type: modifier}, {Type: modifier}}}
			v := NewValidator()
			v.validateStringModifiers(&ast.Rule{Name: "sample", Strings: []*ast.String{nil, str}})
			wantCount := 2
			if modifier == ast.StringModifierCapture {
				wantCount = 0 // Capture duplicates are diagnosed by evidence validation.
			}
			if len(v.errors) != wantCount {
				t.Fatalf("got %v, want %d duplicate errors", v.errors, wantCount)
			}
			for _, err := range v.errors {
				var got *Error
				ok := errors.As(err, &got)
				want := fmt.Sprintf("string $a declares duplicate modifier '%s' (previously at %v)", modifierTypeName(modifier), pos)
				if !ok || got.Code != ErrCodeInvalidModifier || got.Message != want || got.Position != pos || got.Rule != "sample" {
					t.Fatalf("unexpected diagnostic: %#v", err)
				}
			}
			str.Modifiers = str.Modifiers[:1]
			v.errors = nil
			v.validateStringModifiers(&ast.Rule{Name: "sample", Strings: []*ast.String{str, str}})
			if len(v.errors) != 0 {
				t.Fatalf("modifier tracking leaked between strings: %v", v.errors)
			}
		})
	}
}

func TestBase64AlphabetByteTracking(t *testing.T) {
	// Exercise every byte value, including NUL and non-UTF-8 bytes, against
	// the previous map-based uniqueness check and its diagnostic ordering.
	for start := range 256 {
		alphabet := make([]byte, 64)
		for i := range alphabet {
			alphabet[i] = byte((start + i) % 256)
		}
		for duplicate := -1; duplicate < len(alphabet); duplicate++ {
			candidate := append([]byte(nil), alphabet...)
			if duplicate >= 0 {
				candidate[duplicate] = candidate[0]
			}
			want := ""
			seen := make(map[byte]bool)
			for _, ch := range candidate {
				if ch == '=' {
					want = "invalid base64 alphabet: '=' is not allowed"
					break
				}
				if seen[ch] {
					want = "invalid base64 alphabet: duplicate characters"
					break
				}
				seen[ch] = true
			}
			err := ast.ValidateBase64Alphabet(string(candidate))
			got := ""
			if err != nil {
				got = err.Error()
			}
			if got != want {
				t.Fatalf("start=%d duplicate=%d: got %q, want %q", start, duplicate, got, want)
			}
		}
	}
	for _, value := range []any{nil, 42, ""} {
		if err := ast.ValidateBase64Alphabet(value); err != nil {
			t.Fatalf("%v: %v", value, err)
		}
	}
	for _, length := range []int{1, 63, 65} {
		if err := ast.ValidateBase64Alphabet(strings.Repeat("x", length)); err == nil || !strings.Contains(err.Error(), "invalid base64 alphabet length") {
			t.Fatalf("length %d: got %v", length, err)
		}
	}
}
