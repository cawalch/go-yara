package compiler

import (
	"reflect"
	"testing"

	"github.com/cawalch/go-yara/ast"
)

func TestExtractFromTextString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		modifiers []ast.StringModifier
		want      []*Atom
	}{
		{
			name:  "Simple string",
			input: "abcdef",
			want: []*Atom{
				{
					Data:    []byte("abcd"),
					Mask:    []byte{0xFF, 0xFF, 0xFF, 0xFF},
					Offset:  0,
					Length:  4,
					Quality: 80, // Approximation, will be refined
				},
			},
		},
		{
			name:  "Short string",
			input: "abc",
			want: []*Atom{
				{
					Data:    []byte("abc"),
					Mask:    []byte{0xFF, 0xFF, 0xFF},
					Offset:  0,
					Length:  3,
					Quality: 60, // Approximation
				},
			},
		},
		{
			name:  "String with common bytes",
			input: "\x00\x00\x20\xFF",
			want: []*Atom{
				{
					Data:    []byte{0x00, 0x00, 0x20, 0xFF},
					Mask:    []byte{0xFF, 0xFF, 0xFF, 0xFF},
					Offset:  0,
					Length:  4,
					Quality: 54, // Approximation
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFromTextString(tt.input, tt.modifiers)

			// For now, we are just checking if the number of atoms is correct.
			// We will add more detailed checks later.
			if len(got) != len(tt.want) {
				t.Errorf("ExtractFromTextString() len = %v, want %v", len(got), len(tt.want))
				return
			}

			if len(got) > 0 && len(tt.want) > 0 {
				// Crude quality check, we will refine this
				got[0].Quality = calculateAtomQuality(got[0])
				if !reflect.DeepEqual(got[0].Data, tt.want[0].Data) {
					t.Errorf("ExtractFromTextString() got atom data = %v, want %v", got[0].Data, tt.want[0].Data)
				}
			}
		})
	}
}