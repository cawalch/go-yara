package compiler

import "testing"

func TestExternalFloatComparisons(t *testing.T) {
	for _, tc := range []struct {
		condition string
		value     any
		want      bool
	}{
		{condition: "x == 1.5", value: 1.5, want: true},
		{condition: "x == 1", value: 1, want: true},
		{condition: "x == 1.5", value: int64(1), want: false},
		{condition: "1.5 == x", value: 1.5, want: true},
	} {
		t.Run(tc.condition, func(t *testing.T) {
			program, err := NewCompiler().CompileSource("external x rule r { condition: " + tc.condition + " }")
			if err != nil {
				t.Fatal(err)
			}
			scanner := program.NewScanner(WithExternalVariables(map[string]any{"x": tc.value}))
			defer scanner.Close()
			matched, err := scanner.Matches(nil)
			if err != nil || matched != tc.want {
				t.Fatalf("Matches = (%v, %v), want %v", matched, err, tc.want)
			}
		})
	}
}
