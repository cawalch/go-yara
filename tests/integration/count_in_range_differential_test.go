package integration

import (
	"context"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestLibyaraCountInRange(t *testing.T) {
	bin := libyaraOracle(t)
	for _, condition := range []string{
		"#a in (2..3)", "#a in (0..2)", "#a in (0..10)",
		"#a in (0..2) == 1", "#a in (filesize - 7..filesize) == 2",
		"1 + #a in (0..2) == 2", "#a in (0..2) + 1 == 2",
		"#a in (0..2) == #a in (4..4)",
		"#a in (3..4) of ($a,$b)", "#a in (0..8) of them",
		"#a in (0..4) of them in (4..6)",
		"for all of ($a) : (# in (0..4) == 2)",
		"#a in (filesize..0) == 0", "#a in (filesize - 100..0) == 1",
		"not defined (#a in (@a[4]..8))",
	} {
		t.Run(condition, func(t *testing.T) {
			src := `rule offsets {
				strings: $a = "a" $b = "b"
				condition: (` + condition + `) and #b >= 0 }`
			data := []byte("a b a b a b")
			want := runLibyaraMatch(t, bin, src, data)
			p, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), src)
			if err != nil {
				t.Fatal(err)
			}
			got, err := p.MatchesWithContext(context.Background(), data)
			if err != nil || got != want {
				t.Fatalf("Matches = %v, %v, libyara = %v", got, err, want)
			}
		})
	}
}
