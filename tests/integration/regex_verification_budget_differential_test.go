package integration

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestLibyaraRegexVerificationBudgetDifferential(t *testing.T) {
	bin := libyaraOracle(t)

	for _, tc := range []struct {
		name      string
		pattern   string
		modifiers string
		data      []byte
		wantMatch bool
		wantLen   int
	}{
		{
			name:      "lazy-dot-range-4095",
			pattern:   `:.{1,}?TARGET`,
			data:      []byte(":" + strings.Repeat("q", 4095) + "TARGET"),
			wantMatch: true,
			wantLen:   1 + 4095 + 6,
		},
		{
			name:      "lazy-dot-range-4096",
			pattern:   `:.{1,}?TARGET`,
			data:      []byte(":" + strings.Repeat("q", 4096) + "TARGET"),
			wantMatch: true,
			wantLen:   1 + 4096 + 6,
		},
		{
			name:      "lazy-dot-range-5000",
			pattern:   `:.{1,}?TARGET`,
			data:      []byte(":" + strings.Repeat("q", 5000) + "TARGET"),
			wantMatch: true,
			wantLen:   1 + 5000 + 6,
		},
		{
			name:      "lazy-dot-zero-min-5000",
			pattern:   `:.{0,}?TARGET`,
			data:      []byte(":" + strings.Repeat("q", 5000) + "TARGET"),
			wantMatch: true,
			wantLen:   1 + 5000 + 6,
		},
		{
			name:      "lazy-dot-bounded-6000",
			pattern:   `:.{1,6000}?TARGET`,
			data:      []byte(":" + strings.Repeat("q", 5000) + "TARGET"),
			wantMatch: true,
			wantLen:   1 + 5000 + 6,
		},
		{
			name:      "start-lazy-dot-semicolon-5000",
			pattern:   `START.{1,}?;`,
			data:      []byte("START" + strings.Repeat("q", 5000) + ";"),
			wantMatch: true,
			wantLen:   5 + 5000 + 1,
		},
		{
			name:      "multi-chained-lazy-dot-5000",
			pattern:   `ab.{2,}?cd.{1,}?ef`,
			data:      []byte("ab" + strings.Repeat("x", 2500) + "cd" + strings.Repeat("y", 2500) + "ef"),
			wantMatch: true,
			wantLen:   2 + 2500 + 2 + 2500 + 2,
		},
		{
			name:      "lazy-dot-wide-5000",
			pattern:   `:.{1,}?TARGET`,
			modifiers: "wide",
			data:      releaseWideBytes([]byte(":" + strings.Repeat("q", 5000) + "TARGET")),
			wantMatch: true,
			wantLen:   (1 + 5000 + 6) * 2,
		},
		{
			name:      "lazy-dot-nocase-5000",
			pattern:   `:.{1,}?TARGET`,
			modifiers: "nocase",
			data:      []byte(":" + strings.Repeat("q", 5000) + "target"),
			wantMatch: true,
			wantLen:   1 + 5000 + 6,
		},
		{
			name:      "greedy-dot-range-5000-nomatch",
			pattern:   `:.{1,}TARGET`,
			data:      []byte(":" + strings.Repeat("q", 5000) + "TARGET"),
			wantMatch: false,
		},
		{
			name:      "star-lazy-5000-nomatch",
			pattern:   `:.*?TARGET`,
			data:      []byte(":" + strings.Repeat("q", 5000) + "TARGET"),
			wantMatch: false,
		},
		{
			name:      "plus-lazy-5000-nomatch",
			pattern:   `:.+?TARGET`,
			data:      []byte(":" + strings.Repeat("q", 5000) + "TARGET"),
			wantMatch: false,
		},
		{
			name:      "negclass-lazy-5000-nomatch",
			pattern:   `:[^x]*?TARGET`,
			data:      []byte(":" + strings.Repeat("q", 5000) + "TARGET"),
			wantMatch: false,
		},
		{
			name:      "greedy-dotstar-5000-nomatch",
			pattern:   `:.*TARGET`,
			data:      []byte(":" + strings.Repeat("q", 5000) + "TARGET"),
			wantMatch: false,
		},
		{
			name:      "greedy-bounded-6000-nomatch",
			pattern:   `:.{0,6000}TARGET`,
			data:      []byte(":" + strings.Repeat("q", 5000) + "TARGET"),
			wantMatch: false,
		},
		{
			name:      "lazy-bounded-4000-over5000-nomatch",
			pattern:   `:.{1,4000}?TARGET`,
			data:      []byte(":" + strings.Repeat("q", 5000) + "TARGET"),
			wantMatch: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cond := `#a == 0`
			if tc.wantMatch {
				cond = fmt.Sprintf(`#a == 1 and @a[1] == 0 and !a[1] == %d`, tc.wantLen)
			}
			src := fmt.Sprintf(`rule p { strings: $a = /%s/ %s condition: %s }`, tc.pattern, tc.modifiers, cond)
			oracle, err := scanWithLibyara(t, bin, src, tc.data)
			if err != nil {
				t.Fatalf("libyara err=%v", err)
			}
			if _, ok := oracle["p"]; !ok {
				t.Fatalf("libyara rejected expected condition %q", cond)
			}

			prog, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), src)
			if err != nil {
				t.Fatalf("go-yara compile err=%v", err)
			}
			for _, stream := range []bool{false, true} {
				var opts []compiler.ScannerOption
				if stream {
					opts = append(opts, compiler.WithStreamChunkSize(1024), compiler.WithMaxMatchSpan(len(tc.data)+1024))
				}
				s := prog.NewScanner(opts...)
				var res *compiler.ScanResult
				if stream {
					res, err = s.ScanReader(bytes.NewReader(tc.data))
				} else {
					res, err = s.Scan(tc.data)
				}
				s.Close()
				if err != nil {
					t.Fatalf("stream=%v scan err=%v", stream, err)
				}
				if len(res.MatchedRules) != 1 || res.MatchedRules[0].Rule != "p" {
					t.Fatalf("stream=%v go-yara did not match condition %q (got %+v)", stream, cond, res.MatchedRules)
				}
			}
		})
	}
}
