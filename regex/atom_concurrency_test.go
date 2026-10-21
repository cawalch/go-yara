package regex

import (
	"reflect"
	"sync"
	"testing"
)

func TestAtomAnalysisConcurrentSharedAST(t *testing.T) {
	for _, pattern := range []string{
		`(foo|barbaz)[0-9]{4}qux`,
		`[Pp][Aa][Ss][Ss].{1,8}(word|phrase)`,
		`[a-z][0-9]+(suffix|ending)`,
	} {
		t.Run(pattern, func(t *testing.T) {
			parse := func() *AST {
				t.Helper()
				parsed, err := NewParser(0).Parse(pattern)
				if err != nil {
					t.Fatal(err)
				}
				return parsed
			}
			analyze := func(tree *AST) []any {
				plan, ok := LeadingByteGapAtomCover(tree, 0, 2)
				return []any{
					MandatoryLiteralAtoms(tree), MandatoryASCIIFoldedLiteralAtoms(tree),
					MandatoryByteSetAtoms(tree), RequiredLiteralAlternationAtoms(tree, 2),
					LiteralAtomCover(tree, 2),
					AlternativeMandatoryLiteralAtoms(tree), LiteralAlternatives(tree), plan, ok,
				}
			}
			want := analyze(parse())
			shared := parse() // Keep the shared cache cold until all workers start.
			start := make(chan struct{})
			var workers sync.WaitGroup
			for range 16 {
				workers.Go(func() {
					<-start
					for range 10 {
						if got := analyze(shared); !reflect.DeepEqual(got, want) {
							t.Errorf("shared AST analysis differs: got %v, want %v", got, want)
							return
						}
						// Caller edits must not race with other readers of the cache.
						for _, atom := range MandatoryLiteralAtoms(shared) {
							if len(atom.Data) > 0 {
								atom.Data[0] ^= 0xff
							}
						}
					}
				})
			}
			close(start)
			workers.Wait()
		})
	}
}
