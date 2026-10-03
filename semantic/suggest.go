package semantic

import (
	"slices"
	"strings"

	"github.com/cawalch/go-yara/token"
)

// damerauLevenshteinDistance computes the Damerau-Levenshtein distance between two strings,
// case-insensitively, accounting for insertions, deletions, substitutions, and adjacent transpositions.
func damerauLevenshteinDistance(s1, s2 string) int {
	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

	r1 := []rune(s1)
	r2 := []rune(s2)

	len1 := len(r1)
	len2 := len(r2)

	if len1 == 0 {
		return len2
	}
	if len2 == 0 {
		return len1
	}

	d := make([][]int, len1+1)
	for i := range d {
		d[i] = make([]int, len2+1)
		d[i][0] = i
	}
	for j := 0; j <= len2; j++ {
		d[0][j] = j
	}

	for i := 1; i <= len1; i++ {
		for j := 1; j <= len2; j++ {
			cost := 0
			if r1[i-1] != r2[j-1] {
				cost = 1
			}
			d[i][j] = min(
				d[i-1][j]+1,      // deletion
				d[i][j-1]+1,      // insertion
				d[i-1][j-1]+cost, // substitution
			)
			if i > 1 && j > 1 && r1[i-1] == r2[j-2] && r1[i-2] == r2[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1) // transposition
			}
		}
	}

	return d[len1][len2]
}

// findSimilarIdentifier finds the closest candidate for target among the given candidates.
// It returns the best match and true if a candidate meets the similarity criteria.
func findSimilarIdentifier(target string, candidates []string) (string, bool) {
	if len(candidates) == 0 || target == "" {
		return "", false
	}

	// 1. Direct prefix match for missing '$' on string identifiers (e.g. target is "payload" and candidate is "$payload")
	for _, c := range candidates {
		if strings.HasPrefix(c, "$") && target == c[1:] {
			return c, true
		}
		if strings.HasPrefix(target, "$") && c == target[1:] {
			return c, true
		}
	}

	// 2. Exact case-insensitive match (e.g. target "PAYLOAD" vs candidate "$payload" or "payload")
	for _, c := range candidates {
		if strings.EqualFold(target, c) {
			return c, true
		}
		if strings.HasPrefix(c, "$") && strings.EqualFold(target, c[1:]) {
			return c, true
		}
	}

	// 3. Damerau-Levenshtein distance matching
	type match struct {
		name string
		dist int
	}
	var matches []match

	targetLower := strings.ToLower(target)
	targetLen := len([]rune(targetLower))

	maxAllowed := 1
	if targetLen > 3 && targetLen <= 7 {
		maxAllowed = 2
	} else if targetLen > 7 {
		maxAllowed = 3
	}

	for _, c := range candidates {
		cLower := strings.ToLower(c)
		d := damerauLevenshteinDistance(targetLower, cLower)
		if strings.HasPrefix(cLower, "$") && !strings.HasPrefix(targetLower, "$") {
			dWithoutPrefix := damerauLevenshteinDistance(targetLower, cLower[1:])
			if dWithoutPrefix < d {
				d = dWithoutPrefix
			}
		} else if strings.HasPrefix(targetLower, "$") && !strings.HasPrefix(cLower, "$") {
			dWithoutPrefix := damerauLevenshteinDistance(targetLower[1:], cLower)
			if dWithoutPrefix < d {
				d = dWithoutPrefix
			}
		}
		if d <= maxAllowed {
			matches = append(matches, match{name: c, dist: d})
		}
	}

	if len(matches) == 0 {
		return "", false
	}

	// Pick the match with the lowest distance; tiebreak by closest length
	slices.SortFunc(matches, func(a, b match) int {
		if a.dist != b.dist {
			return a.dist - b.dist
		}
		lenDiffA := abs(len(a.name) - len(target))
		lenDiffB := abs(len(b.name) - len(target))
		return lenDiffA - lenDiffB
	})

	return matches[0].name, true
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// builtinFunctionNames is a list of known built-in YARA function names.
var builtinFunctionNames = []string{
	"filesize", "entrypoint", "offset", "read",
	"string", "concat", "tostring", "int", "md5", "sha1", "sha256",
	"uint8", "uint16", "uint32", "uint64",
	"int8", "int16", "int32", "int64",
	"uint8be", "uint16be", "uint32be", "uint64be",
	"int8be", "int16be", "int32be", "int64be",
}

// bitwiseSuggestion returns a suggestion if a bitwise operator was used with boolean operands.
func bitwiseSuggestion(op token.Type, left, right *TypeInfo) string {
	if (op == token.BitwiseAnd || op == token.BitwiseOr) && (left.IsBoolean() || right.IsBoolean()) {
		if op == token.BitwiseAnd {
			return "'and'"
		}
		return "'or'"
	}
	return ""
}
