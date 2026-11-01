package semantic

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/cawalch/go-yara/token"
)

// identifierDistance retains three rows of the existing adjacent-transposition
// recurrence. Only distances within limit matter for suggestions; other results
// are represented by limit+1. Rows are reused within one suggestion search.
type identifierDistance struct {
	rows []int
}

func (d *identifierDistance) bounded(a, b []rune, limit int) int {
	n, m := len(a), len(b)
	if abs(n-m) > limit {
		return limit + 1
	}
	if n == 0 {
		return m
	}
	if m == 0 {
		return n
	}
	width := m + 1
	if cap(d.rows) < 3*width {
		d.rows = make([]int, 3*width)
	}
	rows := d.rows[:3*width]
	older, previous, current := rows[:width], rows[width:2*width], rows[2*width:]
	for j := range previous {
		previous[j] = min(j, limit+1)
	}
	for i := 1; i <= n; i++ {
		first, last := max(1, i-limit), min(m, i+limit)
		current[0] = min(i, limit+1)
		// Guard the band so recycled cells outside it cannot become edit paths.
		if first > 1 {
			current[first-1] = limit + 1
		}
		if last < m {
			current[last+1] = limit + 1
		}
		for j := first; j <= last; j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			value := min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				value = min(value, older[j-2]+1)
			}
			current[j] = min(value, limit+1)
		}
		older, previous, current = previous, current, older
	}
	return previous[m]
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
	targetRunes := []rune(targetLower)
	targetLen := len(targetRunes)
	targetPrefix := strings.HasPrefix(targetLower, "$")
	var distance identifierDistance

	maxAllowed := 1
	if targetLen > 3 && targetLen <= 7 {
		maxAllowed = 2
	} else if targetLen > 7 {
		maxAllowed = 3
	}

	for _, c := range candidates {
		candidatePrefix := strings.HasPrefix(c, "$")
		lengthLimit := maxAllowed
		if candidatePrefix != targetPrefix {
			lengthLimit++
		}
		// Lowercasing preserves rune count. Allow one extra rune for the '$'
		// comparison before allocating or lowercasing an impossible candidate.
		if abs(utf8.RuneCountInString(c)-targetLen) > lengthLimit {
			continue
		}
		candidateRunes := []rune(strings.ToLower(c))
		d := distance.bounded(targetRunes, candidateRunes, maxAllowed)
		if candidatePrefix && !targetPrefix {
			dWithoutPrefix := distance.bounded(targetRunes, candidateRunes[1:], maxAllowed)
			if dWithoutPrefix < d {
				d = dWithoutPrefix
			}
		} else if targetPrefix && !candidatePrefix {
			dWithoutPrefix := distance.bounded(targetRunes[1:], candidateRunes, maxAllowed)
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
