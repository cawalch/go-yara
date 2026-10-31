package compiler

// Literal atoms use libyara 4.5.8's default heuristic, retaining the earliest
// equally scored four-byte window. This ordering is separate from our prefilter.
func regexLiteralAtomOffset(literal []byte) int {
	best, quality := 0, -1
	width := min(4, len(literal))
	for i := 0; i+width <= len(literal); i++ {
		if score := regexLiteralAtomQuality(literal[i : i+width]); score > quality {
			best, quality = i, score
		}
	}
	return best
}

func regexLiteralAtomQuality(atom []byte) int {
	score, unique := 0, 0
	var seen [256]bool
	for _, b := range atom {
		switch {
		case b == 0 || b == 0x20 || b == 0xcc || b == 0xff:
			score += 12
		case toLowerTable[b] >= 'a' && toLowerTable[b] <= 'z':
			score += 18
		default:
			score += 20
		}
		if !seen[b] {
			seen[b] = true
			unique++
		}
	}
	if unique == 1 && (seen[0] || seen[0x20] || seen[0x90] || seen[0xcc] || seen[0xff]) {
		return score - 10*len(atom)
	}
	return score + 2*unique
}
