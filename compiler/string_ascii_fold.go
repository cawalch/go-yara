package compiler

import (
	"bytes"
	"strings"
)

const (
	maxShortFoldedNeedle = 16
	asciiFoldWindowSize  = 4096
)

func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	if a == b {
		return true
	}
	for i := range len(a) {
		if toLowerTable[a[i]] != toLowerTable[b[i]] {
			return false
		}
	}
	return true
}

func asciiHasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && asciiEqualFold(s[:len(prefix)], prefix)
}

func asciiHasSuffixFold(s, suffix string) bool {
	return len(s) >= len(suffix) && asciiEqualFold(s[len(s)-len(suffix):], suffix)
}

// asciiContainsFold searches byte strings using the VM's ASCII fold table.
func asciiContainsFold(s, needle string) bool {
	if len(needle) >= len(s) {
		return asciiEqualFold(s, needle)
	}
	switch len(needle) {
	case 0:
		return true
	case 1:
		return asciiContainsFoldByte(s, needle[0])
	}
	if len(s) <= 256 {
		var haystack, pattern [256]byte
		return bytes.Contains(foldASCII(haystack[:], s), foldASCII(pattern[:], needle))
	}
	if len(needle) <= maxShortFoldedNeedle {
		return asciiContainsFoldWindows(s, needle)
	}
	if strings.HasPrefix(s, needle) {
		return true
	}
	last := len(needle) - 1
	if len(s)-last <= 16 && !asciiContainsFoldByte(s[last:], needle[last]) {
		return false
	}
	return asciiContainsFoldTwoWay(s, needle)
}

func asciiContainsFoldByte(s string, ch byte) bool {
	lower := toLowerTable[ch]
	return strings.IndexByte(s, lower) >= 0 || lower >= 'a' && lower <= 'z' && strings.IndexByte(s, lower-'a'+'A') >= 0
}

func foldASCII(dst []byte, s string) []byte {
	dst = dst[:len(s)]
	for i := range len(s) {
		dst[i] = toLowerTable[s[i]]
	}
	return dst
}

// Fixed-size windows let the byte search skip dense near matches while keeping
// folding allocation-free. The overlap preserves starts across window edges.
func asciiContainsFoldWindows(s, needle string) bool {
	var foldedNeedle [maxShortFoldedNeedle]byte
	var window [asciiFoldWindowSize]byte
	pattern := foldASCII(foldedNeedle[:], needle)
	for {
		chunk := s[:min(len(s), len(window))]
		if bytes.Contains(foldASCII(window[:], chunk), pattern) {
			return true
		}
		if len(chunk) == len(s) {
			return false
		}
		s = s[len(chunk)-len(needle)+1:]
	}
}

// Crochemore–Perrin Two-Way search bounds the work to O(len(s)+len(needle))
// with constant scratch, including when both strings contain long repeats.
func asciiContainsFoldTwoWay(s, needle string) bool {
	suffix, period := asciiMaximalSuffix(needle, false)
	if reverseSuffix, reversePeriod := asciiMaximalSuffix(needle, true); reverseSuffix > suffix {
		suffix, period = reverseSuffix, reversePeriod
	}
	split := suffix + 1
	// A periodic needle can skip the already matched prefix after a shift.
	remember := len(needle) - period
	if !asciiEqualFold(needle[:split], needle[period:period+split]) {
		period = max(suffix, len(needle)-split) + 1
		remember = 0
	}
	matchedPrefix := 0
	for start := 0; start <= len(s)-len(needle); {
		right := max(split, matchedPrefix)
		for right < len(needle) && toLowerTable[needle[right]] == toLowerTable[s[start+right]] {
			right++
		}
		if right < len(needle) {
			start += right - suffix
			matchedPrefix = 0
			continue
		}
		left := split
		for left > matchedPrefix && toLowerTable[needle[left-1]] == toLowerTable[s[start+left-1]] {
			left--
		}
		if left <= matchedPrefix {
			return true
		}
		start += period
		matchedPrefix = remember
	}
	return false
}

// asciiMaximalSuffix returns the index before the maximal suffix and the
// suffix's period, using either ordering of the folded byte alphabet.
func asciiMaximalSuffix(s string, reverse bool) (suffix, period int) {
	suffix, period = -1, 1
	for candidate, offset := 0, 1; offset < len(s)-candidate; {
		a, b := toLowerTable[s[suffix+offset]], toLowerTable[s[candidate+offset]]
		switch {
		case a == b:
			if offset == period {
				candidate += period
				offset = 1
			} else {
				offset++
			}
		case (a > b) != reverse:
			candidate += offset
			offset, period = 1, candidate-suffix
		default:
			suffix = candidate
			candidate++
			offset, period = 1, 1
		}
	}
	return suffix, period
}
