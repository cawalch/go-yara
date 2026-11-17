package compiler

// encodeHexPatternBytes retains the compact, lossy representation exposed in
// CompiledRule.Strings. Matching always uses HexPattern.Tokens instead: wildcards
// are zero, masks/negation retain their value byte, jumps retain the legacy
// 16-bit marker encoding, and alternatives select their first branch.
func encodeHexPatternBytes(tokens []HexPatternToken) []byte {
	return appendHexPatternBytes(make([]byte, 0, hexPatternByteLength(tokens)), tokens)
}

func hexPatternByteLength(tokens []HexPatternToken) int {
	length := 0
	for _, tok := range tokens {
		switch tok.Kind {
		case HexTokenByte, HexTokenMasked, HexTokenWildcard:
			length++
		case HexTokenJump:
			length += 5
		case HexTokenAlt:
			if len(tok.Alternatives) > 0 {
				length += hexPatternByteLength(tok.Alternatives[0])
			}
		}
	}
	return length
}

func appendHexPatternBytes(dst []byte, tokens []HexPatternToken) []byte {
	for _, tok := range tokens {
		switch tok.Kind {
		case HexTokenByte, HexTokenMasked:
			dst = append(dst, tok.Value)
		case HexTokenWildcard:
			dst = append(dst, 0)
		case HexTokenJump:
			dst = append(dst, 0xff, byte(tok.Min&0xff), byte((tok.Min>>8)&0xff), byte(tok.Max&0xff), byte((tok.Max>>8)&0xff))
		case HexTokenAlt:
			if len(tok.Alternatives) > 0 {
				dst = appendHexPatternBytes(dst, tok.Alternatives[0])
			}
		}
	}
	return dst
}
