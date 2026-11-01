package compiler

import (
	"bytes"
	"encoding/binary"

	"github.com/cawalch/go-yara/regex"
)

// Recognize only a literal prefix followed by one terminal bounded class run.
// Deriving this from the existing bytecode also rebuilds the plan on reload,
// without changing the compiled-program format or bypassing branch priorities.
type regexBoundedClass struct {
	prefix   []byte
	class    boundedClassSet
	min, max int
	greedy   bool
	noCase   bool
}

type boundedClassSet struct {
	set       regex.ByteSet
	low, high [32]byte
}

func compileBoundedClass(code []byte, flags regex.Flags) *regexBoundedClass {
	pc := 0
	for pc+1 < len(code) && code[pc] == regex.OpLiteral {
		pc += 2
	}
	size := boundedClassInstructionSize(code[pc:])
	if size == 0 {
		return nil
	}
	atom := code[pc : pc+size]
	minCount := 0
	end := pc
	for bytes.HasPrefix(code[end:], atom) {
		minCount++
		end += size
	}
	if minCount < 16 || minCount > 4096 {
		return nil
	}
	maxCount := minCount
	greedy := end >= len(code) || code[end] != regex.OpSplitB
	split := byte(regex.OpSplitA)
	if !greedy {
		split = regex.OpSplitB
	}
	for end+3 <= len(code) && code[end] == split &&
		int(binary.LittleEndian.Uint16(code[end+1:end+3])) == size+3 && bytes.HasPrefix(code[end+3:], atom) {
		maxCount++
		end += size + 3
	}
	if maxCount > 4096 || end != len(code)-1 || code[end] != regex.OpMatch {
		return nil
	}
	set, _ := boundedClassInstruction(code[pc:pc+size], flags)
	p := &regexBoundedClass{min: minCount, max: maxCount, greedy: greedy, noCase: flags&regex.FlagsNoCase != 0}
	for i := 0; i < pc; i += 2 {
		p.prefix = append(p.prefix, code[i+1])
	}
	p.class = newBoundedClassSet(set)
	return p
}

func boundedClassInstructionSize(code []byte) int {
	if len(code) == 0 {
		return 0
	}
	switch code[0] {
	case regex.OpClass:
		if len(code) >= 34 {
			return 34
		}
	case regex.OpDigit, regex.OpNonDigit, regex.OpWordChar, regex.OpNonWordChar, regex.OpSpace, regex.OpNonSpace:
		return 1
	}
	return 0
}

func boundedClassInstruction(code []byte, flags regex.Flags) (regex.ByteSet, int) {
	if len(code) == 0 {
		return regex.ByteSet{}, 0
	}
	node := &regex.Node{}
	size := 1
	switch code[0] {
	case regex.OpClass:
		if len(code) < 34 {
			return regex.ByteSet{}, 0
		}
		node.Kind, node.Class, size = regex.NodeClass, &regex.Class{Negated: code[33] != 0}, 34
		copy(node.Class.Bitmap[:], code[1:33])
	case regex.OpDigit:
		node.Kind = regex.NodeDigit
	case regex.OpNonDigit:
		node.Kind = regex.NodeNonDigit
	case regex.OpWordChar:
		node.Kind = regex.NodeWordChar
	case regex.OpNonWordChar:
		node.Kind = regex.NodeNonWordChar
	case regex.OpSpace:
		node.Kind = regex.NodeSpace
	case regex.OpNonSpace:
		node.Kind = regex.NodeNonSpace
	default:
		return regex.ByteSet{}, 0
	}
	sets, _ := regex.FixedByteSets(&regex.AST{Root: node}, flags)
	return sets[0], size
}

func newBoundedClassSet(set regex.ByteSet) boundedClassSet {
	c := boundedClassSet{set: set}
	for b := range 256 {
		if set.Contains(byte(b)) {
			if b < 128 {
				c.low[b&15] |= 1 << (b >> 4)
			} else {
				c.high[b&15] |= 1 << ((b >> 4) - 8)
			}
		}
	}
	copy(c.low[16:], c.low[:16])
	copy(c.high[16:], c.high[:16])
	return c
}

//nolint:revive // Keep cancellation explicit in the bounded verifier.
func (p *regexBoundedClass) match(data []byte, start int, greedy bool, done <-chan struct{}) (int, bool) {
	if start < 0 || start > len(data) || len(data)-start < len(p.prefix)+p.min {
		return 0, false
	}
	prefix := data[start : start+len(p.prefix)]
	if p.noCase {
		if !equalRegexPrefixFold(prefix, p.prefix, false) {
			return 0, false
		}
	} else if !bytes.Equal(prefix, p.prefix) {
		return 0, false
	}
	data = data[start+len(p.prefix):]
	limit := p.min
	if p.greedy && greedy {
		limit = min(p.max, len(data))
	}
	count := 0
	for count < limit {
		if scanCanceled(done) {
			return 0, false
		}
		end := min(limit, count+1024)
		n := countBoundedClass(data[count:end], &p.class)
		count += n
		if count < end {
			break
		}
	}
	return len(p.prefix) + count, count >= p.min && !scanCanceled(done)
}

func countBoundedClassScalar(data []byte, class *boundedClassSet) int {
	for i, b := range data {
		if !class.set.Contains(b) {
			return i
		}
	}
	return len(data)
}
