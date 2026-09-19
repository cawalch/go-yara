package compiler

import (
	"encoding/binary"
	"math/bits"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/wordmatch"
	"github.com/cawalch/go-yara/regex"
)

const (
	wordRoutingLimit         = 64
	wordRoutingWorkLimit     = 8 << 20
	wordRoutingMaterialLimit = 16 << 20
)

// Material accounts for conversion buffers, separately from the source-bounded parser.
type wordRoutingConverter struct{ work, material int }

func newWordRoutingConverter() *wordRoutingConverter {
	return &wordRoutingConverter{work: wordRoutingWorkLimit, material: wordRoutingMaterialLimit}
}

func (c *wordRoutingConverter) take(work, material int) bool {
	if work > c.work || material > c.material {
		c.work, c.material = 0, 0
		return false
	}
	c.work -= work
	c.material -= material
	return true
}

func (c *wordRoutingConverter) pattern(str *ast.String) (wordmatch.Pattern, bool) {
	if str == nil || !c.take(len(str.Modifiers), 0) {
		return wordmatch.Pattern{}, false
	}
	var flags regex.Flags
	for _, modifier := range str.Modifiers {
		switch modifier.Type {
		case ast.StringModifierASCII:
		case ast.StringModifierNocase:
			flags |= regex.FlagsNoCase
		default:
			return wordmatch.Pattern{}, false
		}
	}
	var alternatives []wordmatch.Sequence
	switch pattern := str.Pattern.(type) {
	case *ast.TextString:
		if pattern == nil || pattern.Value == "" || !c.take(len(pattern.Value)+1, len(pattern.Value)+128) {
			return wordmatch.Pattern{}, false
		}
		alternatives = []wordmatch.Sequence{{{Literal: []byte(pattern.Value), NoCase: flags&regex.FlagsNoCase != 0}}}
	case *ast.RegexPattern:
		if pattern == nil {
			return wordmatch.Pattern{}, false
		}
		var ok bool
		alternatives, ok = c.regex(pattern.Value, flags)
		if !ok {
			return wordmatch.Pattern{}, false
		}
	default:
		return wordmatch.Pattern{}, false
	}
	for _, sequence := range alternatives {
		hasLiteral := false
		for _, term := range sequence {
			hasLiteral = hasLiteral || len(term.Literal) > 0
		}
		if !hasLiteral {
			return wordmatch.Pattern{}, false
		}
	}
	return wordmatch.Pattern{Any: alternatives}, len(alternatives) > 0
}

func (c *wordRoutingConverter) regex(source string, flags regex.Flags) ([]wordmatch.Sequence, bool) {
	if len(source) > 4096 || !c.take(len(source)+1, 0) {
		return nil, false
	}
	if strings.HasPrefix(source, "/") {
		end := strings.LastIndexByte(source, '/')
		if end == 0 {
			return nil, false
		}
		for _, flag := range source[end+1:] {
			switch flag {
			case 'i', 'I':
				flags |= regex.FlagsNoCase
			case 's', 'S':
				flags |= regex.FlagsDotAll
			default:
				return nil, false
			}
		}
	}
	parsed, err := regex.NewParser(regex.ParserFlagEnableStrictEscapeSequences).Parse(cleanRegexPattern(source))
	if err != nil {
		return nil, false
	}
	return c.node(parsed.Root, flags, 0)
}

func (c *wordRoutingConverter) node(node *regex.Node, flags regex.Flags, depth int) ([]wordmatch.Sequence, bool) {
	if node == nil || depth >= wordRoutingLimit || !c.take(1, 128) {
		return nil, false
	}
	switch node.Kind {
	case regex.NodeEmpty:
		return []wordmatch.Sequence{{}}, true
	case regex.NodeLiteral:
		return []wordmatch.Sequence{{{Literal: []byte{node.Value}, NoCase: flags&regex.FlagsNoCase != 0}}}, true
	case regex.NodeGroup:
		if len(node.Children) != 1 {
			return nil, false
		}
		return c.node(node.Children[0], flags, depth+1)
	case regex.NodeAlt, regex.NodeConcat:
		return c.children(node, flags, depth+1)
	case regex.NodeRange:
		if node.End == 65535 || node.Start > node.End || len(node.Children) != 1 {
			return nil, false
		}
		term, ok := c.byteTerm(node.Children[0], flags)
		if !ok {
			return nil, false
		}
		term.Min, term.Max = int(node.Start), int(node.End)
		if term.Max == 0 {
			return []wordmatch.Sequence{{}}, true
		}
		term = wordRoutingLiteral(term)
		return []wordmatch.Sequence{{term}}, true
	default:
		term, ok := c.byteTerm(node, flags)
		return []wordmatch.Sequence{{wordRoutingLiteral(term)}}, ok
	}
}

func (c *wordRoutingConverter) byteTerm(node *regex.Node, flags regex.Flags) (wordmatch.Term, bool) {
	if !c.take(256, 64) {
		return wordmatch.Term{}, false
	}
	for node.Kind == regex.NodeGroup || node.Kind == regex.NodeRange && node.Start == 1 && node.End == 1 {
		if len(node.Children) != 1 || !c.take(1, 0) {
			return wordmatch.Term{}, false
		}
		node = node.Children[0]
	}
	// Only ask the shared helper about a single consuming node, not an expanded sequence.
	if len(node.Children) != 0 {
		return wordmatch.Term{}, false
	}
	if node.Kind == regex.NodeClass && node.Class != nil {
		term := wordRoutingClass(node.Class, flags)
		return term, term.Set != [4]uint64{}
	}
	sets, ok := regex.FixedByteSets(&regex.AST{Root: node}, flags)
	if !ok || len(sets) != 1 {
		return wordmatch.Term{}, false
	}
	term := wordmatch.Term{Min: 1, Max: 1}
	for b := range 256 {
		if sets[0].Contains(byte(b)) {
			term.Set[b/64] |= uint64(1) << (b % 64)
		}
	}
	return term, term.Set != [4]uint64{}
}

func (c *wordRoutingConverter) children(node *regex.Node, flags regex.Flags, depth int) ([]wordmatch.Sequence, bool) {
	var parts [][]wordmatch.Sequence
	for i := 0; i < len(node.Children); {
		var next []wordmatch.Sequence
		var ok bool
		if node.Kind == regex.NodeConcat && node.Children[i].Kind == regex.NodeLiteral {
			var count int
			next, count = c.literalRun(node.Children[i:], flags)
			ok = count > 0
			i += count
		} else {
			next, ok = c.node(node.Children[i], flags, depth)
			i++
		}
		if !ok {
			return nil, false
		}
		if node.Kind == regex.NodeConcat && len(next) == 1 && len(next[0]) == 0 {
			continue
		}
		if node.Kind == regex.NodeConcat && len(parts) > 0 && c.mergeLiteral(parts[len(parts)-1], next) {
			continue
		}
		if !c.take(1, 64) {
			return nil, false
		}
		parts = append(parts, next)
	}
	var result []wordmatch.Sequence
	if node.Kind == regex.NodeConcat {
		result = []wordmatch.Sequence{{}}
	}
	for _, part := range parts {
		if node.Kind == regex.NodeAlt {
			if len(result)+len(part) > wordRoutingLimit || !c.take(len(part), 48*len(part)) {
				return nil, false
			}
			result = append(result, part...)
			continue
		}
		var ok bool
		result, ok = c.product(result, part)
		if !ok {
			return nil, false
		}
	}
	return result, true
}

func (c *wordRoutingConverter) mergeLiteral(left, right []wordmatch.Sequence) bool {
	if len(left) != 1 || len(right) != 1 || len(left[0]) != 1 || len(right[0]) != 1 {
		return false
	}
	a, b := &left[0][0], &right[0][0]
	if len(a.Literal) == 0 || len(b.Literal) == 0 || a.NoCase != b.NoCase {
		return false
	}
	if !c.take(len(b.Literal), 2*(len(a.Literal)+len(b.Literal))) {
		return false
	}
	a.Literal = append(a.Literal, b.Literal...)
	return true
}

func (c *wordRoutingConverter) product(left, right []wordmatch.Sequence) ([]wordmatch.Sequence, bool) {
	if len(right) == 0 || len(left) > wordRoutingLimit/len(right) {
		return nil, false
	}
	if len(left) == 1 && len(left[0]) == 0 {
		return right, true
	}
	if !c.take(len(left)*len(right), 48*len(left)*len(right)) {
		return nil, false
	}
	result := make([]wordmatch.Sequence, 0, len(left)*len(right))
	for _, a := range left {
		for _, b := range right {
			if !c.take(len(a)+len(b), 128*(len(a)+len(b))) {
				return nil, false
			}
			sequence := make(wordmatch.Sequence, len(a), len(a)+len(b))
			copy(sequence, a)
			for _, term := range b {
				last := len(sequence) - 1
				if last >= 0 && len(sequence[last].Literal) > 0 && len(term.Literal) > 0 && sequence[last].NoCase == term.NoCase {
					length := len(sequence[last].Literal) + len(term.Literal)
					if !c.take(length, length) {
						return nil, false
					}
					joined := make([]byte, length)
					copy(joined, sequence[last].Literal)
					copy(joined[len(sequence[last].Literal):], term.Literal)
					sequence[last].Literal = joined
				} else {
					sequence = append(sequence, term)
				}
			}
			if len(sequence) > wordRoutingLimit {
				return nil, false
			}
			result = append(result, sequence)
		}
	}
	return result, true
}

func wordRoutingLiteral(term wordmatch.Term) wordmatch.Term {
	if term.Min != 1 || term.Max != 1 {
		return term
	}
	var values [2]byte
	count := 0
	for i, word := range term.Set {
		for word != 0 {
			if count == len(values) {
				return term
			}
			values[count] = byte(i*64 + bits.TrailingZeros64(word)) //checkednarrow:ignore four words and a nonzero bit index give 0..255
			count++
			word &= word - 1
		}
	}
	if count == 1 {
		return wordmatch.Term{Literal: []byte{values[0]}}
	}
	if count == 2 && values[0] >= 'A' && values[0] <= 'Z' && values[1] == values[0]+32 {
		return wordmatch.Term{Literal: []byte{values[0]}, NoCase: true}
	}
	return term
}

func (c *wordRoutingConverter) literalRun(nodes []*regex.Node, flags regex.Flags) ([]wordmatch.Sequence, int) {
	count := 0
	for count < len(nodes) && nodes[count].Kind == regex.NodeLiteral {
		count++
	}
	if !c.take(count, count+128) {
		return nil, 0
	}
	literal := make([]byte, count)
	for i := range literal {
		literal[i] = nodes[i].Value
	}
	return []wordmatch.Sequence{{{Literal: literal, NoCase: flags&regex.FlagsNoCase != 0}}}, count
}

func wordRoutingClass(class *regex.Class, flags regex.Flags) wordmatch.Term {
	term := wordmatch.Term{Min: 1, Max: 1}
	for i := range term.Set {
		term.Set[i] = binary.LittleEndian.Uint64(class.Bitmap[i*8:])
	}
	if flags&regex.FlagsNoCase != 0 {
		// Fold the positive set before complementing a negated class.
		letters := ((term.Set[1] >> 1) | (term.Set[1] >> 33)) & ((1 << 26) - 1)
		term.Set[1] |= letters<<1 | letters<<33
	}
	if class.Negated {
		for i := range term.Set {
			term.Set[i] = ^term.Set[i]
		}
	}
	return term
}
