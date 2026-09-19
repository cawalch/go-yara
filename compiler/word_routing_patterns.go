package compiler

import (
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/wordmatch"
	"github.com/cawalch/go-yara/regex"
)

const wordRoutingLimit = 64

func wordRoutingPattern(str *ast.String) (wordmatch.Pattern, bool) {
	if str == nil {
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
		if pattern == nil || pattern.Value == "" {
			return wordmatch.Pattern{}, false
		}
		alternatives = []wordmatch.Sequence{{{Literal: []byte(pattern.Value), NoCase: flags&regex.FlagsNoCase != 0}}}
	case *ast.RegexPattern:
		if pattern == nil {
			return wordmatch.Pattern{}, false
		}
		var ok bool
		alternatives, ok = wordRoutingRegex(pattern.Value, flags)
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

func wordRoutingRegex(source string, flags regex.Flags) ([]wordmatch.Sequence, bool) {
	if len(source) > 4096 {
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
	return wordRoutingNode(parsed.Root, flags, 0)
}

func wordRoutingNode(node *regex.Node, flags regex.Flags, depth int) ([]wordmatch.Sequence, bool) {
	if node == nil || depth >= wordRoutingLimit {
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
		return wordRoutingNode(node.Children[0], flags, depth+1)
	case regex.NodeAlt, regex.NodeConcat:
		return wordRoutingChildren(node, flags, depth+1)
	case regex.NodeRange:
		if node.End == 65535 || node.Start > node.End || len(node.Children) != 1 {
			return nil, false
		}
		term, ok := wordRoutingByte(node.Children[0], flags)
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
		term, ok := wordRoutingByte(node, flags)
		return []wordmatch.Sequence{{wordRoutingLiteral(term)}}, ok
	}
}

func wordRoutingByte(node *regex.Node, flags regex.Flags) (wordmatch.Term, bool) {
	sets, ok := regex.FixedByteSets(&regex.AST{Root: node}, flags)
	if !ok || len(sets) != 1 {
		return wordmatch.Term{}, false
	}
	term := wordmatch.Term{Min: 1, Max: 1}
	for _, b := range sets[0].Values() {
		term.Set[b/64] |= uint64(1) << (b % 64)
	}
	return term, term.Set != [4]uint64{}
}

func wordRoutingChildren(node *regex.Node, flags regex.Flags, depth int) ([]wordmatch.Sequence, bool) {
	var parts [][]wordmatch.Sequence
	for _, child := range node.Children {
		next, ok := wordRoutingNode(child, flags, depth)
		if !ok {
			return nil, false
		}
		if node.Kind == regex.NodeConcat && len(next) == 1 && len(next[0]) == 0 {
			continue
		}
		if node.Kind == regex.NodeConcat && len(parts) > 0 && wordRoutingMergeLiteral(parts[len(parts)-1], next) {
			continue
		}
		parts = append(parts, next)
	}
	var result []wordmatch.Sequence
	if node.Kind == regex.NodeConcat {
		result = []wordmatch.Sequence{{}}
	}
	for _, part := range parts {
		if node.Kind == regex.NodeAlt {
			if len(result)+len(part) > wordRoutingLimit {
				return nil, false
			}
			result = append(result, part...)
			continue
		}
		var ok bool
		result, ok = wordRoutingProduct(result, part)
		if !ok {
			return nil, false
		}
	}
	return result, true
}

func wordRoutingMergeLiteral(left, right []wordmatch.Sequence) bool {
	if len(left) != 1 || len(right) != 1 || len(left[0]) != 1 || len(right[0]) != 1 {
		return false
	}
	a, b := &left[0][0], &right[0][0]
	if len(a.Literal) == 0 || len(b.Literal) == 0 || a.NoCase != b.NoCase {
		return false
	}
	a.Literal = append(a.Literal, b.Literal...)
	return true
}

func wordRoutingProduct(left, right []wordmatch.Sequence) ([]wordmatch.Sequence, bool) {
	if len(right) == 0 || len(left) > wordRoutingLimit/len(right) {
		return nil, false
	}
	result := make([]wordmatch.Sequence, 0, len(left)*len(right))
	for _, a := range left {
		for _, b := range right {
			sequence := make(wordmatch.Sequence, len(a), len(a)+len(b))
			copy(sequence, a)
			for _, term := range b {
				last := len(sequence) - 1
				if last >= 0 && len(sequence[last].Literal) > 0 && len(term.Literal) > 0 && sequence[last].NoCase == term.NoCase {
					joined := make([]byte, len(sequence[last].Literal)+len(term.Literal))
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
	var values []byte
	for b := 0; b < 256; b++ {
		if term.Set[b/64]&(uint64(1)<<uint(b%64)) != 0 {
			values = append(values, byte(b))
			if len(values) > 2 {
				return term
			}
		}
	}
	if len(values) == 1 {
		return wordmatch.Term{Literal: values}
	}
	if len(values) == 2 && values[0] >= 'A' && values[0] <= 'Z' && values[1] == values[0]+32 {
		return wordmatch.Term{Literal: values[:1], NoCase: true}
	}
	return term
}
