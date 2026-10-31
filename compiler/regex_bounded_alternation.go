package compiler

import (
	"slices"

	"github.com/cawalch/go-yara/regex"
)

// Libyara's bounded-repeat atoms point into the first mandatory copy. Each
// literal branch verifies independently, then follows priority through the
// remaining copies. Greedy strings retain the last accepted atom candidate;
// lazy strings keep the first.
// Exported fields are persisted as part of the compiled-program format.
type regexBoundedAlternation struct {
	Branches           []boundedRegexBranch
	Tail               []byte
	Fullword           bool
	CheckEncodingOrder bool
}

func compileBoundedAlternation(parsed *regex.AST, fullword, dual bool) (*regexBoundedAlternation, error) {
	if parsed == nil {
		return nil, nil
	}
	node := ungroupRegexNode(parsed.Root)
	if node.Kind != regex.NodeRange || node.Start == 0 || node.End == 65535 || !isLiteralRegexAlternation(node.Children[0]) {
		return nil, nil
	}
	plan := &regexBoundedAlternation{Fullword: fullword}
	if err := plan.appendPrefixes(node.Children[0]); err != nil {
		return nil, err
	}
	if !plan.overlappingPrefixes() {
		return nil, nil
	}
	tail := &regex.Node{Kind: regex.NodeRange, Start: node.Start - 1, End: node.End - 1, Greedy: node.Greedy, Children: node.Children}
	code, err := regex.Compile(&regex.AST{Root: tail})
	if err != nil {
		return nil, err
	}
	// Without a literal NUL, an ASCII match that also matches wide can only
	// contribute a one-byte atom, which precedes the corresponding wide atom.
	if dual {
		for _, branch := range plan.Branches {
			plan.CheckEncodingOrder = plan.CheckEncodingOrder || slices.Contains(branch.Literal, 0)
		}
	}
	plan.Tail = code
	return plan, nil
}

func (plan *regexBoundedAlternation) appendPrefixes(node *regex.Node) error {
	node = ungroupRegexNode(node)
	if node.Kind == regex.NodeAlt {
		for _, child := range node.Children {
			if err := plan.appendPrefixes(child); err != nil {
				return err
			}
		}
		return nil
	}
	code, err := regex.Compile(&regex.AST{Root: node})
	if err != nil {
		return err
	}
	prefix, _ := regex.LiteralPrefix(code)
	plan.Branches = append(plan.Branches, boundedRegexBranch{Literal: prefix, AtomOffset: boundedAtomOffset(prefix)})
	return nil
}

type boundedRegexBranch struct {
	Literal    []byte
	AtomOffset int
}

func cloneBoundedAlternation(plan *regexBoundedAlternation) *regexBoundedAlternation {
	if plan == nil {
		return nil
	}
	cloned := &regexBoundedAlternation{CheckEncodingOrder: plan.CheckEncodingOrder, Fullword: plan.Fullword, Tail: slices.Clone(plan.Tail), Branches: slices.Clone(plan.Branches)}
	for i := range cloned.Branches {
		cloned.Branches[i].Literal = slices.Clone(plan.Branches[i].Literal)
	}
	return cloned
}

func (plan *regexBoundedAlternation) overlappingPrefixes() bool {
	for _, shorter := range plan.Branches {
		for _, longer := range plan.Branches {
			if len(shorter.Literal) < len(longer.Literal) && equalRegexPrefixFold(longer.Literal, shorter.Literal, false) {
				return true
			}
		}
	}
	return false
}

//nolint:revive // shared verifier arguments stay explicit
func execBoundedAlternation(bs *regex.VMBatch, plan *regexBoundedAlternation, data []byte, flags regex.Flags, start int, done <-chan struct{}) (bool, int, int) {
	end, order := plan.execEncoding(bs, data, flags, start, done)
	if end < 0 {
		return false, -1, -1
	}
	if plan.CheckEncodingOrder {
		otherEnd, otherOrder := plan.execEncoding(bs, data, flags^regex.FlagsWide, start, done)
		if otherEnd >= 0 && (flags&regex.FlagsGreedy != 0) == order.before(otherOrder) {
			return false, -1, -1
		}
	}
	return true, 0, end - start
}

//nolint:revive // shared verifier arguments stay explicit
func (plan *regexBoundedAlternation) execEncoding(bs *regex.VMBatch, data []byte, flags regex.Flags, start int, done <-chan struct{}) (int, boundedAtomOrder) {
	bestEnd := -1
	var bestOrder boundedAtomOrder
	wide := flags&regex.FlagsWide != 0
	for i, branch := range plan.Branches {
		if scanCanceled(done) {
			return -1, boundedAtomOrder{}
		}
		next, ok := boundedLiteralEnd(data, start, branch.Literal, flags)
		if !ok {
			continue
		}
		order := branch.order(data, start, i, wide)
		if bestEnd >= 0 && (flags&regex.FlagsGreedy != 0) == order.before(bestOrder) {
			continue
		}
		matched, _, end, _ := regex.ExecMatchBatchWithCancel(bs, plan.Tail, data, flags|regex.FlagsGreedy, next, done)
		if !matched {
			continue
		}
		end += next
		if !plan.Fullword || isFullwordMatch(data, start, end-start, wide) {
			bestEnd, bestOrder = end, order
		}
	}
	return bestEnd, bestOrder
}

// AC visits earlier atom ends first, then longer suffix atoms. On identical
// atoms, case-variant matches precede original-case matches; wide and nocase
// list construction each reverse the source branch order once.
type boundedAtomOrder struct {
	end, length, index int
	variant            bool
	wide               bool
}

//nolint:revive // candidate order needs the source position and encoding
func (branch boundedRegexBranch) order(data []byte, start, index int, wide bool) boundedAtomOrder {
	step := 1
	if wide {
		step = 2
	}
	length := min(len(branch.Literal)-branch.AtomOffset, 4/step)
	order := boundedAtomOrder{end: branch.AtomOffset*step + length*step, length: length * step, index: index, wide: wide}
	for i := 0; i < length; i++ {
		offset := branch.AtomOffset + i
		if data[start+offset*step] != branch.Literal[offset] {
			order.variant = true
		}
	}
	if wide != order.variant {
		order.index = -index
	}
	return order
}

func (order boundedAtomOrder) before(other boundedAtomOrder) bool {
	if order.end != other.end {
		return order.end < other.end
	}
	if order.length != other.length {
		return order.length > other.length
	}
	if order.variant != other.variant {
		return order.variant
	}
	if order.wide != other.wide {
		return order.wide != order.variant
	}
	return order.index < other.index
}

// Literal atoms use libyara 4.5.8's default heuristic, retaining the earliest
// equally scored four-byte window. This ordering is separate from our prefilter.
func boundedAtomOffset(literal []byte) int {
	best, quality := 0, -1
	width := min(4, len(literal))
	for i := 0; i+width <= len(literal); i++ {
		if score := boundedAtomQuality(literal[i : i+width]); score > quality {
			best, quality = i, score
		}
	}
	return best
}

func boundedAtomQuality(atom []byte) int {
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

//nolint:revive // literal verification keeps its encoding flags explicit
func boundedLiteralEnd(data []byte, start int, literal []byte, flags regex.Flags) (int, bool) {
	step := 1
	if flags&regex.FlagsWide != 0 {
		step = 2
	}
	end := start + len(literal)*step
	if end > len(data) {
		return 0, false
	}
	for i, want := range literal {
		pos := start + i*step
		if data[pos] != want && (flags&regex.FlagsNoCase == 0 || toLowerTable[data[pos]] != toLowerTable[want]) {
			return 0, false
		}
		if step == 2 && data[pos+1] != 0 {
			return 0, false
		}
	}
	return end, true
}
