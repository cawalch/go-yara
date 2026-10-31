package compiler

import (
	"slices"

	"github.com/cawalch/go-yara/regex"
)

// Libyara's bounded-repeat atoms point into the first mandatory copy. Each
// literal branch verifies independently, then follows priority through the
// remaining copies. Greedy strings retain the last accepted atom candidate;
// lazy strings keep the first. Bare literal alternatives use the same plan
// with one mandatory copy and an empty continuation.
// Exported fields are persisted as part of the compiled-program format.
type regexBoundedAlternation struct {
	asciiOrder, wideOrder []int
	Branches              []boundedRegexBranch
	Tail                  []byte
	Repeat                *regexRepeatPlan
	Fullword              bool
	CheckEncodingOrder    bool
}

func compileBoundedAlternation(parsed *regex.AST, fullword, dual bool) (*regexBoundedAlternation, error) {
	if parsed == nil {
		return nil, nil
	}
	node := ungroupRegexNode(parsed.Root)
	if node.Kind == regex.NodeConcat {
		return compileLiteralAffixes(node, fullword, dual)
	}
	if isLiteralRegexAlternation(node) {
		// Keep the original pattern flags: bare alternatives retain the first
		// accepted atom, including runtime wide/nocase candidate order.
		node = &regex.Node{Kind: regex.NodeRange, Start: 1, End: 1, Children: []*regex.Node{node}}
	}
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
	plan.Tail = code
	plan.prepareEncodingOrder(dual)
	return plan, nil
}

func (plan *regexBoundedAlternation) prepareEncodingOrder(dual bool) {
	// Without a literal NUL, an ASCII match that also matches wide can only
	// contribute a one-byte atom, which precedes the corresponding wide atom.
	if dual && plan.Repeat != nil {
		plan.CheckEncodingOrder = slices.Contains(plan.Repeat.Prefix, 0)
		for _, branch := range plan.Repeat.Branches {
			plan.CheckEncodingOrder = plan.CheckEncodingOrder || slices.Contains(branch.Literal, 0)
		}
	}
	if dual {
		for _, branch := range plan.Branches {
			plan.CheckEncodingOrder = plan.CheckEncodingOrder || slices.Contains(branch.Literal, 0)
		}
	}
	plan.prepareOrder()
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
	plan.Branches = append(plan.Branches, boundedRegexBranch{Literal: prefix, AtomOffset: regexLiteralAtomOffset(prefix)})
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
	cloned := &regexBoundedAlternation{CheckEncodingOrder: plan.CheckEncodingOrder, Fullword: plan.Fullword, Repeat: cloneRepeatPlan(plan.Repeat), Tail: slices.Clone(plan.Tail), Branches: slices.Clone(plan.Branches)}
	for i := range cloned.Branches {
		cloned.Branches[i].Literal = slices.Clone(plan.Branches[i].Literal)
	}
	cloned.prepareOrder()
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
	if plan.Repeat != nil {
		return plan.execRepeat(data, flags, start, done)
	}
	bestEnd := -1
	var bestOrder boundedAtomOrder
	wide := flags&regex.FlagsWide != 0
	indices := plan.asciiOrder
	if wide {
		indices = plan.wideOrder
	}
	for position := range indices {
		if flags&regex.FlagsGreedy != 0 {
			position = len(indices) - 1 - position
		}
		i := indices[position]
		branch := plan.Branches[i]
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
			// Without case variants, the prepared order is exact.
			if flags&regex.FlagsNoCase == 0 {
				return bestEnd, bestOrder
			}
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

// prepareOrder prioritizes the likely winning candidate before running the
// continuation. Runtime rank comparisons still account for case variants.
func (plan *regexBoundedAlternation) prepareOrder() {
	if plan.Repeat != nil {
		for _, branch := range plan.Repeat.Branches {
			plan.Repeat.maxLength = max(plan.Repeat.maxLength, len(branch.Literal))
		}
		return // Repeated candidates are ranked at their runtime positions.
	}
	for _, wide := range []bool{false, true} {
		indices := make([]int, len(plan.Branches))
		for i := range indices {
			indices[i] = i
		}
		slices.SortFunc(indices, func(i, j int) int {
			a, b := plan.Branches[i].baseOrder(i, wide), plan.Branches[j].baseOrder(j, wide)
			if a.before(b) {
				return -1
			}
			if b.before(a) {
				return 1
			}
			return 0
		})
		if wide {
			plan.wideOrder = indices
		} else {
			plan.asciiOrder = indices
		}
	}
}

func (branch boundedRegexBranch) baseOrder(index int, wide bool) boundedAtomOrder {
	step := 1
	if wide {
		step = 2
		index = -index
	}
	length := min(len(branch.Literal)-branch.AtomOffset, 4/step) * step
	return boundedAtomOrder{end: branch.AtomOffset*step + length, length: length, index: index, wide: wide}
}

//nolint:revive // candidate order needs the source position and encoding
func (branch boundedRegexBranch) order(data []byte, start, index int, wide bool) boundedAtomOrder {
	order := branch.baseOrder(index, wide)
	step := 1
	if wide {
		step = 2
	}
	for i := 0; i < order.length/step; i++ {
		offset := branch.AtomOffset + i
		if data[start+offset*step] != branch.Literal[offset] {
			order.variant = true
		}
	}
	if order.variant {
		order.index = -order.index
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
