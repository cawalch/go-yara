package compiler

import (
	"context"
	"encoding/binary"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

const (
	minCombinedRegexPatterns      = 4
	maxCombinedRegexPatterns      = 64
	maxCombinedRegexStates        = 4096
	maxCombinedRegexDepth         = 512
	maxCombinedRegexWork          = 32768
	maxCombinedRegexProgramStates = 131072
)

type combinedRegexAccept struct{ target, priority int }
type combinedRegexState struct {
	set      regex.ByteSet
	children []int
	accepts  []combinedRegexAccept
	depth    int
}
type combinedRegexTarget struct {
	entry  sharedAutomatonEntry
	greedy bool
}

// A prefix trie of consuming byte sets is an acyclic position NFA: overlapping
// outgoing sets remain active together. Accept priorities belong to individual
// regexes, so sharing transitions never changes their ordered branch choice.
type combinedRegexNFA struct {
	states  []combinedRegexState
	targets []combinedRegexTarget
	leader  int
}
type combinedRegexInstruction struct {
	set             regex.ByteSet
	next, alternate int
	op              byte
}
type combinedRegexEdge struct {
	parent int
	set    regex.ByteSet
}
type combinedRegexPosition struct{ pc, state int }
type combinedRegexClassKey struct {
	code   [34]byte
	noCase bool
}

type combinedRegexDecoder struct {
	classes      map[combinedRegexClassKey]regex.ByteSet
	instructions []combinedRegexInstruction
	offsets      map[int]int
}

type combinedRegexBuilder struct {
	seen                       map[combinedRegexPosition]bool
	stack                      []combinedRegexPosition
	path                       []int
	nfa                        combinedRegexNFA
	edges                      map[combinedRegexEdge]int
	work, accepts, transitions int
}
type combinedRegexScratch struct {
	current, next    []int
	ends, priorities []int
	enabled          []bool
}

func decodeCombinedRegex(pattern RegexPattern) ([]combinedRegexInstruction, bool) {
	var decoder combinedRegexDecoder
	return decoder.decode(pattern)
}

func (decoder *combinedRegexDecoder) decode(pattern RegexPattern) ([]combinedRegexInstruction, bool) {
	code := pattern.Code
	if len(code) == 0 || len(code) > 16384 || len(pattern.CaptureCode) > 0 || pattern.anchored ||
		pattern.Flags&(regex.FlagsWide|regex.FlagsBackwards|regex.FlagsScan|regex.FlagsExhaustive|regex.FlagsFullwordEnd) != 0 {
		return nil, false
	}
	instructions := decoder.instructions[:0]
	if decoder.offsets == nil {
		decoder.offsets = make(map[int]int)
	}
	offsets := decoder.offsets
	clear(offsets)
	for pc := 0; pc < len(code); {
		offsets[pc] = len(instructions)
		in := combinedRegexInstruction{op: code[pc], alternate: -1}
		size := 1
		switch in.op {
		case regex.OpMatch:
		case regex.OpSplitA, regex.OpSplitB, regex.OpJump:
			if pc+3 > len(code) {
				return nil, false
			}
			relative := int(int16(binary.LittleEndian.Uint16(code[pc+1 : pc+3]))) //checkednarrow:ignore bytecode encodes a signed relative offset
			if relative <= 0 {
				return nil, false
			}
			size, in.alternate = 3, pc+relative
		case regex.OpLiteral:
			if pc+2 > len(code) {
				return nil, false
			}
			size = 2
			in.set = regex.NewByteSet(code[pc+1 : pc+2])
			if pattern.Flags&regex.FlagsNoCase != 0 {
				in.set = in.set.ASCIIFolded()
			}
		default:
			size = boundedClassInstructionSize(code[pc:])
			if size == 0 {
				return nil, false
			}
			key := combinedRegexClassKey{noCase: pattern.Flags&regex.FlagsNoCase != 0}
			copy(key.code[:], code[pc:pc+size])
			var cached bool
			in.set, cached = decoder.classes[key]
			if !cached {
				in.set, _ = boundedClassInstruction(code[pc:pc+size], pattern.Flags)
				if decoder.classes == nil {
					decoder.classes = make(map[combinedRegexClassKey]regex.ByteSet)
				}
				if len(decoder.classes) < 256 {
					decoder.classes[key] = in.set
				}
			}
		}
		in.next = pc + size
		instructions = append(instructions, in)
		pc += size
	}
	decoder.instructions = instructions
	for i := range instructions {
		in := &instructions[i]
		if in.op == regex.OpMatch {
			continue
		}
		var ok bool
		if in.op != regex.OpJump {
			in.next, ok = offsets[in.next]
			if !ok {
				return nil, false
			}
		}
		if in.alternate >= 0 {
			in.alternate, ok = offsets[in.alternate]
			if !ok {
				return nil, false
			}
		}
	}
	return instructions, true
}

func (b *combinedRegexBuilder) add(instructions []combinedRegexInstruction, entry sharedAutomatonEntry, greedy bool) bool {
	target := len(b.nfa.targets)
	b.nfa.targets = append(b.nfa.targets, combinedRegexTarget{entry, greedy})
	b.stack = append(b.stack[:0], combinedRegexPosition{0, 0})
	stack := b.stack
	if b.seen == nil {
		b.seen = make(map[combinedRegexPosition]bool)
	}
	seen := b.seen
	clear(seen)
	priority := 0
	for len(stack) > 0 {
		pos := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[pos] {
			continue
		}
		seen[pos] = true
		b.work++
		if b.work > maxCombinedRegexWork {
			return false
		}
		in := instructions[pos.pc]
		switch in.op {
		case regex.OpMatch:
			if pos.state == 0 {
				return false
			}
			b.accepts++
			if b.accepts > maxCombinedRegexWork {
				return false
			}
			b.nfa.states[pos.state].accepts = append(b.nfa.states[pos.state].accepts, combinedRegexAccept{target, priority})
			priority++
		case regex.OpJump:
			stack = append(stack, combinedRegexPosition{in.alternate, pos.state})
		case regex.OpSplitA, regex.OpSplitB:
			if end, count, set := combinedOptionalRun(instructions, pos.pc); count > 1 {
				b.path = append(b.path[:0], pos.state)
				states := b.path
				for range count {
					child, ok := b.child(states[len(states)-1], set)
					if !ok {
						return false
					}
					states = append(states, child)
				}
				b.path = states
				for i := range states {
					index := i
					if in.op == regex.OpSplitB {
						index = len(states) - 1 - i
					}
					stack = append(stack, combinedRegexPosition{end, states[index]})
				}
				continue
			}
			first, second := in.next, in.alternate
			if in.op == regex.OpSplitB {
				first, second = second, first
			}
			stack = append(stack, combinedRegexPosition{second, pos.state}, combinedRegexPosition{first, pos.state})
		default:
			child, ok := b.child(pos.state, in.set)
			if !ok {
				return false
			}
			stack = append(stack, combinedRegexPosition{in.next, child})
		}
	}
	b.stack = stack
	return priority > 0
}

// Equivalent optional repetitions have many bytecode paths but only one
// consuming path per length. Collapse them before expanding the finite NFA.
func combinedOptionalRun(code []combinedRegexInstruction, pc int) (int, int, regex.ByteSet) {
	end := pc
	var set regex.ByteSet
	for end+1 < len(code) {
		split, atom := code[end], code[end+1]
		if split.op != code[pc].op || split.next != end+1 || split.alternate != end+2 || atom.alternate != -1 || atom.op == regex.OpMatch || atom.next != end+2 {
			break
		}
		if end == pc {
			set = atom.set
		} else if atom.set != set {
			break
		}
		end += 2
	}
	return end, (end - pc) / 2, set
}

func (b *combinedRegexBuilder) child(parent int, set regex.ByteSet) (int, bool) {
	b.transitions++
	key := combinedRegexEdge{parent, set}
	if child, ok := b.edges[key]; ok {
		return child, true
	}
	depth := b.nfa.states[parent].depth + 1
	if len(b.nfa.states) >= maxCombinedRegexStates || depth > maxCombinedRegexDepth {
		return 0, false
	}
	child := len(b.nfa.states)
	b.nfa.states = append(b.nfa.states, combinedRegexState{set: set, depth: depth})
	b.nfa.states[parent].children = append(b.nfa.states[parent].children, child)
	b.edges[key] = child
	return child, true
}

func (cp *CompiledProgram) prepareCombinedRegex() {
	type key struct {
		atom   string
		flags  regex.Flags
		offset int
	}
	groups := make(map[key][]int)
	var order []key
	for i, entry := range cp.sharedLookup {
		if entry.Kind != StringKindRegex || entry.IsWide || entry.alternativeAtom || entry.AtomOffset != entry.AtomMaxOffset || entry.AtomOffset < 0 {
			continue
		}
		rule := cp.Rules[entry.RuleIndex]
		id := rule.IndexToStringID[entry.StringIdx]
		modifiers := rule.StringModifiers[id]
		if hasModifier(modifiers, ast.StringModifierWide) || hasModifier(modifiers, ast.StringModifierFullword) {
			continue
		}
		info := cp.sharedAutomaton.strings[i]
		k := key{string(info.Data), info.Flags, entry.AtomOffset}
		if len(groups[k]) == 0 {
			order = append(order, k)
		}
		groups[k] = append(groups[k], i)
	}
	budget := maxCombinedRegexProgramStates
	var decoder combinedRegexDecoder
	for _, k := range order {
		indices := groups[k]
		for len(indices) >= minCombinedRegexPatterns {
			count := min(len(indices), maxCombinedRegexPatterns)
			chunk := indices[:count]
			indices = indices[count:]
			b := combinedRegexBuilder{nfa: combinedRegexNFA{states: []combinedRegexState{{}}, leader: chunk[0]}, edges: make(map[combinedRegexEdge]int)}
			var members []int
			ok := true
			for _, index := range chunk {
				entry := cp.sharedLookup[index]
				rule := cp.Rules[entry.RuleIndex]
				pattern := rule.RegexPatterns[rule.IndexToStringID[entry.StringIdx]]
				instructions, eligible := decoder.decode(pattern)
				if !eligible {
					continue
				}
				if !b.add(instructions, entry, pattern.Flags&regex.FlagsGreedy != 0) {
					ok = false
					break
				}
				members = append(members, index)
			}
			if !ok || len(members) < minCombinedRegexPatterns || b.transitions < 2*len(b.nfa.states) || len(b.nfa.states)+b.accepts > budget {
				continue
			}
			b.nfa.leader = members[0]
			budget -= len(b.nfa.states) + b.accepts
			nfa := b.nfa // Retain only the immutable plan, not the builder maps and scratch.
			for _, index := range members {
				cp.sharedLookup[index].combined = &nfa
			}
		}
	}
}

func (n *combinedRegexNFA) match(data []byte, scratch *combinedRegexScratch, done <-chan struct{}) {
	scratch.ends = resizeCombinedInts(scratch.ends, len(n.targets))
	scratch.priorities = resizeCombinedInts(scratch.priorities, len(n.targets))
	clear(scratch.ends)
	for i := range scratch.priorities {
		scratch.priorities[i] = int(^uint(0) >> 1)
	}
	scratch.current = append(scratch.current[:0], 0)
	current, next := scratch.current, scratch.next[:0]
	for pos, value := range data {
		if scanCanceledAt(done, pos) {
			break
		}
		next = next[:0]
		for _, parent := range current {
			for _, child := range n.states[parent].children {
				state := &n.states[child]
				if !state.set.Contains(value) {
					continue
				}
				next = append(next, child)
				for _, accept := range state.accepts {
					target := accept.target
					if scratch.ends[target] == 0 || n.targets[target].greedy && accept.priority < scratch.priorities[target] {
						scratch.ends[target] = pos + 1
						scratch.priorities[target] = accept.priority
					}
				}
			}
		}
		current, next = next, current
		if len(current) == 0 {
			break
		}
	}
	scratch.current, scratch.next = current, next
}

func resizeCombinedInts(values []int, size int) []int {
	if cap(values) < size {
		return make([]int, size)
	}
	return values[:size]
}

//nolint:revive // Shared cache routing keeps the candidate batch explicit.
func (s *Scanner) populateCombinedRegex(ctx context.Context, data []byte, cache *nonTextMatchCache, n *combinedRegexNFA, candidates []int) {
	scratch := &s.combinedRegexScratch
	if cap(scratch.enabled) < len(n.targets) {
		scratch.enabled = make([]bool, len(n.targets))
	}
	scratch.enabled = scratch.enabled[:len(n.targets)]
	for i, target := range n.targets {
		rule := s.program.Rules[target.entry.RuleIndex]
		scratch.enabled[i] = !s.canSkipSharedNonTextEntry(target.entry, rule, data)
	}
	for _, target := range n.targets {
		cache.set(target.entry.CacheIndex, cache.matches[target.entry.CacheIndex])
	}
	lastStart := -1
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return
		}
		start := candidate - n.targets[0].entry.AtomOffset
		if start < 0 || start >= len(data) || start <= lastStart {
			continue
		}
		lastStart = start
		end := len(data)
		if s.maxMatchSpan > 0 {
			end = start + min(s.maxMatchSpan, len(data)-start)
		}
		n.match(data[start:end], scratch, ctx.Done())
		if ctx.Err() != nil {
			return
		}
		for i, length := range scratch.ends {
			if length > 0 && scratch.enabled[i] {
				index := n.targets[i].entry.CacheIndex
				cache.matches[index] = append(cache.matches[index], matchSpan{Offset: int64(start), Length: length})
			}
		}
	}
	for _, target := range n.targets {
		index := target.entry.CacheIndex
		cache.set(index, cache.matches[index])
		if len(cache.matches[index]) > 0 {
			s.sharedNonTextMatched = true
			s.markNonTextCacheRules(index)
		}
	}
}
