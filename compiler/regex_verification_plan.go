package compiler

import (
	"slices"

	"github.com/cawalch/go-yara/regex"
)

const regexVerificationDistance = 4096

// The canonical atom is a semantic boundary: libyara permits 4096 bytes on
// either side of it. Prefilter atoms are independently optimized and cannot
// supply this boundary. These programs are only used for potentially long
// matches; literal regexes use libyara's unlimited literal verifier.
type regexVerificationPlan struct {
	Atoms       []regexVerificationAtom
	ForwardOnly bool
	Allowed     [256]bool
}

type regexVerificationAtom struct {
	Bytes, Mask, Forward, Backward []byte
}

func cloneVerificationPlan(plan *regexVerificationPlan) *regexVerificationPlan {
	if plan == nil {
		return nil
	}
	copyPlan := &regexVerificationPlan{Atoms: slices.Clone(plan.Atoms), ForwardOnly: plan.ForwardOnly, Allowed: plan.Allowed}
	for i, atom := range copyPlan.Atoms {
		copyPlan.Atoms[i] = regexVerificationAtom{slices.Clone(atom.Bytes), slices.Clone(atom.Mask), slices.Clone(atom.Forward), slices.Clone(atom.Backward)}
	}
	return copyPlan
}

func compileVerificationPlan(parsed *regex.AST, flags regex.Flags, wide bool) (*regexVerificationPlan, error) {
	step := 1
	if wide {
		step = 2
	}
	length := regex.ASTMaxLength(parsed)
	if isLiteralRegexNode(parsed.Root) || length >= 0 && length <= regexVerificationDistance/step {
		return nil, nil
	}
	choices := verificationAtoms(parsed.Root)
	plan := &regexVerificationPlan{Allowed: verificationAlphabet(parsed.Root, flags)}
	if wide {
		plan.Allowed[0] = true
	}
	if len(choices.atoms) == 0 {
		code, err := regex.CompileForward(parsed)
		if err != nil {
			return nil, err
		}
		plan.Atoms = append(plan.Atoms, regexVerificationAtom{Forward: code})
		plan.ForwardOnly = true
		return plan, nil
	}
	for _, selected := range choices.atoms {
		before, after, _ := splitVerificationNode(parsed.Root, selected[0])
		forward, err := regex.Compile(&regex.AST{Root: after})
		if err != nil {
			return nil, err
		}
		backward, err := compileVerificationPrefix(before)
		if err != nil {
			return nil, err
		}
		atom := regexVerificationAtom{Forward: forward, Backward: backward}
		for _, node := range selected {
			atom.Bytes = append(atom.Bytes, node.Value)
			mask := byte(255)
			if node.Kind == regex.NodeAny {
				mask = 0
			}
			if node.Kind == regex.NodeMaskedLiteral {
				mask = node.Mask
			}
			atom.Mask = append(atom.Mask, mask)
		}
		plan.Atoms = append(plan.Atoms, atom)
	}
	plan.ForwardOnly = len(plan.Atoms) == 1 && len(plan.Atoms[0].Backward) == 1
	if plan.ForwardOnly {
		if length := verificationTerminalMax(parsed.Root); length >= 0 && length <= regexVerificationDistance/step {
			return nil, nil
		}
	}
	return plan, nil
}

type verificationAtomChoice struct {
	atoms   [][]*regex.Node
	quality int
}

// OR chooses the first best-quality run; ALT requires atoms from every arm.
// ALT is appended before a pending run, matching libyara's atom tree order.
func verificationAtoms(root *regex.Node) verificationAtomChoice {
	best := verificationAtomChoice{quality: -1}
	var run []*regex.Node
	choose := func(candidate verificationAtomChoice) {
		if candidate.quality > best.quality {
			best = candidate
		}
	}
	flush := func() {
		if len(run) > 0 {
			choose(verificationRunAtom(run))
			run = nil
		}
	}
	var walk func(*regex.Node)
	walk = func(node *regex.Node) {
		node = ungroupRegexNode(node)
		switch node.Kind {
		case regex.NodeLiteral, regex.NodeMaskedLiteral, regex.NodeAny:
			run = append(run, node)
		case regex.NodeConcat:
			for _, child := range node.Children {
				walk(child)
			}
		case regex.NodeAlt:
			candidate := verificationAtomChoice{quality: 256}
			for _, child := range node.Children {
				part := verificationAtoms(child)
				candidate.quality = min(candidate.quality, part.quality)
				candidate.atoms = append(candidate.atoms, part.atoms...)
			}
			choose(candidate)
			flush()
		case regex.NodePlus:
			walk(node.Children[0])
			flush()
		case regex.NodeRange:
			for range min(int(node.Start), 4) {
				walk(node.Children[0])
			}
			flush()
		default:
			flush()
		}
	}
	walk(root)
	flush()
	return best
}

func verificationRunAtom(run []*regex.Node) verificationAtomChoice {
	best := verificationAtomChoice{quality: -1}
	for start := 0; start <= max(0, len(run)-4); start++ {
		part := run[start:min(len(run), start+4)]
		for len(part) > 0 && part[0].Kind == regex.NodeAny {
			part = part[1:]
		}
		for len(part) > 0 && part[len(part)-1].Kind == regex.NodeAny {
			part = part[:len(part)-1]
		}
		if len(part) == 0 {
			continue
		}
		unknown := 0
		for _, node := range part {
			if node.Kind == regex.NodeAny {
				unknown++
			}
		}
		if unknown*2 >= len(part) {
			part = part[:1]
		}
		quality := 0
		var known []byte
		for _, node := range part {
			if node.Kind == regex.NodeAny {
				quality -= 10
			} else {
				known = append(known, node.Value)
			}
		}
		quality += 255 - 22*4 + regexLiteralAtomQuality(known)
		// The common-byte penalty includes wildcard positions in libyara.
		if len(known) > 0 && slices.IndexFunc(known, func(value byte) bool { return value != known[0] }) < 0 {
			switch known[0] {
			case 0, 0x20, 0x90, 0xcc, 0xff:
				quality -= 10 * unknown
			}
		}
		if quality > best.quality {
			best = verificationAtomChoice{[][]*regex.Node{slices.Clone(part)}, quality}
		}
	}
	return best
}

func verificationConcat(nodes ...*regex.Node) *regex.Node {
	if len(nodes) == 0 {
		return &regex.Node{Kind: regex.NodeEmpty}
	}
	if len(nodes) == 1 {
		return nodes[0]
	}
	return &regex.Node{Kind: regex.NodeConcat, Children: nodes}
}

// Split at the first mandatory instance of a leaf. PLUS admits preceding
// iterations; RANGE's atom references its first emitted mandatory copy.
func splitVerificationNode(node, target *regex.Node) (before, after *regex.Node, found bool) {
	node = ungroupRegexNode(node)
	if node == target {
		return &regex.Node{Kind: regex.NodeEmpty}, node, true
	}
	for i, child := range node.Children {
		left, right, ok := splitVerificationNode(child, target)
		if !ok {
			continue
		}
		switch node.Kind {
		case regex.NodeConcat:
			left = verificationConcat(append(slices.Clone(node.Children[:i]), left)...)
			right = verificationConcat(append([]*regex.Node{right}, node.Children[i+1:]...)...)
		case regex.NodePlus:
			rest := &regex.Node{Kind: regex.NodeStar, Greedy: node.Greedy, Children: node.Children}
			left = verificationConcat(rest, left)
			right = verificationConcat(right, rest)
		case regex.NodeRange:
			end := node.End
			if end != 65535 {
				end--
			}
			rest := &regex.Node{Kind: regex.NodeRange, Start: node.Start - 1, End: end, Greedy: node.Greedy, Children: node.Children}
			right = verificationConcat(right, rest)
		}
		return left, right, true
	}
	return nil, nil, false
}

func reverseVerificationNode(node *regex.Node) *regex.Node {
	if len(node.Children) == 0 {
		return node
	}
	children := make([]*regex.Node, len(node.Children))
	for i, child := range node.Children {
		children[i] = reverseVerificationNode(child)
	}
	if node.Kind == regex.NodeConcat {
		slices.Reverse(children)
	}
	return &regex.Node{Kind: node.Kind, Start: node.Start, End: node.End, Greedy: node.Greedy, Children: children}
}

func compileVerificationPrefix(node *regex.Node) ([]byte, error) {
	if node.Kind == regex.NodeEmpty {
		return []byte{regex.OpMatch}, nil
	}
	return regex.Compile(&regex.AST{Root: reverseVerificationNode(node)})
}

// Every consumed byte must belong to this union. A byte outside the union is
// a guaranteed separator, regardless of alternation or quantifier priority.
func verificationAlphabet(node *regex.Node, flags regex.Flags) [256]bool {
	var result [256]bool
	if len(node.Children) > 0 {
		for _, child := range node.Children {
			part := verificationAlphabet(child, flags)
			for value, present := range part {
				result[value] = result[value] || present
			}
		}
		return result
	}
	switch node.Kind {
	case regex.NodeEmpty, regex.NodeAnchorStart, regex.NodeAnchorEnd, regex.NodeWordBoundary, regex.NodeNonWordBoundary:
		return result
	}
	set, ok := regex.FirstByteSet(&regex.AST{Root: node}, flags)
	for value := range result {
		result[value] = !ok || set.Contains(byte(value))
	}
	return result
}

// A terminal lazy repeat exits after its mandatory copies. With no backwards
// prefix, a finite priority bound proves that verification cannot hit the cap.
func verificationTerminalMax(node *regex.Node) int {
	node = ungroupRegexNode(node)
	if node.Kind == regex.NodeConcat && len(node.Children) > 0 {
		length := 0
		for i, child := range node.Children {
			part := regex.ASTMaxLength(&regex.AST{Root: child})
			if i == len(node.Children)-1 {
				part = verificationTerminalMax(child)
			}
			if part < 0 {
				return -1
			}
			length += part
		}
		return length
	}
	if !node.Greedy {
		switch node.Kind {
		case regex.NodeStar:
			return 0
		case regex.NodePlus:
			return regex.ASTMaxLength(&regex.AST{Root: node.Children[0]})
		case regex.NodeRange:
			if node.Start == 0 {
				return 0
			}
			length := regex.ASTMaxLength(&regex.AST{Root: node.Children[0]})
			if length < 0 {
				return -1
			}
			return int(node.Start) * length
		}
	}
	return regex.ASTMaxLength(&regex.AST{Root: node})
}
