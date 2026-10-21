package regex

import (
	"bytes"
	"encoding/binary"
	"math"
)

// LiteralSuffix returns the required trailing literal bytes that every match
// of code must end with before OpMatch.
func LiteralSuffix(code []byte) []byte {
	if len(code) < 3 || code[len(code)-1] != OpMatch {
		return nil
	}
	matchPC := len(code) - 1

	// Collect all branch targets in code.
	var inlineTargets [16]int
	targets := inlineTargets[:0]

	pc := 0
	for pc < len(code) {
		op := code[pc]
		switch op {
		case OpLiteral, OpNotLiteral, OpSaveStart, OpSaveEnd:
			pc += 2
		case OpMaskedLiteral, OpMaskedNotLiteral:
			pc += 3
		case OpClass:
			pc += 33
		case OpAny, OpWordChar, OpNonWordChar, OpSpace, OpNonSpace, OpDigit, OpNonDigit,
			OpMatchAtStart, OpMatchAtEnd, OpWordBoundary, OpNonWordBoundary,
			OpRepeatAnyGreedy, OpRepeatAnyUngreedy, OpMatch:
			pc++
		case OpJump, OpSplitA, OpSplitB,
			OpRepeatStartGreedy, OpRepeatEndGreedy, OpRepeatStartUngreedy, OpRepeatEndUngreedy:
			if pc+3 > len(code) {
				return nil
			}
			u16 := binary.LittleEndian.Uint16(code[pc+1 : pc+3])
			rel := int16(u16) //checkednarrow:ignore signed relative branch offset
			target := pc + int(rel)
			targets = append(targets, target)
			pc += 3
		default:
			return nil
		}
	}

	for _, target := range targets {
		if target == matchPC {
			return nil
		}
	}

	var suffix []byte
	cur := matchPC
	for cur >= 2 && code[cur-2] == OpLiteral {
		litPC := cur - 2
		// If any branch targets inside (litPC, matchPC], suffix is broken.
		hasBranchInside := false
		for _, target := range targets {
			if target > litPC && target <= matchPC {
				hasBranchInside = true
				break
			}
		}
		if hasBranchInside {
			break
		}
		suffix = append([]byte{code[litPC+1]}, suffix...)
		// If litPC itself is targeted, we cannot extend further back.
		isTarget := false
		for _, target := range targets {
			if target == litPC {
				isTarget = true
				break
			}
		}
		if isTarget {
			break
		}
		cur = litPC
	}

	return suffix
}

func indexASCIIFold(input, target []byte) int {
	if len(target) == 0 {
		return 0
	}
	if len(input) < len(target) {
		return -1
	}
	firstLower := toLowerASCII(target[0])
	firstUpper := toUpperASCII(target[0])
	maxStart := len(input) - len(target)
	for i := 0; i <= maxStart; i++ {
		b := input[i]
		if b == firstLower || b == firstUpper {
			match := true
			for j := 1; j < len(target); j++ {
				if toLowerASCII(input[i+j]) != toLowerASCII(target[j]) {
					match = false
					break
				}
			}
			if match {
				return i
			}
		}
	}
	return -1
}

func containsWideBytes(input, target []byte) bool {
	if len(target) == 0 {
		return true
	}
	var inline [32]byte
	var wideTarget []byte
	if len(target)*2 <= len(inline) {
		wideTarget = inline[:len(target)*2]
	} else {
		wideTarget = make([]byte, len(target)*2)
	}
	for i, ch := range target {
		wideTarget[i*2] = ch
		wideTarget[i*2+1] = 0
	}
	return bytes.Contains(input, wideTarget)
}

// nodeMaxLength computes the maximum match length of node (-1 if unbounded)
// without building literal atoms. It must agree with analyzeAtoms(node).maxLength.
func nodeMaxLength(node *Node) int {
	if node == nil {
		return 0
	}
	switch node.Kind {
	case NodeGroup:
		return nodeMaxLength(firstChild(node))
	case NodeConcat:
		total := 0
		for _, child := range node.Children {
			total = addLength(total, nodeMaxLength(child))
		}
		return total
	case NodeAlt:
		if len(node.Children) == 0 {
			return 0
		}
		longest := nodeMaxLength(node.Children[0])
		for _, child := range node.Children[1:] {
			longest = maxLength(longest, nodeMaxLength(child))
		}
		return longest
	case NodeStar, NodePlus:
		if len(node.Children) == 0 || nodeMaxLength(node.Children[0]) == 0 {
			return 0
		}
		return -1
	case NodeRange:
		child := 0
		if len(node.Children) > 0 {
			child = nodeMaxLength(node.Children[0])
		}
		result := multiplyLength(child, int(node.End))
		if node.End == math.MaxUint16 && child > 0 {
			return -1
		}
		return result
	case NodeRangeAny:
		if node.End == math.MaxUint16 {
			return -1
		}
		return int(node.End)
	case NodeEmpty, NodeAnchorStart, NodeAnchorEnd, NodeWordBoundary, NodeNonWordBoundary:
		return 0
	case NodeLiteral, NodeMaskedLiteral, NodeMaskedNotLiteral, NodeNotLiteral, NodeClass,
		NodeWordChar, NodeNonWordChar, NodeSpace, NodeNonSpace, NodeDigit, NodeNonDigit, NodeAny:
		return 1
	default:
		return -1
	}
}
