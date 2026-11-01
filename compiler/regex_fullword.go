package compiler

import "github.com/cawalch/go-yara/regex"

// Regex patterns without libyara atoms use its forward-only match callback,
// which omits the wide flag when checking fullword boundaries. This serialized
// compiler policy bit is ignored by the VM; matching still uses wide encoding.
const regexASCIIWordBoundary regex.Flags = 1 << 17

// Atomless regexes use forward branch priority. Keep this separate from the
// parsed greedy flag, which also controls ASCII/wide occurrence preference.
const regexForwardPriority regex.Flags = 1 << 18

// Alternative match-start atoms must verify independently when forward repeat
// entries change. Persist this dispatch policy so old artifacts keep their
// original occurrence selection; the VM itself ignores this bit.
const regexStartAtomEntries regex.Flags = 1 << 19

// Match libyara's atom eligibility, not our broader prefilter analysis:
// character classes (even singleton classes) do not provide literal atoms.
func regexHasLiteralAtom(node *regex.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case regex.NodeLiteral:
		return true
	case regex.NodeConcat:
		for _, child := range node.Children {
			if regexHasLiteralAtom(child) {
				return true
			}
		}
	case regex.NodeAlt:
		if len(node.Children) == 0 {
			return false
		}
		for _, child := range node.Children {
			if !regexHasLiteralAtom(child) {
				return false
			}
		}
		return true
	case regex.NodeGroup, regex.NodePlus:
		return len(node.Children) == 1 && regexHasLiteralAtom(node.Children[0])
	case regex.NodeRange:
		return node.Start > 0 && len(node.Children) == 1 && regexHasLiteralAtom(node.Children[0])
	}
	return false
}
