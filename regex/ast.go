package regex

// NodeKind mirrors re.h's RE_NODE_* constants for easier auditing.
// Only a subset is needed initially; we include the full set for parity.

// NodeKind represents the kind of a regex AST node.
type NodeKind int

 // NodeKind values enumerate the AST node kinds.
const (
	NodeLiteral          NodeKind = 1
	NodeMaskedLiteral    NodeKind = 2
	NodeAny              NodeKind = 3
	NodeConcat           NodeKind = 4
	NodeAlt              NodeKind = 5
	NodeRange            NodeKind = 6
	NodeStar             NodeKind = 7
	NodePlus             NodeKind = 8
	NodeClass            NodeKind = 9
	NodeWordChar         NodeKind = 10
	NodeNonWordChar      NodeKind = 11
	NodeSpace            NodeKind = 12
	NodeNonSpace         NodeKind = 13
	NodeDigit            NodeKind = 14
	NodeNonDigit         NodeKind = 15
	NodeEmpty            NodeKind = 16
	NodeAnchorStart      NodeKind = 17
	NodeAnchorEnd        NodeKind = 18
	NodeWordBoundary     NodeKind = 19
	NodeNonWordBoundary  NodeKind = 20
	NodeRangeAny         NodeKind = 21
	NodeNotLiteral       NodeKind = 22
	NodeMaskedNotLiteral NodeKind = 23
)
// Class is a simple 256-bit bitmap (32 bytes) with negation support.
// This mirrors libyara's approach, keeping things ASCII-centric initially.
type Class struct {
	Bitmap  [32]byte
	Negated bool
}
// Node represents a parsed regex node. Many fields are optional depending on kind.
// Greedy defaults to true and is flipped by ungreedy quantifiers.
type Node struct {
	Kind     NodeKind
	Value    byte   // For literal kinds
	Mask     byte   // For masked literal kinds
	Start    uint16 // For {m,n}
	End      uint16 // For {m,n}
	Greedy   bool
	Class    *Class
	Children []*Node
}
 // NewNode creates a new Node with Greedy defaulting to true.
func NewNode(kind NodeKind) *Node {
	return &Node{Kind: kind, Greedy: true}
}
// AST is the root of a parsed regex along with flags captured during parse.
type AST struct {
	Flags Flags
	Root  *Node
}
