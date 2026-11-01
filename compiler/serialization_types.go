package compiler

import (
	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

type serializedProgram struct {
	ModuleSchemas map[string]*ModuleSchema
	Rules         []serializedRule
	Dependencies  map[string][]string
}

type serializedRule struct {
	ModuleAccessNames   []string
	ModuleIterations    []moduleIterationPlan
	Name                string
	Index               int
	Bytecode            []byte
	StringCount         int
	Strings             map[string][]byte
	AutomatonStrings    []acStringInfo
	StringSets          [][]string
	TextStringSets      [][]string
	AnonymousStrings    []string
	StringLiterals      []string
	StringKinds         map[string]StringKind
	StringModifiers     map[string][]serializedStringModifier
	CaptureBindings     map[string][]serializedCaptureBinding
	EvidencePlans       []serializedEvidencePlan
	TextPatterns        map[string][]byte
	RegexPatterns       map[string]serializedRegexPattern
	HexPatterns         map[string]serializedHexPattern
	Stats               map[string]int
	ExternalSlots       map[string]int
	GlobalSlots         map[string]int
	GlobalValues        map[string]serializedGlobalValue
	Tags                []string
	Meta                map[string]serializedScalar
	IsGlobal            bool
	IsPrivate           bool
	FastScanSafe        bool
	ConditionMonotonic  bool
	RequiresStringMatch bool
	RequiredStrings     []string
	ForbiddenStrings    []string
	ModuleNames         map[uint8]string
	ModuleSignatures    map[uint8]serializedModuleFunction
	HeaderConstraints   []HeaderConstraint
	FixedTextOffsets    map[string]int64 // Legacy format 8.
	FixedOffsets        map[string]int64
	Assertions          []conditionAssertion
	AssertionProgram    []assertionInstruction
	MandatoryAssertions []int
}

type serializedModuleFunction struct {
	Signatures  [][]ModuleValueType
	ReturnTypes []ModuleValueType
	ReturnType  ModuleValueType
}

type serializedStringModifier struct {
	Type       ast.StringModifierType
	ValueKind  uint8
	String     string
	XorMinimum int64
	XorMaximum int64
	Captures   []serializedCaptureBinding
}

type serializedCaptureBinding struct {
	Name  string
	Group int
}

type serializedEvidencePlan struct {
	Name   string
	Fields []string
	Anchor string
	Within int64
}

const (
	serializedModifierNone uint8 = iota
	serializedModifierString
	serializedModifierXorRange
	serializedModifierCapture
)

type serializedRegexPattern struct {
	BoundedAlternation   *regexBoundedAlternation
	Verification         *regexVerificationPlan
	Code                 []byte
	CaptureCode          []byte
	CaptureGroups        []int
	Flags                regex.Flags
	Prefix               []byte
	WidePrefix           []byte
	Atom                 []byte
	WideAtom             []byte
	AtomMinOffset        int
	AtomMaxOffset        int
	AtomMaxSuffix        int
	MaxLength            int
	AtomASCIINoCase      bool
	AlternativeAtoms     []serializedRegexAtom
	WideAlternativeAtoms []serializedRegexAtom
	LeadingGap           *serializedLeadingGap
	ByteSet              []byte
	ByteSetMinOffset     int
	ByteSetMaxOffset     int
	ByteSetCount         int
	ByteSetLower         byte
	ByteSetUpper         byte
	ByteSetContiguous    bool
	ByteSetValues        []byte
	FixedByteSets        [][]byte
	Anchored             bool
	CacheKey             string
	FirstByteSet         []byte
	HasFirstByteSet      bool
	PrecedingByteSet     []byte
	HasPrecedingByteSet  bool
	ExactPrefixSuffix    []byte
	WideExactPrefix      []byte
	HasPrefixRepeat      bool
	PrefixRepeatClass    []byte
	PrefixRepeatMin      int
	PrefixRepeatMax      int
}

type serializedRegexAtom struct {
	Data        []byte
	MinOffset   int
	MaxOffset   int
	MaxSuffix   int
	Score       int
	ASCIINoCase bool
}

type serializedLeadingGap struct {
	LeadingSet []byte
	GapSet     []byte
	GapMin     int
	GapMax     int
	Atoms      []serializedRegexAtom
}

type serializedHexPattern struct {
	Present  bool
	Tokens   []HexPatternToken
	XorKeys  []byte
	XorRange []ast.XorRange
	CacheKey string
}

type serializedGlobalValue struct {
	Type   ValueType
	Int    int64
	Double float64
	String string
}

type serializedScalar struct {
	Kind   uint8
	String string
	Int    int64
	Bool   bool
}

const (
	serializedScalarString uint8 = iota + 1
	serializedScalarInt
	serializedScalarBool
)
