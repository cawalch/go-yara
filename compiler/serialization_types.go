package compiler

import (
	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

type serializedProgram struct {
	// Legacy format 4-19 map fields (decoded for backward compatibility; nil in format 20+).
	ModuleSchemas map[string]*ModuleSchema
	Rules         []serializedRule
	Dependencies  map[string][]string

	// Deterministic format 20+ sorted entry slices.
	ModuleSchemaEntries []serializedModuleSchemaEntry
	DependencyEntries   []serializedStringSliceEntry
}

type serializedRule struct {
	ModuleAccessNames   []string
	ModuleIterations    []moduleIterationPlan
	Name                string
	Index               int
	Bytecode            []byte
	StringCount         int
	AutomatonStrings    []acStringInfo
	StringSets          [][]string
	TextStringSets      [][]string
	AnonymousStrings    []string
	StringLiterals      []string
	ModuleRegexes       []serializedModuleRegex
	EvidencePlans       []serializedEvidencePlan
	Tags                []string
	IsGlobal            bool
	IsPrivate           bool
	FastScanSafe        bool
	ConditionMonotonic  bool
	RequiresStringMatch bool
	RequiredStrings     []string
	ForbiddenStrings    []string
	HeaderConstraints   []HeaderConstraint
	Assertions          []conditionAssertion
	AssertionProgram    []assertionInstruction
	MandatoryAssertions []int

	// Legacy format 4-19 map fields (decoded for backward compatibility; nil in format 20+).
	Strings          map[string][]byte
	StringKinds      map[string]StringKind
	StringModifiers  map[string][]serializedStringModifier
	CaptureBindings  map[string][]serializedCaptureBinding
	TextPatterns     map[string][]byte
	RegexPatterns    map[string]serializedRegexPattern
	HexPatterns      map[string]serializedHexPattern
	Stats            map[string]int
	ExternalSlots    map[string]int
	GlobalSlots      map[string]int
	GlobalValues     map[string]serializedGlobalValue
	Meta             map[string]serializedScalar
	ModuleNames      map[uint8]string
	ModuleSignatures map[uint8]serializedModuleFunction
	FixedTextOffsets map[string]int64 // Legacy format 8.
	FixedOffsets     map[string]int64

	// Deterministic format 20+ sorted entry slices.
	StringEntries          []serializedByteEntry
	StringKindEntries      []serializedStringKindEntry
	StringModifierEntries  []serializedStringModifierEntry
	CaptureBindingEntries  []serializedCaptureBindingEntry
	TextPatternEntries     []serializedByteEntry
	RegexPatternEntries    []serializedRegexPatternEntry
	HexPatternEntries      []serializedHexPatternEntry
	StatEntries            []serializedIntEntry
	ExternalSlotEntries    []serializedIntEntry
	GlobalSlotEntries      []serializedIntEntry
	GlobalValueEntries     []serializedGlobalValueEntry
	MetaEntries            []serializedScalarEntry
	ModuleNameEntries      []serializedModuleNameEntry
	ModuleSignatureEntries []serializedModuleSignatureEntry
	FixedOffsetEntries     []serializedInt64Entry
}

type serializedModuleSchemaEntry struct {
	Key   string
	Value *serializedModuleSchema
}

type serializedModuleSchema struct {
	Fields []serializedModuleFieldEntry
}

type serializedModuleFieldEntry struct {
	Key   string
	Value serializedModuleField
}

type serializedModuleField struct {
	Kind     ModuleValueType
	Struct   *serializedModuleSchema
	Element  *serializedModuleField
	Constant *ModuleValue
}

type serializedStringSliceEntry struct {
	Key   string
	Value []string
}

type serializedByteEntry struct {
	Key   string
	Value []byte
}

type serializedStringKindEntry struct {
	Key   string
	Value StringKind
}

type serializedStringModifierEntry struct {
	Key   string
	Value []serializedStringModifier
}

type serializedCaptureBindingEntry struct {
	Key   string
	Value []serializedCaptureBinding
}

type serializedRegexPatternEntry struct {
	Key   string
	Value serializedRegexPattern
}

type serializedHexPatternEntry struct {
	Key   string
	Value serializedHexPattern
}

type serializedIntEntry struct {
	Key   string
	Value int
}

type serializedGlobalValueEntry struct {
	Key   string
	Value serializedGlobalValue
}

type serializedScalarEntry struct {
	Key   string
	Value serializedScalar
}

type serializedModuleNameEntry struct {
	Key   uint8
	Value string
}

type serializedModuleSignatureEntry struct {
	Key   uint8
	Value serializedModuleFunction
}

type serializedInt64Entry struct {
	Key   string
	Value int64
}

type serializedModuleFunction struct {
	Signatures  [][]ModuleValueType
	ReturnTypes []ModuleValueType
	ReturnType  ModuleValueType
}

type serializedModuleRegex struct {
	Code  []byte
	Flags regex.Flags
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
	StreamPriorityBound  bool
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
