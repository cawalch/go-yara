package compiler

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cawalch/go-yara/ast"
)

// CompiledRule represents a compiled YARA rule
type CompiledRule struct {
	moduleSchemas     map[string]*ModuleSchema
	moduleAccessNames []string
	moduleIterations  []moduleIterationPlan
	Name              string            // Rule name
	Index             int               // Rule index in program
	Bytecode          []byte            // Compiled bytecode
	StringCount       int               // Number of strings
	Strings           map[string][]byte // String identifier to pattern data mapping
	automaton         *acAutomaton      // Aho-Corasick automaton for pattern matching
	StringSets        [][]string        // String sets for "of" expressions
	TextStringSets    [][]string        // Text string sets for text-string-set iteration
	AnonymousStrings  []string          // Anonymous string identifiers for "$" expressions
	StringLiterals    []string          // String literal pool for OpPushStr
	StringKinds       map[string]StringKind
	StringModifiers   map[string][]ast.StringModifier
	CaptureBindings   map[string][]ast.CaptureBinding
	EvidencePlans     []EvidencePlan
	TextPatterns      map[string][]byte
	RegexPatterns     map[string]RegexPattern
	HexPatterns       map[string]*HexPattern
	Stats             map[string]any // Compilation statistics (computed at compile time)
	ExternalSlots     map[string]int // external variable name -> interpreter memory slot
	GlobalSlots       map[string]int // global variable name -> interpreter memory slot
	GlobalValues      map[string]compiledGlobalValue

	// Integer string ID optimization (built during compilation)
	StringIDToIndex map[string]int   // string identifier ("$a") -> integer index
	IndexToStringID []string         // integer index -> string identifier (reverse lookup)
	StringNameToRef map[string]int64 // string identifier -> pre-computed StringRef for interpreter

	// prefilterStrings is the per-string data the prefilter reject path needs,
	// resolved at compile time and parallel to IndexToStringID. Built by
	// assignNonTextCacheIndices, immutable afterwards, so it is safe to share
	// across concurrent scanners alongside the rest of the program.
	prefilterStrings []prefilterStringInfo
	requiredStrings  []string
	forbiddenStrings []string
	booleanPatterns  []*ast.String
	dependencies     []string // nil means dependency metadata is unavailable

	// Rule metadata (from AST)
	Tags        []string        // Rule tags (e.g., {"malware", "trojan"})
	Meta        map[string]any  // Meta key-value pairs
	IsGlobal    bool            // Rule is marked as global
	IsPrivate   bool            // Rule is marked as private
	IsDead      bool            // Rule condition statically folded to false
	DeadStrings map[string]bool // Unreferenced strings pruned from automaton compilation
	// FastScanSafe is true when the condition only observes whether strings
	// matched, not occurrence counts, offsets, lengths, or constrained ranges.
	FastScanSafe bool
	// ConditionMonotonic is true when string matches only contribute positively
	// to condition truth (no negations, none-of, etc.).
	ConditionMonotonic bool
	// RequiresStringMatch is true only when the condition is proven false if
	// none of this rule's strings match.
	RequiresStringMatch   bool
	ModuleFunctions       map[builtinFunction]ModuleFunction
	ModuleNames           map[builtinFunction]string
	HeaderConstraints     []HeaderConstraint
	assertions            []conditionAssertion
	mandatoryAssertions   []int
	assertionCacheIndices []int
	headerCacheIndices    []int
}

// GetName returns the rule name
func (cr *CompiledRule) GetName() string {
	return cr.Name
}

// GetBytecode returns an owned snapshot of the compiled bytecode.
func (cr *CompiledRule) GetBytecode() []byte {
	return slices.Clone(cr.Bytecode)
}

// GetStrings returns an owned snapshot of the string pattern data.
func (cr *CompiledRule) GetStrings() map[string][]byte {
	return cloneByteMap(cr.Strings)
}

// GetStringCount returns the number of strings in this rule
func (cr *CompiledRule) GetStringCount() int {
	return cr.StringCount
}

// StringIdentifiers returns all string identifiers defined in the rule.
func (cr *CompiledRule) StringIdentifiers() []string {
	seen := make(map[string]struct{})
	for id := range cr.StringKinds {
		seen[id] = struct{}{}
	}
	for id := range cr.TextPatterns {
		seen[id] = struct{}{}
	}
	for id := range cr.RegexPatterns {
		seen[id] = struct{}{}
	}
	for id := range cr.HexPatterns {
		seen[id] = struct{}{}
	}
	for id := range cr.Strings {
		seen[id] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// BuildStringIndex builds the integer string ID lookup tables.
// Must be called after all string patterns are added to the rule.
func (cr *CompiledRule) BuildStringIndex() {
	ids := cr.StringIdentifiers()
	cr.IndexToStringID = ids
	cr.StringIDToIndex = make(map[string]int, len(ids))
	for i, id := range ids {
		cr.StringIDToIndex[id] = i
	}

	// Pre-compute StringRef values for each string identifier.
	// StringLiterals are stored as negative refs: -1 = StringLiterals[0], -2 = StringLiterals[1], etc.
	// String identifiers that appear in StringLiterals get a fast O(1) lookup path.
	if len(cr.StringLiterals) > 0 {
		cr.StringNameToRef = make(map[string]int64, min(len(ids), len(cr.StringLiterals)))
		for idx, lit := range cr.StringLiterals {
			if cr.ResolveStringIndex(lit) >= 0 {
				cr.StringNameToRef[lit] = int64(-1 - idx)
			}
		}
	}
}

// ResolveStringIndex returns the integer index for a string identifier.
func (cr *CompiledRule) ResolveStringIndex(id string) int {
	if idx, ok := cr.StringIDToIndex[id]; ok {
		return idx
	}
	return -1
}

// IsPrivateString reports whether a string identifier is marked as private.
func (cr *CompiledRule) IsPrivateString(identifier string) bool {
	return hasStringModifier(cr.StringModifiers[identifier], ast.StringModifierPrivate)
}

// IsStringDead reports whether the string with the given identifier is dead
// (either because the entire rule is dead or the string is unreferenced in the condition).
func (cr *CompiledRule) IsStringDead(identifier string) bool {
	if cr.IsDead {
		return true
	}
	if cr.DeadStrings != nil && cr.DeadStrings[identifier] {
		return true
	}
	return false
}

func hasStringModifier(modifiers []ast.StringModifier, modifierType ast.StringModifierType) bool {
	for _, mod := range modifiers {
		if mod.Type == modifierType {
			return true
		}
	}
	return false
}

// GetStats returns compilation statistics (computed at compile time).
func (cr *CompiledRule) GetStats() map[string]any {
	return cloneStats(cr.Stats)
}

// Validate validates the compiled rule
func (cr *CompiledRule) Validate() error {
	for _, schema := range cr.moduleSchemas {
		if err := validateModuleSchema(schema); err != nil {
			return err
		}
	}
	for _, plan := range cr.moduleIterations {
		if err := plan.validate(); err != nil {
			return err
		}
	}
	for _, assertion := range cr.assertions {
		if err := assertion.validate(); err != nil {
			return err
		}
	}
	for _, index := range cr.mandatoryAssertions {
		if index < 0 || index >= len(cr.assertions) || cr.assertions[index].Opcode != OpAssertFilesize {
			return errors.New("invalid mandatory assertion index")
		}
	}
	for _, slots := range []map[string]int{cr.ExternalSlots, cr.GlobalSlots} {
		for name, slot := range slots {
			if slot < 0 || slot >= interpreterMemorySlotCount {
				return fmt.Errorf("variable %q has invalid memory slot %d", name, slot)
			}
		}
	}
	if len(cr.Bytecode) == 0 {
		return errors.New("empty bytecode")
	}

	if len(cr.TextPatterns) > 0 && cr.automaton == nil {
		return errors.New("strings present but no automaton")
	}

	if cr.automaton != nil {
		if err := cr.automaton.Validate(); err != nil {
			return fmt.Errorf("invalid automaton: %w", err)
		}
	}
	if err := validateCompiledEvidence(cr); err != nil {
		return fmt.Errorf("invalid evidence plan: %w", err)
	}

	return nil
}

// GetMemoryUsage returns a deterministic heuristic byte estimate for the rule.
// It includes bytecode, automaton estimate, and coarse stats-map overhead.
// The value is useful for relative sizing and diagnostics; it is not an exact
// measurement of Go heap usage.
func (cr *CompiledRule) GetMemoryUsage() int {
	usage := len(cr.Bytecode)

	if cr.automaton != nil {
		usage += cr.automaton.EstimateMemoryUsage()
	}

	// Add stats map overhead (rough estimate)
	usage += len(cr.Stats) * 100

	return usage
}
