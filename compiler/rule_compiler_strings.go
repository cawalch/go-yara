package compiler

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/regex"
)

// compileStrings compiles all strings in a rule and builds the automaton
func (rc *ruleCompiler) compileStrings(rule *ast.Rule, deadStrings map[string]bool) error {
	// First pass: validate and prepare strings
	if err := rc.validateRuleStrings(rule); err != nil {
		return err
	}

	// Reserve resources for compilation
	rc.reserveCompilationResources(rule)

	// Second pass: compile strings and build automaton
	for _, str := range rule.Strings {
		isDead := deadStrings != nil && deadStrings[str.Identifier]
		if err := rc.compileSingleStringWithDead(str, isDead); err != nil {
			return fmt.Errorf("compiling string %s: %w", str.Identifier, err)
		}
	}

	return nil
}

// compileSingleString compiles a single string and adds it to the automaton
func (rc *ruleCompiler) compileSingleString(str *ast.String) error {
	return rc.compileSingleStringWithDead(str, false)
}

func (rc *ruleCompiler) compileSingleStringWithDead(str *ast.String, isDead bool) error {
	rc.ensurePatternMaps()
	result, err := rc.compileStringPattern(str)
	if err != nil {
		return err
	}

	rc.recordStringOffset(str.Identifier)
	rc.recordPatternData(str.Identifier, result.patternData)
	switch result.kind {
	case StringKindText:
		if len(result.patternData) == 0 && len(result.altPatterns) == 0 {
			return fmt.Errorf("empty text pattern for %s", str.Identifier)
		}
		if err := rc.automaton.AddStringWithFlags(str.Identifier, result.patternData, false, false, result.patternFlags); err != nil {
			return err
		}
		for idx, alt := range result.altPatterns {
			flags := regex.Flags(0)
			if idx < len(result.altPatternFlags) {
				flags = result.altPatternFlags[idx]
			}
			if err := rc.automaton.AddStringWithFlags(str.Identifier, alt, false, false, flags); err != nil {
				return err
			}
		}
		rc.textPatterns[str.Identifier] = result.patternData
	case StringKindRegex:
		prefix, anchored := regex.LiteralPrefix(result.patternData)
		pattern := RegexPattern{
			Code:             result.patternData,
			CaptureCode:      result.captureCode,
			CaptureGroups:    slices.Clone(result.captureGroups),
			Flags:            result.flags,
			prefix:           prefix,
			widePrefix:       widenRegexPrefix(prefix),
			atomMaxOffset:    -1,
			atomMaxSuffix:    -1,
			maxLength:        result.maxLength,
			byteSetMaxOffset: -1,
			anchored:         anchored,
			cacheKey:         result.cacheKey,
			cacheIndex:       -1,
			firstByteSet:     result.regexFirstByteSet,
			hasFirstByteSet:  result.hasFirstByteSet,
		}
		if atom, ok := selectMandatoryRegexAtom(result.regexAtoms); ok {
			pattern.atom = append([]byte(nil), atom.data...)
			pattern.wideAtom = widenRegexPrefix(atom.data)
			pattern.atomMinOffset = atom.minOffset
			pattern.atomMaxOffset = atom.maxOffset
			pattern.atomMaxSuffix = atom.maxSuffix
		}
		if atom, ok := selectMandatoryASCIIFoldedRegexAtom(result.regexASCIIFoldedAtoms); ok {
			current := regexPrefilterAtom{
				data:        pattern.atom,
				minOffset:   pattern.atomMinOffset,
				maxOffset:   pattern.atomMaxOffset,
				maxSuffix:   pattern.atomMaxSuffix,
				score:       prefilterAtomScore(pattern.atom),
				asciiNoCase: pattern.atomASCIINoCase,
			}
			if len(pattern.atom) == 0 || betterRegexPrefilterAtom(atom, current) {
				pattern.atom = append([]byte(nil), atom.data...)
				pattern.wideAtom = widenRegexPrefix(atom.data)
				pattern.atomMinOffset = atom.minOffset
				pattern.atomMaxOffset = atom.maxOffset
				pattern.atomMaxSuffix = atom.maxSuffix
				pattern.atomASCIINoCase = true
			}
		}
		if len(pattern.atom) > 0 && result.parsedAST != nil {
			analysisFlags := result.flags
			if pattern.atomASCIINoCase {
				analysisFlags |= regex.FlagsNoCase
			}
			revInfo := regex.ReversePrefixAnalysisWithOffset(result.parsedAST, pattern.atom, pattern.atomMinOffset, analysisFlags)
			pattern.hasPrecedingByteSet = revInfo.HasPrecedingByteSet
			pattern.precedingByteSet = revInfo.PrecedingByteSet
			pattern.exactPrefixSuffix = revInfo.ExactPrefixSuffix
			if len(revInfo.ExactPrefixSuffix) > 0 {
				pattern.wideExactPrefix = widenRegexPrefix(revInfo.ExactPrefixSuffix)
			}
			pattern.hasPrefixRepeat = revInfo.HasPrefixRepeat
			pattern.prefixRepeatClass = revInfo.PrefixRepeatClass
			pattern.prefixRepeatMin = revInfo.PrefixRepeatMin
			pattern.prefixRepeatMax = revInfo.PrefixRepeatMax
		}
		if len(pattern.atom) == 0 && len(pattern.prefix) > 0 {
			if pattern.maxLength >= len(pattern.prefix) {
				pattern.atomMaxSuffix = pattern.maxLength - len(pattern.prefix)
			}
		}
		if atoms, ok := selectAlternativeRegexAtoms(result.regexAlternatives); ok {
			if len(pattern.prefix) < minPrefilterAtomLength || alternativeAtomsBeatPrefix(atoms, pattern.prefix) {
				pattern.alternativeAtoms = cloneRegexPrefilterAtoms(atoms)
				pattern.wideAlternativeAtoms = widenRegexPrefilterAtoms(atoms)
			}
		}
		if plan, ok := selectLeadingGapRegexPlan(result.regexLeadingGap); ok {
			pattern.leadingGap = plan
		}
		if atom, ok := selectMandatoryRegexByteSetAtom(result.regexByteSetAtoms, result.flags); ok {
			pattern.byteSet = atom.set
			pattern.byteSetMinOffset = atom.minOffset
			pattern.byteSetMaxOffset = atom.maxOffset
			pattern.byteSetCount = atom.count
			pattern.byteSetLower, pattern.byteSetUpper, pattern.byteSetContiguous = atom.set.ContiguousRange()
			if atom.count <= maxSparseRegexByteSetValues {
				pattern.byteSetValues = make([]byte, 0, atom.count)
				for value := range 256 {
					if atom.set.Contains(byte(value)) {
						pattern.byteSetValues = append(pattern.byteSetValues, byte(value))
					}
				}
			}
		}
		pattern.fixedByteSets = slices.Clone(result.regexFixedByteSets)
		rc.regexPatterns[str.Identifier] = pattern
	case StringKindHex:
		rc.hexPatterns[str.Identifier] = result.hexPattern
	default:
		return fmt.Errorf("unsupported string kind for %s", str.Identifier)
	}
	rc.recordStringModifiers(str.Identifier, str.Modifiers)
	rc.stringKinds[str.Identifier] = result.kind
	return nil
}

type stringCompilationResult struct {
	patternData           []byte
	kind                  StringKind
	flags                 regex.Flags
	hexPattern            *HexPattern
	altPatterns           [][]byte
	patternFlags          regex.Flags
	altPatternFlags       []regex.Flags
	cacheKey              string
	regexAtoms            []regex.LiteralAtom
	regexASCIIFoldedAtoms []regex.LiteralAtom
	regexAlternatives     [][]regex.LiteralAtom
	regexLeadingGap       regex.LeadingByteGapPlan
	regexByteSetAtoms     []regex.ByteSetAtom
	regexFixedByteSets    []regex.ByteSet
	regexFirstByteSet     regex.ByteSet
	hasFirstByteSet       bool
	parsedAST             *regex.AST
	captureCode           []byte
	captureGroups         []int
	maxLength             int
}

func (rc *ruleCompiler) compileStringPattern(str *ast.String) (*stringCompilationResult, error) {
	switch p := str.Pattern.(type) {
	case *ast.TextString:
		return rc.compileTextString(p.Value, str.Modifiers)
	case *ast.HexString:
		return rc.compileHexString(p.Value, str.Modifiers)
	case *ast.RegexPattern:
		return rc.compileRegexPattern(p, str.Modifiers)
	default:
		return nil, errors.New("unsupported pattern type")
	}
}

func (rc *ruleCompiler) compileTextString(value string, modifiers []ast.StringModifier) (*stringCompilationResult, error) {
	if hasPositiveCaptureGroup(modifiers) {
		return nil, errors.New("positive capture groups are only supported for regex patterns")
	}
	patterns, err := rc.stringCompiler.EncodeTextPatterns(value, modifiers)
	if err != nil {
		return nil, err
	}
	if len(patterns) == 0 {
		return nil, errors.New("empty text pattern")
	}

	optimized := make([]TextPattern, 0, len(patterns))
	for _, p := range patterns {
		useModifiers := modifiers
		if (p.Flags & regex.FlagsWide) == 0 {
			useModifiers = stripWideModifier(modifiers)
		}
		optimized = append(optimized, TextPattern{
			Data:  rc.stringCompiler.OptimizePattern(p.Data, useModifiers),
			Flags: p.Flags,
		})
	}
	patternData := optimized[0].Data
	patternFlags := optimized[0].Flags
	altPatterns := make([][]byte, 0, len(optimized)-1)
	altFlags := make([]regex.Flags, 0, len(optimized)-1)
	for _, p := range optimized[1:] {
		altPatterns = append(altPatterns, p.Data)
		altFlags = append(altFlags, p.Flags)
	}
	return &stringCompilationResult{
		patternData:     patternData,
		kind:            StringKindText,
		altPatterns:     altPatterns,
		patternFlags:    patternFlags,
		altPatternFlags: altFlags,
	}, nil
}

func stripWideModifier(modifiers []ast.StringModifier) []ast.StringModifier {
	out := make([]ast.StringModifier, 0, len(modifiers))
	for _, m := range modifiers {
		if m.Type == ast.StringModifierWide {
			continue
		}
		out = append(out, m)
	}
	return out
}

func (rc *ruleCompiler) compileHexString(value string, modifiers []ast.StringModifier) (*stringCompilationResult, error) {
	if hasPositiveCaptureGroup(modifiers) {
		return nil, errors.New("positive capture groups are only supported for regex patterns")
	}
	if rc.stringCompiler.hasModifier(modifiers, ast.StringModifierBase64) ||
		rc.stringCompiler.hasModifier(modifiers, ast.StringModifierBase64Wide) {
		return nil, errors.New("base64 modifiers are only supported for text strings")
	}
	hexPattern, err := rc.stringCompiler.parseHexPattern(value)
	if err != nil {
		return nil, err
	}
	if keys, ok := rc.stringCompiler.xorKeys(modifiers); ok {
		hexPattern.XorKeys = keys
	}
	hexPattern.cacheKey = patternCacheKey("hex", value, modifiers)
	hexPattern.cacheIndex = -1
	encodedPattern := rc.stringCompiler.parseHexString(value)
	encodedPattern = rc.stringCompiler.applyXorModifier(encodedPattern, modifiers)
	return &stringCompilationResult{
		patternData: encodedPattern,
		kind:        StringKindHex,
		hexPattern:  hexPattern,
	}, nil
}

func (rc *ruleCompiler) compileRegexPattern(pattern *ast.RegexPattern, modifiers []ast.StringModifier) (*stringCompilationResult, error) {
	if rc.stringCompiler.hasModifier(modifiers, ast.StringModifierBase64) ||
		rc.stringCompiler.hasModifier(modifiers, ast.StringModifierBase64Wide) {
		return nil, errors.New("base64 modifiers are only supported for text strings")
	}
	code, parsed, err := rc.stringCompiler.compileRegexWithAST(pattern.Value, modifiers)
	if err != nil {
		return nil, fmt.Errorf("compile regex pattern: %w", err)
	}

	flags := rc.deriveRegexFlags(pattern.Value, modifiers)
	if parsed != nil {
		flags |= parsed.Flags
		// Fullword needs modifier-aware endpoint selection (see #369).
		if !rc.stringCompiler.hasModifier(modifiers, ast.StringModifierFullword) && greedyLiteralAlternation(parsed) {
			flags |= regex.FlagsExhaustive
		}
	}
	groups := positiveCaptureGroups(modifiers)
	var captureCode []byte
	if len(groups) > 0 {
		captureCode, err = regex.CompileCaptures(parsed, groups)
		if err != nil {
			return nil, fmt.Errorf("compile regex captures: %w", err)
		}
	}
	fixedByteSets, _ := regex.FixedByteSets(parsed, flags)
	leadingGap, _ := regex.LeadingByteGapAtomCover(parsed, flags, minPrefilterAtomLength)
	firstByteSet, hasFirstByteSet := regex.FirstByteSet(parsed, flags)
	return &stringCompilationResult{
		patternData:           code, // VM bytecode
		kind:                  StringKindRegex,
		flags:                 flags,
		cacheKey:              patternCacheKey("regex", pattern.Value, modifiers),
		regexAtoms:            regex.MandatoryLiteralAtoms(parsed),
		regexASCIIFoldedAtoms: regex.MandatoryASCIIFoldedLiteralAtoms(parsed),
		regexAlternatives:     regex.RequiredLiteralAlternationAtoms(parsed, minPrefilterAtomLength),
		regexLeadingGap:       leadingGap,
		regexByteSetAtoms:     regex.MandatoryByteSetAtoms(parsed),
		regexFixedByteSets:    fixedByteSets,
		regexFirstByteSet:     firstByteSet,
		hasFirstByteSet:       hasFirstByteSet,
		captureCode:           captureCode,
		captureGroups:         groups,
		maxLength:             regex.ASTMaxLength(parsed),
		parsedAST:             parsed,
	}, nil
}

func patternCacheKey(kind, value string, modifiers []ast.StringModifier) string {
	var key strings.Builder
	key.Grow(len(kind) + len(value) + len(modifiers)*8 + 2)
	key.WriteString(kind)
	key.WriteByte(0)
	key.WriteString(value)
	for _, modifier := range modifiers {
		if modifier.Type == ast.StringModifierCapture {
			continue
		}
		key.WriteByte(0)
		fmt.Fprintf(&key, "%d=%v", modifier.Type, modifier.Value)
	}
	return key.String()
}

func (rc *ruleCompiler) deriveRegexFlags(patternValue string, modifiers []ast.StringModifier) regex.Flags {
	var flags regex.Flags

	// Flags from string modifiers
	for _, m := range modifiers {
		switch m.Type {
		case ast.StringModifierWide:
			flags |= regex.FlagsWide
		case ast.StringModifierNocase:
			flags |= regex.FlagsNoCase
		}
	}

	// Derive inline regex flags from literal suffix (e.g., /.../is)
	flags |= rc.parseInlineRegexFlags(patternValue)

	return flags
}

func (rc *ruleCompiler) parseInlineRegexFlags(patternValue string) regex.Flags {
	var flags regex.Flags

	if len(patternValue) < 2 || patternValue[0] != '/' {
		return flags
	}

	endIdx := len(patternValue) - 1
	for endIdx > 0 && patternValue[endIdx] != '/' {
		endIdx--
	}

	if endIdx > 0 && endIdx < len(patternValue)-1 {
		for i := endIdx + 1; i < len(patternValue); i++ {
			switch patternValue[i] {
			case 'i', 'I':
				flags |= regex.FlagsNoCase
			case 's', 'S':
				flags |= regex.FlagsDotAll
			}
		}
	}

	return flags
}

func (rc *ruleCompiler) recordStringOffset(identifier string) {
	offset := rc.automaton.GetStringCount()
	rc.stringCompiler.stringOffsets[identifier] = offset
}

func (rc *ruleCompiler) recordStringModifiers(identifier string, modifiers []ast.StringModifier) {
	if rc.stringModifiers == nil {
		rc.stringModifiers = make(map[string][]ast.StringModifier)
	}
	if len(modifiers) == 0 {
		return
	}
	cp := make([]ast.StringModifier, len(modifiers))
	copy(cp, modifiers)
	rc.stringModifiers[identifier] = cp
}

func (rc *ruleCompiler) recordPatternData(identifier string, data []byte) {
	if rc.allPatterns == nil {
		rc.allPatterns = make(map[string][]byte)
	}
	if data == nil {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	rc.allPatterns[identifier] = cp
}

func (rc *ruleCompiler) ensurePatternMaps() {
	if rc.allPatterns == nil {
		rc.allPatterns = make(map[string][]byte)
	}
	if rc.textPatterns == nil {
		rc.textPatterns = make(map[string][]byte)
	}
	if rc.regexPatterns == nil {
		rc.regexPatterns = make(map[string]RegexPattern)
	}
	if rc.hexPatterns == nil {
		rc.hexPatterns = make(map[string]*HexPattern)
	}
	if rc.stringKinds == nil {
		rc.stringKinds = make(map[string]StringKind)
	}
	if rc.stringModifiers == nil {
		rc.stringModifiers = make(map[string][]ast.StringModifier)
	}
}
