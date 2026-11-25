package compiler

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cawalch/go-yara/regex"
)

// Finite repetitions expand into bytecode, so source regexes cannot produce
// extents larger than their compiled programs. Allow headroom for the final
// instruction and historical compiler limits while keeping doubled offsets
// and sums safe on 32-bit targets.
const maxSerializedRegexExtent = 2 * regex.MaxBytecodeSize

const serializedRegexFlags = regex.FlagsFastRegexp | regex.FlagsBackwards | regex.FlagsExhaustive |
	regex.FlagsWide | regex.FlagsNoCase | regex.FlagsScan | regex.FlagsDotAll | regex.FlagsGreedy |
	regex.FlagsUngreedy | regex.FlagsFullwordEnd | regexASCIIWordBoundary | regexForwardPriority | regexStartAtomEntries

func validateSerializedRegexPattern(p serializedRegexPattern) error {
	if p.Flags&^serializedRegexFlags != 0 {
		return fmt.Errorf("unknown regex flags %#x", p.Flags&^serializedRegexFlags)
	}
	if err := regex.ValidateBytecode(p.Code); err != nil {
		return fmt.Errorf("regex code: %w", err)
	}
	if err := validateSerializedRegexCaptures(p.CaptureGroups, p.CaptureCode); err != nil {
		return err
	}
	if p.MaxLength < -1 || p.MaxLength > maxSerializedRegexExtent ||
		p.StreamPriorityBound && (p.MaxLength != -1 || p.Verification != nil) {
		return errors.New("invalid regex stream length metadata")
	}
	if p.CacheKey != "" && !strings.HasPrefix(p.CacheKey, "regex\x00") {
		return errors.New("invalid regex cache key")
	}
	if err := validateSerializedRegexLiterals(p); err != nil {
		return err
	}
	if err := validateSerializedRegexSets(p); err != nil {
		return err
	}
	if err := validateSerializedRegexLeadingGap(p.LeadingGap); err != nil {
		return err
	}
	if err := validateSerializedRegexVerification(p.Verification, p.Flags); err != nil {
		return err
	}
	return validateSerializedRegexAlternation(p.BoundedAlternation)
}

func validateSerializedRegexCaptures(groups []int, code []byte) error {
	if len(groups) == 0 && len(code) == 0 {
		return nil
	}
	if len(groups) == 0 || len(groups) > 256 {
		return errors.New("invalid regex capture group count")
	}
	previous := 0
	for _, group := range groups {
		if group <= previous || group > maxSerializedRegexExtent {
			return errors.New("invalid regex capture group order or number")
		}
		previous = group
	}
	if err := regex.ValidateCaptureBytecode(code, len(groups)); err != nil {
		return fmt.Errorf("regex capture code: %w", err)
	}
	return nil
}

func validateSerializedRegexLiterals(p serializedRegexPattern) error {
	if !validSerializedRegexRange(p.AtomMinOffset, p.AtomMaxOffset, maxSerializedRegexExtent) ||
		p.AtomMaxSuffix < -1 || p.AtomMaxSuffix > maxSerializedRegexExtent ||
		len(p.Atom) == 0 && (p.AtomMinOffset != 0 || p.AtomASCIINoCase) {
		return errors.New("invalid regex atom bounds")
	}
	if len(p.Prefix) > maxSerializedRegexExtent || len(p.Atom) > maxPrefilterAtomLength ||
		len(p.ExactPrefixSuffix) > p.AtomMinOffset ||
		!validWideRegexLiteral(p.Prefix, p.WidePrefix) || !validWideRegexLiteral(p.Atom, p.WideAtom) ||
		!validWideRegexLiteral(p.ExactPrefixSuffix, p.WideExactPrefix) {
		return errors.New("invalid regex literal or wide encoding")
	}
	if len(p.Prefix) != 0 || p.Anchored {
		prefix, anchored := regex.LiteralPrefix(p.Code)
		if !bytes.HasPrefix(prefix, p.Prefix) || p.Anchored && !anchored {
			return errors.New("regex literal prefix or anchor does not agree with its code")
		}
	}
	if len(p.AlternativeAtoms) != len(p.WideAlternativeAtoms) {
		return errors.New("invalid regex alternative encoding count")
	}
	for i, atom := range p.AlternativeAtoms {
		wide := p.WideAlternativeAtoms[i]
		if !validSerializedRegexAtom(atom) || !validWideRegexLiteral(atom.Data, wide.Data) ||
			wide.MinOffset != 2*atom.MinOffset || wide.MaxSuffix != atom.MaxSuffix ||
			wide.Score != atom.Score || wide.ASCIINoCase != atom.ASCIINoCase {
			return fmt.Errorf("invalid regex alternative atom %d", i)
		}
		maxOffset := atom.MaxOffset
		if maxOffset >= 0 {
			maxOffset *= 2
		}
		if wide.MaxOffset != maxOffset {
			return fmt.Errorf("invalid regex wide alternative offset at atom %d", i)
		}
	}
	return nil
}

func validWideRegexLiteral(ascii, wide []byte) bool {
	if len(wide)%2 != 0 || len(wide)/2 != len(ascii) {
		return false
	}
	for i, b := range ascii {
		if wide[2*i] != b || wide[2*i+1] != 0 {
			return false
		}
	}
	return true
}

func validSerializedRegexRange(minimum, maximum, limit int) bool {
	return minimum >= 0 && minimum <= limit && (maximum == -1 || maximum >= minimum && maximum <= limit)
}

func validSerializedRegexAtom(atom serializedRegexAtom) bool {
	return len(atom.Data) >= minPrefilterAtomLength && len(atom.Data) <= maxPrefilterAtomLength &&
		validSerializedRegexRange(atom.MinOffset, atom.MaxOffset, maxSerializedRegexExtent) &&
		atom.MaxSuffix >= -1 && atom.MaxSuffix <= maxSerializedRegexExtent && atom.Score >= 0 && atom.Score <= 7*len(atom.Data)
}

func validateSerializedRegexSets(p serializedRegexPattern) error {
	if !validSerializedRegexByteSet(p.ByteSet, maxRegexByteSetSize) || p.ByteSetCount != len(p.ByteSet) ||
		!validSerializedRegexRange(p.ByteSetMinOffset, p.ByteSetMaxOffset, maxSerializedRegexExtent) {
		return errors.New("invalid regex byte-set entry")
	}
	lower, upper, contiguous := regex.NewByteSet(p.ByteSet).ContiguousRange()
	if lower != p.ByteSetLower || upper != p.ByteSetUpper || contiguous != p.ByteSetContiguous ||
		len(p.ByteSetValues) > maxSparseRegexByteSetValues ||
		len(p.ByteSetValues) != 0 && !bytes.Equal(p.ByteSetValues, p.ByteSet) {
		return errors.New("inconsistent regex byte-set bounds or sparse values")
	}
	if len(p.FixedByteSets) > 256 {
		return errors.New("invalid regex fixed byte-set count")
	}
	for i, set := range p.FixedByteSets {
		if !validSerializedRegexByteSet(set, 256) {
			return fmt.Errorf("invalid regex fixed byte set %d", i)
		}
	}
	if !validSerializedRegexByteSet(p.FirstByteSet, maxRegexByteSetSize) || p.HasFirstByteSet != (len(p.FirstByteSet) != 0) ||
		!validSerializedRegexByteSet(p.PrecedingByteSet, 256) || !p.HasPrecedingByteSet && len(p.PrecedingByteSet) != 0 {
		return errors.New("invalid regex first or preceding byte set")
	}
	if !validSerializedRegexByteSet(p.PrefixRepeatClass, 256) ||
		!validSerializedRegexRange(p.PrefixRepeatMin, p.PrefixRepeatMax, 65535) ||
		!p.HasPrefixRepeat && (p.PrefixRepeatMin != 0 || p.PrefixRepeatMax != 0 || len(p.PrefixRepeatClass) != 0) {
		return errors.New("invalid regex prefix repeat metadata")
	}
	return nil
}

func validSerializedRegexByteSet(values []byte, limit int) bool {
	if len(values) > limit {
		return false
	}
	for i := 1; i < len(values); i++ {
		if values[i] <= values[i-1] {
			return false
		}
	}
	return true
}

func validateSerializedRegexLeadingGap(gap *serializedLeadingGap) error {
	if gap == nil {
		return nil
	}
	if len(gap.Atoms) == 0 || !validSerializedRegexRange(gap.GapMin, gap.GapMax, 65535) ||
		!validSerializedRegexByteSet(gap.LeadingSet, 256) || !validSerializedRegexByteSet(gap.GapSet, maxRegexByteSetSize) {
		return errors.New("invalid regex leading gap")
	}
	for i, atom := range gap.Atoms {
		if !validSerializedRegexAtom(atom) || atom.MaxOffset < 0 || atom.MaxOffset-atom.MinOffset > maxLeadingGapAtomOffsetWidth {
			return fmt.Errorf("invalid regex leading-gap atom %d", i)
		}
	}
	return nil
}

func validateSerializedRegexVerification(plan *regexVerificationPlan, flags regex.Flags) error {
	if plan == nil {
		if flags&regexStartAtomEntries != 0 {
			return errors.New("missing regex match-start verification plan")
		}
		return nil
	}
	if len(plan.Atoms) == 0 || plan.ForwardOnly && (len(plan.Atoms) != 1 || len(plan.Atoms[0].Backward) > 1) {
		return errors.New("invalid regex verification plan shape")
	}
	if flags&regexStartAtomEntries != 0 && (len(plan.Atoms) < 2 || !verificationStartsAtMatch(plan)) {
		return errors.New("invalid regex match-start verification plan")
	}
	if plan.CappedLiteralSuffix && (plan.ForwardOnly || len(plan.Atoms) != 1 || len(plan.Atoms[0].Bytes) == 0 ||
		slices.ContainsFunc(plan.Atoms[0].Mask, func(mask byte) bool { return mask != 255 })) {
		return errors.New("invalid regex capped suffix verification plan")
	}
	for i, atom := range plan.Atoms {
		if len(atom.Bytes) > 4 || len(atom.Mask) != len(atom.Bytes) ||
			(len(atom.Bytes) == 0) != (len(atom.Backward) == 0) || len(atom.Bytes) == 0 && !plan.ForwardOnly {
			return fmt.Errorf("invalid regex verification atom %d", i)
		}
		if err := regex.ValidateBytecode(atom.Forward); err != nil {
			return fmt.Errorf("regex verification atom %d forward code: %w", i, err)
		}
		if len(atom.Backward) > 0 {
			if err := regex.ValidateBytecode(atom.Backward); err != nil {
				return fmt.Errorf("regex verification atom %d backward code: %w", i, err)
			}
		}
	}
	return nil
}

func validateSerializedRegexAlternation(plan *regexBoundedAlternation) error {
	if plan == nil {
		return nil
	}
	if err := validateSerializedRegexBranches(plan.Branches); err != nil {
		return fmt.Errorf("regex alternation: %w", err)
	}
	if plan.Repeat != nil {
		if len(plan.Prefix) != 0 || len(plan.Tail) != 0 {
			return errors.New("regex repeat plan has a bytecode prefix or tail")
		}
		return validateSerializedRegexRepeat(plan.Repeat, plan.Branches)
	}
	if err := regex.ValidateBytecode(plan.Tail); err != nil {
		return fmt.Errorf("regex alternation tail code: %w", err)
	}
	if len(plan.Prefix) != 0 {
		if err := regex.ValidateBytecode(plan.Prefix); err != nil {
			return fmt.Errorf("regex alternation prefix code: %w", err)
		}
	}
	return nil
}

func validateSerializedRegexBranches(branches []boundedRegexBranch) error {
	if len(branches) == 0 {
		return errors.New("missing literal branches")
	}
	remaining := maxSerializedRegexExtent
	for i, branch := range branches {
		if len(branch.Literal) == 0 || len(branch.Literal) > remaining || branch.AtomOffset < 0 ||
			branch.AtomOffset >= len(branch.Literal) {
			return fmt.Errorf("invalid literal branch %d", i)
		}
		remaining -= len(branch.Literal)
	}
	return nil
}

func validateSerializedRegexRepeat(repeat *regexRepeatPlan, branches []boundedRegexBranch) error {
	if len(repeat.Prefix) > maxSerializedRegexExtent || len(repeat.Suffix) > maxSerializedRegexExtent {
		return errors.New("invalid regex repeat prefix or suffix size")
	}
	if err := validateSerializedRegexBranches(repeat.Branches); err != nil {
		return fmt.Errorf("regex repeat: %w", err)
	}
	if repeat.AtomInRepeat {
		if !slices.EqualFunc(branches, repeat.Branches, func(a, b boundedRegexBranch) bool {
			return a.AtomOffset == b.AtomOffset && bytes.Equal(a.Literal, b.Literal)
		}) {
			return errors.New("regex repeat atom branches differ from the repeat body")
		}
	} else if len(branches) != 1 || !bytes.Equal(branches[0].Literal, repeat.Suffix) {
		return errors.New("regex repeat atom branch differs from the literal suffix")
	}
	return nil
}
