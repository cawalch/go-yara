package compiler

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sort"
	"time"
)

// MemoryBlock is a discrete region in a logical address space. Blocks may be
// sparse or overlapping; callers are responsible for keeping overlapping data
// consistent. Patterns crossing a block boundary require overlapping input.
type MemoryBlock struct {
	Base int64
	Data []byte
}

// BlockScanner incrementally scans non-contiguous or chunked blocks across an
// address space or data stream, then evaluates rule conditions once all blocks
// have been supplied via Finish.
//
// Architectural distinction: BlockScanner is designed for segmented or streaming
// workloads where data arrives in multiple chunks and patterns may cross chunk
// boundaries (requiring overlapping input windows). For single-block evaluation
// against a discrete address space region (such as a single memory page), see
// Scanner.MatchingRulesInBlock instead.
//
// Native pcap requires a single contiguous block starting at offset 0 covering
// the full logical file size; multi-block captures evaluate pcap.tls as undefined.
//
// With an active match limit, an error after a block is added is returned by
// subsequent Scan and Finish calls until Reset discards the partial scan.
// BlockScanner is not safe for concurrent use.
type BlockScanner struct {
	program       *CompiledProgram
	scanner       *Scanner
	blocks        []MemoryBlock
	sortedBlocks  []MemoryBlock
	outOfOrder    bool
	blockLookup   map[int64]blockLookupEntry
	indexedBlocks int
	inputBytes    int64
	matches       map[string]map[string][]Match
	fileSize      int64
	fileSizeSet   bool
	profileCounts map[string]blockProfileCounts
}

// Each extension is a later block at the same base that is longer than every
// earlier block at that base. This preserves first-covering-block lookup.
type blockLookupEntry struct {
	first      int
	extensions []int
}

// NewBlockScanner creates an incremental scanner for a compiled program.
func NewBlockScanner(program *CompiledProgram, opts ...ScannerOption) *BlockScanner {
	return &BlockScanner{
		program: program,
		scanner: NewScanner(program, opts...),
		blocks:  make([]MemoryBlock, 0),
		matches: make(map[string]map[string][]Match),
	}
}

// NewBlockScanner creates an incremental block scanner for this program.
func (cp *CompiledProgram) NewBlockScanner(opts ...ScannerOption) *BlockScanner {
	return NewBlockScanner(cp, opts...)
}

// SetFileSize overrides the logical filesize visible to rule conditions. By
// default it is the highest block end offset.
func (scanner *BlockScanner) SetFileSize(size int64) error {
	if size < 0 {
		return errors.New("block scanner file size must be non-negative")
	}
	scanner.fileSize = size
	scanner.fileSizeSet = true
	return nil
}

// Scan copies one block and immediately pattern-scans it.
func (scanner *BlockScanner) Scan(base int64, data []byte) error {
	return scanner.ScanWithContext(context.Background(), base, data)
}

// ScanWithContext copies one block and immediately pattern-scans it.
func (scanner *BlockScanner) ScanWithContext(ctx context.Context, base int64, data []byte) error {
	return scanner.scanBlock(ctx, MemoryBlock{Base: base, Data: data}, false)
}

// ScanBorrowed adds and immediately pattern-scans one block without copying it.
// Keep data unchanged until Reset or Close. The scanner can read it on every
// call to Finish.
func (scanner *BlockScanner) ScanBorrowed(base int64, data []byte) error {
	return scanner.ScanBorrowedWithContext(context.Background(), base, data)
}

// ScanBorrowedWithContext adds and immediately pattern-scans one block without
// copying it. Keep data unchanged until Reset or Close, even if a scan returns
// an error.
func (scanner *BlockScanner) ScanBorrowedWithContext(ctx context.Context, base int64, data []byte) error {
	return scanner.scanBlock(ctx, MemoryBlock{Base: base, Data: data}, true)
}

func (scanner *BlockScanner) scanBlock(ctx context.Context, block MemoryBlock, borrowed bool) (err error) {
	if scanner == nil || scanner.program == nil || scanner.scanner == nil {
		return errors.New("block scanner is closed or has no program")
	}
	if err := scanner.scanner.matchLimitErr; err != nil {
		return err
	}
	base := block.Base
	if base < 0 {
		return errors.New("block base must be non-negative")
	}
	if int64(len(block.Data)) > int64(^uint64(0)>>1)-base {
		return errors.New("block end offset overflows int64")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scanner.scanner.scanError(); err != nil {
		return err
	}

	var started time.Time
	if scanner.scanner.hookMask&hookBitTelemetryLatency != 0 {
		started = time.Now()
	}
	defer func() {
		if !started.IsZero() {
			scanner.scanner.telemetrySink.TotalScanDurationNs += uint64(time.Since(started).Nanoseconds())
		}
	}()
	if scanner.scanner.hookMask&hookBitTelemetryLatency != 0 {
		previous := scanner.scanner.enterScanPhase(PhasePatternSearch)
		defer scanner.scanner.leaveScanPhase(previous)
	}
	if !borrowed {
		block.Data = append([]byte(nil), block.Data...)
	}
	if previous := len(scanner.blocks) - 1; previous >= 0 && base < scanner.blocks[previous].Base {
		scanner.outOfOrder = true
	}
	scanner.blocks = append(scanner.blocks, block)
	blockData := block.Data
	scanner.inputBytes += int64(len(blockData))
	if !scanner.fileSizeSet && base+int64(len(blockData)) > scanner.fileSize {
		scanner.fileSize = base + int64(len(blockData))
	}

	s := scanner.scanner
	if s.matchBudgets != nil {
		defer func() {
			if err != nil {
				s.matchLimitErr = err
			}
		}()
	}
	usesharedAutomaton, err := s.prepareChunkPatternScan(ctx, blockData)
	if err != nil {
		return err
	}

	evalCount := len(scanner.program.Rules)
	if usesharedAutomaton {
		evalCount = len(s.candidateRuleIndices)
	}
	for idx := 0; idx < evalCount; idx++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		var rule *CompiledRule
		if usesharedAutomaton {
			ruleIndex := s.candidateRuleIndices[idx]
			if ruleIndex < 0 || ruleIndex >= len(scanner.program.Rules) {
				continue
			}
			rule = scanner.program.Rules[ruleIndex]
		} else {
			rule = scanner.program.Rules[idx]
		}
		if !s.shouldEvaluateRule(rule) {
			continue
		}

		if s.hookMask&(hookBitPatternProfile|hookBitTelemetry|hookBitRuleProfile) != 0 {
			clear(s.localProfileCandidates)
		}
		s.matchCtx.ResetForRule(rule, blockData)
		s.configureRuleMatchContext(ctx, rule)
		if s.matchBudgets != nil {
			s.limitRuleMatches(rule, base)
		}
		if err := s.addRuleTextMatches(ctx, rule, blockData, usesharedAutomaton); err != nil {
			return err
		}
		if err := s.addLocalNonTextMatches(ctx, rule, blockData, &s.nonTextCache, usesharedAutomaton, false); err != nil {
			return err
		}

		if s.matchLimitErr != nil {
			return s.matchLimitErr
		}
		if len(rule.fixedOffsets) != 0 {
			s.matchCtx.filterFixedOffsets(rule.fixedOffsets, base)
		}
		s.matchCtx.normalizeMatches()
		s.recordPatternProfiles(rule, usesharedAutomaton)
		scanner.recordPatternCounts(rule)
		if s.telemetrySink != nil {
			s.telemetrySink.VerificationBudgetRejects += uint64(s.matchCtx.verificationBudgetRejects)
			s.matchCtx.verificationBudgetRejects = 0
		}
		if !s.matchCtx.hasSpans() {
			continue
		}
		perRule := scanner.matches[rule.Name]
		if perRule == nil {
			perRule = make(map[string][]Match)
			scanner.matches[rule.Name] = perRule
		}
		s.matchCtx.forEachSpanSlice(func(id string, spans []matchSpan) {
			if s.fastScan && rule.FastScanSafe && len(perRule[id]) > 0 {
				return
			}
			for _, span := range spans {
				match := Match{
					Pattern: id,
					Offset:  base + span.Offset,
					Base:    base,
					Length:  span.Length,
				}
				if budget := s.matchBudgets[rule.Index]; budget != nil {
					positions := budget.positions[id]
					if i := positions[match.Offset]; i > 0 {
						if match.Length > perRule[id][i-1].Length {
							perRule[id][i-1] = match
						}
						continue
					}
					positions[match.Offset] = len(perRule[id]) + 1
				}
				perRule[id] = append(perRule[id], match)
				if s.fastScan && rule.FastScanSafe {
					break
				}
			}
		})
	}
	if s.hookMask&hookBitChunkBoundary != 0 {
		s.dispatchChunk(base, len(blockData), len(scanner.matches))
	}
	return nil
}

// Finish evaluates rule conditions against all accumulated block matches.
func (scanner *BlockScanner) Finish() (*ScanResult, error) {
	return scanner.FinishWithContext(context.Background())
}

// FinishWithContext evaluates rule conditions against all accumulated blocks.
func (scanner *BlockScanner) FinishWithContext(ctx context.Context) (result *ScanResult, err error) {
	if scanner == nil || scanner.program == nil || scanner.scanner == nil {
		return nil, errors.New("block scanner is closed or has no program")
	}
	if err := scanner.scanner.matchLimitErr; err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s := scanner.scanner
	if err := s.scanError(); err != nil {
		return nil, err
	}
	if s.hookMask&(hookBitTelemetry|hookBitScanLifecycle) != 0 {
		started := s.beginScan(ctx, scanner.inputBytes)
		defer func() {
			count := 0
			if result != nil {
				count = len(result.MatchedRules)
			}
			started.finish(result, count, err)
		}()
	}
	result = s.initStreamScanResult()

	blocks := scanner.blocksInBaseOrder()
	if !s.omitMatches && len(scanner.matches) > 0 && (s.matchDataMax > 0 || s.matchContextEnabled || s.evidenceMax > 0) {
		scanner.indexMatchBlocks()
	}
	headerContext := &MatchContext{Blocks: blocks, FileSize: scanner.fileSize, cancelDone: ctx.Done()}

	for _, rule := range scanner.program.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !s.shouldEvaluateRule(rule) {
			continue
		}
		if s.hookMask&hookBitPoll != 0 {
			if err := s.dispatchPoll(ctx, PollProgress{
				BytesScanned:   scanner.fileSize,
				TotalBytes:     scanner.fileSize,
				Phase:          PhaseBlockScan,
				CurrentRule:    rule.Name,
				RulesEvaluated: len(result.RuleResults),
				TotalRules:     len(scanner.program.Rules),
			}); err != nil {
				return nil, err
			}
		}
		counts := scanner.profileCounts[rule.Name]
		state := ruleProfileState{iterations: s.interp.iterations, accumulated: true, candidates: counts.candidates, falseCandidates: counts.falseCandidates}
		if s.hookMask&hookBitRuleProfile != 0 {
			state.started = time.Now()
		}
		headerStart := s.prefilterStart()
		previous := s.enterScanPhase(PhasePrefilter)
		headerMatches := s.ruleConstraintsMatchContext(rule, headerContext, s.omitMatches || s.reportedMatchesOnly)
		s.leaveScanPhase(previous)
		if ctx.Err() == nil && (len(rule.HeaderConstraints) > 0 || len(rule.mandatoryAssertions) > 0) {
			s.finishPrefilter(PrefilterDecision{Stage: PrefilterStageHeaderConstraints, Rejected: !headerMatches}, headerStart)
		}
		if !headerMatches {
			s.recordRuleOutcome(result, rule, false)
			result.PrunedRules = append(result.PrunedRules, rule.Name)
			s.recordPrunedRule(rule, state)
			continue
		}

		perRule := normalizedBlockMatches(scanner.matches[rule.Name])
		s.matchCtx.Reset(nil)
		s.matchCtx.moduleCache = &s.moduleCache
		s.matchCtx.assertionResults = s.assertionResults
		s.configureRuleMatchContext(ctx, rule)
		s.matchCtx.Blocks = blocks
		s.matchCtx.FileSize = scanner.fileSize
		for id, matches := range perRule {
			for _, match := range matches {
				s.matchCtx.addMatchSpan(id, matchSpan{Offset: match.Offset, Length: match.Length})
			}
		}
		state.populated = true
		if !s.prefilterDisabled && rule.RequiresStringMatch && !s.matchCtx.hasSpans() {
			s.recordRuleOutcome(result, rule, false)
			if s.hookMask&(hookBitTelemetry|hookBitRuleProfile) != 0 {
				s.recordRuleEvaluatedHooks(rule, false, state)
			}
			continue
		}

		if err := s.executeCondition(rule); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, err
		}
		matched := s.interp.ruleResultByIndex(rule.Index, rule.Name)
		if s.hookMask&(hookBitTelemetry|hookBitRuleProfile) != 0 {
			s.recordRuleEvaluatedHooks(rule, matched, state)
		}
		s.recordRuleOutcome(result, rule, matched)
		materialize := !s.omitMatches && (!s.reportedMatchesOnly || (matched && !rule.IsPrivate))
		if materialize && len(perRule) > 0 && result.Matches != nil {
			publicMatches := clonePublicRuleMatches(rule, perRule)
			if publicMatches != nil {
				if err := scanner.populateMatchEvidence(ctx, publicMatches); err != nil {
					return nil, err
				}
				result.Matches[rule.Name] = publicMatches
			}
		}
	}

	s.resetBorrowedEvidence()
	err = s.finalizeMatchedRules(ctx, result, func(rule *CompiledRule) (map[string][]Match, map[string][]EvidenceFinding, error) {
		var matches map[string][]Match
		if !s.omitMatches && result.Matches != nil {
			matches = result.Matches[rule.Name]
		}
		if s.evidenceMax <= 0 {
			return matches, nil, nil
		}
		evidence, evErr := s.populateRuleEvidence(ctx, rule, matches, func(match Match) (captureInput, bool) {
			block := scanner.blockForMatch(match)
			if block == nil {
				return captureInput{}, false
			}
			start := int(match.Offset - block.Base)
			end := start + match.Length
			if start < 0 || end < start || end > len(block.Data) {
				return captureInput{}, false
			}
			return captureInput{data: block.Data, start: start, end: end, base: block.Base}, true
		})
		return matches, evidence, evErr
	})
	s.clearRuleResultsIfDirty()
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (scanner *BlockScanner) blocksInBaseOrder() []MemoryBlock {
	if !scanner.outOfOrder {
		return scanner.blocks
	}
	if len(scanner.sortedBlocks) != len(scanner.blocks) {
		scanner.sortedBlocks = append(scanner.sortedBlocks[:0], scanner.blocks...)
		slices.SortStableFunc(scanner.sortedBlocks, func(left, right MemoryBlock) int {
			return cmp.Compare(left.Base, right.Base)
		})
	}
	return scanner.sortedBlocks
}

// Reset discards all blocks and accumulated matches while retaining options.
// It invalidates evidence returned with WithBorrowedEvidence.
func (scanner *BlockScanner) Reset() {
	if scanner == nil {
		return
	}
	clear(scanner.blocks)
	scanner.blocks = scanner.blocks[:0]
	clear(scanner.sortedBlocks)
	scanner.sortedBlocks = scanner.sortedBlocks[:0]
	scanner.outOfOrder = false
	clear(scanner.blockLookup)
	scanner.indexedBlocks = 0
	scanner.inputBytes = 0
	if scanner.scanner != nil {
		scanner.scanner.resetMatchLimits()
		scanner.scanner.matchCtx.Reset(nil)
		scanner.scanner.moduleCache.reset()
		scanner.scanner.resetBorrowedEvidence()
	}
	clear(scanner.matches)
	clear(scanner.profileCounts)
	scanner.fileSize = 0
	scanner.fileSizeSet = false
}

// Close releases pooled scanner resources.
func (scanner *BlockScanner) Close() {
	if scanner == nil {
		return
	}
	scanner.scanner.Close()
	*scanner = BlockScanner{}
}

func normalizedBlockMatches(matches map[string][]Match) map[string][]Match {
	if len(matches) == 0 {
		return nil
	}
	result := make(map[string][]Match, len(matches))
	for id, perString := range matches {
		copyMatches := append([]Match(nil), perString...)
		result[id] = sortAndDedupeMatches(copyMatches)
	}
	return result
}

func sortAndDedupeMatches(matches []Match) []Match {
	slices.SortStableFunc(matches, func(left, right Match) int {
		switch {
		case left.Offset < right.Offset:
			return -1
		case left.Offset > right.Offset:
			return 1
		case left.Length > right.Length:
			return -1
		case left.Length < right.Length:
			return 1
		default:
			return 0
		}
	})
	unique := matches[:0]
	for _, match := range matches {
		if len(unique) > 0 && unique[len(unique)-1].Offset == match.Offset {
			continue
		}
		unique = append(unique, match)
	}
	return unique
}

func clonePublicRuleMatches(rule *CompiledRule, matches map[string][]Match) map[string][]Match {
	if len(matches) == 0 {
		return nil
	}
	var cloned map[string][]Match
	for id, perString := range matches {
		if (rule != nil && rule.IsPrivateString(id)) || len(perString) == 0 {
			continue
		}
		if cloned == nil {
			cloned = make(map[string][]Match, len(matches))
		}
		cloned[id] = append([]Match(nil), perString...)
	}
	return cloned
}

func (scanner *BlockScanner) populateMatchEvidence(ctx context.Context, matches map[string][]Match) error {
	s := scanner.scanner
	if s.matchDataMax <= 0 && !s.matchContextEnabled {
		return nil
	}
	for id, perString := range matches {
		for index := range perString {
			if err := ctx.Err(); err != nil {
				return err
			}
			match := &perString[index]
			block := scanner.blockForMatch(*match)
			if block == nil {
				continue
			}
			start := int(match.Offset - block.Base)
			end := start + match.Length
			if start < 0 || end < start || end > len(block.Data) {
				continue
			}
			if s.matchDataMax > 0 {
				copyLength := min(match.Length, s.matchDataMax)
				match.MatchedData = copyBytes(block.Data[start : start+copyLength])
				match.MatchedDataTruncated = copyLength < match.Length
			}
			if s.matchContextEnabled {
				before := max(0, start-s.matchContextBefore)
				after := min(len(block.Data), end+s.matchContextAfter)
				match.ContextBefore = copyBytes(block.Data[before:start])
				match.ContextAfter = copyBytes(block.Data[end:after])
			}
		}
		matches[id] = perString
	}
	return nil
}

func (scanner *BlockScanner) indexMatchBlocks() {
	if len(scanner.blocks) <= 1 {
		return
	}
	if scanner.blockLookup == nil {
		scanner.blockLookup = make(map[int64]blockLookupEntry, len(scanner.blocks))
	}
	for index := scanner.indexedBlocks; index < len(scanner.blocks); index++ {
		block := scanner.blocks[index]
		entry, found := scanner.blockLookup[block.Base]
		if !found {
			scanner.blockLookup[block.Base] = blockLookupEntry{first: index}
			continue
		}
		longest := entry.first
		if count := len(entry.extensions); count > 0 {
			longest = entry.extensions[count-1]
		}
		if len(block.Data) > len(scanner.blocks[longest].Data) {
			entry.extensions = append(entry.extensions, index)
			scanner.blockLookup[block.Base] = entry
		}
	}
	scanner.indexedBlocks = len(scanner.blocks)
}

func (scanner *BlockScanner) blockForMatch(match Match) *MemoryBlock {
	if match.Offset < match.Base {
		return nil
	}
	end := match.Offset - match.Base + int64(match.Length)
	if len(scanner.blocks) == 1 {
		block := &scanner.blocks[0]
		if block.Base == match.Base && end <= int64(len(block.Data)) {
			return block
		}
		return nil
	}
	entry, found := scanner.blockLookup[match.Base]
	if !found {
		return nil
	}
	first := &scanner.blocks[entry.first]
	if end <= int64(len(first.Data)) {
		return first
	}
	index := sort.Search(len(entry.extensions), func(i int) bool {
		return end <= int64(len(scanner.blocks[entry.extensions[i]].Data))
	})
	if index == len(entry.extensions) {
		return nil
	}
	return &scanner.blocks[entry.extensions[index]]
}

type blockProfileCounts struct{ candidates, falseCandidates int }

func (scanner *BlockScanner) recordPatternCounts(rule *CompiledRule) {
	s := scanner.scanner
	if s.hookMask&(hookBitTelemetry|hookBitRuleProfile) == 0 {
		return
	}
	if scanner.profileCounts == nil {
		scanner.profileCounts = make(map[string]blockProfileCounts)
	}
	counts := scanner.profileCounts[rule.Name]
	for _, id := range rule.IndexToStringID {
		if rule.IsStringDead(id) {
			continue
		}
		candidates, known := s.patternCandidateCount(rule, id, false)
		if known {
			counts.candidates += candidates
			counts.falseCandidates += max(candidates-len(s.matchCtx.spansFor(id)), 0)
		}
	}
	scanner.profileCounts[rule.Name] = counts
}
