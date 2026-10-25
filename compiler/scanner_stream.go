package compiler

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math"
	"time"
)

const (
	defaultStreamChunkSize    = 1024 * 1024 // 1 MB default streaming chunk
	streamingLookaheadContext = 2
)

// maxStreamingOverlap calculates the maximum pattern length across all rules
// in the program and adds lookahead context margin to guarantee boundary overlap.
func (cp *CompiledProgram) maxStreamingOverlap() int {
	if cp == nil {
		return 64
	}
	maxLen := 64
	for _, rule := range cp.Rules {
		if rule.automaton != nil {
			for _, str := range rule.automaton.strings {
				if str.Length > maxLen {
					maxLen = str.Length
				}
			}
		}
		for _, p := range rule.HexPatterns {
			if p != nil && len(p.Tokens) > maxLen {
				maxLen = len(p.Tokens)
			}
		}
	}
	// Add 4096 context margin for lookahead, fullword boundaries, and bounded regex spans.
	return maxLen + 4096
}

func (s *Scanner) effectiveStreamChunkSize() int {
	if s != nil && s.streamChunkSize > 0 {
		return s.streamChunkSize
	}
	return defaultStreamChunkSize
}

func (s *Scanner) effectiveStreamOverlapSize() int {
	if s != nil && s.streamOverlapSize > 0 {
		return s.streamOverlapSize
	}
	if s != nil && s.program != nil {
		return s.program.maxStreamingOverlap()
	}
	return 4096
}

func ruleObservesFilesize(rule *CompiledRule) bool {
	if rule == nil {
		return false
	}
	for _, b := range rule.Bytecode {
		if b == byte(OpFilesize) || b == byte(OpAssertFilesize) {
			return true
		}
	}
	for _, a := range rule.assertions {
		if a.Opcode == OpAssertFilesize {
			return true
		}
	}
	return false
}

func (s *Scanner) canRuleEarlyTerminate(rule *CompiledRule) bool {
	if rule == nil || rule.IsPrivate || !rule.ConditionMonotonic {
		return false
	}
	if len(rule.moduleAccessNames) > 0 {
		return false
	}
	if ruleObservesFilesize(rule) {
		return false
	}
	return true
}

type streamAccumulator struct {
	fileSize           int64
	headerBlock        []byte
	accumulatedSpans   map[string]map[string][]matchSpan
	accumulatedMatches map[string]map[string][]Match
}

// scanReaderStream scans an io.Reader sequentially using a preallocated sliding
// buffer of size (chunkSize + overlapCapacity) to ensure constant, bounded resident memory.
func (s *Scanner) scanReaderStream(ctx context.Context, r io.Reader) (result *ScanResult, err error) {
	if s == nil || s.program == nil {
		return &ScanResult{
			MatchedRules: make([]RuleMatch, 0),
			PrunedRules:  make([]string, 0),
		}, nil
	}
	if err := s.scanError(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	reader := contextReader{ctx: ctx, reader: r}
	chunkSize := s.effectiveStreamChunkSize()
	overlapCapacity := s.effectiveStreamOverlapSize()

	if chunkSize <= 0 || chunkSize > math.MaxInt-overlapCapacity-streamingLookaheadContext {
		return nil, errors.New("streaming chunk size is invalid")
	}

	bufReader := bufio.NewReaderSize(reader, 64*1024)

	// Preallocate a single contiguous buffer for sliding window reuse.
	buf := make([]byte, overlapCapacity+chunkSize+streamingLookaheadContext)

	var (
		currentStreamOffset int64
		overlapLen          int
		acc                 = &streamAccumulator{
			accumulatedSpans:   make(map[string]map[string][]matchSpan),
			accumulatedMatches: make(map[string]map[string][]Match),
		}
		recordMatches = !s.omitMatches
	)

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		targetSlice := buf[overlapLen : overlapLen+chunkSize]
		n, readErr := io.ReadFull(bufReader, targetSlice)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return nil, readErr
		}
		if n == 0 {
			break
		}

		primaryStart := currentStreamOffset
		primaryEnd := primaryStart + int64(n)
		chunkOffset := primaryStart - int64(overlapLen)
		windowLen := overlapLen + n

		if lookahead, _ := bufReader.Peek(streamingLookaheadContext); len(lookahead) > 0 {
			copy(buf[windowLen:], lookahead)
			windowLen += len(lookahead)
		}
		windowData := buf[:windowLen]

		// Retain initial header block (up to 64KB) for fixed-offset operations (e.g. uint16(0))
		if currentStreamOffset == 0 {
			hLen := min(len(windowData), 64*1024)
			acc.headerBlock = append([]byte(nil), windowData[:hLen]...)
		}

		// Reset per-chunk scratch caches
		s.nonTextCache.reset(s.program.nonTextCacheSize)
		if err := s.populateFixedRegexCache(ctx, windowData, &s.nonTextCache); err != nil {
			return nil, err
		}
		s.regexByteSetCache.reset()

		for _, rule := range s.program.Rules {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !s.shouldEvaluateRule(rule) {
				continue
			}

			s.matchCtx.Reset(windowData)
			s.matchCtx.cancelDone = ctx.Done()
			s.matchCtx.maxMatchesPerPattern = 0
			if s.fastScan && rule.FastScanSafe {
				s.matchCtx.maxMatchesPerPattern = 1
			}
			s.matchCtx.maxMatchSpan = s.maxMatchSpan

			if err := s.addLocalTextMatches(ctx, rule, windowData); err != nil {
				return nil, err
			}
			if err := s.addLocalNonTextMatches(ctx, rule, windowData, &s.nonTextCache, false, false); err != nil {
				return nil, err
			}
			s.matchCtx.normalizeMatches()

			if len(s.matchCtx.spans) == 0 {
				continue
			}

			for strID, spans := range s.matchCtx.spans {
				for _, sp := range spans {
					absStart := chunkOffset + sp.Offset
					absEnd := absStart + int64(sp.Length)

					// Deduplication invariant: a match belongs uniquely to the chunk
					// that covers its end offset.
					if sp.Length == 0 {
						if absStart < primaryStart || absStart >= primaryEnd {
							continue
						}
					} else {
						if absEnd <= primaryStart || absEnd > primaryEnd {
							continue
						}
					}

					if acc.accumulatedSpans[rule.Name] == nil {
						acc.accumulatedSpans[rule.Name] = make(map[string][]matchSpan)
					}
					acc.accumulatedSpans[rule.Name][strID] = append(acc.accumulatedSpans[rule.Name][strID], matchSpan{
						Offset: absStart,
						Length: sp.Length,
					})

					if recordMatches {
						if acc.accumulatedMatches[rule.Name] == nil {
							acc.accumulatedMatches[rule.Name] = make(map[string][]Match)
						}
						mBytes := copyBytes(windowData[sp.Offset : sp.Offset+int64(sp.Length)])
						acc.accumulatedMatches[rule.Name][strID] = append(acc.accumulatedMatches[rule.Name][strID], Match{
							Pattern:     strID,
							Offset:      absStart,
							Length:      sp.Length,
							MatchedData: mBytes,
						})
					}
				}
			}
		}

		if s.checkStreamEarlyTermination(ctx, acc, currentStreamOffset) {
			break
		}

		currentStreamOffset = primaryEnd
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}

		// Prepare overlap for next chunk: copy the trailing overlapCapacity bytes of read data
		// (excluding lookahead) to buf start
		readWindowLen := overlapLen + n
		nextOverlap := min(overlapCapacity, readWindowLen)
		copy(buf[:nextOverlap], buf[readWindowLen-nextOverlap:readWindowLen])
		overlapLen = nextOverlap
	}

	acc.fileSize = currentStreamOffset
	return s.evaluateStreamMatches(ctx, acc)
}

func (s *Scanner) checkStreamEarlyTermination(
	ctx context.Context,
	acc *streamAccumulator,
	currentStreamOffset int64,
) bool {
	if !s.streamEarlyTermination || len(s.evaluatedGlobalRules) != 0 {
		return false
	}
	var blocks []MemoryBlock
	if len(acc.headerBlock) > 0 {
		blocks = []MemoryBlock{{Base: 0, Data: acc.headerBlock}}
	}
	headerCtx := &MatchContext{Blocks: blocks, FileSize: currentStreamOffset, cancelDone: ctx.Done()}

	for _, rule := range s.program.Rules {
		if !s.canRuleEarlyTerminate(rule) || !s.hasMatchingTag(rule) {
			continue
		}
		if len(acc.accumulatedSpans[rule.Name]) == 0 {
			continue
		}
		if len(rule.HeaderConstraints) > 0 && !s.ruleConstraintsMatchContext(rule, headerCtx, false) {
			continue
		}
		s.matchCtx.Reset(nil)
		s.matchCtx.cancelDone = ctx.Done()
		s.matchCtx.Blocks = blocks
		s.matchCtx.FileSize = currentStreamOffset
		for id, spans := range acc.accumulatedSpans[rule.Name] {
			for _, sp := range spans {
				s.matchCtx.addMatchSpan(id, sp)
			}
		}
		s.matchCtx.normalizeMatches()
		if err := s.executeCondition(rule); err == nil {
			if s.interp.ruleResultByIndex(rule.Index, rule.Name) {
				return true
			}
		}
	}
	return false
}

func (s *Scanner) evaluateStreamMatches(
	ctx context.Context,
	acc *streamAccumulator,
) (result *ScanResult, err error) {
	if s.hookMask&(hookBitTelemetry|hookBitScanLifecycle) != 0 {
		started := s.beginScan(ctx, acc.fileSize)
		defer func() {
			count := 0
			if result != nil {
				count = len(result.MatchedRules)
			}
			started.finish(result, count, err)
		}()
	}

	var ruleResults map[string]bool
	if !s.omitRuleResults {
		ruleResults = make(map[string]bool, len(s.program.Rules))
	}
	var matches map[string]map[string][]Match
	if !s.omitMatches {
		matches = make(map[string]map[string][]Match)
	}
	result = &ScanResult{
		MatchedRules: make([]RuleMatch, 0),
		PrunedRules:  make([]string, 0),
		RuleResults:  ruleResults,
		Matches:      matches,
	}

	clear(s.ruleResultsDense)
	s.matchedRuleIndices = s.matchedRuleIndices[:0]
	s.interp.ResetIterationCount()
	s.moduleCache.reset()
	clear(s.assertionResults)

	blocks := []MemoryBlock{}
	if len(acc.headerBlock) > 0 {
		blocks = append(blocks, MemoryBlock{Base: 0, Data: acc.headerBlock})
	}
	headerContext := &MatchContext{Blocks: blocks, FileSize: acc.fileSize, cancelDone: ctx.Done()}

	for _, rule := range s.program.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !s.shouldEvaluateRule(rule) {
			continue
		}

		counts := s.localProfileCandidates[rule.Name]
		state := ruleProfileState{iterations: s.interp.iterations, candidates: counts}
		if s.hookMask&hookBitRuleProfile != 0 {
			state.started = time.Now()
		}

		// Check fixed-offset header constraints
		if !s.ruleConstraintsMatchContext(rule, headerContext, s.omitMatches || s.reportedMatchesOnly) {
			if rule.Index >= 0 && rule.Index < len(s.ruleResultsDense) {
				s.ruleResultsDense[rule.Index] = false
			}
			if result.RuleResults != nil {
				result.RuleResults[rule.Name] = false
			}
			result.PrunedRules = append(result.PrunedRules, rule.Name)
			s.recordPrunedRule(rule, state)
			continue
		}

		s.matchCtx.Reset(nil)
		s.matchCtx.moduleCache = &s.moduleCache
		s.matchCtx.assertionResults = s.assertionResults
		s.matchCtx.cancelDone = ctx.Done()
		s.matchCtx.maxMatchesPerPattern = 0
		if s.fastScan && rule.FastScanSafe {
			s.matchCtx.maxMatchesPerPattern = 1
		}
		s.matchCtx.Blocks = blocks
		s.matchCtx.FileSize = acc.fileSize

		for id, spans := range acc.accumulatedSpans[rule.Name] {
			for _, sp := range spans {
				s.matchCtx.addMatchSpan(id, sp)
			}
		}
		s.matchCtx.normalizeMatches()

		state.populated = true
		if !s.prefilterDisabled && rule.RequiresStringMatch && len(s.matchCtx.spans) == 0 {
			if rule.Index >= 0 && rule.Index < len(s.ruleResultsDense) {
				s.ruleResultsDense[rule.Index] = false
			}
			if result.RuleResults != nil {
				result.RuleResults[rule.Name] = false
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

		if rule.Index >= 0 && rule.Index < len(s.ruleResultsDense) {
			s.ruleResultsDense[rule.Index] = matched
		}
		if result.RuleResults != nil {
			result.RuleResults[rule.Name] = matched
		}
		if matched && !rule.IsPrivate && s.hasMatchingTag(rule) {
			s.matchedRuleIndices = append(s.matchedRuleIndices, rule.Index)
		}
	}

	// YARA spec: all evaluated global rules must match
	allGlobalMatched := true
	for _, ruleIndex := range s.evaluatedGlobalRules {
		if ruleIndex >= 0 && ruleIndex < len(s.ruleResultsDense) {
			if !s.ruleResultsDense[ruleIndex] {
				allGlobalMatched = false
				break
			}
		} else if result.RuleResults != nil && !result.RuleResults[s.program.Rules[ruleIndex].Name] {
			allGlobalMatched = false
			break
		}
	}

	// Build final MatchedRules
	if len(s.matchedRuleIndices) > 0 {
		result.MatchedRules = make([]RuleMatch, 0, len(s.matchedRuleIndices))
	}
	for _, ruleIndex := range s.matchedRuleIndices {
		rule := s.program.Rules[ruleIndex]
		if !rule.IsGlobal && !allGlobalMatched {
			continue
		}
		if !s.hasMatchingTag(rule) || rule.IsPrivate {
			continue
		}

		var ruleMatches map[string][]Match
		if !s.omitMatches {
			ruleMatches = acc.accumulatedMatches[rule.Name]
		}

		evidence, evErr := s.populateStreamRuleEvidence(ctx, rule, ruleMatches)
		if evErr != nil {
			return nil, evErr
		}
		if len(evidence) != 0 {
			if result.Evidence == nil {
				result.Evidence = make(map[string]map[string][]EvidenceFinding)
			}
			result.Evidence[rule.Name] = evidence
		}

		ruleMatch := newPublicRuleMatch(rule, ruleMatches, evidence)

		if s.hookMask&hookBitMatch != 0 && s.matchHook != nil {
			action := s.matchHook(rule, ruleMatch)
			switch action {
			case MatchActionStopScan:
				result.MatchedRules = append(result.MatchedRules, ruleMatch)
				clear(s.ruleResultsDense)
				return result, nil
			case MatchActionSkipRule:
				continue
			case MatchActionContinue:
			}
		}

		result.MatchedRules = append(result.MatchedRules, ruleMatch)
		if result.Matches != nil && ruleMatches != nil {
			result.Matches[rule.Name] = ruleMatches
		}
		if s.streamEarlyTermination {
			clear(s.ruleResultsDense)
			s.matchCtx.Reset(nil)
			return result, nil
		}
	}

	clear(s.ruleResultsDense)
	s.matchCtx.Reset(nil)
	return result, nil
}

func (s *Scanner) populateStreamRuleEvidence(
	ctx context.Context,
	rule *CompiledRule,
	ruleMatches map[string][]Match,
) (map[string][]EvidenceFinding, error) {
	if s.evidenceMax <= 0 || len(rule.CaptureBindings) == 0 {
		return nil, nil
	}
	return s.populateRuleEvidence(ctx, rule, ruleMatches, func(match Match) (captureInput, bool) {
		if len(match.MatchedData) == 0 {
			return captureInput{}, false
		}
		return captureInput{
			data:  match.MatchedData,
			start: 0,
			end:   len(match.MatchedData),
			base:  match.Offset,
		}, true
	})
}
