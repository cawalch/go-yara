package compiler

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"time"

	"github.com/cawalch/go-yara/regex"
)

const (
	defaultStreamChunkSize    = 1024 * 1024 // 1 MB default streaming chunk
	streamingLookaheadContext = 2
	streamingHeaderSize       = 64 * 1024
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
		for _, pattern := range rule.RegexPatterns {
			maxLen = max(maxLen, streamingRegexLength(pattern))
		}
		for _, p := range rule.HexPatterns {
			maxLen = max(maxLen, streamingHexLength(p))
		}
	}
	// Add 4096 context margin for lookahead, fullword boundaries, and bounded regex spans.
	if maxLen > math.MaxInt-4096 {
		return math.MaxInt
	}
	return maxLen + 4096
}

func addSaturatedInt(a, b int) int {
	if a >= math.MaxInt-b {
		return math.MaxInt
	}
	return a + b
}

func streamingHexLength(p *HexPattern) int {
	if p == nil {
		return 0
	}
	minSpan, maxSpan, bounded := hexTokensSpanRange(p.Tokens)
	if bounded {
		return maxSpan
	}
	return max(minSpan, 2*regexVerificationDistance)
}

func hexTokensSpanRange(tokens []HexPatternToken) (minSpan, maxSpan int, bounded bool) {
	bounded = true
	for _, tok := range tokens {
		switch tok.Kind {
		case HexTokenByte, HexTokenMasked, HexTokenWildcard:
			minSpan = addSaturatedInt(minSpan, 1)
			if bounded {
				maxSpan = addSaturatedInt(maxSpan, 1)
			}
		case HexTokenJump:
			if tok.Min > 0 {
				minSpan = addSaturatedInt(minSpan, tok.Min)
			}
			if tok.Max < 0 {
				bounded = false
			} else if bounded && tok.Max > 0 {
				maxSpan = addSaturatedInt(maxSpan, tok.Max)
			}
		case HexTokenAlt:
			altMin, altMax, altBounded := hexAltSpanRange(tok.Alternatives)
			minSpan = addSaturatedInt(minSpan, altMin)
			if !altBounded {
				bounded = false
			} else if bounded {
				maxSpan = addSaturatedInt(maxSpan, altMax)
			}
		}
	}
	return minSpan, maxSpan, bounded
}

func hexAltSpanRange(alts [][]HexPatternToken) (minSpan, maxSpan int, bounded bool) {
	if len(alts) == 0 {
		return 0, 0, true
	}
	bounded = true
	first := true
	for _, alt := range alts {
		subMin, subMax, subBounded := hexTokensSpanRange(alt)
		if first || subMin < minSpan {
			minSpan = subMin
			first = false
		}
		if !subBounded {
			bounded = false
		} else if bounded && subMax > maxSpan {
			maxSpan = subMax
		}
	}
	return minSpan, maxSpan, bounded
}

// streamingRegexLength is the maximum byte length across the enabled encodings.
// Unbounded expressions use their verifier's finite decision horizon.
// A negative length denotes legacy analysis with no proven horizon.
func streamingRegexLength(pattern RegexPattern) int {
	length := pattern.maxLength
	if length >= 0 {
		if pattern.Flags&regex.FlagsWide != 0 {
			if length > math.MaxInt/2 {
				return math.MaxInt
			}
			length *= 2
		}
		return length
	}
	if pattern.verification != nil {
		if pattern.verification.ForwardOnly {
			return regexVerificationDistance
		}
		return 2 * regexVerificationDistance
	}
	if pattern.streamPriorityBound {
		return regexVerificationDistance
	}
	return -1
}

// Small explicit caps bypass atom-relative verification, so the complete
// expression is decided inside the caller's start-relative window. Larger caps
// still need the verifier's whole horizon, even when the returned span is short.
func (s *Scanner) streamRegexHorizon(pattern RegexPattern) int {
	horizon := streamingRegexLength(pattern)
	if s.maxMatchSpan > 0 && (pattern.verification == nil || s.maxMatchSpan <= regexVerificationDistance) {
		if horizon < 0 || s.maxMatchSpan < horizon {
			horizon = s.maxMatchSpan
		}
	}
	return horizon
}

// streamMatchWindow assigns each settled start to exactly one window.
// Two retained bytes preserve the left boundary for wide/fullword assertions.
type streamMatchWindow struct {
	offset, primaryStart, primaryEnd int64
	overlapCapacity                  int
	final                            bool
}

func (window streamMatchWindow) owns(span matchSpan, horizon int) bool {
	start := window.offset + span.Offset
	if horizon >= 0 && horizon <= window.overlapCapacity-streamingLookaheadContext {
		first := max(int64(0), window.primaryStart-int64(horizon))
		limit := max(int64(0), window.primaryEnd-int64(horizon))
		if window.final {
			limit = window.primaryEnd
		}
		return start >= first && start < limit
	}
	// Undersized explicit overlap for bounded patterns retains end ownership.
	if span.Length == 0 {
		return start >= window.primaryStart && start < window.primaryEnd
	}
	end := start + int64(span.Length)
	return end > window.primaryStart && end <= window.primaryEnd
}

func (s *Scanner) effectiveStreamChunkSize() int {
	if s != nil && s.streamChunkSize > 0 {
		return s.streamChunkSize
	}
	return defaultStreamChunkSize
}

func (s *Scanner) effectiveStreamOverlapSize() (int, error) {
	overlap := s.streamOverlapSize
	if overlap <= 0 {
		overlap = s.program.maxStreamingOverlap()
	}
	for _, rule := range s.program.Rules {
		if !s.shouldEvaluateRule(rule) {
			continue
		}
		for id, pattern := range rule.RegexPatterns {
			if pattern.maxLength >= 0 {
				continue
			}
			horizon := s.streamRegexHorizon(pattern)
			if horizon < 0 {
				return 0, fmt.Errorf("streaming regex %s.%s has no finite verification horizon; recompile the program or use WithMaxMatchSpan", rule.Name, id)
			}
			if horizon > math.MaxInt-streamingLookaheadContext {
				return 0, errors.New("streaming overlap size is too large")
			}
			overlap = max(overlap, horizon+streamingLookaheadContext)
		}
	}
	return overlap, nil
}

func ruleStreamEarlyTerminationProfile(rule *CompiledRule) (forbidden, readsHeader bool) {
	if rule == nil {
		return false, false
	}
	bc := rule.Bytecode
	for ip := 0; ip < len(bc); {
		op := Opcode(bc[ip])
		operandSize, valid := bytecodeOperandSize(op)
		if !valid || ip+1+operandSize > len(bc) {
			return true, false
		}
		switch {
		case op == OpFilesize || op == OpAssertFilesize || op == OpEntrypoint ||
			op == OpPushRule || op == OpPushRuleRef || op == OpInitRule:
			return true, false
		case (op >= OpReadInt && op <= OpUint64be) || op == OpAssertUint16Eq || op == OpAssertUint32Eq:
			readsHeader = true
		case op == OpCall:
			fn, _ := decodeBuiltinCall(binary.LittleEndian.Uint32(bc[ip+1 : ip+5]))
			if fn == builtinMD5 || fn == builtinSHA1 || fn == builtinSHA256 || fn >= firstModuleFunctionID {
				readsHeader = true
			}
		}
		ip += 1 + operandSize
	}
	for _, a := range rule.assertions {
		switch a.Opcode {
		case OpAssertFilesize:
			return true, false
		case OpAssertUint16Eq, OpAssertUint32Eq:
			readsHeader = true
		}
	}
	for _, hc := range rule.HeaderConstraints {
		if hc.Kind == HeaderIntegerEquals {
			readsHeader = true
		}
	}
	if len(rule.ModuleFunctions) > 0 {
		readsHeader = true
	}
	return false, readsHeader
}

func (s *Scanner) canRuleEarlyTerminate(rule *CompiledRule, headerLen int) bool {
	if rule == nil || rule.IsPrivate || !rule.ConditionMonotonic {
		return false
	}
	if len(rule.moduleAccessNames) > 0 {
		return false
	}
	if s.program != nil && len(s.program.dependencies[rule.Name]) > 0 {
		return false
	}
	forbidden, readsHeader := ruleStreamEarlyTerminationProfile(rule)
	if forbidden {
		return false
	}
	if readsHeader && headerLen < streamingHeaderSize {
		return false
	}
	return true
}

type streamAccumulator struct {
	pcapReader         io.ReaderAt
	fileSize           int64
	headerBlock        []byte
	accumulatedSpans   map[string]map[string][]matchSpan
	accumulatedMatches map[string]map[string][]Match
	captureInputs      map[string]map[string][]captureInput
}

// retainHeader appends only the unseen prefix bytes from a contiguous scan window.
// Both overlap and lookahead can already be present in the retained header.
func (acc *streamAccumulator) retainHeader(window []byte, offset int64) {
	if len(acc.headerBlock) == streamingHeaderSize {
		return
	}
	data := window[int64(len(acc.headerBlock))-offset:]
	data = data[:min(len(data), streamingHeaderSize-len(acc.headerBlock))]
	needed := len(acc.headerBlock) + len(data)
	if needed > cap(acc.headerBlock) {
		capacity := min(streamingHeaderSize, max(needed, 2*cap(acc.headerBlock)))
		header := make([]byte, len(acc.headerBlock), capacity)
		copy(header, acc.headerBlock)
		acc.headerBlock = header
	}
	acc.headerBlock = append(acc.headerBlock, data...)
}

// scanReaderStream reuses a sliding input buffer bounded by chunk size,
// overlap capacity, and lookahead. Retained matches are accumulated separately.
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

	if s.matchBudgets != nil {
		s.resetMatchLimits()
	}
	s.skipUnmatchedNonText = false
	fastScan := s.fastScan
	defer func() {
		s.fastScan = fastScan
	}()

	reader := contextReader{ctx: ctx, reader: r}
	chunkSize := s.effectiveStreamChunkSize()
	overlapCapacity, err := s.effectiveStreamOverlapSize()
	if err != nil {
		return nil, err
	}

	if chunkSize <= 0 || chunkSize > math.MaxInt-overlapCapacity-streamingLookaheadContext {
		return nil, errors.New("streaming chunk size is invalid")
	}

	if s.streamBufReader == nil {
		s.streamBufReader = bufio.NewReaderSize(reader, 64*1024)
	} else {
		s.streamBufReader.Reset(reader)
	}
	bufReader := s.streamBufReader
	defer bufReader.Reset(nil)

	// Reuse a single contiguous buffer for sliding window scans.
	neededBuf := overlapCapacity + chunkSize + streamingLookaheadContext
	if cap(s.streamBuf) < neededBuf {
		s.streamBuf = make([]byte, neededBuf)
	}
	buf := s.streamBuf[:neededBuf]

	recordMatches := !s.omitMatches
	var accumulatedMatches map[string]map[string][]Match
	if recordMatches {
		accumulatedMatches = make(map[string]map[string][]Match)
	}
	var (
		currentStreamOffset int64
		overlapLen          int
		acc                 = &streamAccumulator{
			headerBlock:        s.streamHeaderBuf[:0],
			accumulatedSpans:   make(map[string]map[string][]matchSpan),
			accumulatedMatches: accumulatedMatches,
		}
	)
	// ReaderAt offsets are absolute while Read starts at the current position.
	// Only seek when the compiled program can request native capture data.
	_, suppliedPCAP := s.moduleData["pcap"]
	needsPCAP := s.program.nativePCAP && !suppliedPCAP
	if needsPCAP {
		acc.pcapReader = streamPCAPReader(ctx, r)
	}
	defer func() {
		s.streamHeaderBuf = acc.headerBlock[:0]
	}()

	var window streamMatchWindow
	var currentRule *CompiledRule
	var fastFilter func(string, matchSpan) bool
	if s.fastScan {
		fastFilter = func(id string, span matchSpan) bool {
			horizon := -1
			if pattern, ok := currentRule.RegexPatterns[id]; ok {
				horizon = s.streamRegexHorizon(pattern)
			}
			return window.owns(span, horizon)
		}
	}

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

		lookahead, peekErr := bufReader.Peek(streamingLookaheadContext)
		// Peek can consume a pending reader error, even when it returns bytes.
		// Propagate it before evaluating matches or allowing early termination.
		if peekErr != nil && peekErr != io.EOF {
			return nil, peekErr
		}
		if len(lookahead) > 0 {
			copy(buf[windowLen:], lookahead)
			windowLen += len(lookahead)
		}
		windowData := buf[:windowLen]
		window = streamMatchWindow{
			offset: chunkOffset, primaryStart: primaryStart, primaryEnd: primaryEnd,
			overlapCapacity: overlapCapacity,
			final:           readErr != nil || peekErr == io.EOF && len(lookahead) == 0,
		}

		// Integer reads use the retained prefix, regardless of chunk boundaries.
		if len(acc.headerBlock) < streamingHeaderSize {
			acc.retainHeader(windowData, chunkOffset)
			if s.streamEarlyTermination {
				// An assertion that was undefined may now have all its input bytes.
				clear(s.assertionResults)
			}
		}

		s.fastScan = false
		usesharedAutomaton, prepErr := s.prepareChunkPatternScan(ctx, windowData)
		s.fastScan = fastScan
		if prepErr != nil {
			return nil, prepErr
		}

		evalCount := len(s.program.Rules)
		if usesharedAutomaton {
			evalCount = len(s.candidateRuleIndices)
		}
		for idx := 0; idx < evalCount; idx++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			var rule *CompiledRule
			if usesharedAutomaton {
				ruleIndex := s.candidateRuleIndices[idx]
				if ruleIndex < 0 || ruleIndex >= len(s.program.Rules) {
					continue
				}
				rule = s.program.Rules[ruleIndex]
			} else {
				rule = s.program.Rules[idx]
			}
			if !s.shouldEvaluateRule(rule) {
				continue
			}

			s.matchCtx.ResetForRule(rule, windowData)
			s.configureRuleMatchContext(ctx, rule)
			savedMaxMatches := s.matchCtx.maxMatchesPerPattern
			// Never clip text patterns per-window before window.owns() runs;
			// a boundary fullword match at index 0 can be provisional/unowned.
			s.matchCtx.maxMatchesPerPattern = 0
			if s.matchBudgets != nil {
				s.limitRuleMatches(rule, chunkOffset, &window)
			}
			if err := s.addRuleTextMatches(ctx, rule, windowData, usesharedAutomaton); err != nil {
				return nil, err
			}
			s.matchCtx.maxMatchesPerPattern = savedMaxMatches
			if s.matchBudgets == nil && s.fastScan && rule.FastScanSafe {
				// Filter non-text candidates before clipping: the first local
				// occurrence may be provisional or belong to an earlier window.
				currentRule = rule
				s.matchCtx.matchFilter = fastFilter
			}
			if err := s.addLocalNonTextMatches(ctx, rule, windowData, &s.nonTextCache, usesharedAutomaton, false); err != nil {
				return nil, err
			}
			if s.matchLimitErr != nil {
				return nil, s.matchLimitErr
			}
			if len(rule.fixedOffsets) != 0 {
				s.matchCtx.filterFixedOffsets(rule.fixedOffsets, chunkOffset)
			}
			s.matchCtx.normalizeMatches()
			if s.telemetrySink != nil {
				s.telemetrySink.VerificationBudgetRejects += uint64(s.matchCtx.verificationBudgetRejects)
				s.matchCtx.verificationBudgetRejects = 0
			}

			if !s.matchCtx.hasSpans() {
				continue
			}

			s.matchCtx.forEachSpanSlice(func(strID string, spans []matchSpan) {
				horizon := -1
				if pattern, ok := rule.RegexPatterns[strID]; ok {
					horizon = s.streamRegexHorizon(pattern)
				}
				needsEvidenceData := s.evidenceMax > 0 && len(rule.CaptureBindings[strID]) > 0
				for _, sp := range spans {
					if !window.owns(sp, horizon) {
						continue
					}
					if s.fastScan && rule.FastScanSafe && len(acc.accumulatedSpans[rule.Name][strID]) > 0 {
						continue
					}
					absStart := chunkOffset + sp.Offset
					if s.matchBudgets != nil {
						s.matchBudgets[rule.Index].positions[strID][absStart] = 1
					}
					if acc.accumulatedSpans[rule.Name] == nil {
						acc.accumulatedSpans[rule.Name] = make(map[string][]matchSpan)
					}
					acc.accumulatedSpans[rule.Name][strID] = append(acc.accumulatedSpans[rule.Name][strID], matchSpan{
						Offset: absStart,
						Length: sp.Length,
					})
					if recordMatches {
						acc.recordSpanMatch(streamMatchRecord{
							rule:              rule,
							strID:             strID,
							span:              sp,
							absStart:          absStart,
							chunkOffset:       chunkOffset,
							windowData:        windowData,
							matchDataMax:      s.matchDataMax,
							needsEvidenceData: needsEvidenceData,
						})
					}
				}
			})
		}

		currentStreamOffset = primaryEnd

		// A short read cannot establish whether the capture is complete.
		if !needsPCAP && s.checkStreamEarlyTermination(ctx, acc, currentStreamOffset) {
			break
		}

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

func (s *Scanner) prepareChunkPatternScan(ctx context.Context, chunkData []byte) (bool, error) {
	s.skipUnmatchedNonText = false
	if s.matchBudgets != nil {
		return s.preparePatternScan(ctx, chunkData)
	}
	if len(s.program.Rules) <= 1 {
		s.nonTextCache.reset(s.program.nonTextCacheSize)
		if err := s.populateFixedRegexCache(ctx, chunkData, &s.nonTextCache); err != nil {
			return false, err
		}
		s.regexByteSetCache.reset()
		return false, nil
	}
	usesharedAutomaton, err := s.preparePatternScan(ctx, chunkData)
	if err != nil {
		return false, err
	}
	if usesharedAutomaton {
		s.markChunkCandidateRules()
	}
	return usesharedAutomaton, nil
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
		if !s.shouldEvaluateRule(rule) || !s.hasMatchingTag(rule) || !s.canRuleEarlyTerminate(rule, len(acc.headerBlock)) {
			continue
		}
		if len(acc.accumulatedSpans[rule.Name]) == 0 {
			continue
		}
		if len(rule.HeaderConstraints) > 0 && !s.ruleConstraintsMatchContext(rule, headerCtx, false) {
			continue
		}
		s.matchCtx.ResetForRule(rule, nil)
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
	s.resetBorrowedEvidence()
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

	result = s.initStreamScanResult()
	s.moduleCache.pcapReader = acc.pcapReader
	defer func() { s.moduleCache.pcapReader = nil }()

	blocks := []MemoryBlock{}
	if len(acc.headerBlock) > 0 {
		blocks = append(blocks, MemoryBlock{Base: 0, Data: acc.headerBlock})
	}
	headerContext := &MatchContext{Blocks: blocks, FileSize: acc.fileSize, cancelDone: ctx.Done()}

	done := ctx.Done()
	for _, rule := range s.program.Rules {
		if scanCanceled(done) {
			return nil, ctx.Err()
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
			s.recordRuleResult(rule, false)
			if result.RuleResults != nil {
				result.RuleResults[rule.Name] = false
			}
			result.PrunedRules = append(result.PrunedRules, rule.Name)
			s.recordPrunedRule(rule, state)
			continue
		}

		s.matchCtx.ResetForRule(rule, nil)
		s.matchCtx.moduleCache = &s.moduleCache
		s.matchCtx.assertionResults = s.assertionResults
		s.configureRuleMatchContext(ctx, rule)
		s.matchCtx.Blocks = blocks
		s.matchCtx.FileSize = acc.fileSize

		for id, spans := range acc.accumulatedSpans[rule.Name] {
			for _, sp := range spans {
				s.matchCtx.addMatchSpan(id, sp)
			}
		}
		s.matchCtx.normalizeMatches()

		state.populated = true
		if !s.prefilterDisabled && rule.RequiresStringMatch && !s.matchCtx.hasSpans() {
			s.recordRuleOutcome(result, rule, false)
			continue
		}

		if err := s.executeCondition(rule); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, err
		}
		matched := s.interp.ruleResultByIndex(rule.Index, rule.Name)
		s.recordRuleOutcome(result, rule, matched)
		if s.hookMask&(hookBitTelemetry|hookBitRuleProfile) != 0 {
			s.recordRuleEvaluatedHooks(rule, matched, state)
		}
		if !s.omitMatches && !s.reportedMatchesOnly && result.Matches != nil {
			if ruleMatches := materializeStreamRuleMatches(acc, rule); ruleMatches != nil {
				result.Matches[rule.Name] = ruleMatches
			}
		}
	}

	err = s.finalizeMatchedRulesCore(ctx, result, s.streamEarlyTermination, func(rule *CompiledRule) (map[string][]Match, map[string][]EvidenceFinding, error) {
		var ruleMatches map[string][]Match
		if !s.omitMatches {
			ruleMatches = materializeStreamRuleMatches(acc, rule)
			if result.Matches != nil && ruleMatches != nil {
				result.Matches[rule.Name] = ruleMatches
			}
		}
		evidence, evErr := s.populateStreamRuleEvidence(ctx, acc, rule, ruleMatches)
		return ruleMatches, evidence, evErr
	})
	s.clearRuleResultsIfDirty()
	s.matchCtx.Reset(nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}

type streamMatchRecord struct {
	rule              *CompiledRule
	strID             string
	span              matchSpan
	absStart          int64
	chunkOffset       int64
	windowData        []byte
	matchDataMax      int
	needsEvidenceData bool
}

func (acc *streamAccumulator) recordSpanMatch(rec streamMatchRecord) {
	if rec.rule.IsPrivateString(rec.strID) {
		return
	}
	if acc.accumulatedMatches[rec.rule.Name] == nil {
		acc.accumulatedMatches[rec.rule.Name] = make(map[string][]Match)
	}
	raw := rec.windowData[rec.span.Offset : rec.span.Offset+int64(rec.span.Length)]
	copyLen := len(raw)
	truncated := false
	if rec.matchDataMax > 0 && copyLen > rec.matchDataMax {
		copyLen = rec.matchDataMax
		truncated = true
	}
	acc.accumulatedMatches[rec.rule.Name][rec.strID] = append(acc.accumulatedMatches[rec.rule.Name][rec.strID], Match{
		Pattern:              rec.strID,
		Offset:               rec.absStart,
		Length:               rec.span.Length,
		MatchedData:          copyBytes(raw[:copyLen]),
		MatchedDataTruncated: truncated,
	})
	if !rec.needsEvidenceData {
		return
	}
	if acc.captureInputs == nil {
		acc.captureInputs = make(map[string]map[string][]captureInput)
	}
	if acc.captureInputs[rec.rule.Name] == nil {
		acc.captureInputs[rec.rule.Name] = make(map[string][]captureInput)
	}
	margin := 0
	if hasPositiveBindingGroups(rec.rule.CaptureBindings[rec.strID]) {
		margin = streamingLookaheadContext
	}
	srcStart := max(0, int(rec.span.Offset)-margin)
	srcEnd := min(len(rec.windowData), int(rec.span.Offset)+rec.span.Length+margin)
	startInSrc := int(rec.span.Offset) - srcStart
	acc.captureInputs[rec.rule.Name][rec.strID] = append(acc.captureInputs[rec.rule.Name][rec.strID], captureInput{
		data:  copyBytes(rec.windowData[srcStart:srcEnd]),
		start: startInSrc,
		end:   startInSrc + rec.span.Length,
		base:  rec.chunkOffset + int64(srcStart),
	})
}

func materializeStreamRuleMatches(acc *streamAccumulator, rule *CompiledRule) map[string][]Match {
	if existing := acc.accumulatedMatches[rule.Name]; existing != nil {
		for strID, ms := range existing {
			if rule.IsPrivateString(strID) || len(ms) == 0 {
				delete(existing, strID)
			}
		}
		if len(existing) == 0 {
			return nil
		}
		return existing
	}
	spansByPattern := acc.accumulatedSpans[rule.Name]
	if len(spansByPattern) == 0 {
		return nil
	}
	out := make(map[string][]Match, len(spansByPattern))
	for strID, spans := range spansByPattern {
		if rule.IsPrivateString(strID) || len(spans) == 0 {
			continue
		}
		ms := make([]Match, len(spans))
		for i, sp := range spans {
			ms[i] = Match{
				Pattern: strID,
				Offset:  sp.Offset,
				Length:  sp.Length,
			}
		}
		out[strID] = ms
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

//nolint:revive // argument-limit: stream evidence replay needs accumulator capture sources
func (s *Scanner) populateStreamRuleEvidence(
	ctx context.Context,
	acc *streamAccumulator,
	rule *CompiledRule,
	ruleMatches map[string][]Match,
) (map[string][]EvidenceFinding, error) {
	if s.evidenceMax <= 0 || len(rule.CaptureBindings) == 0 {
		return nil, nil
	}
	var ruleCaptureInputs map[string][]captureInput
	if acc != nil {
		ruleCaptureInputs = acc.captureInputs[rule.Name]
		for _, inputs := range ruleCaptureInputs {
			if !slices.IsSortedFunc(inputs, compareCaptureInputs) {
				slices.SortStableFunc(inputs, compareCaptureInputs)
			}
		}
	}
	return s.populateRuleEvidence(ctx, rule, ruleMatches, func(match Match) (captureInput, bool) {
		if inputs := ruleCaptureInputs[match.Pattern]; len(inputs) > 0 {
			if input, ok := findStreamCaptureInput(inputs, match); ok {
				return input, true
			}
		}
		if match.Length < 0 || (match.Length > 0 && len(match.MatchedData) < match.Length) {
			return captureInput{}, false
		}
		return captureInput{
			data:  match.MatchedData,
			start: 0,
			end:   match.Length,
			base:  match.Offset,
		}, true
	})
}

func compareCaptureInputs(left, right captureInput) int {
	leftOff := left.base + int64(left.start)
	rightOff := right.base + int64(right.start)
	if leftOff < rightOff {
		return -1
	}
	if leftOff > rightOff {
		return 1
	}
	leftLen := left.end - left.start
	rightLen := right.end - right.start
	if leftLen < rightLen {
		return -1
	}
	if leftLen > rightLen {
		return 1
	}
	return 0
}

func findStreamCaptureInput(inputs []captureInput, match Match) (captureInput, bool) {
	idx, _ := slices.BinarySearchFunc(inputs, match.Offset, func(in captureInput, target int64) int {
		off := in.base + int64(in.start)
		if off < target {
			return -1
		}
		if off > target {
			return 1
		}
		return 0
	})
	for i := idx; i < len(inputs); i++ {
		in := inputs[i]
		if in.base+int64(in.start) != match.Offset {
			break
		}
		if in.end-in.start == match.Length {
			return in, true
		}
	}
	return captureInput{}, false
}

type contextReaderAt struct {
	ctx    context.Context
	reader io.ReaderAt
}

func (r contextReaderAt) ReadAt(data []byte, off int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.ReadAt(data, off)
}

type fdContextReaderAt struct {
	contextReaderAt
	fd interface{ Fd() uintptr }
}

func (r fdContextReaderAt) Fd() uintptr {
	return r.fd.Fd()
}

func wrapContextReaderAt(ctx context.Context, r io.ReaderAt) io.ReaderAt {
	if fd, ok := r.(interface{ Fd() uintptr }); ok {
		return fdContextReaderAt{
			contextReaderAt: contextReaderAt{ctx: ctx, reader: r},
			fd:              fd,
		}
	}
	return contextReaderAt{ctx: ctx, reader: r}
}

func streamPCAPReader(ctx context.Context, r io.Reader) io.ReaderAt {
	src, ok := r.(interface {
		io.ReaderAt
		io.Seeker
	})
	if !ok {
		return nil
	}
	start, err := src.Seek(0, io.SeekCurrent)
	if err != nil || start < 0 {
		return nil
	}
	var readerAt io.ReaderAt = src
	if start > 0 {
		// Shift ReaderAt offsets so relative capture offsets start at 0.
		readerAt = io.NewSectionReader(src, start, math.MaxInt64-start)
	}
	if ctx.Done() != nil {
		return wrapContextReaderAt(ctx, readerAt)
	}
	return readerAt
}
