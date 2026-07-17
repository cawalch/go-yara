package compiler

import (
	"context"
	"fmt"
	"slices"
)

// MemoryBlock is a discrete region in a logical address space. Blocks may be
// sparse or overlapping; callers are responsible for keeping overlapping data
// consistent. Patterns crossing a block boundary require overlapping input.
type MemoryBlock struct {
	Base int64
	Data []byte
}

// BlockScanner incrementally scans non-contiguous blocks, then evaluates rule
// conditions once all blocks have been supplied. It is not safe for concurrent
// use.
type BlockScanner struct {
	program     *CompiledProgram
	scanner     *Scanner
	blocks      []MemoryBlock
	matches     map[string]map[string][]Match
	fileSize    int64
	fileSizeSet bool
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
		return fmt.Errorf("block scanner file size must be non-negative")
	}
	scanner.fileSize = size
	scanner.fileSizeSet = true
	return nil
}

// Scan adds and immediately pattern-scans one block.
func (scanner *BlockScanner) Scan(base int64, data []byte) error {
	return scanner.ScanWithContext(context.Background(), base, data)
}

// ScanWithContext adds and immediately pattern-scans one block.
func (scanner *BlockScanner) ScanWithContext(ctx context.Context, base int64, data []byte) error {
	if scanner == nil || scanner.program == nil || scanner.scanner == nil {
		return fmt.Errorf("block scanner is closed or has no program")
	}
	if base < 0 {
		return fmt.Errorf("block base must be non-negative")
	}
	if int64(len(data)) > int64(^uint64(0)>>1)-base {
		return fmt.Errorf("block end offset overflows int64")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if scanner.scanner.externalErr != nil {
		return scanner.scanner.externalErr
	}

	blockData := append([]byte(nil), data...)
	block := MemoryBlock{Base: base, Data: blockData}
	scanner.blocks = append(scanner.blocks, block)
	if !scanner.fileSizeSet && base+int64(len(blockData)) > scanner.fileSize {
		scanner.fileSize = base + int64(len(blockData))
	}

	s := scanner.scanner
	s.nonTextCache.reset(scanner.program.nonTextCacheSize)
	s.populateFixedRegexCache(blockData, &s.nonTextCache)
	s.regexByteSetCache.reset()
	for _, rule := range scanner.program.Rules {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !rule.IsGlobal && !s.hasMatchingTag(rule) {
			continue
		}

		s.matchCtx.Reset(blockData)
		s.matchCtx.maxMatchesPerPattern = 0
		if s.fastScan && rule.FastScanSafe {
			s.matchCtx.maxMatchesPerPattern = 1
		}
		s.addLocalTextMatches(rule, blockData)
		s.addLocalNonTextMatches(rule, blockData, &s.nonTextCache)

		if len(s.matchCtx.spans) == 0 {
			continue
		}
		perRule := scanner.matches[rule.Name]
		if perRule == nil {
			perRule = make(map[string][]Match)
			scanner.matches[rule.Name] = perRule
		}
		for id, spans := range s.matchCtx.spans {
			if s.fastScan && rule.FastScanSafe && len(perRule[id]) > 0 {
				continue
			}
			for _, span := range spans {
				perRule[id] = append(perRule[id], Match{
					Pattern: id,
					Offset:  base + span.Offset,
					Base:    base,
					Length:  span.Length,
				})
				if s.fastScan && rule.FastScanSafe {
					break
				}
			}
		}
	}
	return nil
}

// Finish evaluates rule conditions against all accumulated block matches.
func (scanner *BlockScanner) Finish() (*ScanResult, error) {
	return scanner.FinishWithContext(context.Background())
}

// FinishWithContext evaluates rule conditions against all accumulated blocks.
func (scanner *BlockScanner) FinishWithContext(ctx context.Context) (*ScanResult, error) {
	if scanner == nil || scanner.program == nil || scanner.scanner == nil {
		return nil, fmt.Errorf("block scanner is closed or has no program")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s := scanner.scanner
	result := &ScanResult{
		MatchedRules: make([]RuleMatch, 0),
		PrunedRules:  make([]string, 0),
		RuleResults:  make(map[string]bool, len(scanner.program.Rules)),
		Matches:      make(map[string]map[string][]Match),
	}
	clear(s.ruleResults)
	s.interp.ResetIterationCount()

	blocks := append([]MemoryBlock(nil), scanner.blocks...)
	slices.SortStableFunc(blocks, func(left, right MemoryBlock) int {
		switch {
		case left.Base < right.Base:
			return -1
		case left.Base > right.Base:
			return 1
		default:
			return 0
		}
	})
	headerContext := &MatchContext{Blocks: blocks, FileSize: scanner.fileSize}

	for _, rule := range scanner.program.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !rule.IsGlobal && !s.hasMatchingTag(rule) {
			continue
		}
		if !ruleHeaderConstraintsMatchContext(rule, headerContext) {
			s.ruleResults[rule.Name] = false
			result.RuleResults[rule.Name] = false
			result.PrunedRules = append(result.PrunedRules, rule.Name)
			continue
		}

		perRule := normalizedBlockMatches(scanner.matches[rule.Name])
		s.matchCtx.Reset(nil)
		s.matchCtx.Blocks = blocks
		s.matchCtx.FileSize = scanner.fileSize
		for id, matches := range perRule {
			for _, match := range matches {
				s.matchCtx.addMatchSpan(id, matchSpan{Offset: match.Offset, Length: match.Length})
			}
		}

		s.prepareInterpreter(rule)
		s.interp.SetItersmax(s.itersmax)
		if err := s.interp.Execute(); err != nil {
			return nil, err
		}
		matched := s.interp.GetRuleResults()[rule.Name]
		materialize := !s.reportedMatchesOnly || matched && !rule.IsPrivate
		if materialize && len(perRule) > 0 {
			publicMatches := cloneRuleMatches(perRule)
			publicMatches = filterPrivateStrings(rule, publicMatches)
			if err := scanner.populateMatchEvidence(ctx, publicMatches); err != nil {
				return nil, err
			}
			result.Matches[rule.Name] = publicMatches
		}
		result.RuleResults[rule.Name] = matched
	}

	allGlobalMatched := true
	for _, rule := range scanner.program.Rules {
		if rule.IsGlobal && !result.RuleResults[rule.Name] {
			allGlobalMatched = false
			break
		}
	}
	for _, rule := range scanner.program.Rules {
		if !rule.IsGlobal && !allGlobalMatched {
			if s.reportedMatchesOnly {
				delete(result.Matches, rule.Name)
			}
			continue
		}
		if !s.hasMatchingTag(rule) {
			if s.reportedMatchesOnly {
				delete(result.Matches, rule.Name)
			}
			continue
		}
		if rule.IsPrivate || !result.RuleResults[rule.Name] {
			continue
		}
		matches := result.Matches[rule.Name]
		result.MatchedRules = append(result.MatchedRules, RuleMatch{
			Rule:    rule.Name,
			Tags:    rule.Tags,
			Meta:    rule.Meta,
			Matches: matches,
		})
	}
	clear(s.ruleResults)
	return result, nil
}

// Reset discards all blocks and accumulated matches while retaining options.
func (scanner *BlockScanner) Reset() {
	if scanner == nil {
		return
	}
	scanner.blocks = scanner.blocks[:0]
	clear(scanner.matches)
	scanner.fileSize = 0
	scanner.fileSizeSet = false
}

// Close releases pooled scanner resources.
func (scanner *BlockScanner) Close() {
	if scanner != nil && scanner.scanner != nil {
		scanner.scanner.Close()
		scanner.scanner = nil
	}
}

func normalizedBlockMatches(matches map[string][]Match) map[string][]Match {
	if len(matches) == 0 {
		return nil
	}
	result := make(map[string][]Match, len(matches))
	for id, perString := range matches {
		copyMatches := append([]Match(nil), perString...)
		slices.SortStableFunc(copyMatches, func(left, right Match) int {
			switch {
			case left.Offset < right.Offset:
				return -1
			case left.Offset > right.Offset:
				return 1
			case left.Length < right.Length:
				return -1
			case left.Length > right.Length:
				return 1
			default:
				return 0
			}
		})
		unique := copyMatches[:0]
		for _, match := range copyMatches {
			if len(unique) > 0 && unique[len(unique)-1].Offset == match.Offset && unique[len(unique)-1].Length == match.Length {
				continue
			}
			unique = append(unique, match)
		}
		result[id] = unique
	}
	return result
}

func cloneRuleMatches(matches map[string][]Match) map[string][]Match {
	cloned := make(map[string][]Match, len(matches))
	for id, perString := range matches {
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

func (scanner *BlockScanner) blockForMatch(match Match) *MemoryBlock {
	for index := range scanner.blocks {
		block := &scanner.blocks[index]
		if block.Base == match.Base && match.Offset >= block.Base &&
			match.Offset+int64(match.Length) <= block.Base+int64(len(block.Data)) {
			return block
		}
	}
	return nil
}
