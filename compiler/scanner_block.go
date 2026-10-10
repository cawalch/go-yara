package compiler

import (
	"context"
	"fmt"
	"math"
)

// MatchingRulesInBlock evaluates public rules against one explicit block in a
// logical address space. Match offsets are absolute, and fileSize is visible to
// rule conditions. Patterns cannot inspect bytes outside block. Reuse a Scanner
// for high-throughput structured-event streams.
func (s *Scanner) MatchingRulesInBlock(
	block MemoryBlock,
	fileSize int64,
) ([]RuleMatch, error) {
	return s.MatchingRulesInBlockWithContext(context.Background(), block, fileSize)
}

// MatchingRulesInBlockWithContext evaluates public rules against one explicit
// block without constructing the all-rules maps in ScanResult.
func (s *Scanner) MatchingRulesInBlockWithContext(
	ctx context.Context,
	block MemoryBlock,
	fileSize int64,
) ([]RuleMatch, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if block.Base < 0 {
		return nil, fmt.Errorf("block base must be non-negative")
	}
	if fileSize < 0 {
		return nil, fmt.Errorf("block file size must be non-negative")
	}
	if int64(len(block.Data)) > math.MaxInt64-block.Base {
		return nil, fmt.Errorf("block end offset overflows int64")
	}
	if s == nil || s.program == nil {
		return nil, nil
	}
	if err := s.scanError(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	clear(s.ruleResults)
	defer clear(s.ruleResults)
	s.blockContext[0] = block
	s.blockFileSize = fileSize
	s.blockScan = true
	s.matchedRuleIndices = s.matchedRuleIndices[:0]
	evaluation, err := s.evaluatePublicRules(ctx, block.Data, &s.matchedRuleIndices)
	if err != nil {
		s.resetBlockScan()
		return nil, err
	}
	matches, err := s.materializeMatchingRules(ctx, block.Data, evaluation)
	s.resetBlockScan()
	return matches, err
}

func (s *Scanner) resetBlockScan() {
	s.blockScan = false
	s.blockFileSize = 0
	s.blockContext[0] = MemoryBlock{}
}
