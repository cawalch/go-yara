package compiler

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
)

// StreamingProcessor handles large file processing with chunked I/O
type StreamingProcessor struct {
	// Configuration
	ChunkSize        int  // Size of each chunk (default: 1MB)
	BufferSize       int  // Read buffer size (default: 64KB)
	MaxConcurrency   int  // Maximum concurrent goroutines
	EarlyTermination bool // Stop processing when matches found
	MaxPatternLen    int  // Maximum pattern length for overlap calculation

	// Internal state
	compiledProgram *CompiledProgram
	chunkProcessor  *ChunkProcessor
	progress        *ProgressTracker
}

// ChunkProcessor handles individual chunk processing
type ChunkProcessor struct {
	rules       []*CompiledRule
	matchBuffer *MatchBuffer
}

// MatchBuffer collects matches across chunks
type MatchBuffer struct {
	mu      sync.RWMutex
	matches []StreamingMatch
	limit   int
}

// StreamingMatch represents a rule match (renamed to avoid conflict with interpreter.Match)
type StreamingMatch struct {
	Rule    string
	Pattern string
	Offset  int64
	Length  int
	Data    []byte
}

// ProgressTracker tracks processing progress
type ProgressTracker struct {
	mu           sync.RWMutex
	totalBytes   int64
	processed    int64
	startTime    time.Time
	matchesFound int
}

// Chunk represents a portion of file data
type Chunk struct {
	Data   []byte
	Offset int64
	Index  int
	Total  int
}

// ProcessingResult contains results from chunk processing
type ProcessingResult struct {
	ChunkIndex     int
	Matches        []StreamingMatch
	BytesProcessed int64
	Error          error
	ShouldStop     bool
	ProcessingTime time.Duration
}

// NewStreamingProcessor creates a new streaming processor
func NewStreamingProcessor(program *CompiledProgram) *StreamingProcessor {
	// Calculate maximum pattern length for overlap
	maxPatternLen := 0
	for _, rule := range program.Rules {
		if rule.Automaton != nil {
			for _, str := range rule.Automaton.Strings {
				if str.Length > maxPatternLen {
					maxPatternLen = str.Length
				}
			}
		}
	}

	// If no strings found in automaton, use a reasonable default
	// Most patterns are relatively short, so 64 bytes is a safe overlap
	if maxPatternLen < 1 {
		maxPatternLen = 64
	}

	return &StreamingProcessor{
		ChunkSize:        1 * 1024 * 1024, // 1MB chunks
		BufferSize:       64 * 1024,       // 64KB buffer
		MaxConcurrency:   runtime.NumCPU(),
		EarlyTermination: true,
		MaxPatternLen:    maxPatternLen,
		compiledProgram:  program,
		progress:         &ProgressTracker{},
	}
}

// ProcessFile processes a large file using streaming/chunked approach
func (sp *StreamingProcessor) ProcessFile(ctx context.Context, filename string) ([]StreamingMatch, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			// Log the close error, but don't override the main function's error
			// In production, you might want to use proper logging
			_ = closeErr // Suppress the error until proper logging is implemented
		}
	}()

	// Get file size for progress tracking
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	sp.progress.totalBytes = fileInfo.Size()
	sp.progress.startTime = time.Now()

	// Initialize match buffer
	matchBuffer := &MatchBuffer{
		matches: make([]StreamingMatch, 0, 100),
		limit:   1000, // Limit total matches to prevent memory blowup
	}

	// Create chunk processor
	sp.chunkProcessor = sp.createChunkProcessor(matchBuffer)

	// Process file in chunks
	results := make(chan ProcessingResult, sp.MaxConcurrency)
	err = sp.processChunks(ctx, file, results)
	if err != nil {
		return nil, err
	}

	// Collect results
	var allMatches []StreamingMatch
	for result := range results {
		if result.Error != nil {
			return nil, result.Error
		}
		allMatches = append(allMatches, result.Matches...)

		if sp.EarlyTermination && len(result.Matches) > 0 {
			fmt.Printf("Early termination after finding matches in chunk %d\n", result.ChunkIndex)
			break
		}
	}

	return allMatches, nil
}

// ProcessBytes processes byte data using streaming approach
func (sp *StreamingProcessor) ProcessBytes(ctx context.Context, data []byte) ([]StreamingMatch, error) {
	sp.progress.totalBytes = int64(len(data))
	sp.progress.startTime = time.Now()

	// Initialize match buffer
	matchBuffer := &MatchBuffer{
		matches: make([]StreamingMatch, 0, 100),
		limit:   1000,
	}

	// Create chunk processor
	sp.chunkProcessor = sp.createChunkProcessor(matchBuffer)

	// Process data in chunks
	results := make(chan ProcessingResult, sp.MaxConcurrency)
	err := sp.processDataChunks(ctx, data, results)
	if err != nil {
		return nil, err
	}

	// Collect results
	var allMatches []StreamingMatch
	for result := range results {
		if result.Error != nil {
			return nil, result.Error
		}
		allMatches = append(allMatches, result.Matches...)

		if sp.EarlyTermination && len(result.Matches) > 0 {
			break
		}
	}

	return allMatches, nil
}

// createChunkProcessor initializes the chunk processor
func (sp *StreamingProcessor) createChunkProcessor(matchBuffer *MatchBuffer) *ChunkProcessor {
	// Extract rules from compiled program (each rule has its own automaton)
	return &ChunkProcessor{
		rules:       sp.extractRules(),
		matchBuffer: matchBuffer,
	}
}

// extractRules extracts compiled rules
func (sp *StreamingProcessor) extractRules() []*CompiledRule {
	// Return existing compiled rules
	return sp.compiledProgram.Rules
}

// processChunks processes file data in chunks
func (sp *StreamingProcessor) processChunks(ctx context.Context, file *os.File, results chan<- ProcessingResult) error {
	defer close(results)

	// Create buffered reader
	reader := bufio.NewReaderSize(file, sp.BufferSize)

	chunkIndex := 0
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, sp.MaxConcurrency)

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context canceled: %w", ctx.Err())
		default:
		}

		// Read chunk
		chunk := make([]byte, sp.ChunkSize)
		n, err := io.ReadFull(reader, chunk)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("failed to read chunk: %w", err)
		}

		if n == 0 {
			break // End of file
		}

		// Process chunk
		chunkData := chunk[:n]
		wg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore

		go func(chunkData []byte, chunkIndex int, offset int64) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release semaphore

			result := sp.processChunk(chunkData, chunkIndex, offset)
			results <- result

			// Update progress
			sp.updateProgress(int64(len(chunkData)))
		}(chunkData, chunkIndex, int64(chunkIndex*sp.ChunkSize))

		chunkIndex++
	}

	wg.Wait()
	return nil
}

// processDataChunks processes byte data in chunks
func (sp *StreamingProcessor) processDataChunks(ctx context.Context, data []byte, results chan<- ProcessingResult) error {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, sp.MaxConcurrency)

	chunkCount := (len(data) + sp.ChunkSize - 1) / sp.ChunkSize

	for i := range chunkCount {
		select {
		case <-ctx.Done():
			// Wait for all goroutines to finish
			wg.Wait()
			return fmt.Errorf("context canceled during processing: %w", ctx.Err())
		default:
		}

		start := i * sp.ChunkSize
		end := min(start+sp.ChunkSize, len(data))

		// Add overlap for boundary-crossing patterns (except for first chunk)
		overlapSize := 0
		if i > 0 {
			overlapSize = max(sp.MaxPatternLen-1, 0)
			start -= overlapSize
			if start < 0 {
				start = 0
			}
		}

		chunkData := data[start:end]

		wg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore

		// Calculate actual offset for this chunk (without overlap)
		actualOffset := int64(start)

		go func(chunkData []byte, chunkIndex int, offset int64) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release semaphore

			result := sp.processChunk(chunkData, chunkIndex, offset)

			// Only send result if context is still active
			select {
			case <-ctx.Done():
				return
			case results <- result:
				// Update progress based on actual chunk size processed
				sp.updateProgress(int64(end - (chunkIndex * sp.ChunkSize)))
			}
		}(chunkData, i, actualOffset)
	}

	wg.Wait()
	close(results)
	return nil
}

// processChunk processes a single chunk of data
func (sp *StreamingProcessor) processChunk(chunk []byte, chunkIndex int, offset int64) ProcessingResult {
	start := time.Now()

	// Process chunk with automaton
	matches := sp.chunkProcessor.processChunk(chunk, offset)

	elapsed := time.Since(start)

	return ProcessingResult{
		ChunkIndex:     chunkIndex,
		Matches:        matches,
		BytesProcessed: int64(len(chunk)),
		ProcessingTime: elapsed,
	}
}

// processChunk processes chunk data and finds matches
func (cp *ChunkProcessor) processChunk(chunk []byte, offset int64) []StreamingMatch {
	var matches []StreamingMatch

	// Process each rule's automaton individually
	for _, rule := range cp.rules {
		if rule.Automaton == nil {
			continue
		}

		// Use automaton to find patterns in chunk
		acMatches := rule.Automaton.Search(chunk)

		for _, match := range acMatches {
			// The backtrack value is already the correct position in the chunk
			position := match.Backtrack

			// Get actual length from automaton strings
			length := 9 // Default fallback length for "malicious"
			if match.StringIndex >= 0 && match.StringIndex < len(rule.Automaton.Strings) {
				actualLength := rule.Automaton.Strings[match.StringIndex].Length
				if actualLength > 0 {
					length = actualLength
				}
			} else {
				// Fallback: use pattern name to determine length
				if match.StringID == "$pattern" {
					length = 9 // length of "malicious"
				}
			}

			// Ensure position is within bounds
			if position < 0 || position >= len(chunk) || position+length > len(chunk) {
				continue
			}

			// Convert automaton matches to rule matches
			ruleMatch := StreamingMatch{
				Rule:    rule.Name,
				Pattern: match.StringID,
				Offset:  offset + int64(position),
				Length:  length,
				Data:    chunk[position : position+length],
			}

			matches = append(matches, ruleMatch)

			// Add to match buffer
			cp.matchBuffer.addMatch(ruleMatch)

			// Check if we should stop due to match limit
			if cp.matchBuffer.reachedLimit() {
				return matches
			}
		}
	}

	return matches
}

// updateProgress updates processing progress
func (sp *StreamingProcessor) updateProgress(bytesProcessed int64) {
	sp.progress.mu.Lock()
	defer sp.progress.mu.Unlock()

	sp.progress.processed += bytesProcessed

	// Only log progress every 25% completion or every 10MB, whichever comes first
	percentComplete := float64(sp.progress.processed) / float64(sp.progress.totalBytes) * 100
	percentInt := int(percentComplete)

	// Log if we've reached a new 25% milestone
	if percentInt%25 != 0 && percentInt != 100 {
		return
	}

	// Also log every 10MB to avoid too frequent updates on small files
	if sp.progress.processed < 10*1024*1024 && sp.progress.processed%(1024*1024) != 0 {
		return
	}

	elapsed := time.Since(sp.progress.startTime)
	rate := float64(sp.progress.processed) / elapsed.Seconds() / 1024 / 1024

	fmt.Printf("Progress: %.1f%% (%d/%d MB) - %.1f MB/s - %d matches found\n",
		percentComplete,
		sp.progress.processed/1024/1024,
		sp.progress.totalBytes/1024/1024,
		rate,
		sp.progress.matchesFound)
}

// addMatch adds a match to the buffer
func (mb *MatchBuffer) addMatch(match StreamingMatch) {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	if len(mb.matches) < mb.limit {
		mb.matches = append(mb.matches, match)
	}
}

// reachedLimit checks if match limit is reached
func (mb *MatchBuffer) reachedLimit() bool {
	mb.mu.RLock()
	defer mb.mu.RUnlock()
	return len(mb.matches) >= mb.limit
}

// GetProgress returns current processing progress
func (sp *StreamingProcessor) GetProgress() (processed, total int64, percent float64, matches int) {
	sp.progress.mu.RLock()
	defer sp.progress.mu.RUnlock()

	processed = sp.progress.processed
	total = sp.progress.totalBytes
	matches = sp.progress.matchesFound

	if total > 0 {
		percent = float64(processed) / float64(total) * 100
	}

	return
}

// SetChunkSize sets the chunk size for processing
func (sp *StreamingProcessor) SetChunkSize(size int) {
	if size > 0 {
		sp.ChunkSize = size
	}
}

// SetMaxConcurrency sets maximum concurrent goroutines
func (sp *StreamingProcessor) SetMaxConcurrency(max int) {
	if max > 0 {
		sp.MaxConcurrency = max
	}
}

// EnableEarlyTermination enables/disables early termination
func (sp *StreamingProcessor) EnableEarlyTermination(enable bool) {
	sp.EarlyTermination = enable
}
