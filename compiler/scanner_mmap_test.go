package compiler

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cawalch/go-yara/utils/fs"
)

func TestScanFile_MmapLargeFile(t *testing.T) {
	ruleSource := `
rule LargeMmapMatch {
  strings:
    $start = "START_MMAP_TOKEN"
    $middle = "MID_MMAP_TOKEN"
    $end = "END_MMAP_TOKEN"
  condition:
    all of them
}`

	comp := NewCompiler()
	program, err := comp.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource error = %v", err)
	}

	// Create 256 KB file (>= fs.MinMmapFileSize)
	fileSize := 256 * 1024
	buf := bytes.Repeat([]byte("."), fileSize)

	copy(buf[100:], []byte("START_MMAP_TOKEN"))
	copy(buf[150000:], []byte("MID_MMAP_TOKEN"))
	copy(buf[fileSize-100:], []byte("END_MMAP_TOKEN"))

	dir := t.TempDir()
	path := filepath.Join(dir, "large_mmap.dat")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	scanner := program.NewScanner()
	defer scanner.Close()

	res, err := scanner.ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile error = %v", err)
	}

	if len(res.MatchedRules) != 1 || res.MatchedRules[0].Rule != "LargeMmapMatch" {
		t.Fatalf("MatchedRules = %+v, want LargeMmapMatch", res.MatchedRules)
	}

	// Verify matches on program.ScanFile as well
	resProg, err := program.ScanFile(path)
	if err != nil {
		t.Fatalf("program.ScanFile error = %v", err)
	}
	if len(resProg.MatchedRules) != 1 || resProg.MatchedRules[0].Rule != "LargeMmapMatch" {
		t.Fatalf("program MatchedRules = %+v, want LargeMmapMatch", resProg.MatchedRules)
	}
}

func TestScanFile_SmallFileFallback(t *testing.T) {
	ruleSource := `
rule SmallFile {
  strings:
    $a = "SMALL_TARGET"
  condition:
    $a
}`

	comp := NewCompiler()
	program, err := comp.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource error = %v", err)
	}

	// 1 KB file (< 128 KB MinMmapFileSize)
	content := append([]byte("preamble_"), []byte("SMALL_TARGET")...)
	content = append(content, bytes.Repeat([]byte("x"), 1000)...)

	dir := t.TempDir()
	path := filepath.Join(dir, "small.dat")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	scanner := program.NewScanner()
	defer scanner.Close()

	res, err := scanner.ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile error = %v", err)
	}
	if len(res.MatchedRules) != 1 || res.MatchedRules[0].Rule != "SmallFile" {
		t.Fatalf("MatchedRules = %+v, want SmallFile", res.MatchedRules)
	}
}

func TestScanFile_EmptyFile(t *testing.T) {
	ruleSource := `
rule EmptyRule {
  strings:
    $a = "NON_EXISTENT"
  condition:
    filesize == 0
}`

	comp := NewCompiler()
	program, err := comp.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource error = %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "empty.dat")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	scanner := program.NewScanner()
	defer scanner.Close()

	res, err := scanner.ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile error = %v", err)
	}
	if len(res.MatchedRules) != 1 || res.MatchedRules[0].Rule != "EmptyRule" {
		t.Fatalf("MatchedRules = %+v, want EmptyRule", res.MatchedRules)
	}
}

func TestScanFile_NonExistentFile(t *testing.T) {
	comp := NewCompiler()
	program, err := comp.CompileSource(`rule R { condition: true }`)
	if err != nil {
		t.Fatalf("CompileSource error = %v", err)
	}

	scanner := program.NewScanner()
	defer scanner.Close()

	missing := filepath.Join(t.TempDir(), "nonexistent.bin")
	_, err = scanner.ScanFile(missing)
	if err == nil {
		t.Fatal("expected error scanning nonexistent file, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) && !os.IsNotExist(err) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestScanFile_ContextCancellation(t *testing.T) {
	comp := NewCompiler()
	program, err := comp.CompileSource(`rule R { condition: true }`)
	if err != nil {
		t.Fatalf("CompileSource error = %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "large.dat")
	if err := os.WriteFile(path, make([]byte, fs.MinMmapFileSize*2), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before call

	scanner := program.NewScanner()
	defer scanner.Close()

	_, err = scanner.ScanFileWithContext(ctx, path)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestScanFile_ConcurrentMmapScans(t *testing.T) {
	ruleSource := `
rule ConcurrentMmap {
  strings:
    $tok = "SHARED_CONCURRENT_DATA"
  condition:
    $tok
}`
	comp := NewCompiler()
	program, err := comp.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource error = %v", err)
	}

	fileSize := 300 * 1024
	buf := bytes.Repeat([]byte("A"), fileSize)
	copy(buf[150000:], []byte("SHARED_CONCURRENT_DATA"))

	dir := t.TempDir()
	path := filepath.Join(dir, "concurrent_target.dat")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 10)

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := program.NewScanner()
			defer s.Close()

			res, scanErr := s.ScanFile(path)
			if scanErr != nil {
				errCh <- scanErr
				return
			}
			if len(res.MatchedRules) != 1 || res.MatchedRules[0].Rule != "ConcurrentMmap" {
				errCh <- errors.New("rule mismatch in concurrent scan")
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for scanErr := range errCh {
		t.Errorf("concurrent scan error: %v", scanErr)
	}
}

func TestScanFile_StringMatchesWithMmapEvidence(t *testing.T) {
	ruleSource := `
rule MmapEvidence {
  strings:
    $a = "TARGET_EVIDENCE_PATTERN"
  condition:
    $a
}`
	comp := NewCompiler()
	program, err := comp.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource error = %v", err)
	}

	fileSize := 200 * 1024
	buf := bytes.Repeat([]byte("."), fileSize)
	offset := 145000
	copy(buf[offset:], []byte("TARGET_EVIDENCE_PATTERN"))

	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.dat")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	scanner := program.NewScanner(WithMatchData(64))
	defer scanner.Close()

	res, err := scanner.ScanFile(path)
	if err != nil {
		t.Fatalf("ScanFile error = %v", err)
	}
	if len(res.MatchedRules) != 1 {
		t.Fatalf("want 1 matched rule, got %d", len(res.MatchedRules))
	}
	matches := res.MatchedRules[0].Matches["$a"]
	if len(matches) != 1 {
		t.Fatalf("want 1 match for $a, got %d", len(matches))
	}
	if int(matches[0].Offset) != offset {
		t.Fatalf("offset = %d, want %d", matches[0].Offset, offset)
	}
}

func TestScanFile_DeadlineExceeded(t *testing.T) {
	ruleSource := `
rule SlowRegex {
  strings:
    $re = /a.*b.*c.*d.*e/
  condition:
    $re
}`
	comp := NewCompiler()
	program, err := comp.CompileSource(ruleSource)
	if err != nil {
		t.Fatalf("CompileSource error = %v", err)
	}

	buf := bytes.Repeat([]byte("a"), 200*1024)
	dir := t.TempDir()
	path := filepath.Join(dir, "timeout.dat")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // Ensure deadline has passed

	scanner := program.NewScanner()
	defer scanner.Close()

	_, err = scanner.ScanFileWithContext(ctx, path)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context timeout error, got %v", err)
	}
}
