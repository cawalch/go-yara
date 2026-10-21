package fs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestMapFile_RegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.dat")
	content := bytes.Repeat([]byte("MemoryMappedTest12345!\n"), 1000)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	data, cleanup, err := MapFile(path)
	if err != nil {
		t.Fatalf("MapFile failed: %v", err)
	}
	defer cleanup()

	if !bytes.Equal(data, content) {
		t.Fatalf("mapped content mismatch: got %d bytes, want %d bytes", len(data), len(content))
	}

	// Test cleanup idempotency
	cleanup()
	cleanup()
}

func TestMapFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.dat")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	data, cleanup, err := MapFile(path)
	if err != nil {
		t.Fatalf("MapFile failed on empty file: %v", err)
	}
	defer cleanup()

	if len(data) != 0 {
		t.Fatalf("expected empty data, got %d bytes", len(data))
	}
	cleanup()
}

func TestMapFile_NonExistentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.dat")

	_, cleanup, err := MapFile(path)
	if err == nil {
		cleanup()
		t.Fatalf("expected error for nonexistent file, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) && !os.IsNotExist(err) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestMapFile_Directory(t *testing.T) {
	dir := t.TempDir()

	_, cleanup, err := MapFile(dir)
	if err == nil {
		cleanup()
		t.Fatalf("expected error mapping directory, got nil")
	}
}

func TestMapFile_LargeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.dat")
	// 512 KB
	content := make([]byte, 512*1024)
	for i := range content {
		content[i] = byte(i % 251)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	data, cleanup, err := MapFile(path)
	if err != nil {
		t.Fatalf("MapFile failed: %v", err)
	}
	defer cleanup()

	if len(data) != len(content) {
		t.Fatalf("size mismatch: got %d, want %d", len(data), len(content))
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("content mismatch for large file")
	}
}

func TestMapFile_Concurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "concurrent.dat")
	content := bytes.Repeat([]byte("ConcurrentAccessData0123456789"), 500)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, cleanup, err := MapFile(path)
			if err != nil {
				t.Errorf("concurrent MapFile failed: %v", err)
				return
			}
			defer cleanup()

			if !bytes.Equal(data, content) {
				t.Errorf("concurrent data mismatch")
			}
		}()
	}
	wg.Wait()
}
