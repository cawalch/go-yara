package fs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(path, []byte("sample"), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	for _, test := range []struct {
		name     string
		baseDir  string
		filename string
	}{
		{name: "relative", baseDir: dir, filename: "sample.txt"},
		{name: "absolute", filename: path},
	} {
		t.Run(test.name, func(t *testing.T) {
			content, err := ReadFile(test.baseDir, test.filename)
			if err != nil {
				t.Fatalf("ReadFile() error = %v", err)
			}
			if got := string(content); got != "sample" {
				t.Fatalf("ReadFile() = %q, want sample", got)
			}
		})
	}

	if _, err := ReadFile(dir, "missing.txt"); err == nil {
		t.Fatal("ReadFile() missing file error = nil")
	}
}

func TestReadFileString(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(path, []byte("sample"), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	content, err := ReadFileString(dir, "sample.txt")
	if err != nil {
		t.Fatalf("ReadFileString() error = %v", err)
	}
	if content != "sample" {
		t.Fatalf("ReadFileString() = %q, want sample", content)
	}
}
