// Package fs provides file system utilities for go-yara.
package fs

import (
	"fmt"
	"os"
	"path/filepath"
)

// ReadFile reads a file and returns its content
// If baseDir is provided, relative paths are resolved against it
func ReadFile(baseDir, filename string) ([]byte, error) {
	// Determine the full path
	var fullPath string
	switch {
	case filepath.IsAbs(filename):
		fullPath = filename
	case baseDir != "":
		fullPath = filepath.Join(baseDir, filename)
	default:
		fullPath = filename
	}

	// Read the file
	content, err := os.ReadFile(fullPath) // #nosec G304 - file reading is intentional
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", fullPath, err)
	}

	return content, nil
}

// ReadFileString reads a file and returns its content as a string
// If baseDir is provided, relative paths are resolved against it
func ReadFileString(baseDir, filename string) (string, error) {
	content, err := ReadFile(baseDir, filename)
	if err != nil {
		return "", err
	}
	return string(content), nil
}
