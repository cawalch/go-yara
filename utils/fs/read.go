// Package fs provides file system utilities for go-yara
package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReadFile reads a file and returns its content
// If baseDir is provided, relative paths are resolved against it
func ReadFile(baseDir, filename string) ([]byte, error) {
	// Determine the full path
	var fullPath string
	if filepath.IsAbs(filename) {
		fullPath = filename
	} else if baseDir != "" {
		fullPath = filepath.Join(baseDir, filename)
	} else {
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

// ValidatePath checks if a path is safe to access
// Prevents path traversal attacks by ensuring the resolved path is within baseDir
func ValidatePath(baseDir, filename string) (string, error) {
	// Clean the base directory
	cleanBaseDir := filepath.Clean(baseDir)

	// Determine the full path
	var fullPath string
	if filepath.IsAbs(filename) {
		fullPath = filepath.Clean(filename)
	} else {
		fullPath = filepath.Clean(filepath.Join(cleanBaseDir, filename))
	}

	// If baseDir is not empty, ensure the resolved path is within baseDir
	if cleanBaseDir != "" {
		rel, err := filepath.Rel(cleanBaseDir, fullPath)
		if err != nil {
			return "", fmt.Errorf("invalid path: %w", err)
		}

		// Check if the path tries to escape baseDir
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("path traversal detected: %s", filename)
		}
	}

	return fullPath, nil
}

// SafeReadFile reads a file with path validation
// Prevents path traversal attacks by validating the path is within baseDir
func SafeReadFile(baseDir, filename string) ([]byte, error) {
	// Validate the path first
	fullPath, err := ValidatePath(baseDir, filename)
	if err != nil {
		return nil, err
	}

	// Read the file
	content, err := os.ReadFile(fullPath) // #nosec G304 - path has been validated
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", fullPath, err)
	}

	return content, nil
}

// SafeReadFileString reads a file with path validation and returns content as string
func SafeReadFileString(baseDir, filename string) (string, error) {
	content, err := SafeReadFile(baseDir, filename)
	if err != nil {
		return "", err
	}
	return string(content), nil
}
