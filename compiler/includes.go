package compiler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/lexer"
	"github.com/cawalch/go-yara/parser"
)

// processIncludesWithContext processes include statements in the YARA rules with context support
func (c *Compiler) processIncludesWithContext(ctx context.Context, program *ast.Program) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return c.processIncludesWithBaseDirContext(ctx, program, c.baseDir)
}

// processIncludesWithBaseDir processes includes with a specific base directory
func (c *Compiler) processIncludesWithBaseDir(program *ast.Program, baseDir string) error {
	return c.processIncludesWithBaseDirContext(context.Background(), program, baseDir)
}

// processIncludesWithBaseDirContext processes includes with a specific base directory and context support
func (c *Compiler) processIncludesWithBaseDirContext(ctx context.Context, program *ast.Program, baseDir string) error {
	traversal := includeTraversal{
		compiler:    c,
		ctx:         ctx,
		activePaths: make(map[string]struct{}),
	}
	return traversal.processTree(program, baseDir)
}

type includeTraversal struct {
	compiler    *Compiler
	ctx         context.Context
	activePaths map[string]struct{}
}

func (traversal *includeTraversal) processTree(program *ast.Program, baseDir string) error {
	for _, include := range program.Includes {
		select {
		case <-traversal.ctx.Done():
			return traversal.ctx.Err()
		default:
		}

		if err := traversal.processInclude(program, baseDir, include); err != nil {
			return err
		}
	}

	return nil
}

func (traversal *includeTraversal) processInclude(program *ast.Program, baseDir string, include *ast.Include) error {
	cleanIncludePath := filepath.Clean(filepath.Join(baseDir, include.File))

	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("failed to resolve base directory: %w", err)
	}
	absBaseDir, err = filepath.EvalSymlinks(filepath.Clean(absBaseDir))
	if err != nil {
		return fmt.Errorf("failed to resolve include base directory: %w", err)
	}

	absIncludePath, err := filepath.Abs(cleanIncludePath)
	if err != nil {
		return fmt.Errorf("failed to resolve include path: %w", err)
	}
	absIncludePath, err = filepath.EvalSymlinks(filepath.Clean(absIncludePath))
	if err != nil {
		return fmt.Errorf("failed to read include file %s: %w", include.File, err)
	}

	if !pathWithinBase(absBaseDir, absIncludePath) {
		return fmt.Errorf("failed to read include file %s: path traversal detected", include.File)
	}
	if _, exists := traversal.activePaths[absIncludePath]; exists {
		return fmt.Errorf("circular include detected: %s", include.File)
	}
	traversal.activePaths[absIncludePath] = struct{}{}
	defer delete(traversal.activePaths, absIncludePath)

	includedContent, err := readFileWithLimit(absIncludePath, traversal.compiler.options.MaxIncludeSize)
	if err != nil {
		return fmt.Errorf("failed to read include file %s: %w", include.File, err)
	}

	includedLexer := lexer.New(string(includedContent))
	includedParser := parser.NewWithOptions(includedLexer, parser.Options{
		MaxRecursionDepth: traversal.compiler.options.MaxRecursionDepth,
	})
	if traversal.compiler.options.IgnoreInvalidRules {
		includedParser.SetErrorRecovery(true)
		includedParser.SetSkipInvalidRules(true)
	}
	includedProgram, parseErr := includedParser.ParseRulesWithContext(traversal.ctx)
	if parseErr != nil {
		var partialErr *parser.PartialParseError
		if !traversal.compiler.options.IgnoreInvalidRules ||
			!errors.As(parseErr, &partialErr) ||
			len(includedParser.ProgramErrors()) != 0 {
			return fmt.Errorf("failed to parse include file %s: %w", include.File, parseErr)
		}
		includedProgram = partialErr.Program
		for _, invalid := range includedParser.InvalidRules() {
			traversal.compiler.recordParseInvalidRule(invalid)
		}
	}
	if len(includedParser.Errors()) > 0 && !traversal.compiler.options.IgnoreInvalidRules {
		return fmt.Errorf("parser errors in include file %s: %v", include.File, includedParser.Errors())
	}

	if len(includedProgram.Includes) > 0 {
		if err := traversal.processTree(includedProgram, filepath.Dir(absIncludePath)); err != nil {
			return fmt.Errorf("failed to process includes in %s: %w", include.File, err)
		}
	}

	program.Rules = append(program.Rules, includedProgram.Rules...)
	program.Imports = append(program.Imports, includedProgram.Imports...)
	return nil
}

// ProcessIncludes is a public wrapper for processIncludesWithBaseDir
func (c *Compiler) ProcessIncludes(program *ast.Program) error {
	return c.processIncludesWithBaseDir(program, c.baseDir)
}

// processImportsWithContext processes import statements with context support
func (c *Compiler) processImportsWithContext(ctx context.Context, program *ast.Program) error {
	if len(program.Imports) == 0 {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	for _, importStmt := range program.Imports {
		if _, supported := c.options.Modules[importStmt.Module]; supported {
			continue
		}
		message := "unsupported module: " + importStmt.Module
		c.stats.Errors = append(c.stats.Errors, CompilationError{
			Phase:   "imports",
			Message: message,
			Line:    importStmt.Pos.Line,
			Column:  importStmt.Pos.Column,
		})
		return errors.New(message)
	}
	return nil
}

func resolveFilePath(baseDir, filename string) (string, error) {
	resolved := filename
	if !filepath.IsAbs(resolved) && baseDir != "" {
		resolved = filepath.Join(baseDir, resolved)
	}
	return filepath.Abs(resolved)
}

func pathWithinBase(baseDir, filename string) bool {
	relative, err := filepath.Rel(baseDir, filename)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func readFileWithLimit(filename string, limit int64) ([]byte, error) {
	file, err := os.Open(filename) // #nosec G304 - callers intentionally select compiler inputs
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	if limit > 0 {
		info, statErr := file.Stat()
		if statErr != nil {
			return nil, statErr
		}
		if info.Mode().IsRegular() && info.Size() > limit {
			return nil, fmt.Errorf("file size %d bytes exceeds maximum allowed %d bytes", info.Size(), limit)
		}
	}

	reader := io.Reader(file)
	if limit > 0 {
		readLimit := limit
		if readLimit < math.MaxInt64 {
			readLimit++
		}
		reader = io.LimitReader(file, readLimit)
	}
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if limit > 0 && int64(len(content)) > limit {
		return nil, fmt.Errorf("file size exceeds maximum allowed %d bytes", limit)
	}
	return content, nil
}
