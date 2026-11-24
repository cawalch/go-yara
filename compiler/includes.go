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

const maxIncludeDepth = 64

// processIncludesWithBaseDirContext processes includes with a specific base directory and context support
func (c *Compiler) processIncludesWithBaseDirContext(ctx context.Context, program *ast.Program, baseDir string) error {
	if program == nil || len(program.Includes) == 0 {
		return nil
	}
	absRootBase, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("failed to resolve base directory: %w", err)
	}
	absRootBase, err = filepath.EvalSymlinks(filepath.Clean(absRootBase))
	if err != nil {
		return fmt.Errorf("failed to resolve include base directory: %w", err)
	}
	traversal := includeTraversal{
		compiler:      c,
		ctx:           ctx,
		rootBaseDir:   absRootBase,
		activePaths:   make(map[string]struct{}),
		includedPaths: make(map[string]struct{}),
	}
	return traversal.processTree(program, absRootBase, 0)
}

type includeTraversal struct {
	compiler      *Compiler
	ctx           context.Context
	rootBaseDir   string
	activePaths   map[string]struct{}
	includedPaths map[string]struct{}
}

func (traversal *includeTraversal) processTree(program *ast.Program, baseDir string, depth int) error {
	if depth > maxIncludeDepth {
		return fmt.Errorf("include nesting depth exceeds maximum (%d)", maxIncludeDepth)
	}
	var includedRules []*ast.Rule
	var includedImports []*ast.Import
	for _, include := range program.Includes {
		select {
		case <-traversal.ctx.Done():
			return traversal.ctx.Err()
		default:
		}

		rules, imports, err := traversal.processInclude(baseDir, include, depth)
		if err != nil {
			return err
		}
		includedRules = append(includedRules, rules...)
		includedImports = append(includedImports, imports...)
	}
	if len(includedRules) > 0 {
		program.Rules = append(includedRules, program.Rules...)
	}
	if len(includedImports) > 0 {
		program.Imports = append(includedImports, program.Imports...)
	}

	return nil
}

//nolint:revive // argument-limit: internal traversal helper tracks baseDir and depth
func (traversal *includeTraversal) processInclude(baseDir string, include *ast.Include, depth int) ([]*ast.Rule, []*ast.Import, error) {
	cleanIncludePath := filepath.Clean(filepath.Join(baseDir, include.File))

	absIncludePath, err := filepath.Abs(cleanIncludePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve include path: %w", err)
	}
	absIncludePath, err = filepath.EvalSymlinks(filepath.Clean(absIncludePath))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read include file %s: %w", include.File, err)
	}

	if !pathWithinBase(traversal.rootBaseDir, absIncludePath) {
		return nil, nil, fmt.Errorf("failed to read include file %s: path traversal detected", include.File)
	}
	if _, exists := traversal.activePaths[absIncludePath]; exists {
		return nil, nil, fmt.Errorf("circular include detected: %s", include.File)
	}
	if _, alreadyIncluded := traversal.includedPaths[absIncludePath]; alreadyIncluded {
		return nil, nil, nil
	}
	traversal.activePaths[absIncludePath] = struct{}{}
	defer delete(traversal.activePaths, absIncludePath)

	includedContent, err := readFileWithLimit(absIncludePath, traversal.compiler.options.MaxIncludeSize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read include file %s: %w", include.File, err)
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
		partialErr, ok := errors.AsType[*parser.PartialParseError](parseErr)
		if !traversal.compiler.options.IgnoreInvalidRules ||
			!ok ||
			len(includedParser.ProgramErrors()) != 0 {
			return nil, nil, fmt.Errorf("failed to parse include file %s: %w", include.File, parseErr)
		}
		includedProgram = partialErr.Program
		for _, invalid := range includedParser.InvalidRules() {
			traversal.compiler.recordParseInvalidRule(invalid)
		}
	}
	if len(includedParser.Errors()) > 0 && !traversal.compiler.options.IgnoreInvalidRules {
		return nil, nil, fmt.Errorf("parser errors in include file %s: %v", include.File, includedParser.Errors())
	}

	if len(includedProgram.Includes) > 0 {
		if err := traversal.processTree(includedProgram, filepath.Dir(absIncludePath), depth+1); err != nil {
			return nil, nil, fmt.Errorf("failed to process includes in %s: %w", include.File, err)
		}
	}

	traversal.includedPaths[absIncludePath] = struct{}{}
	return includedProgram.Rules, includedProgram.Imports, nil
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
