# go-yara Implementation Guidelines

## Core Principles

### 1. Data-Driven Development
- **Benchmark First**: Create benchmarks before optimization
- **Measure Everything**: Profile before and after changes
- **Reject Unproven Optimizations**: If benchmarks don't show improvement, remove it
- **Document Results**: Keep benchmark results and analysis

### 2. Idiomatic Go
- Follow Go 1.24+ conventions
- Use interfaces for abstraction
- Prefer composition over inheritance
- Keep functions small and focused
- Use error returns, not panics

### 3. Error Handling
- Use error tokens in lexer (already implemented)
- Structured error recovery in parser
- Detailed error messages with position info
- Graceful degradation on errors

### 4. Performance
- Zero-allocation fast paths where possible
- Memory pooling for frequently allocated objects
- String interning for common tokens
- Avoid unnecessary allocations
- Profile regularly

### 5. Testing
- Test-driven development (write tests first)
- Unit tests for all components
- Integration tests for end-to-end flows
- Benchmark tests for performance-critical code
- Use libyara test suite as reference

## Code Organization

### Package Structure
```
ast/          - AST node definitions
parser/       - Parser implementation
semantic/     - Semantic analysis
compiler/     - Code generation
executor/     - Execution engine
lsp/          - LSP server
```

### File Naming
- `types.go` - Type definitions
- `*_test.go` - Tests
- `*_bench_test.go` - Benchmarks
- `example_test.go` - Example tests

## Implementation Checklist

### For Each Phase
- [ ] Design document (architecture, data structures)
- [ ] Type definitions (interfaces, structs)
- [ ] Core implementation
- [ ] Error handling
- [ ] Tests (unit + integration)
- [ ] Benchmarks
- [ ] Documentation
- [ ] Code review

### For Each Component
- [ ] Clear responsibility
- [ ] Minimal dependencies
- [ ] Comprehensive error handling
- [ ] Performance considerations
- [ ] Test coverage > 80%

## Testing Guidelines

### Unit Tests
```go
func TestComponentFeature(t *testing.T) {
    // Arrange
    input := setupTestData()
    
    // Act
    result := component.Method(input)
    
    // Assert
    if result != expected {
        t.Errorf("got %v, want %v", result, expected)
    }
}
```

### Benchmark Tests
```go
func BenchmarkComponentFeature(b *testing.B) {
    input := setupTestData()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        component.Method(input)
    }
}
```

### Integration Tests
- Test with real YARA rules
- Use libyara test suite
- Compare results with libyara
- Test error cases

## Performance Guidelines

### Profiling
```bash
# CPU profiling
go test -cpuprofile=cpu.prof -bench=. ./...
go tool pprof cpu.prof

# Memory profiling
go test -memprofile=mem.prof -bench=. ./...
go tool pprof mem.prof

# Allocation tracking
go test -benchmem -bench=. ./...
```

### Optimization Process
1. Establish baseline with benchmarks
2. Profile to identify hot paths
3. Implement optimization
4. Benchmark to verify improvement
5. Document results
6. If no improvement, revert

### Memory Optimization
- Reduce allocations (target: 1-2 per operation)
- Use sync.Pool for frequently allocated objects
- Pre-allocate slices with known capacity
- Avoid string concatenation in loops
- Use []byte instead of string where possible

## Error Handling Patterns

### Lexer (Already Implemented)
```go
// Collect errors, emit ILLEGAL tokens
l.addError(pos, "error message")
return l.makeToken(token.ILLEGAL, text, pos)
```

### Parser
```go
// Synchronize on errors
if err := p.parseRule(); err != nil {
    p.addError(err)
    p.synchronize()
}
```

### Semantic Analysis
```go
// Collect diagnostics
d := &Diagnostic{
    Level:    Error,
    Message:  "type mismatch",
    Position: pos,
}
v.diagnostics = append(v.diagnostics, d)
```

## Documentation Standards

### Package Documentation
```go
// Package parser implements a recursive descent parser for YARA rules.
// It consumes tokens from the lexer and builds an Abstract Syntax Tree (AST).
package parser
```

### Function Documentation
```go
// ParseRule parses a single YARA rule from the token stream.
// It returns an error if the rule is malformed.
func (p *Parser) ParseRule() (*ast.Rule, error) {
```

### Type Documentation
```go
// Rule represents a YARA rule with metadata, strings, and conditions.
type Rule struct {
    Name      string
    Modifiers []Modifier
    Meta      []Meta
    Strings   []String
    Condition Expression
}
```

## Code Review Checklist

- [ ] Follows Go conventions
- [ ] Error handling is comprehensive
- [ ] Tests are included and passing
- [ ] Benchmarks show no regression
- [ ] Documentation is clear
- [ ] No unnecessary allocations
- [ ] Performance is acceptable
- [ ] Code is readable and maintainable

## Common Pitfalls to Avoid

1. **Premature Optimization**: Profile first, optimize second
2. **Ignoring Errors**: Always handle errors explicitly
3. **Allocating in Loops**: Pre-allocate or use pooling
4. **String Concatenation**: Use strings.Builder
5. **Goroutine Leaks**: Always clean up goroutines
6. **Unbounded Allocations**: Set limits on collections
7. **Panic on Errors**: Use error returns instead

## Integration with Existing Code

### Lexer Integration
- Use `lexer.New()` to create lexer
- Call `NextToken()` in loop
- Check `lexer.Errors()` for error collection
- Use `token.Position` for diagnostics

### Token Types
- All token types defined in `token/token.go`
- Use `token.TokenType` for type checking
- Position info in `token.Position`

## Performance Targets

- **Lexer**: 125-170 MB/s (already achieved)
- **Parser**: Target 50+ MB/s
- **Compiler**: Target 20+ MB/s
- **Executor**: Target 10+ MB/s
- **Overall**: Match or exceed libyara

## Continuous Integration

### Before Committing
```bash
# Run tests
go test ./...

# Run benchmarks
go test -bench=. -benchmem ./...

# Check coverage
go test -cover ./...

# Lint
golangci-lint run ./...

# Format
go fmt ./...
```

### Performance Regression
- Maintain benchmark baselines
- Compare new benchmarks with baselines
- Alert on significant regressions (>10%)
- Document performance changes

