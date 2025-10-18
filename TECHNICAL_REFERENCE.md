# go-yara Technical Reference

## Lexer (Complete)

### Location
- `internal/lexer/` - Main lexer implementation
- `token/token.go` - Token type definitions

### Key Components
- **Lexer**: Main tokenization engine with error recovery
- **Reader**: Character reading with position tracking
- **Scanners**: Specialized scanners for strings, hex, identifiers, numbers
- **Error Recovery**: Two modes (Basic, Section) for error synchronization
- **Pooling**: Memory pooling and string interning for performance

### Performance
- 47-203x faster than C YARA compiler
- 125-170 MB/s throughput
- 80-144 bytes per operation
- 1-2 allocations per operation

## Parser (Phase 2)

### Design Pattern
- Recursive descent parser
- Token stream consumption
- Error recovery with synchronization points
- Position tracking for diagnostics

### Grammar Structure (from libyara reference)
```
rules → (rule | import | include)*
rule → modifiers RULE identifier tags meta strings condition
meta → META: (key = value)*
strings → STRINGS: (identifier = pattern)*
condition → CONDITION: expression
```

### Key Challenges
- Operator precedence (logical, comparison, arithmetic, bitwise)
- String identifier wildcards ($a*, $a?)
- Quantifiers (all, any, none, for-in)
- Error recovery without losing context

## AST (Phase 1)

### Node Hierarchy
```
Node (interface)
├── Program
├── Rule
│   ├── Meta
│   ├── String
│   └── Condition
├── Expression
│   ├── BinaryOp
│   ├── UnaryOp
│   ├── FunctionCall
│   ├── StringRef
│   └── Literal
└── Pattern
    ├── TextString
    ├── HexString
    └── RegexPattern
```

### Visitor Pattern
- Visitor interface for AST traversal
- Accept methods on all nodes
- Concrete visitors for analysis, code generation

## Semantic Analysis (Phase 3)

### Symbol Table
- Rule definitions
- String definitions
- Variable scoping
- Import resolution

### Type System
- Integer (8, 16, 32 bit, signed/unsigned, big-endian)
- String
- Boolean
- Array
- Type inference and checking

### Validation
- Rule structure validation
- String reference validation
- Condition type checking
- Module function validation

## Code Generation (Phase 4)

### Bytecode Format (from libyara)
- Instruction set: ~50 opcodes
- Operand types: immediate, relative, absolute
- Arena-based memory allocation
- Relocation support for references

### Key Components
- **Bytecode Emitter**: Instruction emission and encoding
- **String Compilation**: Pattern encoding and optimization
- **Aho-Corasick**: Multi-pattern matching automaton
- **Rule Compilation**: Combine strings and conditions

### Instruction Categories
- Stack operations (PUSH, POP)
- Arithmetic (ADD, SUB, MUL, DIV, MOD)
- Comparison (EQ, NEQ, LT, LE, GT, GE)
- Logical (AND, OR, NOT)
- String operations (MATCH, CONTAINS, etc.)
- Control flow (JMP, JZ, CALL)

## Execution Engine (Phase 5)

### Stack Machine Architecture
- Value stack for operands
- Call stack for function calls
- Instruction pointer for control flow
- State for pattern matching

### Pattern Matching
- Aho-Corasick automaton execution
- String matching with modifiers (nocase, wide, ascii)
- Position tracking for @ operator
- Match collection and filtering

### String Operations
- contains, icontains
- startswith, istartswith
- endswith, iendswith
- matches (regex)
- iequals

### Data Type Functions
- int8, int16, int32 (signed)
- uint8, uint16, uint32 (unsigned)
- Big-endian variants (int8be, etc.)

## Performance Optimization (Phase 6)

### Profiling Tools
- CPU profiling (pprof)
- Memory profiling (pprof)
- Allocation tracking
- Benchmark suite

### Optimization Targets
- Hot paths in lexer (already optimized)
- Parser token consumption
- Pattern matching performance
- Memory allocation reduction

### Benchmarking
- Lexer: 125-170 MB/s
- Parser: TBD
- Compiler: TBD
- Execution: TBD
- Comparison with libyara

## LSP Integration (Phase 7)

### Protocol Implementation
- JSON-RPC 2.0 over stdio
- Document synchronization
- Incremental updates

### Features
- **Diagnostics**: Errors, warnings, suggestions
- **Hover**: Symbol info, type info, documentation
- **Completion**: Keywords, identifiers, functions
- **Go-to-Definition**: Cross-file navigation
- **Find References**: Usage tracking
- **Syntax Highlighting**: Semantic tokens

## Testing Strategy

### Unit Tests
- Lexer: Token correctness, error recovery
- Parser: Grammar coverage, error handling
- Semantic: Type checking, validation
- Code Gen: Bytecode correctness
- Execution: Pattern matching, operations

### Integration Tests
- End-to-end compilation
- Real YARA rules from libyara test suite
- Performance benchmarks
- LSP protocol compliance

### Test Data
- libyara test suite (`yara/tests/`)
- Fuzzer corpus
- Real-world YARA rules

## Dependencies

### Current
- Go 1.24+ standard library only
- libyara submodule (reference only)

### Future
- LSP library (if needed)
- Benchmarking tools (built-in)

## File Organization

```
go-yara/
├── ast/                    # Phase 1: AST nodes
├── parser/                 # Phase 2: Parser
├── semantic/               # Phase 3: Semantic analysis
├── compiler/               # Phase 4: Code generation
├── executor/               # Phase 5: Execution engine
├── internal/lexer/         # Lexer (complete)
├── token/                  # Token types
├── lsp/                    # Phase 7: LSP server
├── benchmarks/             # Phase 6: Benchmarks
├── examples/               # Example YARA rules
├── yara/                   # libyara reference
└── cmd/                    # CLI tools
```

## References

- YARA Documentation: https://yara.readthedocs.io/
- libyara Source: `/Users/cawalch/go-yara/yara/libyara/`
- LSP Specification: https://microsoft.github.io/language-server-protocol/
- Go Performance: https://golang.org/doc/effective_go

