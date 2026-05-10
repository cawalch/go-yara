# Compiler Package

This package implements the bytecode interpreter for YARA rules. It provides a stack-based virtual machine architecture for efficient pattern matching and rule execution.

## Architecture

The interpreter uses a bytecode format based on libyara's instruction set, providing:

- Stack-based execution model
- Direct function table dispatch for optimal performance
- Support for all YARA rule features including strings, regular expressions, and complex conditions

## Performance Optimization

The interpreter has been optimized with a direct function table dispatch system:

### Before (Nested Switch Chain)
```go
executeMainLoop()
  → executeOpcode(opcode)        // Level 1: switch on ~15 opcode groups
    → executeStringOperation()   // Level 2: switch on ~20 string opcodes
      → executeFoundOperation()  // Level 3: actual handler
```

### After (Direct Function Table)
```go
executeMainLoop()
  → handler = opcodeTable[opcode]  // O(1) direct lookup
  → handler(i)  // Direct function call
```

This optimization eliminates the overhead of multiple switch comparisons for every instruction, providing:
- O(1) dispatch instead of O(log n) or worse
- Better branch prediction
- Reduced code size (~100+ lines eliminated)
- Cleaner handler functions (each handles exactly one opcode)

## Key Components

- **Interpreter**: Main execution engine
- **Bytecode**: Compiled YARA rules
- **Opcode**: Instruction set
- **MatchContext**: Pattern matching state
- **CompiledRule**: Pre-compiled rule representations

## Usage

```go
// Compile a YARA rule
rule, err := ParseRule(ruleString)
if err != nil {
    // handle error
}

// Compile to bytecode
compiledRule, err := CompileRule(rule)
if err != nil {
    // handle error
}

// Execute with data
interpreter := NewInterpreter(compiledRule.Bytecode)
result, err := interpreter.Execute()
if err != nil {
    // handle error
}
```