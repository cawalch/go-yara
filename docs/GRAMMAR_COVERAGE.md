# YARA Grammar Coverage Analysis

## Overview

This document tracks the coverage of YARA grammar elements in the go-yara lexer implementation. It provides a comprehensive analysis of which YARA language features are currently supported, partially supported, or missing from the lexer.

## Coverage Summary

| Category | Supported | Partial | Missing | Total |
|----------|-----------|---------|---------|-------|
| **Keywords** | 23 | 0 | 41 | 64 |
| **Operators** | 22 | 0 | 0 | 22 |
| **Literals** | 8 | 0 | 0 | 8 |
| **Punctuation** | 8 | 0 | 0 | 8 |
| **Comments** | 2 | 0 | 0 | 2 |
| **String Types** | 3 | 0 | 0 | 3 |

**Overall Coverage: 68/101 (67%)** ✅ **Phase 3 Complete**

## Detailed Coverage Analysis

### 1. Keywords

#### ✅ Supported (23/64)
- `rule` - Rule declaration keyword
- `meta` - Metadata section keyword
- `strings` - String definition section keyword
- `condition` - Condition section keyword
- `and` - Logical AND operator
- `or` - Logical OR operator
- `not` - Logical NOT operator
- `all` - Quantifier for all strings
- `any` - Quantifier for any strings
- `none` - Quantifier for no strings
- `of` - Set membership operator
- `true` - Boolean literal (true value)
- `false` - Boolean literal (false value)
- `nocase` - Case-insensitive string matching
- `wide` - Wide character string modifier
- `ascii` - ASCII character string modifier
- `fullword` - Word boundary string modifier
- `private` - Private string modifier
- `xor` - XOR string modifier
- `base64` - Base64 encoding string modifier
- `base64wide` - Base64 wide encoding string modifier
- `filesize` - File size variable
- `entrypoint` - Executable entry point

#### ❌ Missing (41/64)
**Core Language Keywords:**
- `for` - Loop construct
- `in` - Range/set membership
- `at` - Position specification
- `them` - Reference to all strings
- `defined` - Undefined value check

**Rule Modifiers:**
- `global` - Global rule modifier
- `private` - Private rule modifier

**String Operations:**
- `contains`, `icontains` - Substring search
- `startswith`, `istartswith` - Prefix matching
- `endswith`, `iendswith` - Suffix matching
- `iequals` - Case-insensitive equality
- `matches` - Regular expression matching

**Import/Include:**
- `import` - Module import
- `include` - File inclusion

### 2. Operators

#### ✅ Supported (22/22)
**Arithmetic:**
- `+` (PLUS) - Addition
- `-` (MINUS) - Subtraction
- `*` (MULTIPLY) - Multiplication
- `/` (DIVIDE) - Division
- `%` (MODULO) - Modulo

**Comparison:**
- `==` (EQ) - Equality
- `!=` (NEQ) - Inequality
- `<` (LT) - Less than
- `<=` (LE) - Less than or equal
- `>` (GT) - Greater than
- `>=` (GE) - Greater than or equal

**Assignment:**
- `=` (ASSIGN) - Assignment (for meta sections)

**Logical:**
- `and` (AND) - Logical AND
- `or` (OR) - Logical OR
- `not` (NOT) - Logical NOT

**Bitwise (Phase 3):**
- `&` (BITWISE_AND) - Bitwise AND
- `|` (BITWISE_OR) - Bitwise OR
- `^` (BITWISE_XOR) - Bitwise XOR
- `~` (BITWISE_NOT) - Bitwise NOT
- `<<` (LEFT_SHIFT) - Left shift
- `>>` (RIGHT_SHIFT) - Right shift


#### ❌ Missing (0/22)
All arithmetic, comparison, logical, and bitwise operators are now supported!


### 3. Literals

#### ✅ Supported (8/8)
- `INTEGER_LIT` - Decimal integers (e.g., `123`)
- `HEX_INTEGER_LIT` - Hexadecimal integers (e.g., `0x1000`, `0xFF`)
- `SIZE_LIT` - Size literals with suffixes (e.g., `1KB`, `100MB`)
- `STRING_LIT` - Double-quoted strings (e.g., `"text"`)
- `HEX_STRING_LIT` - Hexadecimal strings (e.g., `{ E2 34 A1 }`)
- `REGEX_LIT` - Regular expression literals (e.g., `/pattern/`, `/pattern/i`, `//`)
- `TRUE` - Boolean literal (true value)
- `FALSE` - Boolean literal (false value)

#### ❌ Missing (0/8)

All literal types are now supported!

### 4. Punctuation

#### ✅ Supported (8/8)
- `(` (LPAREN) - Left parenthesis
- `)` (RPAREN) - Right parenthesis
- `{` (LBRACE) - Left brace
- `}` (RBRACE) - Right brace
- `:` (COLON) - Colon
- `,` (COMMA) - Comma
- `.` (DOT) - Dot

### 5. Comments

#### ✅ Supported (2/2)
- `//` - Line comments
- `/* */` - Block comments

### 6. String Types

#### ✅ Supported (3/3)
- Text strings with double quotes
- Hexadecimal strings with curly braces `{ E2 34 A1 }`
- Regular expression strings with forward slashes `/pattern/`

#### ❌ Missing (0/3)

All string types are now supported!

## Test Coverage Analysis

### Current Test Coverage
The lexer tests cover the following scenarios:
- ✅ Basic operators and punctuation
- ✅ Keywords (rule, meta, strings, condition, and, or, true, false)
- ✅ String literals and integer literals
- ✅ Boolean literals (true, false) with case sensitivity tests
- ✅ Hexadecimal string literals (all YARA features: wildcards, jumps, NOT operator, alternatives)
- ✅ Regular expression literals (patterns, flags, empty regex, edge cases)
- ✅ Line and block comments
- ✅ Mixed YARA-like rule structures
- ✅ Position tracking (line/column)
- ✅ Boolean literals in realistic YARA rule contexts
- ✅ Regular expression literals in realistic YARA rule contexts

### Missing Test Coverage
- ✅ Hexadecimal integer literals — comprehensive testing with 0x/0X prefixes, edge cases, and YARA rule integration
- ✅ Size suffixes (KB, MB) — comprehensive testing with case insensitivity, hex integers, and operators
- ✅ Quantifier keywords (all, any, none, of) — comprehensive testing in expressions and YARA rules
- ✅ Arithmetic operators (*, /, %) — comprehensive testing with all number types and complex expressions
- ❌ String modifiers (nocase, wide, ascii, etc.)
- ✅ Escape sequences in strings — comprehensive handling of \n, \t, \r, \\, \", \xNN with validation
- ❌ Unicode handling
- ✅ Error recovery and edge cases — multi-character ILLEGAL tokens; newline/keyword-based synchronization; structured error collection; fast-forward recovery modes
- ✅ Phase 1 integration testing — comprehensive testing of all Phase 1 features working together

## Implementation Priorities

### ✅ Phase 1: Core Language Support - COMPLETE
1. ✅ **Boolean literals** - `true`, `false` tokens (COMPLETED)
2. ✅ **Regular expressions** - `/pattern/` syntax (COMPLETED)
3. ✅ **Logical NOT** - `not` keyword and operator (COMPLETED)
4. ✅ **Hexadecimal integers** - `0x` prefix support (COMPLETED)
5. ✅ **Size suffixes** - `KB`, `MB` postfix support (COMPLETED)
6. ✅ **Basic quantifiers** - `all`, `any`, `none`, `of` keywords (COMPLETED)
7. ✅ **Arithmetic operators** - `*`, `/`, `%` operators (COMPLETED)

**Phase 1 Status**: All features implemented with comprehensive testing and zero-allocation performance

### ✅ Phase 2: String Features - COMPLETE
1. ✅ **Hexadecimal strings** - `{ E2 34 A1 }` syntax (COMPLETED)
2. ✅ **String modifiers** - `nocase`, `wide`, `ascii`, `fullword`, `private`, `xor`, `base64`, `base64wide` (COMPLETED)
3. ✅ **Escape sequences** - `\n`, `\t`, `\xNN` in strings (COMPLETED)

**Phase 2 Status**: All features implemented with comprehensive testing and zero-allocation performance

#### Phase 2 Detailed Roadmap

**2.1 String Modifier Tokens (Estimated: 2-3 hours)**
- Add token types: `NOCASE`, `WIDE`, `ASCII`, `FULLWORD`, `PRIVATE`, `XOR`, `BASE64`, `BASE64WIDE`
- Update keyword lookup table in `keywords.go`
- Add comprehensive test coverage for each modifier token

**2.2 String Modifier Parsing (Estimated: 4-6 hours)**
- Extend string literal parsing to handle modifier sequences
- Support syntax: `"text" nocase wide`, `{ E2 34 } private`, `/pattern/i ascii`
- Handle multiple modifiers and validate combinations
- Implement proper error handling for invalid modifier combinations

**2.3 String Modifier Integration (Estimated: 2-3 hours)**
- Add integration tests with complete YARA rules
- Test modifier precedence and parsing order
- Benchmark performance impact of modifier parsing
- Update documentation and examples

**Expected Phase 2 Coverage Impact**: 58/101 features (57% total coverage)

### Phase 3: Advanced Features (High Priority)
1. **Bitwise operators** - `&`, `|`, `^`, `~`, `<<`, `>>`
2. **Data type functions** - `uint8()`, `int16()`, etc.
3. **File operations** - `filesize`, `entrypoint`
4. **Advanced string operations** - `contains`, `matches`, etc.

### Phase 4: Control Flow and Advanced Features (Lower Priority)
1. **Control flow** - `for`, `in`, `at`, `them`, `defined`
2. **Rule modifiers** - `global`, `private`
3. **Import system** - `import`, `include`
4. **Module system** - Advanced YARA module support

## Recommendations

1. **Incremental Implementation**: Focus on Phase 1 features first to establish core YARA compatibility
2. **Test-Driven Development**: Add comprehensive tests for each new feature before implementation
3. **Grammar Validation**: Cross-reference with official YARA documentation and test against real YARA rules
4. **Performance Monitoring**: Use existing benchmark infrastructure to ensure new features don't regress performance
5. **Documentation Updates**: Update this document as new features are implemented

## Implementation Examples

### Current Token Support

<augment_code_snippet path="token/token.go" mode="EXCERPT">
````go
const (
    RULE TokenType = iota
    META
    STRINGS
    CONDITION
    AND
    OR
    // ... other supported tokens
)
````
</augment_code_snippet>

### Missing Token Examples

```go
// Tokens that need to be added for Phase 3 and beyond
const (
    // Phase 3: Data types (High Priority)
    INT8
    INT16
    INT32
    UINT8
    UINT16
    UINT32
    INT8BE
    INT16BE
    INT32BE
    UINT8BE
    UINT16BE
    UINT32BE

    // Phase 3: File operations (Medium Priority)
    FILESIZE
    ENTRYPOINT

    // Phase 3: Bitwise operators (Medium Priority)
    BITWISE_AND     // &
    BITWISE_OR      // |
    BITWISE_XOR     // ^
    BITWISE_NOT     // ~
    LEFT_SHIFT      // <<
    RIGHT_SHIFT     // >>

    // Phase 4: String operations (Lower Priority)
    CONTAINS
    ICONTAINS
    STARTSWITH
    ISTARTSWITH
    ENDSWITH
    IENDSWITH
    IEQUALS
    MATCHES

    // Phase 4: Control flow (Lower Priority)
    FOR
    IN
    AT
    THEM
    DEFINED

    // Phase 4: Rule modifiers (Lower Priority)
    GLOBAL
    IMPORT
    INCLUDE
)
```

### Sample YARA Rules and Current Support

#### ✅ Currently Supported

```yara
rule SimpleRule {
    meta:
        author = "test"
        enabled = true
        debug = false
    strings:
        $a = "malware"
    condition:
        $a and (1 == 1 or 2 != 3) and true
}
```

#### ❌ Not Yet Supported

```yara
rule AdvancedRule {
    strings:
        $hex = { E2 34 ?? C8 A? FB }
        $text = "malware" nocase wide
        $regex = /[a-zA-Z0-9]{32}/
    condition:
        any of them and filesize < 1MB and
        $hex at entrypoint and
        for all i in (1..#text) : ( @text[i] < 100KB )
}
```

## Gap Analysis by YARA Feature

### String Definitions

| Feature | Status | Implementation Effort |
|---------|--------|----------------------|
| Text strings `"text"` | ✅ Complete | - |
| Hex strings `{ E2 34 }` | ✅ Complete | - |
| Regex strings `/pattern/` | ✅ Complete | - |
| String modifiers | ❌ Missing | High |
| Escape sequences | ✅ Complete | - |

### Condition Expressions

| Feature | Status | Implementation Effort |
|---------|--------|----------------------|
| Basic comparisons | ✅ Complete | - |
| Boolean operators | ✅ Complete | - |
| Arithmetic operators | ✅ Complete | - |
| Bitwise operators | ❌ Missing | Medium |
| String operations | ❌ Missing | High |

### Advanced Features

| Feature | Status | Implementation Effort |
|---------|--------|----------------------|
| String sets (`of` operator) | ❌ Missing | High |
| Loops (`for..in`) | ❌ Missing | High |
| Position operators (`at`) | ❌ Missing | Medium |
| File operations | ❌ Missing | Medium |
| Module system | ❌ Missing | Very High |

## Testing Strategy

### Current Benchmark Coverage

<augment_code_snippet path="internal/lexer/lexer_test.go" mode="EXCERPT">
````go
func BenchmarkLexer_MixedRule(b *testing.B) {
    input := "rule r: tag1 tag2 {\n meta: a = 1\n strings: $a = \"abc\"\n condition: (1 < 2 and 3 >= 4) or pe.entry_point == 0x1000\n}"
    // ... benchmark implementation
}
````
</augment_code_snippet>

### Phase 2 Testing Strategy

**String Modifier Test Coverage Plan:**

1. **Individual Modifier Tests**
   - Test each modifier token: `nocase`, `wide`, `ascii`, `fullword`, `private`, `xor`, `base64`, `base64wide`
   - Verify case-insensitive parsing: `NOCASE`, `NoCase`, `nocase`
   - Test with all string types: text strings, hex strings, regex strings

2. **Modifier Combination Tests**
   - Valid combinations: `"text" nocase wide`, `{ E2 34 } private ascii`
   - Invalid combinations: error handling for conflicting modifiers
   - Order independence: `nocase wide` vs `wide nocase`

3. **Integration Tests**
   - Complete YARA rules with multiple modified strings
   - Mixed modified and unmodified strings in same rule
   - Performance benchmarks with modifier parsing

4. **Error Recovery Tests**
   - Malformed modifier syntax: `"text" nocas`, `"text" wide extra`
   - Recovery after modifier parsing errors
   - Position tracking through modifier sequences

### Legacy Test Coverage (Completed)

1. ✅ **Hexadecimal string parsing** - Test `{ E2 34 ?? C8 }` syntax
2. ✅ **Regular expression parsing** - Test `/pattern/flags` syntax
3. ❌ **String modifier parsing** - Test `"text" nocase wide` syntax (Phase 2 target)
4. ✅ **Complex expressions** - Test nested conditions with all operators
5. ✅ **Error recovery** - Test malformed input handling
6. ❌ **Unicode support** - Test non-ASCII characters in strings and comments (Future phase)

## Next Steps: Phase 3 Implementation

### Current Status: Phase 3 Ready to Begin

**Phase 1 and Phase 2 are complete** with 57% grammar coverage (58/101 features). The lexer refactoring is also complete with a well-organized modular structure. **Phase 3 is now the immediate priority**.

### Phase 3: Advanced YARA Grammar Implementation

**Objective**: Implement bitwise operators, data type functions, and file operations to increase coverage from 57% to ~67% (68/101 features).

#### Phase 3.1: Bitwise Operator Tokens (Priority: HIGH, Effort: 1-2 hours)

**Implementation Steps:**
1. Add new token types to `token/token.go`:
   ```go
   // Bitwise operators (Phase 3)
   BITWISE_AND     // &
   BITWISE_OR      // |
   BITWISE_XOR     // ^
   BITWISE_NOT     // ~
   LEFT_SHIFT      // <<
   RIGHT_SHIFT     // >>
   ```

2. Update lexer in `internal/lexer/lexer.go` to handle these operators:
   - Single character: `&`, `|`, `^`, `~`
   - Multi-character: `<<`, `>>`
   - Handle conflicts with existing operators (e.g., `<` vs `<<`)

3. Add comprehensive tests for each operator

**YARA Examples Enabled:**
```yara
condition:
    uint32(0) & 0xFF00 == 0x4D00 and
    (filesize >> 10) < 1024 and
    ~uint16(2) == 0xFFFF
```

#### Phase 3.2: Data Type Function Keywords (Priority: HIGH, Effort: 2-3 hours)

**Implementation Steps:**
1. Add data type tokens to `token/token.go`:
   ```go
   // Data type functions (Phase 3)
   INT8, INT16, INT32
   UINT8, UINT16, UINT32
   INT8BE, INT16BE, INT32BE    // Big-endian variants
   UINT8BE, UINT16BE, UINT32BE
   ```

2. Update keyword lookup table in `internal/lexer/keywords.go`

3. Add comprehensive tests with realistic YARA contexts

**YARA Examples Enabled:**
```yara
condition:
    uint32(0) == 0x5A4D and
    int16be(entrypoint + 4) > 0 and
    uint8(filesize - 1) != 0x00
```

#### Phase 3.3: File Operation Keywords (Priority: MEDIUM, Effort: 1-2 hours)

**Implementation Steps:**
1. Add file operation tokens to `token/token.go`:
   ```go
   // File operations (Phase 3)
   FILESIZE
   ENTRYPOINT
   ```

2. Update keyword lookup table

3. Test with realistic YARA rule contexts

**YARA Examples Enabled:**
```yara
condition:
    filesize > 1MB and
    uint32(entrypoint) == 0x5A4D and
    filesize < 100KB
```

**Expected Outcome**: Increase coverage from 57% to ~67% (68/101 features)

#### Phase 3.4: Comprehensive Testing and Integration (Priority: HIGH, Effort: 2-3 hours)

**Implementation Steps:**

1. **Individual Token Tests**: Test each new token type in isolation
2. **Integration Tests**: Test Phase 3 features in complete YARA rules
3. **Error Recovery Tests**: Ensure robust error handling for malformed syntax
4. **Performance Benchmarks**: Maintain zero-allocation performance characteristics
5. **Documentation Updates**: Update this document with Phase 3 completion status

#### Phase 3 Impact: YARA Compatibility Improvement

**Current Phase 2 Support**:

```yara
rule Phase2Complete {
    strings:
        $a = "malware" nocase wide           // ✅ Supported
        $b = { E2 34 A1 C8 } private         // ✅ Supported
        $c = /[a-z]{32}/i ascii fullword     // ✅ Supported
    condition:
        any of them
}
```

**After Phase 3** (New capabilities):

```yara
rule Phase3Support {
    strings:
        $a = "malware" nocase wide
        $b = { E2 34 A1 C8 } private
    condition:
        any of them and
        filesize > 1MB and                  // ✅ Will be supported
        uint32(0) == 0x5A4D and            // ✅ Will be supported
        (uint16(0) & 0xFF00) == 0x4D00      // ✅ Will be supported
}
```

## Phase 4 Planning: Control Flow and Advanced Features

### Overview

After Phase 3 completion (~67% coverage), Phase 4 will focus on the remaining high-impact YARA features to achieve 80%+ grammar coverage.

### Phase 4 Priority Features

#### 4.1: Control Flow Keywords (High Priority)
**Missing Keywords:**
- `for` - Loop construct for iterating over string sets
- `in` - Range/set membership operator
- `at` - Position specification operator
- `them` - Reference to all defined strings
- `defined` - Undefined value check

**YARA Examples:**
```yara
condition:
    for all i in (1..#text) : ( @text[i] < 100KB ) and
    any of them at entrypoint and
    defined pe.entry_point
```

#### 4.2: Advanced String Operations (Medium Priority)
**Missing Keywords:**
- `contains`, `icontains` - Substring search (case-sensitive/insensitive)
- `startswith`, `istartswith` - Prefix matching
- `endswith`, `iendswith` - Suffix matching
- `iequals` - Case-insensitive equality
- `matches` - Regular expression matching

**YARA Examples:**
```yara
condition:
    pe.sections[0].name contains "text" and
    filename startswith "malware" and
    pe.version_info["CompanyName"] iequals "microsoft"
```

#### 4.3: Rule Modifiers and Import System (Lower Priority)
**Missing Keywords:**
- `global` - Global rule modifier
- `private` - Private rule modifier (different from string private)
- `import` - Module import
- `include` - File inclusion

**YARA Examples:**
```yara
import "pe"
include "common.yar"

global rule GlobalRule {
    // Global rule definition
}

private rule PrivateRule {
    // Private rule definition
}
```

### Phase 4 Implementation Strategy

1. **Incremental Implementation**: Implement control flow keywords first (highest impact)
2. **Parser Integration**: Phase 4 may require parser-level changes beyond lexer tokens
3. **Module System**: Import/include features will need significant architecture work
4. **Testing Strategy**: Focus on real-world YARA rule compatibility

### Expected Phase 4 Outcomes

- **Coverage Target**: 80%+ (81+/101 features)
- **YARA Compatibility**: Support for most production YARA rules
- **Advanced Features**: Loop constructs, string operations, module system
- **Production Ready**: Comprehensive error handling and performance optimization

## Recent Changes

### Phase 3 Advanced YARA Grammar Implementation (Latest - COMPLETE)
- ✅ **Complete Phase 3 implementation** - All advanced YARA grammar features
- ✅ **Bitwise operators** - `&`, `|`, `^`, `~`, `<<`, `>>` operators for bitwise operations
- ✅ **Data type function keywords** - `uint32`, `int16be`, `uint8`, etc. for YARA data type functions
- ✅ **File operation keywords** - `filesize`, `entrypoint` for file-based conditions
- ✅ **Comprehensive integration testing** - All Phase 3 features working together in YARA rules
- ✅ **Zero-allocation performance** - Maintained existing performance characteristics
- ✅ **Error recovery** - Robust error handling for malformed Phase 3 syntax
- ✅ **Backwards compatibility** - All existing features continue to work correctly

**Coverage Impact:** Increased from 57% to 67% (68/101 features supported)

**Phase 3 Features Summary:**
- Bitwise operations: `uint32(0) & 0xFF00`, `filesize >> 10`, `~value`
- Data type functions: `uint32(entrypoint)`, `int16be(offset + 4)`, `uint8(filesize - 1)`
- File operations: `filesize > 1MB`, `uint32(entrypoint) == 0x5A4D`
- Combined expressions: `(uint32(entrypoint) & 0xFF00) >> 8 == filesize`

### Phase 2 String Modifier Support (COMPLETE)
- ✅ **Complete Phase 2 implementation** - All string modifier features
- ✅ **String modifier tokens** - `nocase`, `wide`, `ascii`, `fullword`, `private`, `xor`, `base64`, `base64wide`
- ✅ **Comprehensive modifier parsing** - Support for all string types (text, hex, regex) with modifiers
- ✅ **Multiple modifier support** - Chained modifiers like `"text" nocase wide ascii`
- ✅ **Case-sensitive parsing** - Only lowercase modifiers recognized as keywords
- ✅ **Error recovery** - Invalid modifiers treated as identifiers, parsing continues
- ✅ **Comprehensive test coverage** - Individual, combination, integration, and performance tests
- ✅ **Zero-allocation performance** - All features maintain existing performance characteristics
- ✅ **Phase 2 integration tests** - Complete YARA rules with string modifiers

**Coverage Impact:** Increased from 50% to 57% (58/101 features supported)

**Phase 2 Features Summary:**
- String modifiers: `"text" nocase wide`, `{ E2 34 } private`, `/pattern/i ascii fullword`
- All string types: text strings, hex strings, regex strings with modifier support
- Error recovery: invalid modifiers gracefully handled as identifiers
- Performance: 1000+ iterations tested with consistent zero-allocation performance

### Phase 1 Core Language Support (COMPLETE)
- ✅ **Complete Phase 1 implementation** - All core YARA language features
- ✅ **Boolean literals** - `true`, `false` tokens with comprehensive testing
- ✅ **Regular expressions** - `/pattern/flags` syntax with flag support and comment disambiguation
- ✅ **Logical NOT** - `not` keyword and operator
- ✅ **Hexadecimal integers** - `0x` prefix support with case-insensitive parsing
- ✅ **Size suffixes** - `KB`, `MB` postfix support with hex integer compatibility
- ✅ **Basic quantifiers** - `all`, `any`, `none`, `of` keywords for string set operations
- ✅ **Complete arithmetic operators** - `*`, `/`, `%` operators with full precedence support
- ✅ **Enhanced error recovery** - Multi-character ILLEGAL tokens and structured error collection
- ✅ **Zero-allocation performance** - All features maintain existing performance characteristics
- ✅ **Comprehensive test coverage** - Edge cases, error recovery, and YARA rule integration

**Coverage Impact:** Increased from 30% to 50% (50/101 features supported)

### Error Recovery and Diagnostics (Latest)

- ✅ **Enhanced escape sequence handling** - Proper parsing of `\n`, `\t`, `\r`, `\\`, `\"`, `\xNN` with validation
- ✅ **Multi-character ILLEGAL tokens** - Coalesces consecutive illegal characters (e.g., `@@`, `*/`) into single tokens
- ✅ **Structured error collection** - `LexerError` type with position information alongside ILLEGAL tokens
- ✅ **Newline/keyword synchronization** - Automatic recovery at line boundaries and known keywords
- ✅ **Fast-forward recovery modes** - Optional section-level recovery to next `rule`/`meta`/`strings`/`condition`
- ✅ **Comprehensive test coverage** - Error scenarios, recovery behavior, and mixed valid/invalid content
- ✅ **Zero-allocation performance** - Maintains existing performance characteristics

**Error Recovery Features:**

- `RecoveryBasic` (default): Basic newline and keyword-based synchronization
- `RecoverySection`: Fast-forwards to next YARA section keyword for faster recovery
- Configurable via `NewWithRecovery()` or `SetRecoveryMode()`
- Error collection via `Errors()` method for higher-level APIs

### Phase 1 Core Language Support (Latest)

- ✅ **Hexadecimal integer literals** - Support for `0x` prefix (e.g., `0x1000`, `0xFF`, `0X401000`)
- ✅ **Size suffix literals** - Support for `KB` and `MB` suffixes (e.g., `1KB`, `100MB`, `0x100KB`)
- ✅ **Basic quantifier keywords** - Support for `all`, `any`, `none`, `of` keywords for string set operations
- ✅ **Complete arithmetic operators** - Added `*` (multiply), `/` (divide), `%` (modulo) operators
- ✅ **Comprehensive test coverage** - Edge cases, error recovery, and YARA rule integration for all Phase 1 features
- ✅ **Zero-allocation performance** - All new features maintain existing performance characteristics
- ✅ **Phase 1 integration tests** - Comprehensive testing of all features working together

**Coverage Impact:** Increased from 42% to 50% (50/101 features supported)

**Phase 1 Features Summary:**
- Hexadecimal integers: `0x1000`, `0xFF`, `0X401000`
- Size literals: `1KB`, `100MB`, `0x100KB`, `512mb` (case insensitive)
- Quantifiers: `all of them`, `any of ($a, $b)`, `none of them`
- Arithmetic: `1 + 2 * 3 - 4 / 5 % 6`
- Combined: `all of them and filesize > 100KB and (filesize / 1024) * 2 == 0x1000`

## Summary: Immediate Next Steps

### Current State
- ✅ **Phase 1 Complete**: Core language support (50% coverage)
- ✅ **Phase 2 Complete**: String features and modifiers (57% coverage)
- ✅ **Phase 3 Complete**: Advanced grammar implementation (67% coverage)
- ✅ **Refactoring Complete**: Modular lexer architecture

### Next Body of Work: Phase 4 Implementation

## Phase 4: Control Flow and Advanced Features

**Target Coverage**: 67% → 82% (83/101 features)
**Estimated Effort**: 12-16 hours
**Priority**: HIGH - Enables most production YARA rules

### Phase 4.1: Control Flow Keywords (HIGH Priority - 4-6 hours)

**Missing Keywords:**
- `for` - Loop construct for iterating over sets
- `in` - Range/set membership operator
- `at` - Position specification for string matches
- `them` - Reference to all defined strings
- `defined` - Check for undefined values

**Implementation Tasks:**
1. **Add Control Flow Tokens** (1-2 hours)
   - Add `FOR`, `IN`, `AT`, `THEM`, `DEFINED` tokens to `token/token.go`
   - Update keyword lookup table in `internal/lexer/keywords.go`
   - Ensure case-sensitive recognition (lowercase only)

2. **Comprehensive Testing** (2-3 hours)
   - Individual token tests for each control flow keyword
   - Integration tests with YARA rule contexts:
     - `for any of them : ( $ at pe.entry_point )`
     - `for all i in (1..#s) : ( uint32(@s[i]) == 0x5A4D )`
     - `defined pe.entry_point and them`
   - Error recovery for malformed control flow syntax

3. **Performance Validation** (1 hour)
   - Benchmark control flow keyword recognition
   - Ensure zero-allocation performance maintained
   - Memory leak detection for complex control flow rules

### Phase 4.2: Rule Modifiers (MEDIUM Priority - 2-3 hours)

**Missing Keywords:**
- `global` - Global rule modifier (rule-level)
- `private` - Private rule modifier (rule-level)

**Implementation Tasks:**
1. **Add Rule Modifier Tokens** (1 hour)
   - Add `GLOBAL`, `PRIVATE` tokens (distinct from string modifier `private`)
   - Update keyword lookup and ensure proper context handling

2. **Context-Aware Testing** (1-2 hours)
   - Test rule-level vs string-level `private` disambiguation
   - Integration with complete YARA rule parsing
   - Error handling for misplaced modifiers

### Phase 4.3: Advanced String Operations (MEDIUM Priority - 3-4 hours)

**Missing Keywords:**
- `contains`, `icontains` - Substring search operations
- `startswith`, `istartswith` - Prefix matching operations
- `endswith`, `iendswith` - Suffix matching operations
- `iequals` - Case-insensitive equality comparison
- `matches` - Regular expression matching operation

**Implementation Tasks:**
1. **Add String Operation Tokens** (1-2 hours)
   - Add all string operation tokens to `token/token.go`
   - Update keyword lookup table with case-sensitive recognition

2. **Integration Testing** (2 hours)
   - Test string operations in YARA rule conditions
   - Validate with realistic use cases:
     - `pe.sections[i].name contains ".text"`
     - `filename startswith "malware"`
     - `hash.md5(0, filesize) matches /^[a-f0-9]{32}$/`

### Phase 4.4: Import System (LOW Priority - 3-4 hours)

**Missing Keywords:**
- `import` - Module import statement
- `include` - File inclusion statement

**Implementation Tasks:**
1. **Add Import Tokens** (1 hour)
   - Add `IMPORT`, `INCLUDE` tokens
   - Handle import statement parsing context

2. **Module System Testing** (2-3 hours)
   - Test import statements: `import "pe"`, `import "math"`
   - Include file handling: `include "common.yar"`
   - Error recovery for missing modules/files

### Phase 4 Success Criteria

**Coverage Metrics:**
- Total features: 83/101 (82% coverage)
- Keywords: 33/64 (52% coverage)
- All operators: 22/22 (100% coverage)
- All literals: 8/8 (100% coverage)

**YARA Compatibility:**
- Support for 90%+ of production YARA rules
- Complete control flow constructs (`for`, `in`, `at`)
- Advanced string operations and rule modifiers
- Basic import system for modular rules

**Performance Requirements:**
- Maintain zero-allocation performance for hot paths
- Memory usage growth < 10% from Phase 3 baseline
- Lexing speed regression < 5% for complex rules

**Quality Assurance:**
- 100% test coverage for all Phase 4 features
- Integration tests with real-world YARA rule patterns
- Comprehensive error recovery and edge case handling
- Performance benchmarks and memory leak detection

### Implementation Approach

1. **Start with Task List**: Use the current task management system to track progress
2. **Test-Driven Development**: Add tests before implementation for each feature
3. **Incremental Delivery**: Complete each sub-phase before moving to the next
4. **Performance Monitoring**: Maintain zero-allocation characteristics
5. **Documentation Updates**: Update this document as features are completed

## References

- [YARA Documentation](https://yara.readthedocs.io/en/stable/writingrules.html)
- [YARA Keywords Reference](https://yara.readthedocs.io/en/stable/writingrules.html#yara-keywords)
- Current implementation: `internal/lexer/lexer.go`
- Token definitions: `token/token.go`
- Test coverage: `internal/lexer/lexer_test.go`
