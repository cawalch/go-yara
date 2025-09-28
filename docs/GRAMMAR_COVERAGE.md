# YARA Grammar Coverage Analysis

## Overview

This document tracks the coverage of YARA grammar elements in the go-yara lexer implementation. It provides a comprehensive analysis of which YARA language features are currently supported, partially supported, or missing from the lexer.

## Coverage Summary

| Category | Supported | Partial | Missing | Total |
|----------|-----------|---------|---------|-------|
| **Keywords** | 13 | 0 | 51 | 64 |
| **Operators** | 16 | 0 | 0 | 16 |
| **Literals** | 8 | 0 | 0 | 8 |
| **Punctuation** | 8 | 0 | 0 | 8 |
| **Comments** | 2 | 0 | 0 | 2 |
| **String Types** | 3 | 0 | 0 | 3 |

**Overall Coverage: 50/101 (50%)** ✅ **Phase 1 Complete**

## Detailed Coverage Analysis

### 1. Keywords

#### ✅ Supported (13/64)
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

#### ❌ Missing (51/64)
**Core Language Keywords:**
- `for` - Loop construct
- `in` - Range/set membership
- `at` - Position specification
- `them` - Reference to all strings
- `defined` - Undefined value check

**String Modifiers:**
- `ascii`, `wide` - Character encoding modifiers
- `nocase` - Case-insensitive matching
- `fullword` - Word boundary matching
- `private` - Private string modifier
- `xor` - XOR string modifier
- `base64`, `base64wide` - Base64 encoding modifiers

**Data Type Keywords:**
- `int8`, `int16`, `int32` - Signed integer types
- `uint8`, `uint16`, `uint32` - Unsigned integer types
- `int8be`, `int16be`, `int32be` - Big-endian signed integers
- `uint8be`, `uint16be`, `uint32be` - Big-endian unsigned integers

**Rule Modifiers:**
- `global` - Global rule modifier
- `private` - Private rule modifier

**String Operations:**
- `contains`, `icontains` - Substring search
- `startswith`, `istartswith` - Prefix matching
- `endswith`, `iendswith` - Suffix matching
- `iequals` - Case-insensitive equality
- `matches` - Regular expression matching

**File/Process Keywords:**
- `filesize` - File size variable
- `entrypoint` - Executable entry point

**Import/Include:**
- `import` - Module import
- `include` - File inclusion

### 2. Operators

#### ✅ Supported (16/16)
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


#### ❌ Missing (0/16)
All basic arithmetic and comparison operators are now supported! Additional operators that could be added:
- `&` - Bitwise AND
- `|` - Bitwise OR
- `^` - Bitwise XOR
- `~` - Bitwise NOT
- `<<` - Left shift
- `>>` - Right shift


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

### Phase 2: String Features (Medium Priority)
1. ✅ **Hexadecimal strings** - `{ E2 34 A1 }` syntax (COMPLETED)
2. **String modifiers** - `nocase`, `wide`, `ascii`
3. ✅ **Escape sequences** - `\n`, `\t`, `\xNN` in strings (COMPLETED)

### Phase 3: Advanced Features (Lower Priority)
1. ✅ **Arithmetic operators** - `*`, `/`, `%` (MOVED TO PHASE 1 - COMPLETED)
2. **Bitwise operators** - `&`, `|`, `^`, `~`, `<<`, `>>`
3. **Data type functions** - `uint8()`, `int16()`, etc.
4. **Advanced string operations** - `contains`, `matches`, etc.
5. **File operations** - `filesize`, `entrypoint`

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
// Tokens that need to be added for better YARA support
const (
    // Boolean literals
    TRUE TokenType = iota + 100
    FALSE

    // Logical operators
    NOT

    // Quantifiers
    ALL
    ANY
    NONE
    OF

    // String modifiers
    NOCASE
    WIDE
    ASCII
    FULLWORD
    PRIVATE
    XOR
    BASE64
    BASE64WIDE

    // Data types
    INT8
    INT16
    INT32
    UINT8
    UINT16
    UINT32

    // File operations
    FILESIZE
    ENTRYPOINT

    // Advanced operators
    MULTIPLY
    DIVIDE
    MODULO
    BITWISE_AND
    BITWISE_OR
    BITWISE_XOR
    BITWISE_NOT
    LEFT_SHIFT
    RIGHT_SHIFT

    // String operations
    CONTAINS
    ICONTAINS
    STARTSWITH
    ISTARTSWITH
    ENDSWITH
    IENDSWITH
    IEQUALS
    MATCHES

    // Control flow
    FOR
    IN
    AT
    THEM
    DEFINED

    // Literals
    HEX_INTEGER_LIT
    REGEX_LIT

    // Size suffixes
    KB_SUFFIX
    MB_SUFFIX
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
| Regex strings `/pattern/` | ❌ Missing | Medium |
| String modifiers | ❌ Missing | High |
| Escape sequences | 🔶 Partial | Low |

### Condition Expressions

| Feature | Status | Implementation Effort |
|---------|--------|----------------------|
| Basic comparisons | ✅ Complete | - |
| Boolean operators | 🔶 Partial (missing NOT) | Low |
| Arithmetic operators | 🔶 Partial (missing *, /, %) | Low |
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

### Recommended Test Additions

1. **Hexadecimal string parsing** - Test `{ E2 34 ?? C8 }` syntax
2. **Regular expression parsing** - Test `/pattern/flags` syntax
3. **String modifier parsing** - Test `"text" nocase wide` syntax
4. **Complex expressions** - Test nested conditions with all operators
5. **Error recovery** - Test malformed input handling
6. **Unicode support** - Test non-ASCII characters in strings and comments

## Recent Changes

### Regex Literal Support (Latest)
- ✅ **Added REGEX_LIT token type** - New token for regular expression literals
- ✅ **Implemented regex parsing** - Support for `/pattern/flags` syntax
- ✅ **Flag support** - Case-insensitive (`i`) and single-line (`s`) flags
- ✅ **Empty regex support** - Handles `//` and `//flags` patterns
- ✅ **Escape sequence handling** - Proper parsing of escaped characters in regex patterns
- ✅ **Comment disambiguation** - Smart detection between `//` comments and empty regex literals
- ✅ **Comprehensive test coverage** - Edge cases, YARA rule integration, and performance benchmarks
- ✅ **Zero-allocation performance** - Maintains existing performance characteristics

**Coverage Impact:** Increased from 38% to 40% (39/97 features supported)

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

## References

- [YARA Documentation](https://yara.readthedocs.io/en/stable/writingrules.html)
- [YARA Keywords Reference](https://yara.readthedocs.io/en/stable/writingrules.html#yara-keywords)
- Current implementation: `internal/lexer/lexer.go`
- Token definitions: `token/token.go`
- Test coverage: `internal/lexer/lexer_test.go`
