# Phase 4 Implementation Plan - Corrected & Updated
**Date**: 2025-10-18  
**Status**: Ready for Implementation  
**Priority**: CRITICAL - Blocks Phase 5

---

## Current State Assessment

### What's Working ✅
- Lexer: Complete, optimized (47-203x faster)
- Parser: Complete (87.6% coverage)
- Semantic Analysis: Complete
- Basic bytecode generation framework
- Atom extraction for text and hex strings

### What's Broken 🚨
- Regex atom extraction: Returns nil (not implemented)
- Aho-Corasick: Bounds checking issues
- Hex string parser: Incomplete grammar support
- Main command: Only lexes, doesn't execute
- Execution engine: Completely missing

### What's Missing ❌
- Pattern matching engine
- Bytecode interpreter
- Rule execution
- Full hex grammar support

---

## Phase 4 Completion Tasks

### Task 4.1: Fix Regex Atom Extraction
**File**: `compiler/atoms.go:224-238`
**Current**: Returns nil always
**Required**:
1. Parse regex pattern string
2. Extract literal byte sequences
3. Handle case-insensitive modifier
4. Return atoms for optimization

**Example**:
```
/Hello.*World/i → extract "ello", "orl", "wor"
```

**Effort**: 2-3 hours
**Tests**: Add 5+ test cases

### Task 4.2: Fix Aho-Corasick Bounds Checking
**File**: `compiler/ahocorasick.go:241-327`
**Issues**:
- Line 317: `transitionIndex := slot*256 + input` can overflow
- No pre-validation of table size
- Potential runtime panics

**Required**:
1. Calculate exact table size needed
2. Validate before allocation
3. Add bounds checks
4. Add comprehensive tests

**Effort**: 3-4 hours
**Tests**: Add 10+ test cases for edge cases

### Task 4.3: Complete Hex String Parser
**File**: `compiler/string_compiler.go:194-218`
**Current**: Simplified, incomplete
**Missing**:
- Alternatives: `[AA BB CC]`
- Jumps: `[1-5]`
- Wildcards with masks: `A? B?`
- Comments: `// comment`

**Required**:
1. Implement full YARA hex grammar
2. Parse all wildcard types
3. Handle alternatives
4. Support jumps

**Reference**: `yara/sample.rules` has hex pattern example
```
$a = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8}
```

**Effort**: 4-5 hours
**Tests**: Add 15+ test cases

### Task 4.4: Implement Bytecode Interpreter
**File**: New file `compiler/interpreter.go`
**Required**:
1. Create interpreter struct
2. Implement opcode execution
3. Handle pattern matching
4. Manage execution state

**Effort**: 6-8 hours
**Tests**: Add 20+ test cases

### Task 4.5: Add Pattern Matching Engine
**File**: New file `compiler/matcher.go`
**Required**:
1. Implement string matching
2. Implement hex matching
3. Implement regex matching
4. Handle modifiers (nocase, wide, etc.)

**Effort**: 5-6 hours
**Tests**: Add 15+ test cases

### Task 4.6: Update Main Command
**File**: `cmd/main.go:135-201`
**Current**: Only lexes/parses
**Required**:
1. Add execution mode
2. Test pattern matching
3. Print match results
4. Handle errors properly

**Effort**: 2-3 hours
**Tests**: Add 5+ integration tests

### Task 4.7: Refactor High-Complexity Functions
**Files**: Multiple
**Functions**:
- `BuildTransitionTable()` (32 complexity)
- `parsePrimary()` (32 complexity)
- `calculateAtomQuality()` (22 complexity)

**Required**:
1. Break into smaller functions
2. Extract helper methods
3. Improve readability
4. Maintain performance

**Effort**: 4-5 hours
**Tests**: Ensure no regression

### Task 4.8: Increase Test Coverage to 88%
**Current**: 69.3%
**Target**: 88%
**Focus Areas**:
- Aho-Corasick transition table (0%)
- Regex compilation (0%)
- Pattern optimization (0%)
- Type checker methods (0%)

**Effort**: 5-6 hours
**Tests**: Add 30+ test cases

---

## Implementation Order

**Week 1**:
1. Task 4.1: Regex atom extraction (2-3h)
2. Task 4.2: Aho-Corasick bounds (3-4h)
3. Task 4.3: Hex string parser (4-5h)

**Week 2**:
1. Task 4.4: Bytecode interpreter (6-8h)
2. Task 4.5: Pattern matching (5-6h)
3. Task 4.6: Main command update (2-3h)

**Week 3**:
1. Task 4.7: Refactor complexity (4-5h)
2. Task 4.8: Test coverage (5-6h)

**Total Effort**: 36-45 hours (1 week intensive)

---

## Success Criteria

✅ All 8 Phase 4 tasks complete
✅ Test coverage ≥ 88%
✅ No cognitive complexity > 10
✅ All critical issues fixed
✅ Main command executes full pipeline
✅ Real-world rules compile and execute

---

## Validation

Test with `yara/sample.rules`:
```
rule UPX : Packer {
    strings: 
        $a = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8}
    condition:
        $a at pe.entry_point
}
```

Expected: Compile successfully, extract atoms, match patterns

---

## Next Phase (Phase 5)

After Phase 4 completion:
- Implement execution engine
- Create bytecode VM
- Add rule execution
- Support all YARA features

