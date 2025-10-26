# Test Regression Suite

This directory contains regression tests for the newly implemented YARA features:

## Critical Features Test Cases

### AT Operator Tests
- `test_at_operator.yar` - Tests `$string at offset` syntax
- `test_at_data.txt` - Test data for AT operator (contains "hello world")

### IN Operator Tests
- `test_in_operator.yar` - Tests `$string in (start..end)` syntax
- Test data will be generated on demand

### XOR Modifier Tests
- `test_xor_modifier.yar` - Tests `"pattern" xor 0x42` syntax
- `test_xor_correct.txt` - XOR-transformed test data (0x42 XOR "test" = "6'16")

### Comprehensive Integration Tests
- `test_comprehensive.yar` - Tests all features working together
- `test_comprehensive_data.bin` - Test data containing all pattern types

## Running Tests

```bash
# Test AT operator
go run ./cmd/main.go test_regression/rules/test_at_operator.yar --execute --data test_regression/data/test_at_data.txt

# Test XOR modifier
go run ./cmd/main.go test_regression/rules/test_xor_modifier.yar --execute --data test_regression/data/test_xor_correct.txt

# Test comprehensive integration
go run ./cmd/main.go test_regression/rules/test_comprehensive.yar --execute --data test_regression/data/test_comprehensive_data.bin
```

## Expected Results

All tests should return `MATCH` with appropriate pattern matches found.