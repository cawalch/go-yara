# Regression Fixtures

These rules and inputs cover behavior that previously regressed:

- `at`: `rules/test_at_operator.yar` with `data/test_at_data.txt`
- `in`: `rules/test_in_operator.yar` with `data/test_at_data.txt`
- `xor`: `rules/test_xor_modifier.yar` with `data/test_xor_correct.txt`
- combined operators and pattern types: `rules/test_comprehensive.yar` with
  `data/test_comprehensive_data.bin`

They are exercised by `TestRegressionRules`:

```bash
go test ./compiler -run '^TestRegressionRules$' -count=1
```
