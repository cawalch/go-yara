# Regex deadline regression

The scanner now polls cancellation inside ASCII and wide VM attempts and
between search starts. `matches` conditions propagate cancellation, including
when the last interpreter instruction finishes after the context expires.
Pattern verification and fixed-offset header checks carry the same signal.
The scanner maps cancellation back to the caller's context error, preserving
`context.DeadlineExceeded`.

## Reproduce and validate

```sh
go test ./compiler -run 'TestRegexConditionDeadline|TestRegexMatchContentDeadlineAndReuse|TestAnchoredRegexDeadline|TestCancellationDuringLastInstruction' -count=1
go test ./regex -run 'TestCancelableRegex|TestRegexCancellation' -count=1
go test ./compiler -run '^$' -bench '^BenchmarkRegexConditionReject$' -benchtime=3x -count=1
```

Before this change, the deadline tests reproduced compact scan APIs returning
`nil` errors after the context expired. The full scan returned a deadline error
only after the regex finished. The condition was `/a+b/` against 8 KiB of `a`,
provided either as a condition string or through `$a = /^a+$/`.

A local reproduction on an Apple M3 Max, Go 1.27.1, using a 10 ms deadline:

| Input bytes | Before | After |
| --- | --- | --- |
| 2,048 | 59 ms, nil error | 10.1 ms, deadline error |
| 4,096 | 167 ms, nil error | 10.7 ms, deadline error |
| 8,192 | 659 ms, nil error | 11.1 ms, deadline error |

These are individual diagnostic measurements, not latency guarantees.
Regression tests allow scheduler headroom and also check matching semantics,
pooled state reuse after interruption, and the final-instruction boundary.

## Remaining performance work

This patch retains the existing search algorithm. Without a deadline, regex
search still retries every start position, yielding quadratic work on this
negative input. A three-iteration benchmark of the same condition measured:

| Input bytes | Base commit 12be4f5 | This change |
| --- | --- | --- |
| 2,048 | 43.2 ms/op | 46.3 ms/op |
| 4,096 | 186.8 ms/op | 169.4 ms/op |
| 8,192 | 715.4 ms/op | 668.0 ms/op |

The short benchmark establishes the scaling problem; it does not establish a
speedup or a statistically significant overhead difference. A follow-up can
replace repeated starts for Boolean regex searches with a single advancing
NFA simulation, tested against existing behavior for anchors, word boundaries,
wide strings, case folding, and empty matches. Span-producing APIs must retain
their leftmost-longest results.
