# Agent guidelines

Apply a strict YAGNI ("you aren't gonna need it") bar to every change in
`go-yara`.

## Decision ladder

Before writing new code, evaluate options in order and stop at the first match:

1. **Skip unnecessary work.** Do not add speculative abstractions, pass-through
   wrappers, or test-only helpers to production files.
2. **Reuse existing repo code.** Check existing helpers in the package before
   adding a new one.
3. **Use the Go standard library.** Prefer standard-library primitives (`slices`,
   `maps`, `bytes`, `cmp`, `iter`) over hand-rolled equivalents.
4. **Keep changes minimal and bounded.** Enforce explicit work/memory limits and
   cancellation checks without cutting corners on input validation or libyara
   compatibility.

## Verification

Run before finishing any Go code change:

```sh
gofmt -w .
golangci-lint run ./...
go vet ./...
go test -race ./compiler ./regex
```
