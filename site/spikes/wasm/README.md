# Browser and WASI spike

**Decision:** a browser playground is feasible as an opt-in tool loaded in a Web Worker. Keep this prototype separate from the default documentation bundle. Use the Go library directly in Go applications; consider WASI when another host needs a Wasm boundary. A supported JavaScript package or a general WASI ABI needs more work.

This experiment builds the **published v0.8.0 module**, without patches, using Go 1.27.2. The browser binary contains the Go runtime, compiler, and scanner. Rules compile to go-yara's bytecode inside that binary. The reactor is a separate `wasip1/wasm` build; it exports a fixed fixture check, not a general compile/scan API.

## Reproduce

From the repository root, with Go, Node, and Python installed:

```sh
python3 site/spikes/wasm/build.py --ref v0.8.0 --out /tmp/go-yara-wasm-spike
python3 -m http.server 4322 --bind 127.0.0.1 --directory /tmp/go-yara-wasm-spike
```

The output directory must be new and outside the checkout. The builder creates a temporary module pinned to the requested release, runs the native fixtures, builds the browser, WASI command, and WASI reactor, then runs both WASI builds in Node. It copies `wasm_exec.js` from the same compiler installation. `build.json` records the toolchain and binary sizes; generated files stay out of Git.

Open `http://127.0.0.1:4322/` in a browser. **Compile and scan** uses the rule and UTF-8 text fields. **Run fixture and worker checks** exercises the cases below and displays JSON measurements. The result is also available as `window.spikeResults`. Stop the local server when finished.

Browser transport uses messages and transferred `ArrayBuffer`s, then `syscall/js.CopyBytesToGo` copies into the Go heap. A worker owns one sequential scanner. Failed compilation clears its previous rules. The prototype limits source to 32 KiB and input to 8 MiB, applies a three-second operation deadline, and terminates the worker on cancellation or timeout. These caps do not bound total memory or result size.

## Results, 2026-10-24

Environment: Apple M3 Max, macOS, Go 1.27.2, Node 26.12.0, Chrome 155. Browser files were served uncompressed over localhost. The browser profile and Wasm code cache were not reset, so startup numbers are warm/local observations, not first-visit download measurements.

| Build | Uncompressed bytes | Gzip bytes (measured locally) |
| --- | ---: | ---: |
| Browser worker | 9,284,369 | 2,413,140 |
| WASI command | 9,260,227 | 2,410,430 |
| WASI reactor | 9,223,880 | 2,401,515 |

Both targets use `-trimpath -ldflags='-s -w'`, with `GOEXPERIMENT` unset. The reactor additionally uses `-buildmode=c-shared`. No TinyGo, Binaryen, or custom runtime was evaluated. The gzip column does not imply that a particular hosting service serves this encoding.

| Check | Observed result |
| --- | --- |
| Native, browser worker, WASI command | All 12 fixtures passed; three scans for each valid compiled rule set. |
| WASI reactor | Initialized once and called three times; each call passed the fixture suite. |
| Browser startup | 97.4 ms to worker-ready in the recorded final run; 19.4 ms for restart. Earlier local runs observed 64.8–93.1 ms and 20.1–23.6 ms. |
| One literal at the end of a 1 MiB buffer | Six scans: 0.40–4.00 ms inside the scan/result-flattening function; 0.80–16.20 ms for the worker round trip. This small smoke workload is not a throughput benchmark. |
| Wasm linear memory | 6 MiB at startup; grew to 13,369,344 bytes during the fixture/1 MiB sequence, then peaked at 13,434,880 bytes through 50 additional 1 MiB clean rejects. This excludes JavaScript memory, browser overhead, and compiled Wasm code. |
| Cancel during an 8 MiB `/a.*b/` scan | Worker terminated, pending promise rejected, page timer continued, and a fresh worker scanned successfully. Final observed cancellation round trip: about 72 ms with a requested 50 ms delay. |
| Automatic timeout | A separate active scan hit the 100 ms test deadline and terminated its worker. Browser timers are not real-time guarantees. |
| API edge cases | Scan before compile, failed-compile stale-state clearing, and oversized source/input checks passed. |

The fixtures cover nocase and wide literals, regex verification, a hex jump, counts/offsets, occurrences retained for a false rule condition, fixed-offset reads, SHA-256, undefined reads, stringless matches, and a compile error. Expected rule names and occurrence spans are written in `engine/fixtures.json`; passing merely means these cases agreed with those expectations.

Selected existing compiler tests also passed under Go's Node-based `js/wasm` test runner on the current tree: compiler integration, hex matching, cooperative scan cancellation, fused assertions, module-cache reset/reuse, and module smoke tests. The shared-AST test in `regex` passed too. A broader compiler selection hit `TestCompileSourceWithImportDoesNotWriteStdout`, whose `os.Pipe` test harness is unavailable on `js`. The full repository suite was **not** qualified for Wasm.

```sh
GOOS=js GOARCH=wasm go test \
  -exec="$(go env GOROOT)/lib/wasm/go_js_wasm_exec" ./compiler \
  -run '^(TestCompilerIntegration|TestHexPatternMatching|TestScanWithContextCancellation|TestConditionAssertions.*|TestModuleRangeCacheAcrossRulesAndScans|TestModuleCacheBoundedAndReset|TestExpandedModuleSmoke)$' -count=1
node --check site/spikes/wasm/client.mjs
node --check site/spikes/wasm/worker.js
node --check site/spikes/wasm/wasi.mjs
golangci-lint run ./site/spikes/wasm/...
GOOS=js GOARCH=wasm golangci-lint run ./site/spikes/wasm/browser ./site/spikes/wasm/engine
GOOS=wasip1 GOARCH=wasm golangci-lint run ./site/spikes/wasm/reactor ./site/spikes/wasm/engine
```

## Before a public playground

- Add bounded output, a documented rule/input budget, and memory stress cases. A short pattern can produce millions of occurrences even below the input cap. The present bridge serializes every occurrence.
- Test Firefox, Safari, mobile devices, slow downloads, and cold startup. Measure UI responsiveness under background-tab timer throttling. Handle worker failure and restart in the final interface.
- Decide how to expose compile/reuse/reset, byte input, integer offsets, errors, and result ownership as a versioned JavaScript API. Avoid running compilation or scanning on the main thread.
- Build from the documented release in CI with its matching runtime shim, and run browser correctness tests. Keep the download lazy and make the loaded engine version visible.
- Limit the initial interface to byte buffers. File paths, mmap, arbitrary host callbacks, and native Go concurrency do not transfer automatically to a browser API. Input transfer still needs a copy into Go memory.

For a WASI product, define buffer allocation, program handles, error/result encoding, and teardown before choosing a host. Test that host's memory and execution limits. Node's experimental WASI integration proves the exports work here; it is not a security-isolation qualification. Wasmtime, wazero, and other hosts were not tested. A reactor initialized once is possible, but this probe recompiles its fixed fixtures on each exported call.

## Primary references

- [Go WebAssembly wiki](https://go.dev/wiki/WebAssembly): browser target and matching runtime shim.
- [Extensible Wasm Applications with Go](https://go.dev/blog/wasmexport): exported functions and WASI reactor initialization.
- [Node WASI documentation](https://nodejs.org/api/wasi.html): host API, experimental status, and security limits.
- [Worker termination](https://developer.mozilla.org/en-US/docs/Web/API/Worker/terminate): stopping work by discarding a worker.

Re-run this experiment when changing the toolchain, compiler, scan-result contract, or bridge. These measurements describe this dated spike; they are not a continuing browser-support guarantee.
