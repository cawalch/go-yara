# Browser playground

The quickstart page embeds a small byte-buffer scanner. The UI loads normally with the docs; a Web Worker, Go runtime shim, and Wasm engine are downloaded only after **Compile and scan**. Rules and input are passed by worker messages, never sent to a server. Each operation terminates its worker on completion, failure, timeout, cancellation, or page navigation.

## Build and test

Generate the documentation release first, then build from the repository root:

```sh
python3 site/scripts/prepare.py --ref v0.8.0
npm ci --prefix site
npm run build --prefix site
npm run check --prefix site
cd site
npx playwright install chromium firefox webkit
npm run test-playground
```

`build.py` reads `src/generated/release.json`, extracts that Git tag to a temporary directory, and overlays only the current playground bridge. It runs the bridge tests against the released library and builds `js/wasm`. It copies `wasm_exec.js` from the effective compiler installation, including automatic toolchain selection. Wasm, shim, and worker bytes determine the generated directory name. `src/generated/playground.json` supplies the UI version, limits, worker URL, and binary hash. Generated files are ignored by Git and included in the Pages artifact.

The documentation workflow pins Go 1.27.2 and uses Playwright 1.64.1. It installs Chromium, Firefox, and WebKit and runs them **headed under Xvfb** on Linux. Deployment depends on those tests. Locally the same suite opens isolated browser windows; it does not use a personal browser profile. WebKit coverage is not a claim that every Safari or iOS version is qualified.

The browser suite checks lazy loading, local-only requests, 12 shared rule/byte fixtures, display truncation without changed conditions, UTF-8 source and file limits, long identifiers and rule-list limits, download failure, cancellation during loading and scanning, timeouts, recovery, actual memory-growth rejection, match-explosion failure, and mobile/dark presentation. Go tests additionally verify the exact serialized-byte budget. No real malware samples are used.

## Limits and result semantics

`engine/limits.json` is the source for build-time memory limits, worker/client limits, and Go bridge limits:

| Resource | Limit | Enforcement |
| --- | ---: | --- |
| Rule source | 16 KiB, UTF-8 | UI client, worker, Go bridge |
| Input | 1 MiB | File size before reading; client, worker, Go bridge |
| Compilation and scan | 3 seconds | Parent-page timer terminates the worker; Go context also cancels cooperatively |
| Runtime download/startup | 20 seconds | Parent-page timer |
| Wasm linear memory | 128 MiB | Maximum in the binary's memory section |
| Go runtime memory target | 64 MiB | `debug.SetMemoryLimit`; a soft GC target |
| Displayed results | 100 rule names, 200 occurrences | Applied after complete condition evaluation |
| Result JSON | 64 KiB UTF-8 | Bounded JSON encoder; worker and client verify size |

The hard ceiling covers Wasm linear memory, not the entire tab. JavaScript strings, downloaded/compiled Wasm, the transferred input, DOM, and browser overhead are additional. Browser timers can be delayed, especially in background tabs. Neither a timeout nor an out-of-memory stop is presented as “no matches”: an incomplete scan has no result panel.

Do not use scanner occurrence limits to implement display pagination. Truncating occurrence collection could change `#a`, `@a`, ranges, or other conditions. This bridge scans normally, then counts occurrences and selects bounded rows for presentation. Very dense matches may therefore hit the memory ceiling before a result can be returned. Only names, offsets, and lengths are returned; matched byte contents and metadata are not copied into the result table.

The encoder also budgets escaped identifiers and error messages. The UI uses `textContent`, limits rendered rows, clears old results on each request, and creates a fresh worker for every run. There is no shared compiled state after an error, stored history, URL-encoded rule source, or sample upload endpoint.

## Memory ceiling

Go's linker currently emits one defined memory without a maximum. The builder parses the Wasm section lengths and adds a maximum to that memory's limits; it preserves other sections. It fails closed if the header, memory count, flags, or initial size differ from the supported layout. Unit tests cover the transformation and refusal paths. Each browser instantiates the **actual built binary** and verifies that growth past the ceiling raises `RangeError`.

When changing Go versions, inspect the new linker layout and rerun all tests. Do not replace the maximum with a polling check or rely only on the soft Go GC target. See the [WebAssembly memory definition](https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/Definitions/memory) and [Go runtime memory target](https://pkg.go.dev/runtime/debug#SetMemoryLimit).

## Scope

This is a documentation playground, not a general JavaScript SDK or a security sandbox for arbitrary workloads. It scans supplied byte buffers with go-yara semantics. There are no native file paths, mmap calls, application-defined host modules, or Wasm/WASI host ABI exposed by this UI. The [earlier spike](../spikes/wasm/README.md) records the separate WASI feasibility work.

Review this directory when changing scanner result semantics, the compiler, the Go toolchain, limits, or the documented release. All versioned assets must come from one build; stale pages with deleted asset paths should fail visibly and ask the reader to reload, rather than run a different engine silently.
