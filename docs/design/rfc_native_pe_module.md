# Native PE module

Status: headers, sections, section lookup, RVA-to-file-offset mapping, overlay
metadata, standard import metadata, ordinal display aliases, queries, and
import hash, and export counts, details, timestamps, DLL names, name/ordinal
queries, and index lookups implemented. DLL and bitness classification helpers
reuse the header cache. Follow-up work is tracked in
[#359](https://github.com/cawalch/go-yara/issues/359).

The PE module lets pure-Go applications evaluate binary metadata conditions
without linking libyara. The implementation covers headers, sections, section
lookup, RVA mapping, overlay metadata, standard import counts, details, ordinal
aliases, queries, and imphash, export metadata and queries, and related
constants. See [PE metadata](../pe-module.md) for the supported fields and
compatibility limits.

## Library boundary

[go-pe](https://github.com/cawalch/go-pe) owns bounded parsing of DOS, COFF, and
optional headers, section tables, COFF section names, standard imports, and
exports. It remains a standalone library. It doesn't import go-yara, expose YARA values, or
implement scanner lifecycle hooks.

go-yara owns the module schema, YARA constant names, undefined values,
target offset mapping, import name filtering, export field selection, exposure
limits, and scan-local caching. The dependency is pinned to a go-pe revision. Parser
improvements must make sense for independent
clients; YARA-specific compatibility belongs in the adapter.

Existing libraries remain useful comparison points. Go's `debug/pe` provides
header and section parsing but documents that it isn't hardened against
adversarial input. `saferwall/pe` provides a broader analysis API, including
byte-slice input and options to skip directory parsing. `Velocidex/go-pe`
provides reader-based analysis. The earlier proposal's blanket claims about
maintenance, eager parsing, and missing APIs are not a basis for this design.
Evaluate concrete capabilities and measured costs when considering reuse.

## Scan lifecycle

The adapter uses the existing structured-module bytecode. A field load creates
a PE snapshot only when needed and shares it across rules in the current scan.
Nested objects are constructed on demand. A new scan clears the snapshot.
Constants don't require parsing, and non-PE rejection doesn't allocate.

This phase introduces no public parsing callback or new dependency from go-pe
to the scanner. Custom module data continues to take precedence over automatic
loading. Serialized schemas allow the loader to recognize the built-in PE
schema after a compiled-program round trip.

Reader scans retain the existing 64 KiB input prefix. The adapter doesn't
increase stream buffering. It documents and tests the resulting metadata limit.
Block scans use file offsets and require the headers in the offset-zero block.

## Compatibility and validation

Differential tests compare the supported surface with libyara 4.5.8. They cover
ordinary images and address-mapping edge cases. Separate tests record layouts
that go-pe deliberately rejects even though libyara accepts them. A rejected
image exposes `is_pe = 0`; it does not return partially initialized headers.

Performance checks cover the parser guard, PE scans, reuse across many rules,
and scans that don't use PE. Performance claims must identify the workload and
separate parser cost from complete scan cost. Valid PE parsing allocates;
there is no blanket zero-allocation guarantee.

## Input availability, block boundaries, and cancellation

Native PE metadata falls into three availability tiers, governed by
`peScanData` (contiguous offset-0 bytes) and `peFullScanData` (complete input
where `FileSize > 0` and `int64(len(data)) == FileSize`):

1. **Bounded prefix (`<= 64 KiB`)**: Headers, sections, COFF long names,
   directories, imports, exports, and section/RVA lookups use `peScanData` plus
   full stream `FileSize` for offset bounds and `overlay` extents. Metadata past
   the retained prefix stays `undefined` instead of triggering whole-stream
   buffering.
2. **Whole-input operations (`peFullScanData`)**: Full-file checksums (`#480`)
   and Authenticode digests (`#481`) require a complete contiguous offset-0
   slice covering `FileSize`. Partial stream prefixes and segmented/incomplete
   blocks leave these operations `undefined` rather than returning partial
   checksums or digests.
3. **Explicitly deferred random access and process memory**: Standalone
   `io.ReaderAt` support (`go-pe#16`) and VA-mapped process-memory PE parsing are
   out of scope. Existing callers needing complete metadata alongside
   cancellation acquire bytes explicitly and pass them to `ScanWithContext`.

| Entry point | Retained PE bytes (`peScanData`) | Full-file ops (`peFullScanData`) | Domain & limits |
| --- | --- | --- | --- |
| `Scan*`, `Matches*`, `MatchingRules*` | Complete buffer | Available (`len == FileSize`) | File offsets |
| `ScanFile`, `ScanFileWithContext` (`ctx.Done() == nil`) | Full file (`MapFile` `>= 128 KiB`, else `os.ReadFile`) | Available (`len == FileSize`) | File offsets |
| `ScanFileWithContext` (cancellable, regular `>= 128 KiB`) | Complete file via `fs.MapFile` | Available (`len == FileSize`) | File offsets |
| `ScanFileWithContext` (cancellable, `< 128 KiB` or non-regular / mmap fallback) | Streamed via `ScanReaderWithContext` (`<= 64 KiB` prefix) | Available only when `FileSize <= 64 KiB`; otherwise `undefined` | File offsets |
| `ScanReader*`, `MatchesReader*` | First `64 KiB` (`streamingHeaderSize`) + full `FileSize` | Available only when `FileSize <= 64 KiB`; otherwise `undefined` | File offsets; `MatchesReader*` may early-exit once a rule matches |
| `MatchingRulesInBlock*` (`base == 0`) | Single block `Data` + `FileSize` (`filesize >= 0` else `len(Data)`) | Available only when `int64(len(Data)) == FileSize` | File offsets; **not** process VAs |
| `BlockScanner` (`Base == 0` present) | First `Base == 0` block verbatim + aggregate/configured `FileSize` | Available only when that `Base == 0` block covers full `FileSize` | File offsets; multi-block ranges are not concatenated |
| `MatchingRulesInBlock*` (`base != 0`) / `BlockScanner` (no `Base == 0`) | None (`is_pe == 0`) | `undefined` | File offsets; non-zero bases are never treated as VAs |
| `WithModuleData("pe", ...)` | Host snapshot (bypasses `loadPE`) | Snapshot-defined (`undefined` if absent) | Host-controlled |

### Cancellation and scan isolation

`go-pe` remains a synchronous `[]byte` parser with no dependency on
`context.Context` or scanner lifecycles, keeping non-PE and non-cancellable
scans at zero overhead (`executeMainLoop` does not poll `cancelDone`). On
cancellable scans (`cancelDone != nil`):

- Reader scans poll `ctx.Err()` on every `Read()` via `contextReader`.
- Rule loops poll `ctx.Err()` between rules, and `executeMainLoopWithCancel`
  polls `scanCanceled(done)` every `scanCancellationInterval` (4096) VM steps
  (covering condition loops such as `for any e in pe.export_details`) and at
  rule exit.
- Bounded PE loops up to 16,384 entries (import filtering, `imphash`, import/export
  queries, export detail materialization) poll `scanCanceledAt(done, n)` every
  4096 items and skip caching incomplete results on cancellation.
- Multi-megabyte whole-file operations (`calculate_checksum`, Authenticode
  digests) must process `peFullScanData` in bounded chunks and poll
  `scanCanceled(done)` between chunks.

## Follow-up work

Additional import overloads, delayed imports, import address-table RVAs, regex
export queries, resources, Rich headers, whole-file checksums (`#480`),
Authenticode (`#481`), standalone `ReaderAt` (`go-pe#16`), and opt-in
process-memory VA behavior remain outside this phase. Each addition needs a
bounded parsing design, differential coverage, and performance measurements.
The Authenticode work also needs explicit certificate and signature-verification
semantics; exposing a certificate alone must not imply a verified signature.
Process-memory PE support requires an explicit virtual-address mode rather than
interpreting `MemoryBlock` file offsets as virtual addresses.
