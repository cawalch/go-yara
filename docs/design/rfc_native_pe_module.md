# Native PE module

Status: headers, sections, section lookup, RVA-to-file-offset mapping, standard
import metadata and queries, standard import hash, and export counts, details,
timestamps, DLL names, name/ordinal queries, and index lookups implemented. DLL
and bitness classification helpers reuse the header cache. Follow-up work is
tracked in [#359](https://github.com/cawalch/go-yara/issues/359).

The PE module lets pure-Go applications evaluate binary metadata conditions
without linking libyara. The implementation covers headers, sections, section
lookup, RVA mapping, standard import counts, details, queries, and imphash,
export metadata and queries, and related constants. See
[PE metadata](../pe-module.md) for the supported fields and compatibility
limits.

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

## Follow-up work

Additional import overloads, delayed imports, ordinal aliases, import
address-table RVAs, regex export queries, resources, Rich headers, Authenticode,
and process-memory behavior remain outside
this phase. Each addition needs a bounded parsing design, differential coverage,
and performance measurements.
The Authenticode work also needs explicit certificate and signature-verification
semantics; exposing a certificate alone must not imply a verified signature.
