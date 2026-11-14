# PE headers, sections, imports, and exports

Import `pe` to inspect PE32 and PE32+ headers, sections, standard imports, and
export metadata. This module uses
[go-pe](https://github.com/cawalch/go-pe) for parsing. go-pe is an independent
library; it has no dependency on go-yara or its module interfaces.

```yara
import "pe"

rule WritableExecutableSection {
    condition:
        pe.is_pe and
        for any section in pe.sections : (
            section.characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            section.characteristics & pe.SECTION_MEM_WRITE != 0
        )
}
```

The module implements headers, sections, section lookup, RVA-to-file-offset
mapping, standard import and export metadata, import and export queries by name
or ordinal, and the standard import hash under
[#359](https://github.com/cawalch/go-yara/issues/359). Regex import queries,
delayed imports, regex export queries, resources, Rich headers, computed
checksums, and Authenticode signatures remain unsupported and fail compilation.

## Supported fields

All numeric fields are YARA integers. Array indexes are zero-based. An index
outside an array produces an undefined value. As in libyara, `sections` exposes
at most 96 entries; `number_of_sections` preserves the declared count.

| Object | Fields |
| --- | --- |
| `pe` | `is_pe`, `machine`, `number_of_sections`, `timestamp`, `pointer_to_symbol_table`, `number_of_symbols`, `size_of_optional_header`, `characteristics` |
| `pe` optional header | `entry_point`, `entry_point_raw`, `image_base`, `number_of_rva_and_sizes`, `opthdr_magic`, `size_of_code`, `size_of_initialized_data`, `size_of_uninitialized_data`, `base_of_code`, `base_of_data`, `section_alignment`, `file_alignment`, `win32_version_value`, `size_of_image`, `size_of_headers`, `checksum`, `subsystem`, `dll_characteristics`, `size_of_stack_reserve`, `size_of_stack_commit`, `size_of_heap_reserve`, `size_of_heap_commit`, `loader_flags` |
| `pe` standard exports | `number_of_exports`, `export_timestamp`, `dll_name` |
| `pe.export_details[i]` | `ordinal`, `rva`, `offset`, `name`, `forward_name` |
| `pe` standard imports | `number_of_imports`, `number_of_imported_functions` |
| `pe.import_details[i]` | `library_name`, `number_of_functions`, `functions` |
| `pe.import_details[i].functions[j]` | `name`, `ordinal` |
| `pe.linker_version`, `pe.os_version`, `pe.image_version`, `pe.subsystem_version` | `major`, `minor` |
| `pe.data_directories[i]` | `virtual_address`, `size` |
| `pe.sections[i]` | `name`, `full_name`, `characteristics`, `virtual_address`, `virtual_size`, `raw_data_offset`, `raw_data_size`, `pointer_to_relocations`, `pointer_to_line_numbers`, `number_of_relocations`, `number_of_line_numbers` |

`base_of_data` is undefined for PE32+. `checksum` contains the stored header
value; it doesn't verify the file. Data directory entries describe locations
and sizes. The array exposes at most the first 16 entries, limited by
`number_of_rva_and_sizes`. The adapter parses imports and exports on demand.

`name` contains the eight-byte section name with trailing NUL bytes removed.
Embedded NUL bytes remain. `full_name` resolves a COFF string-table reference
when present. A resolved name with nonprintable bytes is undefined, following
the libyara oracle's C-locale behavior.

The module provides libyara's machine, subsystem, COFF characteristics, DLL
characteristics, directory-index, optional-header magic, and section-flag
constants. For the complete list, see
[`modules_pe_constants.go`](../compiler/modules_pe_constants.go). Constants are
available even when the input isn't a PE image.

## Section lookup

`pe.section_index(name)` returns the zero-based index of the first exposed
section whose raw `name` matches. Matching is case-sensitive and uses C-string
semantics: both values stop at the first NUL byte. It searches the same
96-section exposure limit as `pe.sections`.

`pe.section_index(file_offset)` returns the first exposed section containing the
file offset, where `raw_data_offset <= file_offset < raw_data_offset +
raw_data_size`. The end is exclusive, empty sections never match, and negative
or out-of-range offsets are undefined. Process-memory virtual-address semantics
are not implemented. Overlapping sections return the first match.

Both overloads return undefined for non-PE input, rejected headers, an undefined
`number_of_sections`, or no match. They read the cached raw section records and
names without constructing `pe.sections` objects. With `WithModuleData`, the
supplied `number_of_sections` and `sections` array are authoritative; an
incomplete snapshot returns undefined and never falls back to file parsing.

## RVA mapping

`pe.rva_to_offset(rva)` maps a relative virtual address to a file offset using
the same libyara-compatible policy as `pe.entry_point` and export offsets. It
accounts for the larger of virtual and raw section sizes, overlapping sections,
file-alignment rounding, page-aligned raw offsets, headers before the first
section, virtual tails without raw data, and out-of-file targets. Unmapped and
negative values are undefined; 64-bit arguments are not narrowed to 32-bit.
Process-memory virtual addresses are not supported.

The mapper uses the scan's input length. With `WithModuleData`, it requires the
host `number_of_sections`, exposed `sections`, `file_alignment`, and
`section_alignment` fields; incomplete or out-of-range host metadata is
undefined and never falls back to file parsing. The supplied host fields remain
owned by the scanner snapshot.

## Standard imports

Use `pe.imports` to check for a named function or numeric ordinal:

```yara
import "pe"

rule ImportsVirtualAlloc {
    condition:
        pe.imports("kernel32.dll", "VirtualAlloc")
}
```

`pe.imports(dll, function_name)` and `pe.imports(dll, ordinal)` return integer
`1` for a match and `0` otherwise.
For example, `pe.imports("ws2_32.dll", 1)` checks for ordinal 1. Named imports
don't match their hint as an ordinal, and values outside 0 through 65,535 don't
match file imports. DLL and function-name comparisons fold ASCII case and stop
at the first NUL byte, matching libyara 4.5.8's C-locale behavior. They don't use
Unicode case folding.

Use `pe.imports(dll)` to count imported functions from a DLL. For example,
`pe.imports("kernel32.dll") > 5` matches images that import more than five
functions from that DLL. The count includes named and ordinal imports across
all matching descriptors, including duplicates. It returns `0` when no
functions match and uses the same DLL-name comparison as the two-argument
queries. It reads the cached import records without constructing
`import_details` objects.

Queries are undefined for non-PE input, rejected import metadata, or undefined
arguments. Only standard imports are searched. The regex and flagged overloads
are not implemented and fail compilation.

Use `import_details` and collection loops to inspect records directly. Names
preserve their spelling; ordinary string equality remains case-sensitive.
`number_of_imports` counts descriptors with accepted functions,
including duplicate DLL descriptors. `number_of_imported_functions` counts
functions across those descriptors. Empty or filtered libraries are omitted.

For an import by name, `name` is defined and `ordinal` is undefined. For an
import by ordinal, `ordinal` is defined and `name` is undefined, including for
ordinal zero. Unlike libyara, this adapter doesn't synthesize `ordN` names or
resolve DLL-specific ordinal aliases. Name queries don't resolve those aliases
either; query the ordinal directly. Import address-table RVAs
(`functions[j].rva`) aren't implemented and fail compilation.

The adapter follows libyara 4.5.8's name filtering: DLL names must have fewer
than 256 bytes and contain printable ASCII other than `"*<>?|`. Function names
are limited to their first 512 bytes and accept ASCII letters, digits, and
`._?@$()<>`. It examines at most 16,384 functions per descriptor and exposes at
most 16,384 accepted functions in total. These policies belong to go-yara;
go-pe preserves the underlying names and has its own parsing limits.

A valid PE image with no import directory has zero import counts and an empty
`import_details` array. If go-pe rejects import metadata, all three import
fields, import queries, and `pe.imphash()` are undefined; the header and section
fields remain available. Failures are cached for the scan, with no partial
import results.

Import parsing inherits go-pe's bounds checks, required terminators, directory
size checks, and resource limits. It uses the lookup table when present and
falls back to the import address table only for an unbound descriptor with a
zero lookup-table RVA. libyara can expose partial imports from malformed files
that go-pe rejects. The adapter doesn't reproduce that recovery behavior.

### Import hash

`pe.imphash()` returns libyara's standard import hash as a lowercase MD5 hex
string. It hashes the cached standard imports once per scan in descriptor order,
including duplicates:

```yara
import "pe"

rule KnownImportHash {
    condition:
        pe.imphash() == "52ee6f8c06f82c1a4906c4287b38a731"
}
```

For each import, the adapter appends `library.function`, separated by commas,
then lowercases the complete sequence with ASCII rules. It removes `.ocx`,
`.sys`, and `.dll` suffixes using libyara's four-byte suffix comparison. Named
imports keep their spelling. Ordinal imports use frozen `ws2_32.dll`,
`wsock32.dll`, and `oleaut32.dll` alias tables from libyara 4.5.8, falling back
to `ordN`; ordinary import/display-name synthesis is not used for the hash.

A valid PE with no imports hashes the empty sequence
(`d41d8cd98f00b204e9800998ecf8427e`). Non-PE input, rejected import metadata, or
an unavailable host snapshot leaves the value undefined. With `WithModuleData`,
the supplied `import_details` array is hashed in the same way; a missing array
is undefined, while an empty array hashes the empty sequence. Delayed imports
are excluded. Imphash is a clustering feature, not a cryptographic trust or
unique-identity claim.

libyara can return the empty-sequence hash when its permissive parser skips a
malformed import directory. go-pe rejects that metadata, so this adapter returns
undefined instead, matching the existing strict import boundary.

## Standard exports

Use `pe.exports` to check for a named export or numeric ordinal:

```yara
import "pe"

rule NamedExport {
    condition:
        pe.exports("ExampleFunction")
}
```

`pe.exports(name)` and `pe.exports(ordinal)` return integer `1` for a match and
`0` otherwise. Queries are undefined for non-PE input, rejected export metadata,
or undefined arguments. They use the existing export cache without constructing
`export_details` objects.

Name queries fold ASCII case and compare the complete query string. Embedded
NUL bytes are significant, and Unicode case folding is not applied. Queries
search the same first alias and 512-byte name projection exposed by
`export_details`; they do not search additional aliases or forwarder targets.

Ordinal queries compare the base-adjusted ordinal, including slots with a zero
RVA. To match libyara 4.5.8, they return `0` for ordinal zero or an ordinal above
`number_of_exports`, even if that ordinal appears in the details. For example,
a directory with base 7 and three slots exposes ordinals 7, 8, and 9, but none
matches an ordinal query. Use a collection loop over `export_details` to test
those ordinals directly.

Use `pe.exports_index(name)` or `pe.exports_index(ordinal)` to get the zero-based
index of the first matching entry in `export_details`. These overloads use the
same comparisons, ordinal guard, and scan cache as `pe.exports`. They return
undefined for a miss or unavailable metadata. Index zero is valid: use `defined`
to check for a match instead of treating the index as a boolean.

```yara
import "pe"

rule ExportAtFileOffset {
    condition:
        pe.export_details[pe.exports_index("ExampleFunction")].offset == 0x200
}
```

An undefined index produces an undefined field value. Index lookups do not
construct detail objects until a rule accesses the details themselves.

`pe.export_timestamp` exposes the export directory's unsigned 32-bit timestamp
as a YARA integer. It is separate from `pe.timestamp`, which comes from the COFF
header. Zero is a defined value, including in a valid directory with no exports.
Use `defined pe.export_timestamp` to test availability. The field is undefined
for non-PE input, a missing directory, or export metadata rejected by go-pe.

Timestamp access shares the export cache with counts, details, and queries. It
validates the complete directory without constructing detail objects. On malformed
tables, libyara can expose the timestamp from the directory header even when it
cannot parse the exports; this adapter leaves it undefined.

`pe.dll_name` exposes the export directory's DLL name, preserving case and raw
bytes. A present empty name is a defined empty string. The field is undefined
for non-PE input, an absent directory or name RVA, a name mapped to file offset
zero, or metadata rejected by go-pe. It shares the export cache and doesn't
construct detail objects.

Unlike export symbol names, DLL names aren't truncated to 512 bytes. They must
fit within go-pe's 4,096-byte string limit, including the terminator, and its
mapping and file bounds. Libyara can expose an unterminated name or one that
crosses a raw section boundary; this adapter rejects those cases. It also leaves
`dll_name` undefined when malformed export tables prevent a complete snapshot,
even if libyara recovers the name from the directory header.

Use `number_of_exports` and `export_details` to inspect individual records.
The array follows export address table order, including unused slots with a
zero RVA. `number_of_exports` counts those slots, up to 16,384. `ordinal` includes
the directory's ordinal base, and `rva` preserves the table value. `name` is the
first alias in name-pointer order, limited to 512 bytes. It is undefined for an
unnamed slot; an empty name remains a defined empty string. Field values preserve
case and bytes; ordinary YARA string equality is case-sensitive. Additional
aliases remain available through go-pe's own API.

For a forwarder, `forward_name` contains up to 512 bytes of the raw target
string, and `offset` is undefined. For an ordinary target, `offset` uses the same
file mapping policy as `entry_point` and is undefined when the RVA cannot map to
a file byte. `forward_name` is undefined for ordinary targets. Zero-RVA slots
use the same mapping rules; they don't necessarily map to offset zero. The
adapter doesn't validate or resolve forwarder syntax.

A missing directory gives a zero count and an empty array. If go-pe rejects any
export metadata, both fields are undefined; headers and imports remain usable.
The parser validates the complete directory before the adapter applies its
exposure limit. It retains go-pe's bounds, terminator, and resource checks.

The adapter follows go-pe's RVA range when identifying forwarders. libyara
4.5.8 instead tests mapped file offsets and excludes the directory's first
byte. Those policies can differ at that boundary or with unusual mappings.
The adapter selects the first alias from the complete validated name table;
libyara examines only the initial name pointers up to its exposed address count.
Aliases beyond that window can therefore produce different names. Strict
rejection also differs from libyara's partial recovery on malformed tables.
Tests record these differences separately from parity cases.

Regex `pe.exports` and `pe.exports_index` overloads remain
unsupported and fail compilation.

## DLL classification

`pe.is_dll()` takes no arguments and returns `pe.characteristics & pe.DLL`.
The result is `0x2000` when the DLL flag is set and `0` when it is clear. Use
it directly as a condition or compare it with `pe.DLL`; comparing it with `1`
doesn't test whether the file is a DLL.

The function returns undefined when header metadata is unavailable. It reuses
the header cache without parsing imports or exports. If you supply PE module
data with `WithModuleData`, it uses the supplied `characteristics` field;
a missing field stays undefined and doesn't trigger file parsing.

## Bitness

`pe.is_32bit()` returns `1` for a PE32 image and `0` for a PE32+ image.
`pe.is_64bit()` returns the opposite result. Both take no arguments and return
undefined when header metadata is unavailable.

The functions classify the optional-header format and reuse the header cache
without parsing imports or exports. The machine field and COFF flags do not
change the result.

If you supply PE module data with `WithModuleData`, its `opthdr_magic` controls
both functions. `IMAGE_NT_OPTIONAL_HDR32_MAGIC` selects PE32, and
`IMAGE_NT_OPTIONAL_HDR64_MAGIC` selects PE32+. A missing or unrecognized magic
leaves both functions undefined, even if the scanned file has valid headers.
Other host fields, including `is_pe` and `machine`, do not affect classification.

Libyara accepts some images with unrecognized optional-header magic and reports
them as 32-bit. go-pe rejects those images, so both functions remain undefined.
This preserves the adapter's existing strict-header compatibility boundary.

## Address mapping

`entry_point_raw` is the entry-point RVA from the optional header.
`entry_point` is its file offset, or `-1` if it doesn't map to a file byte.
The latter follows libyara 4.5.8's file-scan policy, including alignment rounding
and selection of overlapping sections. This policy belongs to the adapter;
go-pe retains its own RVA mapping contract. Import and export metadata use
go-pe's mapping, including first-section precedence, unrounded raw offsets, and strict
raw-data bounds. These policies can differ from libyara on unusual layouts.

All scan APIs use file semantics. Block offsets are file offsets, not process
virtual addresses. The adapter reads headers from the block at offset zero
and doesn't concatenate separate blocks. Process-memory PE semantics are not
implemented.

## Input limits and compatibility

For unrecognized or rejected input, `is_pe` is `0` and the other runtime fields
are undefined. Empty section loops and integer ranges evaluate to false for
`any`, `all`, and `none`. The numeric `0` quantifier is an alias for `none`.
Undefined integer range bounds also produce a false
loop result instead of a scan error.

The adapter inherits go-pe's validation and resource limits. In particular, it
requires a complete declared section table, accepts at most 256 sections, and
bounds COFF long names to 256 bytes including the NUL terminator. It rejects
unsupported optional-header magic values, inconsistent header or directory
sizes, PE headers overlapping the DOS header, and invalid COFF name references.
libyara accepts some of these malformed layouts and can expose partial results.
This implementation does not claim parity for them. Tests record these
intentional differences separately from differential parity checks.

`Scan`, `ScanWithContext`, and `ScanFile` make the complete input available.
`ScanReader` retains only the first 64 KiB, as it does for integer reads. PE
headers, section tables, and COFF names must fit in that prefix for the image to
be recognized. Import descriptors, lookup tables, and names must also fit there
for import fields to be defined. Export tables and names must fit there for
export fields to be defined. Target offset bounds use the full stream length.

`ScanFileWithContext` uses the same bounded reader fallback when its context is
cancellable and the file isn't memory-mapped. It attempts mapping for regular
files of at least 128 KiB. A file below that threshold can therefore expose
headers but have undefined import or export fields if their metadata extends
beyond 64 KiB. For complete metadata with cancellation, acquire the file bytes in your
application and call `ScanWithContext`.

## Runtime behavior

The compiler imports go-pe directly, so Go downloads it during builds even
when an application uses no PE rules. Applications do not need a separate
checkout. The parser uses only the standard library and requires no CGO. PE
support is built in; it is not a separately installed plugin.

The first field access or PE query parses the headers and sections.
Subsequent rules share that scan's snapshot. Version objects, directory
descriptors, and section objects are constructed on demand. `pe.section_index`
and `pe.rva_to_offset` answer from the cached raw section records without
constructing section objects. The first import
query, import-field access, or `pe.imphash()` call parses and filters imports
once. Queries, fields, and the hash share this cache. Counts and queries don't
construct detail objects; each library constructs its function objects only
when accessed. Constants and unused module imports don't invoke the parser.
Export counts, details, and queries share a separate lazy cache in the same
snapshot; counts and queries don't construct detail objects.
Import and export parsing can run in either order. Starting another scan
invalidates the snapshot.

Headers and parsed import and export records own their names. Deferred parsing
reads from the active scan context without holding another reference to the
input buffer. Clearing that context releases the deferred input too.
Parsing failures become module values rather than scan errors. The fast
non-PE guard allocates no memory; complete scan cost still includes rule
interpretation and result construction.

Compiled programs preserve the schema and restore built-in PE loading when
read by this version of go-yara. Previously serialized header-only and
import-only PE schemas still load automatically. Existing custom modules named
`pe` with a different schema retain their host-data behavior. An explicit
`WithModuleData("pe", data)` snapshot takes precedence over automatic loading.
Import queries use that snapshot's `import_details`: a missing array gives an
undefined result, and an empty array gives `0`. `pe.imphash()` uses the same
array; a missing array is undefined and an empty array hashes the empty
sequence. DLL counts include non-null function records in matching libraries
and ignore the supplied `number_of_functions` field. Export queries use the
snapshot's `export_details`, with the same missing-array and empty-array
behavior. Index queries return undefined for both an absent array and a miss,
and preserve array positions when entries are undefined. Their ordinal guard
uses the array length, ignoring a separately
supplied `number_of_exports`. Names are compared as supplied, including embedded
NULs. Custom `ModuleFunction.Evaluate` callbacks
take precedence over built-in query dispatch, including on copied registrations.
Only unmodified built-in PE function registrations can omit that callback.
Changing a name, schema, or signature requires a custom implementation.
Rebind custom callbacks when loading a compiled program. Native function
dispatch uses the same schema check as automatic field loading.

## Validation

The differential suite uses libyara 4.5.8 in CI. It covers PE32 and PE32+
headers, constants, section names, section lookup, RVA mapping, standard import
counts, details, queries, and imphash, export metadata and queries, undefined
fields, entry-point mappings, real Go-toolchain PE fixtures, scanner reuse,
compiled-program round trips, compact scans, and reader scans within the
retention limit.

To run the focused tests, install the `yara` CLI on `PATH`, then run:

```sh
go test ./compiler ./tests/integration -run 'TestPE|TestLibyaraPE' -count=1
go test ./compiler -run '^$' -bench 'BenchmarkPE(Module|Scanner|Sections|RVA|Imports|Imphash|Exports|ExportQueries)$' -benchmem
```

The oracle tests skip if the CLI is absent. CI installs and checks the pinned
oracle before running the suite. `FuzzPEAdapter` exercises the adapter with
arbitrary input, including PE32/PE32+ imports, ordinals, and exports. Separate
tests record strict rejection and name or forwarder differences from libyara.
