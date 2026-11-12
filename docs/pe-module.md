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

The module implements headers, sections, standard import and export metadata,
and import and export queries by name or ordinal under
[#359](https://github.com/cawalch/go-yara/issues/359). Regex import queries,
delayed imports, import hashes, regex export queries, resources, Rich headers,
computed checksums, and Authenticode signatures remain unsupported and fail
compilation.

## Supported fields

All numeric fields are YARA integers. Array indexes are zero-based. An index
outside an array produces an undefined value. As in libyara, `sections` exposes
at most 96 entries; `number_of_sections` preserves the declared count.

| Object | Fields |
| --- | --- |
| `pe` | `is_pe`, `machine`, `number_of_sections`, `timestamp`, `pointer_to_symbol_table`, `number_of_symbols`, `size_of_optional_header`, `characteristics` |
| `pe` optional header | `entry_point`, `entry_point_raw`, `image_base`, `number_of_rva_and_sizes`, `opthdr_magic`, `size_of_code`, `size_of_initialized_data`, `size_of_uninitialized_data`, `base_of_code`, `base_of_data`, `section_alignment`, `file_alignment`, `win32_version_value`, `size_of_image`, `size_of_headers`, `checksum`, `subsystem`, `dll_characteristics`, `size_of_stack_reserve`, `size_of_stack_commit`, `size_of_heap_reserve`, `size_of_heap_commit`, `loader_flags` |
| `pe` standard exports | `number_of_exports` |
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
fields and import queries are undefined; the header and section fields remain
available. Failures are cached for the scan, with no partial import results.

Import parsing inherits go-pe's bounds checks, required terminators, directory
size checks, and resource limits. It uses the lookup table when present and
falls back to the import address table only for an unbound descriptor with a
zero lookup-table RVA. libyara can expose partial imports from malformed files
that go-pe rejects. The adapter doesn't reproduce that recovery behavior.

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

Regex `pe.exports` and `pe.exports_index` overloads, `dll_name`, and
`export_timestamp` remain unsupported and fail compilation.

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
descriptors, and section objects are constructed on demand. The first import
query or import-field access parses and filters imports once. Queries and fields
share this cache. Counts and queries don't construct detail objects; each
library constructs its function objects only when accessed. Constants and unused
module imports don't invoke the parser. Export counts, details, and queries share
a separate lazy cache in the same snapshot; counts and queries don't construct
detail objects.
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
undefined result, and an empty array gives `0`. DLL counts include non-null
function records in matching libraries and ignore the supplied
`number_of_functions` field. Export queries use the snapshot's `export_details`, with the same
missing-array and empty-array behavior. Index queries return undefined for
both an absent array and a miss, and preserve array positions when entries are
undefined. Their ordinal guard uses the array length, ignoring a separately
supplied `number_of_exports`. Names are compared as supplied, including embedded
NULs. Custom `ModuleFunction.Evaluate` callbacks
take precedence over built-in query dispatch, including on copied registrations.
Only the unmodified built-in `pe.imports`, `pe.exports`, and `pe.exports_index`
registrations can omit that callback. Changing a name, schema, or signature
requires a custom implementation. Rebind custom callbacks when loading a compiled
program. Native query dispatch uses the same schema check as automatic field
loading.

## Validation

The differential suite uses libyara 4.5.8 in CI. It covers PE32 and PE32+
headers, constants, section names, standard import counts, details, and queries,
export metadata and queries, undefined fields, entry-point mappings, real
Go-toolchain PE fixtures, scanner reuse, compiled-program round trips, compact
scans, and reader scans within the retention limit.

To run the focused tests, install the `yara` CLI on `PATH`, then run:

```sh
go test ./compiler ./tests/integration -run 'TestPE|TestLibyaraPE' -count=1
go test ./compiler -run '^$' -bench 'BenchmarkPE(Module|Scanner|Imports|Exports|ExportQueries)$' -benchmem
```

The oracle tests skip if the CLI is absent. CI installs and checks the pinned
oracle before running the suite. `FuzzPEAdapter` exercises the adapter with
arbitrary input, including PE32/PE32+ imports, ordinals, and exports. Separate
tests record strict rejection and name or forwarder differences from libyara.
