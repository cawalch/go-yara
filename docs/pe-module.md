# PE headers, sections, and standard imports

Import `pe` to inspect PE32 and PE32+ headers, sections, and standard imports.
This module uses
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

This implements headers, sections, and standard import metadata under
[#359](https://github.com/cawalch/go-yara/issues/359). The module exposes fields
and constants. `pe.imports(...)` calls, delayed imports, import hashes, exports,
resources, Rich headers, computed checksums, and Authenticode signatures remain
unsupported and fail compilation.

## Supported fields

All numeric fields are YARA integers. Array indexes are zero-based. An index
outside an array produces an undefined value. As in libyara, `sections` exposes
at most 96 entries; `number_of_sections` preserves the declared count.

| Object | Fields |
| --- | --- |
| `pe` | `is_pe`, `machine`, `number_of_sections`, `timestamp`, `pointer_to_symbol_table`, `number_of_symbols`, `size_of_optional_header`, `characteristics` |
| `pe` optional header | `entry_point`, `entry_point_raw`, `image_base`, `number_of_rva_and_sizes`, `opthdr_magic`, `size_of_code`, `size_of_initialized_data`, `size_of_uninitialized_data`, `base_of_code`, `base_of_data`, `section_alignment`, `file_alignment`, `win32_version_value`, `size_of_image`, `size_of_headers`, `checksum`, `subsystem`, `dll_characteristics`, `size_of_stack_reserve`, `size_of_stack_commit`, `size_of_heap_reserve`, `size_of_heap_commit`, `loader_flags` |
| `pe` standard imports | `number_of_imports`, `number_of_imported_functions` |
| `pe.import_details[i]` | `library_name`, `number_of_functions`, `functions` |
| `pe.import_details[i].functions[j]` | `name`, `ordinal` |
| `pe.linker_version`, `pe.os_version`, `pe.image_version`, `pe.subsystem_version` | `major`, `minor` |
| `pe.data_directories[i]` | `virtual_address`, `size` |
| `pe.sections[i]` | `name`, `full_name`, `characteristics`, `virtual_address`, `virtual_size`, `raw_data_offset`, `raw_data_size`, `pointer_to_relocations`, `pointer_to_line_numbers`, `number_of_relocations`, `number_of_line_numbers` |

`base_of_data` is undefined for PE32+. `checksum` contains the stored header
value; it doesn't verify the file. Data directory entries describe locations
and sizes. The adapter parses standard imports on demand. It exposes at most the
first 16 entries, limited by `number_of_rva_and_sizes`.

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

Use collection loops to query the imported DLLs and functions:

```yara
import "pe"

rule ImportsVirtualAlloc {
    condition:
        for any library in pe.import_details : (
            library.library_name == "KERNEL32.dll" and
            for any function in library.functions : (
                function.name == "VirtualAlloc"
            )
        )
}
```

Names preserve their spelling; the string comparisons in this example are
case-sensitive. `number_of_imports` counts descriptors with accepted functions,
including duplicate DLL descriptors. `number_of_imported_functions` counts
functions across those descriptors. Empty or filtered libraries are omitted.

For an import by name, `name` is defined and `ordinal` is undefined. For an
import by ordinal, `ordinal` is defined and `name` is undefined, including for
ordinal zero. Unlike libyara, this adapter doesn't synthesize `ordN` names or
resolve DLL-specific ordinal aliases. Query the ordinal directly. Import
address-table RVAs (`functions[j].rva`) aren't implemented and fail compilation.

The adapter follows libyara 4.5.8's name filtering: DLL names must have fewer
than 256 bytes and contain printable ASCII other than `"*<>?|`. Function names
are limited to their first 512 bytes and accept ASCII letters, digits, and
`._?@$()<>`. It examines at most 16,384 functions per descriptor and exposes at
most 16,384 accepted functions in total. These policies belong to go-yara;
go-pe preserves the underlying names and has its own parsing limits.

A valid PE image with no import directory has zero import counts and an empty
`import_details` array. If go-pe rejects import metadata, all three import
fields are undefined; the header and section fields remain available. Failures
are cached for the scan, with no partial import results.

Import parsing inherits go-pe's bounds checks, required terminators, directory
size checks, and resource limits. It uses the lookup table when present and
falls back to the import address table only for an unbound descriptor with a
zero lookup-table RVA. libyara can expose partial imports from malformed files
that go-pe rejects. The adapter doesn't reproduce that recovery behavior.

## Address mapping

`entry_point_raw` is the entry-point RVA from the optional header.
`entry_point` is its file offset, or `-1` if it doesn't map to a file byte.
The latter follows libyara 4.5.8's file-scan policy, including alignment rounding
and selection of overlapping sections. This policy belongs to the adapter;
go-pe retains its own RVA mapping contract. Standard imports use go-pe's
mapping, including first-section precedence, unrounded raw offsets, and strict
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
for import fields to be defined. Entry-point bounds use the full stream length.

`ScanFileWithContext` uses the same bounded reader fallback when its context is
cancellable and the file isn't memory-mapped. It attempts mapping for regular
files of at least 128 KiB. A file below that threshold can therefore expose
headers but have undefined import fields if import metadata extends beyond
64 KiB. For complete metadata with cancellation, acquire the file bytes in your
application and call `ScanWithContext`.

## Runtime behavior

The first field access parses the headers and sections. Subsequent rules share
that scan's snapshot. Version objects, directory descriptors, and section
objects are constructed on demand. The first import-field access parses and
filters imports once. Counts don't construct detail objects; each library
constructs its function objects only when accessed. Constants and unused module
imports don't invoke the parser. Starting another scan invalidates the snapshot.

Headers and parsed import records own their names. Deferred import parsing
reads from the active scan context without holding another reference to the
input buffer. Clearing that context releases the deferred input too.
Parsing failures become module values rather than scan errors. The fast
non-PE guard allocates no memory; complete scan cost still includes rule
interpretation and result construction.

Compiled programs preserve the schema and restore built-in PE loading when
read by this version of go-yara. Previously serialized header-only PE schemas
still load automatically. Existing custom modules named `pe` with a
different schema retain their host-data behavior. An explicit
`WithModuleData("pe", data)` snapshot takes precedence over automatic loading.

## Validation

The differential suite uses libyara 4.5.8 in CI. It covers PE32 and PE32+
headers, constants, section names, standard import counts and details, undefined
fields, entry-point mappings, real Go-toolchain PE fixtures, scanner reuse,
compiled-program round trips,
compact scans, and reader scans within the retention limit.

To run the focused tests, install the `yara` CLI on `PATH`, then run:

```sh
go test ./compiler ./tests/integration -run 'TestPE|TestLibyaraPE' -count=1
go test ./compiler -run '^$' -bench 'BenchmarkPE(Module|Scanner|Imports)$' -benchmem
```

The oracle tests skip if the CLI is absent. CI installs and checks the pinned
oracle before running the suite. `FuzzPEAdapter` exercises the adapter with
arbitrary input, including PE32/PE32+ imports and ordinals. Separate tests record
strict import rejection and ordinal-name differences from libyara.
