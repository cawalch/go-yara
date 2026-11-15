# PE Capability Report (YARA Forge 20261108)

This report benchmarks `go-yara`'s compiler, `pe` module coverage, non-PE compiler blockers, and planned PE feature benefit against a pinned snapshot of the public YARA Forge full rule corpus. Bulk third-party rules are excluded from the repository; pinned hashes, source manifests, minimized parser/compiler reproducers, and generated PE fixture tests provide full reproducibility.

## Pinned Corpus & Verification Metadata

| Artifact | Value |
| --- | --- |
| Upstream project | [YARAHQ/yara-forge](https://github.com/YARAHQ/yara-forge) |
| Release tag / commit | `20261108` (`38825cf1e3cdda6e0112d0bab6a262ea2ea50f89`) |
| Archive asset | `yara-forge-rules-full.zip` (3,921,842 bytes) |
| Archive SHA-256 | `1248e8e121625eacf3eb7f74d825486612b0d5ed9c29659548d37a7fbf616704` |
| Extracted rule file | `packages/full/yara-rules-full.yar` (19,472,759 bytes) |
| Extracted `.yar` SHA-256 | `652e369c8cb781c541d7737b7bd0be04b0fe9a1f3d488c19d22965d2ffb98f4f` |
| Reference oracle | `yara` / `yarac` `4.6.0` (compiles full file cleanly with exit code `0`) |
| Independent AST/token parser | `plyara` `2.2.8` |
| `go-yara` / `go-pe` base | `main` at `10ccb28`, `github.com/cawalch/go-pe v0.0.0-20261112204814-1fd2b3174895` |

## Methodology

1. **Independent corpus parsing & feature census (`plyara==2.2.8`)**: Parsed all `11,866` rules across the 40 repository sections without depending on `go-yara`'s lexer/parser. Extracted all dotted member chains, overload shapes (0-arg vs. `(string)` vs. `(string, string)` vs. regex/int), constants, loop-variable aliases (`for <q> <var> in pe.<collection> : ...`), cross-rule dependencies (`58` total: `38` `private` rules, `0` `global` rules, including `2` PE rules referencing `BINARYALERT_Cobaltstrike_Template_Exe_PRIVATE`), and external variable references (`0` found in `20261108`).
2. **Real compiler audit (`compiler.NewCompiler().CompileSourceWithContext`)**: Compiled every rule together with its closed cross-rule dependency closure (plus file-header `import` directives) through `go-yara`'s supported compilation entry point and recorded `GetStats().Errors` (`parsing`, `imports`, `semantic`).
3. **Condition-isolated separation**: Rules blocked early by non-PE syntax or metadata errors were also probed on their condition expression with `pe`, `hash`, `math`, and `string` imported, plus combined with the `plyara` member census, so rules fail-fasting at parse time still report every PE slice they depend on.
4. **Source & malware-family deduplication**: Grouped rule counts by both source repository (40 upstream repos) and normalized rule family (stripping trailing hex hashes, date-index suffixes, and version/numbered suffixes; collapsing certificate-blocklist rule families in `ReversingLabs`, `DitekSHen`, and `Signature Base`).
5. **Minimized reproducer verification**: Every failure class reported below was reduced to a minimal self-contained rule that compiles cleanly with `yarac 4.6.0` and triggers the documented error in `go-yara`.

## Overall Compiler Audit (`11,866` Rules)

| Outcome / First Failure Phase | Rules | Share | Primary Causes |
| --- | ---: | ---: | --- |
| Compiles cleanly (`ok`) | 7,102 | 59.9% | Ready to compile and scan today |
| `parsing` failure | 1,965 | 16.6% | >500-byte hex lookback (`1,893`), negative `meta:` int (`27`), parenthesized range arithmetic (`24`), `base64` modifier combinations (`15`), `expected '}'` (`3`), `expr..expr` without space (`3`) |
| `imports` failure | 29 | 0.2% | Unsupported non-PE modules: `dotnet` (`16`), `elf` (`11`), `console` (`2`) |
| `semantic` failure | 2,770 | 23.3% | Unsupported PE attributes (`1,582`), duplicate `meta:` keys (`1,187`), unsupported PE function `pe.rich_signature.toolid` (`1`) |
| **Total** | **11,866** | **100.0%** | **0 external variable errors** |

Duplicate `meta:` key distribution across the full corpus (`1,187` rules): `hash` (`1,178`), `packed` (`6`), `actor_type` (`2`), `version` (`1`).

## Non-PE Blockers Separated from PE Scope

All nine minimized non-PE reproducers below pass `yarac 4.6.0` (`exit 0`) and fail in `go-yara`:

| Failure Class | All Rules | PE Rules | Solo PE Unlocks | Root Cause & Verified Minimized Reproducer |
| --- | ---: | ---: | ---: | --- |
| Hex lookback limit (`got LBRACE`) | 1,893 | 36 | 34 | `internal/lexer/scanner_hex.go` `isInStringsSection` limits lookback to 500 bytes; once a hex literal exceeds 500 bytes and contains two whitespace-separated decimal-looking bytes (e.g. `50 72`), `looksLikeArithmeticExpression()` classifies the next `{` as `LBRACE`: `$pad = { <200x "41"> 50 72 } $b = { 4D 5A }` |
| Duplicate `meta:` keys | 1,187 | 162 | 81 | Semantic checker rejects repeated `meta:` keys such as multi-sample hashes (`meta: hash = "aaa" hash = "bbb"`), whereas `libyara` allows duplicate meta keys |
| Negative integers in `meta:` | 27 | 0 | 0 | Parser rejects unary `-` in `meta:` (`meta: score = -10` -> `invalid meta value type 'MINUS'`) |
| Range arithmetic / indexed offset in parens | 24 | 1 | 0 | Parser expects `)` inside `$b in ( @a .. @a + 100 )` and `for any i in (1..#a) : ( $b in ( @a[i] .. @a[i] + 10 ) )` (blocks `SEKOIA_Implant_Win_Sliver_Dll`) |
| `base64` modifier combinations | 15 | 0 | 0 | Parser rejects `"hello" base64 wide` (`9`) and `"hello" base64 base64wide` (`6`) |
| `..` range operator without space | 3 | 3 | 2 | Lexer tokenizes `.` before `..` in `$mz in ( s.raw_data_offset..s.raw_data_offset + s.raw_data_size )` (`expected identifier after '.'`) |
| `$xor` identifier / `@1 [ 1 ]` spacing | 3 | 0 | 0 | `#xor > 0` (`$xor = "a"`) tokenizes `xor` keyword instead of string identifier (`2` rules); `@1 [ 1 ] < @2 [ 1 ]` with space before `[` fails rule end (`1` rule) -> `expected '}' at end of rule` |
| Unsupported non-PE modules | 29 | 2 | 2 | `dotnet` (`16` total, `1` PE), `elf` (`11` total, `0` PE), `console` (`2` total, `1` PE) — note `pe`, `hash`, `math`, and `string` are already supported |

*PE-subset unlock insight*: Resolving only the non-PE syntax/lexer/parser/duplicate-meta bugs (with **zero** new PE module work) immediately unlocks **118 PE rules** (`232 -> 350`) and **~3,100+ non-PE rules** across the full corpus.

## PE-Subset Partition (`2,018` Rules Using `pe`)

| Category | PE Rules | Share | Distinct Repos | Notes |
| --- | ---: | ---: | ---: | --- |
| Compiles cleanly today | 232 | 11.5% | 20 | 212 normalized families (includes cross-rule `private` dependencies) |
| Blocked **only** by non-PE syntax / duplicate `meta` | 118 | 5.8% | 12 | `81` duplicate meta key, `34` >500B hex lookback, `2` no-space `..`, `1` `@a .. @a + N` |
| Blocked **only** by non-PE module imports | 2 | 0.1% | 2 | `console` (`1`), `dotnet` (`1`) |
| Blocked **only** by unimplemented PE slices (`#474`–`#478`) | 1,582 | 78.4% | 11 | Direct PE module unlocks once respective slice lands |
| Blocked by **both** PE slices and non-PE syntax / meta | 84 | 4.2% | 8 | All non-PE co-blockers here are duplicate `meta` (`81`) or syntax (`3`) |
| **Total PE rules** | **2,018** | **100.0%** | **25** | Combined unlock if all PE slices + syntax/meta land: **2,016 / 2,018 (99.9%)** |

## Implemented PE Capabilities Used in `20261108`

All 26 `pe` features below are implemented in `go-yara` and actively referenced in the pinned corpus:

| Implemented `pe` API / Constant | Corpus Rules | Repos | Normalized Families |
| --- | ---: | ---: | ---: |
| `pe.imphash()` | 203 | 10 | 173 |
| `pe.exports(string)` | 100 | 11 | 95 |
| `pe.number_of_sections` | 46 | 6 | 46 |
| `pe.sections[].raw_data_size` | 40 | 5 | 40 |
| `pe.sections[].raw_data_offset` | 36 | 4 | 36 |
| `pe.number_of_exports` | 19 | 6 | 19 |
| `pe.is_dll()` | 17 | 5 | 17 |
| `pe.entry_point` | 15 | 2 | 15 |
| `pe.DLL` | 15 | 6 | 15 |
| `pe.imports(string, string)` | 15 | 9 | 15 |
| `pe.sections[].name` | 14 | 7 | 14 |
| `pe.imports(string)` | 14 | 5 | 14 |
| `pe.characteristics` | 12 | 5 | 12 |
| `pe.is_pe` | 8 | 4 | 8 |
| `pe.section_index(string)` | 7 | 6 | 7 |
| `pe.timestamp` | 7 | 2 | 5 |
| `pe.number_of_imports` | 3 | 3 | 3 |
| `pe.data_directories[].size` (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`) | 2 | 2 | 2 |
| `pe.export_details` (`.forward_name`, `.name`, `.offset`) | 2 | 2 | 2 |
| `pe.is_32bit()` / `pe.is_64bit()` | 2 / 2 | 1 | 2 |
| `pe.machine` (`MACHINE_AMD64`: 2, `MACHINE_I386`: 1, `MACHINE_IA64`: 1) | 2 | 1 | 2 |
| `pe.sections[].characteristics` (`SECTION_MEM_EXECUTE`, `SECTION_MEM_WRITE`) | 1 | 1 | 1 |
| `pe.data_directories[].virtual_address` | 1 | 1 | 1 |
| `pe.overlay.offset` / `pe.overlay.size` | 1 | 1 | 1 |
| `pe.subsystem` (`SUBSYSTEM_NATIVE`) | 1 | 1 | 1 |

## Unimplemented PE Work-Slice Benefit Matrix

| Work Slice | Total PE Rules | Solo Today | After Syntax/Meta Fixes | Distinct Repos | Normalized Families | Exact Corpus Subfields & Overloads |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `#478` Signature metadata | 1,608 | 1,544 | 1,605 | 9 | 40 | `number_of_signatures` (1,607 / 39 fams), `signatures[].serial` (1,582 / 15), `.subject` (1,575 / 16), `.not_after` (930 / 2), `.issuer` (27 / 18), `.thumbprint` (3 / 3), `.not_before` (1 / 1), `signatures` array (1) |
| `#474` Resources | 32 | 18 | 26 | 8 | 32 | `number_of_resources` (32), `resources[].offset` (24), `.length` (22), `.name_string` (5), `.type` (4), `.language` (3), `.id` (1), `.type_string` (1), `resources` array (3), `RESOURCE_TYPE_VERSION` (1), `RESOURCE_TYPE_RCDATA` (1) |
| `#476` Rich signature | 25 | 9 | 20 | 3 | 25 | `rich_signature.clear_data` (20), `rich_signature.toolid(int, int)` (5), `rich_signature.length` (1) |
| `#475` Version info | 8 | 5 | 6 | 5 | 8 | `version_info[string]` (`version_info[]`: 8) |
| `#477` PDB path | 2 | 1 | 1 | 2 | 2 | `pdb_path` (2) |
| `#481` Verified signatures | 0 | 0 | 0 | 0 | 0 | `is_signed`, `verified`, `valid_on`, `digest`, `algorithm`: `0` direct references in `20261108` *(trust/security semantic prerequisite for Authenticode verification rather than raw rule count)* |

*Multi-slice overlaps (`8` rules total)*:
- 4 rules need `#474` + `#476`: `SEKOIA_Downloader_Win_Apt33_Tickler`, `SEKOIA_Dropper_Win_Ninerat`, `SEKOIA_Stealer_Win_Luca`, `SEKOIA_Backdoor_Win_Mgbot_Main`
- 1 rule needs `#474` + `#475` + `#477`: `R3C0NST_ATM_Malware_Ploutusi`
- 1 rule needs `#474` + `#478`: `SEKOIA_Wiper_Hermeticwiper_Variants`
- 1 rule needs `#476` + `#478`: `SEKOIA_Rootkit_Win_Purplefox_Kernel_Driver`
- 1 rule needs `#475` + `#478`: `SEKOIA_Yara_Runascs`

*Deduplication note*: While `#478` unlocks `1,608` rules by raw count (`1,544` solo today, `1,605` after syntax/meta), `944` of those are generated `ReversingLabs` certificate-blocklist rules and `646` are generated `DitekSHen` certificate/signer rules, leaving `40` distinct normalized families across `9` repositories (`Signature Base`, `SEKOIA`, `DitekSHen`, `ReversingLabs`, `Trellix ARC`, `R3c0nst`, `WithSecureLabs`, `EmbeeResearch`, `Cod3nym`). Conversely, `#474` (`32` rules across `8` repos / `32` unique families) and `#476` (`25` rules across `3` repos / `25` unique families) represent nearly 1:1 unique malware family coverage.

## Behavioral Parity & Strict-Compatibility Validation

Compilation alone does not prove semantic parity. Behavioral verification against `libyara` is enforced in CI via:

* [`tests/integration/pe_capability_matrix_test.go`](../tests/integration/pe_capability_matrix_test.go):
  * `TestLibyaraPECapabilityMatrix`: Exercises representative YARA Forge rule idioms (`private` rule gating + PE predicates, `imphash`, `imports` name/ordinal/regex counts, `exports` & `export_details` loops, `sections` & loop-variable aliasing, `section_index`, `data_directories` / `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`, `overlay.offset` / `overlay.size`, `is_pe` / `is_dll()` / `is_32bit()` / `is_64bit()` / `machine` / `subsystem` / `timestamp`) across generated PE32, PE32+, overlay, non-PE, and empty fixtures through buffer, file, reader, `MatchingRules`, and compiled-program round trips.
  * `TestPECapabilityMatrixUnsupportedAndStrict`: Asserts compile-time semantic rejection for `#474`–`#478` slices (versus clean `libyara` compilation) and verifies strict `go-pe` header validation (`>16` data directories) sets `pe.is_pe == 0` with undefined subfields rather than clamping permissively.
* [`tests/integration/pe_differential_test.go`](../tests/integration/pe_differential_test.go): Differential parity suite plus deliberate strict-parser compatibility tests (`TestLibyaraPEStrictHeaderCompatibility`).

## Source & License Manifest (40 Upstream Repositories)

| Source Repository | Pinned Commit | Total Rules | Compiling | PE Rules | Compiling PE | Upstream License Header |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| [ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules/) | `e0a0be54aa1e` | 1,240 | 15 | 946 | 2 | Copyright (c) 2020 ReversingLabs |
| [R3c0nst](https://github.com/fboldewin/YARA-rules/) | `54e9e6899b25` | 26 | 16 | 4 | 2 | NO LICENSE SET |
| [CAPE](https://github.com/kevoreilly/CAPEv2) | `03679e437795` | 192 | 160 | 2 | 2 | Cuckoo Sandbox Copyright / GPL (per banner) |
| [BinaryAlert](https://github.com/airbnb/binaryalert/) | `a9c0f06affc3` | 84 | 72 | 2 | 2 | Apache License |
| [DeadBits](https://github.com/deadbits/yara-rules/) | `d002f7ecee23` | 19 | 19 | 0 | 0 | NO LICENSE SET |
| [DelivrTo](https://github.com/delivr-to/detections) | `f85e1d0c477c` | 11 | 11 | 0 | 0 | NO LICENSE SET |
| [ESET](https://github.com/eset/malware-ioc) | `825b826c5cbf` | 128 | 108 | 15 | 6 | Copyright (c) 2014-2018 ESET spol. s r.o. |
| [FireEye-RT](https://github.com/mandiant/red_team_tool_countermeasures/) | `3561b71724db` | 166 | 153 | 1 | 1 | BSD 2-Clause License |
| [GCTI](https://github.com/chronicle/GCTI) | `1c5fd42b1895` | 90 | 90 | 0 | 0 | Apache License |
| [Malpedia](https://github.com/malpedia/signator-rules/) | `c252249801c8` | 1,670 | 464 | 0 | 0 | NO LICENSE SET |
| [Trellix ARC](https://github.com/advanced-threat-research/Yara-Rules/) | `1919562a59f1` | 163 | 120 | 25 | 8 | Apache License |
| [Arkbird SOLG](https://github.com/StrangerealIntel/DailyIOC) | `a873ff1298c4` | 215 | 29 | 13 | 9 | NO LICENSE SET |
| [Telekom Security](https://github.com/telekom-security/malware_analysis/) | `755efb66586f` | 12 | 11 | 0 | 0 | MIT License |
| [Volexity](https://github.com/volexity/threat-intel) | `683296427d8c` | 148 | 126 | 3 | 1 | Copyright 2022 by Volexity, Inc. |
| [JPCERTCC](https://github.com/JPCERTCC/MalConfScan/) | `19ec0d145535` | 29 | 27 | 0 | 0 | The 3-Clause BSD License |
| [SecuInfra](https://github.com/SIFalcon/Detection) | `2d7c66d7d16c` | 45 | 35 | 7 | 2 | NO LICENSE SET |
| [RussianPanda](https://github.com/RussianPanda95/Yara-Rules) | `b59e13d90d02` | 114 | 107 | 11 | 11 | NO LICENSE SET |
| [CadoSecurity](https://github.com/mikesxrs/Open-Source-YARA-rules) | `ec0056f767db` | 8 | 6 | 0 | 0 | NO LICENSE SET |
| [Check Point](https://github.com/mikesxrs/Open-Source-YARA-rules) | `ec0056f767db` | 4 | 1 | 0 | 0 | NO LICENSE SET |
| [BlackBerry](https://github.com/mikesxrs/Open-Source-YARA-rules) | `ec0056f767db` | 22 | 19 | 8 | 5 | NO LICENSE SET |
| [Cluster25](https://github.com/mikesxrs/Open-Source-YARA-rules) | `ec0056f767db` | 9 | 5 | 3 | 1 | NO LICENSE SET |
| [Dragon Threat Labs](https://github.com/mikesxrs/Open-Source-YARA-rules) | `ec0056f767db` | 7 | 7 | 0 | 0 | NO LICENSE SET |
| [Microsoft](https://github.com/mikesxrs/Open-Source-YARA-rules) | `ec0056f767db` | 21 | 21 | 1 | 1 | NO LICENSE SET |
| [NCSC](https://github.com/mikesxrs/Open-Source-YARA-rules) | `ec0056f767db` | 17 | 17 | 1 | 1 | NO LICENSE SET |
| [Dr4k0nia](https://github.com/dr4k0nia/yara-rules) | `4b10f9b79a4c` | 5 | 2 | 0 | 0 | Detection Rule License (DRL) 1.1 |
| [EmbeeResearch](https://github.com/embee-research/Yara-detection-rules/) | `ac56d6f6fd2a` | 39 | 19 | 2 | 0 | NO LICENSE SET |
| [AvastTI](https://github.com/avast/ioc) | `eb6d7fc10cb0` | 33 | 30 | 0 | 0 | NO LICENSE SET |
| [SBousseaden](https://github.com/sbousseaden/YaraHunts/) | `71b27a2a7c57` | 37 | 31 | 6 | 6 | NO LICENSE SET |
| [Elceef](https://github.com/elceef/yara-rulz) | `5683b294a12c` | 20 | 12 | 0 | 0 | MIT License |
| [GodModeRules](https://github.com/Neo23x0/god-mode-rules/) | `436dc682164c` | 1 | 0 | 0 | 0 | Apache License |
| [Cod3nym](https://github.com/cod3nym/detection-rules/) | `a9f1cbab3840` | 12 | 10 | 1 | 0 | Detection Rule License (DRL) 1.1 |
| [craiu](https://github.com/craiu/yararules) | `23cf0ca22021` | 13 | 7 | 0 | 0 | GNU GENERAL PUBLIC LICENSE |
| [DitekSHen](https://github.com/ditekshen/detection) | `e76c93dcdedf` | 1,442 | 772 | 671 | 25 | Copyright 2021 by ditekSHen |
| [WithSecureLabs](https://github.com/WithSecureLabs/iocs) | `1a8384468dd2` | 27 | 18 | 9 | 3 | BSD 2-Clause License |
| [HarfangLab](https://github.com/HarfangLab/iocs) | `3e2b674bf2f5` | 39 | 33 | 0 | 0 | NO LICENSE SET |
| [LOLDrivers](https://github.com/magicsword-io/LOLDrivers/) | `39c70ca64ae9` | 21 | 21 | 0 | 0 | Apache License |
| [SEKOIA](https://github.com/SEKOIA-IO/Community) | `1bf54592ffd5` | 746 | 592 | 82 | 27 | Detection Rule License (DRL) 1.1 |
| [Synacktiv](https://github.com/synacktiv/synacktiv-rules) | `d234cc4da078` | 8 | 0 | 0 | 0 | Detection Rule License (DRL) 1.1 |
| [ArtifactDrop](https://github.com/matthieugras/artifact-drop/) | `d2bcbe820bc1` | 1 | 1 | 0 | 0 | NO LICENSE SET |
| [Signature Base](https://github.com/Neo23x0/signature-base) | `de3c7252c22b` | 4,982 | 3,915 | 205 | 117 | Detection Rule License (DRL) 1.1 |
