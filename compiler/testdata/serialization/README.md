`format17-optional-repeat.goyara` was emitted by `CompiledProgram.MarshalBinary`
from commit `97e14fb61aeebeb4b65d3d5606e27fe7365faa2e`, whose tree is identical to
merged main `03cd51023a3bc5ec7d889c2c1d5ea985f6b74f52`, using Go 1.27.3:

```yara
rule p {strings:$a=/(a?.)+/ ascii wide condition:$a}
```

It preserves the historical occurrences `(0,2), (1,1)` on input `00 21`.
Newly compiled programs use forward-only effective repeat entries and produce
`(0,1), (1,1)`. Both use format 17: the correction changes emitted jump offsets,
not the VM instruction set or serialized schema. Loading or reserializing an
older program must not silently replace its bytecode or matching policy.

`format17-prefix-repeat.goyara` was emitted from the source tree merged as
`e295bc0905700138a44bad2d60ba6eda33c6d45e` (PR #430), using Go 1.27.3:

```yara
rule p {strings:$a=/!(a?.)+/ ascii wide capture(part=1) condition:$a}
```

On `!b!b`, its historical occurrences are `(0,4), (2,2)` and the first
occurrence's capture starts at offset 3. The prefix-atom correction produces
`(0,2), (2,2)`, with the first capture at offset 1. The fixture preserves both
ordinary and distance-limited bytecode, plus capture replay, before that fix.

`format17-start-atoms.goyara` was emitted from the source tree merged as
`61f1818` (PR #431), using Go 1.27.3:

```yara
rule anchored {strings:$a=/^!(a?.)+/ condition:#a>0}
rule alternatives {strings:$a=/(x|xy)(a?.)+/ condition:#a>0}
```

The historical first occurrence has length 4 for `anchored` on `!b!b` and
`alternatives` on `xy!!`. Newly compiled format-18 programs report lengths 2
and 3 respectively. Reading and reserializing this fixture must preserve both
historical behaviors. Format 18 adds an atom-dispatch policy bit; format-17
readers must reject new artifacts rather than silently ignore that policy.

`format18-pe-headers.goyara` was emitted from `03727d7141e5f73a260455d3a7f2490a03af4354`
(PR #452), using Go 1.27.3, before adding standard import fields:

```yara
import "pe"
rule headers {
    condition:
        pe.is_pe and pe.number_of_sections == 2 and pe.sections[0].name == ".text"
}
```

It preserves the original built-in PE schema. Reading and reserializing this
artifact must retain automatic PE loading even after the schema gains fields.

`format18-pe-import-details.goyara` was emitted from `5729d6bb1cfdbf7ec51077e7e6c899f43d8840bf`
(PR #453), using Go 1.27.3, before adding import queries:

```yara
import "pe"
import "string"
rule before_queries {
    condition:
        pe.number_of_imported_functions == 3 and
        pe.import_details[0].functions[1].ordinal == 7 and
        string.length("abc") == 3
}
```

It preserves the import-details schema and historical module function IDs.
Adding `pe.imports` must not change the binding of `string.length` when this
artifact is read and reserialized.

`format18-pe-import-queries.goyara` was emitted from `b60531b94679e2a9cb33727861d669fab23b1e9c`
(PR #454), using Go 1.27.3, before adding the DLL-count overload:

```yara
import "pe"
import "string"
rule before_dll_count {
    condition:
        pe.imports("Example.DLL", "NamedFunction") and
        pe.imports("Example.DLL", 7) and string.length("abc") == 3
}
```

It preserves the two-argument `pe.imports` signatures and module function IDs.
Reading and reserializing it must retain both import queries and the unrelated
`string.length` binding after an overload is added.
