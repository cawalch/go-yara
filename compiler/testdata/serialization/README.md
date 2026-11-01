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
