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
