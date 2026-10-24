# Writing the go-yara docs

Write for a Go developer who has a rule set and needs to make a decision or finish a task. Lead with the answer, show working code, then explain the constraints that affect its use.

## Sources and decisions

This guide draws on these sources, reviewed on 2026-10-24:

- [Google developer documentation style: tone](https://developers.google.com/style/tone): be conversational, direct, and respectful. Avoid promotional language, filler, and claims that a task is easy.
- [Google style highlights](https://developers.google.com/style/highlights): use active voice, descriptive links, sentence case, and conditions before instructions.
- [Microsoft: scannable content](https://learn.microsoft.com/en-us/style-guide/scannable-content/): put useful information first; keep paragraphs focused; use tables when readers need to compare.
- [Diátaxis](https://diataxis.fr/): distinguish a guided first success, instructions for a task, reference facts, and explanations of tradeoffs.

These are editorial choices, not a recipe for making every sentence sound alike. Read the finished page aloud. Vary sentence length when the thought calls for it. A short sentence can state a limit; the next paragraph can explain why it matters.

## Page contract

Each page answers one reader question. Its first paragraph gives a useful answer without announcing what the page will cover. Headings describe tasks or concepts. Paragraphs develop one idea, usually in two to four sentences; do not split every sentence into a separate paragraph.

Use the tone of a maintainer explaining the code to another developer. Name the subject directly: “Documentation,” “Scan results,” “Function arguments,” or “Benchmarks.” Avoid generic coaching headings such as “Find the detail you need,” “Where it fits,” “Choose the result you need,” and “Run a useful comparison.” They add a helpful-sounding voice without identifying the technical subject. Instructions such as “Build from source” are appropriate because they name a concrete operation.

Apply the same rule to body text. State what a function does, what it returns, or what the reader must do. Omit invitations to explore, navigation patter, slogans, and repeated assurances about the documentation. Keep testing and publishing details in the maintenance guide or the documentation-version section. Do not make the prose stiff or remove useful explanations just to shorten it.

Use complete examples where setup matters. Put the expected result next to the command. Explain a constraint before the reader encounters it: memory use, unsupported modules, result ownership, or a serialization boundary.

Prefer prose for explanations, numbered steps for a dependent sequence, and tables for choices. Use lists only for parallel items. Skip decorative cards, slogans, emoji, and stock illustrations. The interface should give space to code and reading.

## Editing examples

| Avoid | Prefer |
| --- | --- |
| “Unlock seamless, blazing-fast YARA scanning.” | “Compile YARA rules and scan byte slices in Go, without CGO.” |
| “Simply use ScanReader for streaming.” | “ScanReader reads the entire input into memory before evaluating rules.” |
| “In this comprehensive guide, we'll explore…” | Start with the instruction or answer. |
| “Production-ready YARA compatibility.” | Name the supported features and link to the differences. |
| “Zero allocations.” | State the scan path, warm-up requirement, and measurement. |
| “Find the detail you need” | “Documentation” |
| “Start with the result contract” | “Result collection” |
| “Memory before throughput” | “Input memory use” |

Avoid “leverage,” “delve,” “seamless,” “robust,” “powerful,” “effortlessly,” “it's worth noting,” and “let's dive in.” Do not replace them mechanically with synonyms. Remove the empty claim. Avoid repetitive “X, not Y” contrasts and artificial question-and-answer headings.

Use `go-yara` for this project and `libyara` for the native engine. Use exact API names. Distinguish supported behavior, an extension, a known limitation, and a measured result. Never infer full YARA compatibility from a successful example.

For performance explanations, describe the mechanism, when it applies, and its costs. Link implementation details to release-specific source and cite original papers for the algorithms. Distinguish an algorithmic influence from an implementation of an entire published system. Scope complexity claims to the stage they describe.

Compare engines on concrete properties using versioned primary sources: execution model, integration requirements, module coverage, and semantics. State where another engine already provides functionality that go-yara lacks. Avoid rankings without matched measurements, and do not infer speed from implementation language or the absence of CGO. Record the comparison date and versions; review them separately from go-yara's generated version stamp.

## Review before publishing

1. Can a reader act on the opening paragraph?
2. Does each claim have a code, test, or release source? Are performance claims scoped to their measurement?
3. Are limitations next to the relevant operation?
4. Does each paragraph earn its space? Does the page sound like a developer explaining the implementation? Do headings name a subject or operation rather than coach the reader?
5. Do the displayed examples run, and do links and anchors resolve?
6. Does the page describe the published release? If `main` changes behavior, record the required prose update in the same change and complete it before release.

The small phrase check catches accidental filler. It cannot judge accuracy, cadence, or whether prose sounds machine-written. Those remain review responsibilities.
