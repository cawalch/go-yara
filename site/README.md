# Documentation site

The nine public pages use Astro Starlight and deploy to [GitHub Pages](https://cawalch.github.io/go-yara/). Read [WRITING.md](WRITING.md) before editing. Sources live in `src/content/docs/`; generated files and build output are ignored.

## Local checks

Use Node 26, Python 3.12 or later, and the Go version required by the repository. From the repository root:

```sh
npm ci --prefix site
python3 site/scripts/prepare.py --ref HEAD --check-only
python3 site/scripts/prepare.py --ref "$(gh release view --json tagName --jq .tagName)"
npm run build --prefix site
npm run check --prefix site
npm run check-external --prefix site
cd site
npx playwright install chromium firefox webkit
npm run test-playground
cd ..
npm run dev --prefix site
```

Open the local URL with `/go-yara/` appended. A production preview uses `npm run preview --prefix site`.

## Preventing drift

Examples also cover text/hex/regex conditions, detailed result semantics, sparse-block overlap, external-value replacement, custom callbacks after deserialization, tolerant compilation diagnostics, and cancellation. Additional examples cover hook lifecycle events, telemetry counters and reset, stop-on-match versus poll abort, semantic diagnostic codes, and runtime undefined values. CLI checks cover recursive JSON with metadata, no-match success, and compilation errors.

The evidence examples exercise ready, partial, ambiguous, and truncated findings, a fixture validator handoff, and real offline PKCS#8 parsing. Their checked output is imported beside their source on the scanning page. They make no network validation requests.

The deployment workflow resolves the latest stable GitHub release on every build. It runs the displayed Go and CLI examples against that tag, then repeats them against the working tree. Code blocks import those same files; copied Go snippets are rejected. A program compiled against the release exports the module signatures and serialized format version. The release's `go.mod`, changelog, commit, and built CLI supply the version stamp and help output. The playground builder overlays its current bridge onto a temporary copy of that same release, pairs its binary with the compiling toolchain's runtime shim, and writes content-addressed assets. The build validates the embedded version, asset files, and binary hash.

Every page shows its release version and links to that release. The site has one current version; older release notes remain on GitHub. A release publication or completion of the Release workflow rebuilds the site. The latter also covers releases created with `GITHUB_TOKEN`, which do not trigger another release event workflow. Pushes to `main` rebuild it too, so prose fixes do not need a Go release. Internal links, anchors, local assets, canonical URLs, page metadata, and the nine-page sitemap are checked on every build. External links are checked before deployment.

Automated checks cannot establish that every explanatory sentence still matches the implementation. Use this table during code review. For an unreleased behavior change, add a documentation task to the changelog and finish the corresponding prose change before publishing the release. Do not update a page to promise unreleased behavior.

| Changed code or contract | Pages to review |
| --- | --- |
| Compiler API, imports, rule syntax, semantic validation | Quickstart diagnostics, compatibility, modules |
| Hooks, telemetry, instrumentation paths | Performance metrics, scanning control hooks; remove the v0.8.0 timing/profile gaps and update completion ordering when releasing the current main fixes |
| Scanner results, readers, blocks, cancellation | Scanning, performance, compatibility |
| Capture groups, evidence correlation, finding status | Scanning credential examples, compatibility |
| Module definitions, schemas, binding, cache | Modules, compatibility, performance |
| CLI flags, output, exit behavior | CLI, installation |
| Go requirement, packaging, release assets | Installation, releases |
| Serialization reader or writer | Releases, compatibility |
| Optimization or benchmark claim | Performance, including source links, applicability limits, and measurement scope |

The engine comparison records separate versions for libyara and YARA-X. During release review, recheck those pinned sources and the comparison date; do not present them as automatically current. Historical benchmark figures retain their original release attribution and must not be relabeled as measurements of a newer release.

`src/components/ArchitectureDiagram.astro` contains the pipeline, scanner-ownership, sparse-block, module-binding, evidence-validation, serialization, semantic-analysis, telemetry-export, and browser diagrams. Review their labels with the adjacent prose when those contracts change. They use HTML text and CSS, reflow on narrow screens, and add no diagram-rendering JavaScript.

The [browser playground](playground/README.md) has native fixture tests, byte-budget and memory-section tests, and a headed Chromium/Firefox/WebKit suite. All three engines must pass before Pages deploys. The same suite opens the longer documentation examples and checks diagram bounds and horizontal overflow in desktop/light and mobile/dark layouts. Browser binaries and traces are ignored; generated runtime assets are included only in the Pages artifact. Astro checks the UI/client; the worker is syntax-checked and exercised by the browser suite. CI uses Go 1.27.2 to build the runtime; review the memory-section transformation when changing toolchains.

The [Wasm spike](spikes/wasm/README.md) remains a dated experiment, separate from the maintained playground. Its WASI probe does not establish a supported host ABI.

Keep the README as the repository entry point and the site as the task-oriented guide. API details belong in Go doc comments and pkg.go.dev. Avoid adding a second handwritten API signature table.

## Release check

Before tagging, review prose for behavior changes since the previous tag. Record the release, all nine page names, and the review scope in `reviews.json`. Keep older entries so a pre-release build can still validate the current stable version. If prose must change for the new release, publish the matching docs change once that tag is available. The build refuses to deploy a release absent from the review record. This deliberate gate prevents generated version labels from making unreviewed prose look current.

After publishing, run the checks above and confirm the Pages workflow passed and the live release stamp, download links, navigation, and search match the new release. The generated reference refuses an untagged version; a missing or malformed release fails the build instead of silently publishing `main` documentation.
