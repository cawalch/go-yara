# Documentation work

Read `WRITING.md` before changing prose. Keep the nine pages focused on their reader questions. Use tested files from `examples/` for Go code and generated release data for versions, signatures, and CLI help.

Follow `README.md` to validate changes. Published pages describe the latest stable release. Check examples against both that release and the working tree. When changing behavior in the Go library, review the affected pages using the documentation impact table; update release-facing prose before publishing the next release. Do not describe unreleased behavior as available.
