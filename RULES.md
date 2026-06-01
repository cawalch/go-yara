## Agent shell rules

- Use `python3`, not `python`.
- Never pass multiline markdown, JSON, YAML, code, or PR bodies directly as shell arguments.
- For multiline content, write a temp file first, then pass the file path.
- For `gh pr create`, prefer:
  - `gh pr create --fill-verbose`, or
  - `gh pr create --title "..." --body-file /tmp/pr_body.md`
- Before creating a PR, run:
  - `git status --short`
  - `git diff --stat origin/main...HEAD`
  - `go test ./...`
- If a shell command fails due to quoting, do not retry with more escaping. Switch to a file-based approach.
- Keep PR bodies concise. Do not paste large diffs or test logs into the PR body.

## Context/read discipline

- Do not bulk-read multiple whole files late in a session.
- Before reading files, prefer:
  - reamerx mcp / skill
  - `wc -l file`
  - `rg "pattern" path`
  - `sed -n 'start,endp' file`
  - `git diff --stat`
  - `git diff --name-only`
- If more than two files need inspection, read them one at a time and summarize findings before continuing.
- When context is large, avoid full test-file reads unless necessary.
- For large files, inspect targeted functions or failing test names instead of reading the entire file.
- If the agent needs broad context, create a short repo map or summary file instead of loading many files into chat.
