"""Check source conventions that support the editorial and release policy."""
import json
from pathlib import Path
import re

SITE = Path(__file__).resolve().parents[1]
EXPECTED = {"index", "quickstart", "installation", "scanning", "compatibility",
            "modules", "performance", "cli", "releases"}
pages = list((SITE / "src/content/docs").glob("*.mdx"))
if {page.stem for page in pages} != EXPECTED:
    raise SystemExit("Expected exactly the nine documented routes")
release = json.loads((SITE / "src/generated/release.json").read_text())
reviews = json.loads((SITE / "reviews.json").read_text())
if set(reviews[release["version"]]["pages"]) != EXPECTED:
    raise SystemExit("Release prose review must cover all nine pages")
titles, descriptions = set(), set()
all_text = ""
for page in pages:
    source = page.read_text()
    all_text += source
    title = re.search(r"^title: (.+)$", source, re.M)
    description = re.search(r"^description: (.+)$", source, re.M)
    if not title or not description or not 60 <= len(description[1]) <= 180:
        raise SystemExit(f"{page.name}: missing title or useful description (60–180 characters)")
    if title[1] in titles or description[1] in descriptions:
        raise SystemExit(f"{page.name}: duplicate page metadata")
    titles.add(title[1])
    descriptions.add(description[1])
    if re.search(r"```go\b", source):
        raise SystemExit(f"{page.name}: import executable Go examples instead of copying them")
    for phrase in ["delve", "seamless", "effortlessly", "blazing-fast", "let's dive in", "it's worth noting"]:
        if re.search(r"\b" + re.escape(phrase) + r"\b", source, re.I):
            raise SystemExit(f"{page.name}: edit filler phrase {phrase!r}; see WRITING.md")
for name in ["quickstart", "reuse", "modules", "serialization", "evidence", "evidence-key", "results", "blocks", "externals", "custom-module", "compilation", "cancellation", "patterns"]:
    if f"examples/{name}/main.go?raw" not in all_text:
        raise SystemExit(f"The checked {name} example is not displayed")
if any(f"examples/{name}?raw" not in all_text for name in ["cli.sh", "cli-directory.sh"]):
    raise SystemExit("The checked CLI example is not displayed")
print("Source checks passed: nine pages, unique metadata, imported examples, release prose review")
