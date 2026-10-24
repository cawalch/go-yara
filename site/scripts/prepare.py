"""Run the displayed examples and derive reference data from one Go revision."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

SITE = Path(__file__).resolve().parents[1]
ROOT = SITE.parent


def run(args, cwd, **kwargs):
    return subprocess.check_output(args, cwd=cwd, text=True, **kwargs)


def prepare(ref, check_only):
    with tempfile.TemporaryDirectory(prefix="go-yara-docs-") as directory:
        temp = Path(directory)
        if ref == "HEAD":
            source = ROOT
            version = "main"
        else:
            if not re.fullmatch(r"v\d+\.\d+\.\d+", ref):
                raise ValueError("Use HEAD or a stable vMAJOR.MINOR.PATCH tag")
            source = temp / "source"
            source.mkdir()
            archive = subprocess.check_output(["git", "archive", ref], cwd=ROOT)
            with tarfile.open(fileobj=io.BytesIO(archive)) as files:
                files.extractall(source, filter="data")
            version = ref
        env = {**os.environ, "GOWORK": "off"}
        outputs = {"quickstart": "greeting\n", "reuse": "false\ntrue\n",
                   "modules": "true\n", "serialization": "true\n"}
        for name, expected in outputs.items():
            output = run(["go", "run", str(SITE / "examples" / name / "main.go")], source, env=env)
            if output != expected:
                raise ValueError(f"{ref}: {name}: expected {expected!r}, got {output!r}")
            print(f"{ref}: {name} example passed", flush=True)
        catalog = json.loads(run(["go", "run", str(SITE / "examples/catalog/main.go")], source, env=env))
        binary = temp / "go-yara"
        run(["go", "build", "-o", str(binary), "./cmd"], source, env=env)
        cli_env = {**env, "PATH": str(temp) + os.pathsep + env["PATH"]}
        output = run(["sh", str(SITE / "examples/cli.sh")], temp, env=cli_env)
        lines = output.splitlines()
        if len(lines) != 2 or "greeting" not in lines[0]:
            raise ValueError(f"Unexpected CLI output: {output}")
        hit = json.loads(lines[1])
        if hit["rule"] != "greeting" or hit["matches"][0]["offset"] != 0:
            raise ValueError(f"Unexpected CLI match: {hit}")
        for mode in ["compile", "lex", "parse"]:
            run([str(binary), "greeting.yar", f"--mode={mode}"], temp, env=cli_env)
        print(f"{ref}: CLI example passed", flush=True)
        help_result = subprocess.run([str(binary), "--help"], capture_output=True, text=True, env=env)
        help_text = help_result.stdout + help_result.stderr
        if "Usage: go-yara" not in help_text or "-streaming" not in help_text:
            raise ValueError("CLI help could not be generated")
        if check_only:
            return
        if version == "main":
            raise ValueError("Published reference data must use a release tag")
        review = json.loads((SITE / "reviews.json").read_text())
        if version not in review or len(review[version]["pages"]) != 9:
            raise ValueError(f"Review all nine pages for {version} and record it in site/reviews.json before publishing")
        go_version = re.search(r"^go ([\d.]+)$", (source / "go.mod").read_text(), re.M)[1]
        changelog = (source / "CHANGELOG.md").read_text()
        release_section = re.search(r"^## \[" + re.escape(version) + r"\] - (\S+)\n(.*?)(?=^## \[|\Z)", changelog, re.M | re.S)
        if not release_section:
            raise ValueError(f"No dated changelog section for {version}")
        serialization = (source / "compiler/serialization.go").read_text()
        reader_guard = re.search(r"if (version != .*?) \{", serialization)
        if not reader_guard or "compiledProgramVersion" not in reader_guard[1]:
            raise ValueError("Serialization reader changed; update the reference extraction after review")
        readable_formats = sorted({catalog["format"], *map(int, re.findall(r"version != (\d+)", reader_guard[1]))})
        generated = SITE / "src/generated"
        generated.mkdir(parents=True, exist_ok=True)
        metadata = {"version": version, "goVersion": go_version,
                    "commit": run(["git", "rev-parse", ref + "^{commit}"], ROOT).strip(),
                    "date": release_section[1], "readableFormats": readable_formats, **catalog}
        (generated / "release.json").write_text(json.dumps(metadata, indent=2) + "\n")
        (generated / "cli.txt").write_text(help_text)
        print(f"Generated reference for {version}, format {catalog['format']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--check-only", action="store_true")
    arguments = parser.parse_args()
    prepare(arguments.ref, arguments.check_only)
