"""Exercise the native and Node WASI Preview 1 comparator on the same fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples/pcap/update-review"
CORPUS = {"control": "control.pcap", "positive": "positive.pcap",
          "split": "positive-split.pcap", "unavailable": "unavailable.pcap"}


def run(args, *, env=None):
    return subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True,
                          timeout=120, check=False)


def check(result, expected):
    if result.returncode != expected:
        raise ValueError(f"Expected status {expected}, got {result.returncode}\n{result.stderr}\n{result.stdout}")
    return json.loads(result.stdout) if result.stdout else None


def arguments(directory, candidate, manifest, captures):
    return ["-baseline", f"{directory}/baseline.yar", "-candidate", f"{directory}/{candidate}",
            "-expect", f"{directory}/{manifest}"] + [f"{key}={directory}/{name}" for key, name in captures.items()]


def comparable(report):
    return {key: value for key, value in report.items() if key != "engine"} if report is not None else None


def stage_cases(directory):
    files = {*CORPUS.values(), "baseline.yar", "candidate.yar", "alternate.yar", "corpus.json",
             "evidence-change.json", "entities.pcap"}
    for filename in files:
        shutil.copyfile(FIXTURES / filename, directory / filename)
    invalid = b"invalid capture fixture"
    (directory / "invalid.pcap").write_bytes(invalid)
    fixture = {
        "id": "invalid", "sha256": hashlib.sha256(invalid).hexdigest(), "rule": "revoked_update",
        "mode": "http", "baseline": {"outcome": "unobservable"}, "candidate": {"outcome": "unobservable"},
    }
    (directory / "invalid.json").write_text(json.dumps({"schema_version": 1, "fixtures": [fixture]}))
    (directory / "too-many.json").write_text(json.dumps({
        "schema_version": 1, "fixtures": [{**fixture, "id": str(i)} for i in range(33)],
    }))
    cases = [
        ("corpus", "candidate.yar", "corpus.json", CORPUS, [], 0),
        ("different", "alternate.yar", "evidence-change.json", {"different": "entities.pcap"}, [], 0),
        ("mismatch", "candidate.yar", "corpus.json", {**CORPUS, "positive": "control.pcap"}, [], 2),
        ("invalid", "candidate.yar", "invalid.json", {"invalid": "invalid.pcap"}, [], 1),
        ("budget", "candidate.yar", "too-many.json", {str(i): "invalid.pcap" for i in range(33)}, [], 1),
        ("cancelled", "candidate.yar", "corpus.json", CORPUS, ["-timeout", "1ns"], 1),
    ]
    return cases


def verify(output, native_only):
    with tempfile.TemporaryDirectory(prefix="go-yara-pcap-parity-") as temp:
        workspace = Path(temp)
        fixture_dir = workspace / "fixtures"
        fixture_dir.mkdir()
        cases = stage_cases(fixture_dir)
        for path in fixture_dir.iterdir():
            path.chmod(0o444)
        fixture_dir.chmod(0o555)
        try:
            base_env = {**os.environ, "GOWORK": "off", "CGO_ENABLED": "0"}
            native = workspace / ("compare.exe" if os.name == "nt" else "compare")
            subprocess.run(["go", "build", "-o", native, "./cmd/compare"], cwd=ROOT, env=base_env, check=True)
            wasm = workspace / "compare.wasm"
            if not native_only:
                wasm_env = {**base_env, "GOOS": "wasip1", "GOARCH": "wasm"}
                subprocess.run(["go", "build", "-trimpath", "-ldflags=-s -w", "-o", wasm, "./cmd/compare"],
                               cwd=ROOT, env=wasm_env, check=True)
            references = {}
            for label, candidate, manifest, captures, flags, code in cases:
                native_args = arguments(fixture_dir, candidate, manifest, captures)
                reference = check(run([native, *flags, *native_args]), code)
                if code == 0:
                    references[label] = reference
                if native_only:
                    print(f"{label}: native status {code}", flush=True)
                else:
                    wasm_args = arguments("/fixtures", candidate, manifest, captures)
                    result = run(["node", ROOT / "scripts/wasi-compare.mjs", wasm, fixture_dir, *flags, *wasm_args])
                    observed = check(result, code)
                    if label == "cancelled" and "deadline exceeded" not in result.stderr:
                        raise ValueError("WASI cancellation did not report its deadline")
                    if comparable(observed) != comparable(reference):
                        raise ValueError(f"Native and WASI reports differ for {label}")
                    metrics = json.loads(result.stderr.splitlines()[-1])
                    print(f"{label}: native/WASI status {code} and report agree {json.dumps(metrics)}", flush=True)
            if output is not None:
                output.write_text(json.dumps(references, indent=2) + "\n")
        finally:
            fixture_dir.chmod(0o755)
            for path in fixture_dir.iterdir():
                path.chmod(0o644)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-only", action="store_true", help="verify only the native command")
    parser.add_argument("--output", type=Path, help="write reference reports for the browser suite")
    options = parser.parse_args()
    verify(options.output, options.native_only)
