#!/usr/bin/env python3
"""Summarize frozen witness-study artifacts without discarding incomplete cases."""

import json
import math
from pathlib import Path
import re
import statistics
import sys


def benchmarks(paths, prefix):
    values = {}
    for path in paths:
        for line in path.read_text().splitlines():
            match = re.match(r"(" + prefix + r"/\S+?)-\d+\s+\d+\s+(.*)", line)
            if not match:
                continue
            case, variant = match[1].removeprefix(prefix + "/").rsplit("/", 1)
            metrics = values.setdefault(case, {}).setdefault(variant, {})
            for number, unit in re.findall(r"([\d.eE+-]+)\s+(ns/op|B/op|allocs/op|unknown/op)", match[2]):
                metrics.setdefault(unit, []).append(float(number))
    return {
        case: {variant: {unit: {"median": statistics.median(samples), "samples": len(samples)}
                         for unit, samples in metrics.items()}
               for variant, metrics in variants.items()}
        for case, variants in sorted(values.items())
    }


def median(variants, variant, unit="ns/op"):
    return variants.get(variant, {}).get(unit, {}).get("median")


def primary(case):
    split, family, count, size, traffic = case.split("/")
    return (split == "heldout" and family in {"literal", "conjunction", "complex"}
            and count in {"rules_24", "rules_256", "rules_2048"}
            and size == "bytes_256" and traffic == "sparse")


def geometric_mean(values):
    return math.exp(sum(math.log(v) for v in values) / len(values)) if values else None


def display(value, precision=2):
    return "missing" if value is None else f"{value:.{precision}f}"


def memory_results(paths):
    values = {}
    for path in paths:
        case = None
        for line in path.read_text().splitlines():
            if line.startswith("=== RUN   TestWitnessStudyMemory/"):
                case = line.split("TestWitnessStudyMemory/", 1)[1]
            if case and "program_heap_B=" in line:
                for metric, number in re.findall(r"(program_heap_B|compile_alloc_B|compile_allocs)=(-?\d+)", line):
                    values.setdefault(case, {}).setdefault(metric, []).append(int(number))
    return {case: {metric: {"median": statistics.median(samples), "samples": len(samples)}
                   for metric, samples in metrics.items()}
            for case, metrics in sorted(values.items())}


def summarize(directory):
    scans = benchmarks(sorted(directory.glob("scan-*.txt")), "BenchmarkWitnessStudy")
    compile_results = benchmarks(sorted(directory.glob("compile-*.txt")), "BenchmarkWitnessCompile")
    memory = memory_results(sorted(directory.glob("memory-*.txt")))
    parity_path = directory / "parity.txt"
    parity = parity_path.read_text() if parity_path.exists() else ""
    parity_pass = parity.rstrip().endswith("PASS") and "--- FAIL" not in parity
    ratios, missing = {}, []
    for case, variants in scans.items():
        for variant in ("baseline", "candidate", "hybrid"):
            if variants.get(variant, {}).get("ns/op", {}).get("samples") != 6:
                missing.append(f"{case}/{variant}: expected six samples")
        baseline, hybrid = median(variants, "baseline"), median(variants, "hybrid")
        if baseline and hybrid:
            ratios[case] = hybrid / baseline
    if len(compile_results) != 9:
        missing.append(f"expected nine compile cases, found {len(compile_results)}")
    for case, variants in compile_results.items():
        for variant in ("baseline", "candidate"):
            if variants.get(variant, {}).get("ns/op", {}).get("samples") != 6:
                missing.append(f"compile {case}/{variant}: expected six samples")
    if len(memory) != 18:
        missing.append(f"expected 18 memory cases, found {len(memory)}")
    for case, metrics in memory.items():
        if metrics.get("program_heap_B", {}).get("samples") != 3:
            missing.append(f"memory {case}: expected three samples")
    if len(scans) != 76:
        missing.append(f"expected 76 cases, found {len(scans)}")
    primaries = {case: ratio for case, ratio in ratios.items() if primary(case)}
    if len(primaries) != 9:
        missing.append(f"expected nine primary comparisons, found {len(primaries)}")
    overall = geometric_mean(list(primaries.values()))
    families = {family: geometric_mean([ratio for case, ratio in primaries.items()
                                       if case.split("/")[1] == family])
                for family in ("literal", "conjunction", "complex")}
    guards = {case: ratio for case, ratio in ratios.items()
              if case.startswith("heldout/") and not primary(case)}
    primary_failures = {case: ratio for case, ratio in primaries.items() if ratio > 1.05}
    guard_failures = {case: ratio for case, ratio in guards.items() if ratio > 1.10}
    accepted = (parity_pass and not missing and overall is not None and overall <= 0.90
                and all(value is not None and value < 1 for value in families.values())
                and not primary_failures and not guard_failures)
    report = {"decision": "PASS" if accepted else "HOLD", "parity_pass": parity_pass,
              "incomplete": missing, "primary_ratio": overall, "family_ratios": families,
              "primary_over_5pct": primary_failures, "guardrails_over_10pct": guard_failures,
              "scan": scans, "compile": compile_results, "memory": memory}
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    change = None if overall is None else 100 * (overall - 1)
    lines = ["# Frozen witness study", "", f"Decision: **{report['decision']}**. "
             f"Parity: {'PASS' if parity_pass else 'missing/failed'}. "
             f"Scan cases: {len(scans)}/76; primary comparisons: {len(primaries)}/9.", "",
             f"Held-out primary hybrid latency geomean: **{display(change)}%** versus baseline "
             "(negative is faster; required ≤−10%).", ""]
    for family, ratio in families.items():
        lines.append(f"- {family}: {display(None if ratio is None else 100 * (ratio - 1))}% (must improve)")
    lines += ["", f"Primary regressions above 5%: {len(primary_failures)}; "
              f"held-out guardrails above 10%: {len(guard_failures)}.", ""]
    if missing:
        lines += ["Incomplete evidence (no pass permitted):", ""] + [f"- {item}" for item in missing] + [""]
    lines += ["## Held-out guardrail regressions", "", "| Case | Hybrid latency change |", "|---|---:|"]
    for case, ratio in sorted(guards.items(), key=lambda item: item[1], reverse=True):
        if ratio > 1:
            lines.append(f"| {case} | {100 * (ratio - 1):+.2f}% |")
    lines += ["", "## All scan comparisons", "",
              "Median ns/op; candidate can return Unknown and is not a complete scan. "
              "Hybrid includes fallback. Unknown is the measured corpus fraction, not a successful rejection.", "",
              "| Case | Baseline | Candidate | Hybrid | Naive | Hybrid change | Unknown |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for case, variants in scans.items():
        delta = None if case not in ratios else 100 * (ratios[case] - 1)
        unknown = median(variants, "hybrid", "unknown/op")
        columns = [case] + [display(median(variants, v)) for v in ("baseline", "candidate", "hybrid", "naive")]
        columns += [display(delta) + "%", display(None if unknown is None else 100 * unknown) + "%"]
        lines.append("| " + " | ".join(columns) + " |")
    lines += ["", "## Compilation", "", "Candidate uses prebuilt IR; baseline includes YARA parsing. "
              "These are different frontend costs.", "",
              "| Case | Variant | ns/op | B/op | allocs/op | Samples |", "|---|---|---:|---:|---:|---:|"]
    for case, variants in compile_results.items():
        for variant, metrics in variants.items():
            columns = [case, variant] + [display(median(variants, variant, unit)) for unit in ("ns/op", "B/op", "allocs/op")]
            columns += [str(metrics.get("ns/op", {}).get("samples", 0))]
            lines.append("| " + " | ".join(columns) + " |")
    lines += ["", "## Retained program heap", "", "Medians of three fresh processes; "
              "hybrid retains both programs. Raw compile allocation and scanner stats remain in artifacts.", "",
              "| Case | Baseline bytes | Candidate bytes | Combined bytes |", "|---|---:|---:|---:|"]
    for case in sorted({key.rsplit("/", 1)[0] for key in memory}):
        base = memory.get(case + "/baseline", {}).get("program_heap_B", {}).get("median")
        candidate = memory.get(case + "/candidate", {}).get("program_heap_B", {}).get("median")
        combined = base + candidate if base is not None and candidate is not None else None
        lines.append(f"| {case} | {display(base, 0)} | {display(candidate, 0)} | {display(combined, 0)} |")
    lines += ["", "Medians describe the recorded runs; this summary makes no statistical significance claim. "
              "Training rows do not contribute to the frozen held-out decision.", ""]
    (directory / "summary.md").write_text("\n".join(lines))
    print(f"{report['decision']}: primary {display(change)}%; {len(missing)} incomplete checks; "
          f"{len(guard_failures)} guardrail violations")


if __name__ == "__main__":
    summarize(Path(sys.argv[1] if len(sys.argv) > 1 else "results"))
