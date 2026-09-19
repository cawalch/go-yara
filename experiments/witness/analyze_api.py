#!/usr/bin/env python3
"""Audit one public API study run. Strict median gates; significance is external."""
import argparse
import json
import math
from pathlib import Path
import re
import statistics
import sys

COUNTS = (24, 256, 2048)
VARIANTS = ("baseline", "routed")
METRICS = ("ns/op", "B/op", "allocs/op", "plan_active/op")


def case(family, count, size=256, traffic="sparse"):
    return f"{family}/rules_{count}/bytes_{size}/{traffic}"


PRIMARY = {case(f, n) for f in ("literal", "conjunction", "complex") for n in COUNTS}
FROZEN = PRIMARY | {case(f, n, traffic="near") for f in ("shared_tail", "shared_context") for n in COUNTS}
FROZEN |= {case("shared_prefix", 256, traffic="near"), case("complex", 256, traffic="binary"), case("nocase", 256), case("irreducible", 256, traffic="near"), case("conjunction", 256, traffic="shuffled")}
FROZEN |= {case("repeated", 256, 4096, t) for t in ("near", "positive")}
FROZEN |= {case(f, 24, traffic=t) for f in ("short1", "short2", "mixed_short") for t in ("clean", "positive")}
FROZEN |= {case("complex", 24, size, t) for size in (4096, 65536) for t in ("clean", "late")}
POSITIVE = {case(f, n, traffic="positive") for f in ("literal", "complex", "shared_tail", "shared_context") for n in COUNTS}
STARTUP = {f"{f}/rules_{n}" for f in ("complex", "shared_tail", "shared_context") for n in COUNTS}


class InvalidEvidence(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidEvidence(message)


def normalize(value):
    return " ".join(value.split())


def environment(directory):
    text = (directory / "environment.txt").read_text()
    head = text.splitlines()[0]
    require(re.fullmatch(r"[a-f0-9]{40}", head), "environment: missing exact HEAD")
    require(re.search(r"^go version go1\.26\.0 linux/amd64$", text, re.M), "environment: requires Go 1.26.0 linux/amd64")
    require("\nlinux\namd64\nv1\nlocal\nGOMAXPROCS=2" in text, "environment: GOAMD64/v1 or GOMAXPROCS/2 metadata missing")
    cpu = re.search(r"^Model name:\s*(.+)$", text, re.M)
    require(cpu, "environment: CPU model missing")
    binary = (directory / "binary.sha256").read_text().split()[0]
    require(re.fullmatch(r"[a-f0-9]{64}", binary), "invalid binary digest")
    return {"head": head, "cpu": normalize(cpu[1]), "go": "go1.26.0", "goos": "linux", "goarch": "amd64", "goamd64": "v1", "gomaxprocs": 2, "binary_sha256": binary}


def check_validation(directory):
    parity = (directory / "parity.txt").read_text()
    require("\nPASS\n" in "\n" + parity, "parity: missing final PASS")
    expected = {"frozen/" + n for n in FROZEN} | {"positive/" + n for n in POSITIVE}
    passed = re.findall(r"--- PASS: TestBooleanRoutingAPIParity/(\S+) ", parity)
    require(len(passed) == 44 and set(passed) == expected, "parity: expected exactly all 44 passing cases")
    for name in ("repository-tests.txt", "race.txt", "vet.txt", "build.txt"):
        text = (directory / name).read_text()
        require(not re.search(r"(^FAIL(?:\s|$)|--- FAIL:)", text, re.M), f"{name}: failure recorded")
    hashes = (directory / "fixture-check.txt").read_text()
    for name in ("routing_study_test.go", "study_test.go", "api_study_test.go"):
        require(f"experiments/witness/{name}: OK" in hashes, f"fixture checksum not verified: {name}")
    require((directory / "sources.sha256").stat().st_size > 0, "source hashes missing")
    order = (directory / "order.txt").read_text()
    rounds = re.findall(r"^round=(\d+) reverse=(\d+) start=\S+$", order, re.M)
    require(rounds == [(str(i), str((i - 1) % 2)) for i in range(1, 7)], "expected six alternating rounds")


def read_group(directory, stem, prefix, expected, machine, iterations=None):
    files = sorted(directory.glob(stem + "-[0-9]*.txt"))
    require([p.name for p in files] == [f"{stem}-{i}.txt" for i in range(1, 7)], f"{stem}: expected exactly six numbered files")
    scan = stem in ("scan", "positive")
    wanted_metrics = METRICS + (("size_bypass/op",) if scan else ())
    all_samples = {(name, variant): [] for name in expected for variant in VARIANTS}
    pattern = re.compile(r"^" + re.escape(prefix) + r"/(\S+)/(baseline|routed)-2\s+(\d+)\s+(.*)$")
    for path in files:
        text = path.read_text()
        require("\nPASS\n" in "\n" + text, f"{path.name}: incomplete process result")
        for key in ("goos", "goarch", "cpu"):
            values = re.findall(r"^" + key + r":\s*(.+)$", text, re.M)
            require(len(values) == 1 and normalize(values[0]) == machine[key], f"{path.name}: inconsistent {key}")
        seen = set()
        for line in text.splitlines():
            if not line.startswith("Benchmark"):
                continue
            match = pattern.match(line)
            require(match, f"{path.name}: unexpected or malformed benchmark row: {line}")
            name, variant, count, values = match.groups()
            key = (name, variant)
            require(key in all_samples and key not in seen, f"{path.name}: unexpected/duplicate case {key}")
            require(int(count) > 0 and (iterations is None or int(count) == iterations), f"{path.name}: wrong iteration count {count}")
            fields = values.split()
            require(len(fields) % 2 == 0, f"{path.name}: malformed metrics {key}")
            metrics = {}
            for value, unit in zip(fields[::2], fields[1::2]):
                require(unit not in metrics, f"{path.name}: duplicate metric {key}/{unit}")
                number = float(value)
                require(math.isfinite(number) and number >= 0, f"{path.name}: invalid metric {key}/{unit}")
                metrics[unit] = number
            require(set(wanted_metrics) <= metrics.keys(), f"{path.name}: missing required metrics for {key}")
            require(metrics["ns/op"] > 0, f"{path.name}: zero latency {key}")
            require(metrics["plan_active/op"] in (0, 1), f"{path.name}: non-Boolean activation {key}")
            require(variant != "baseline" or metrics["plan_active/op"] == 0, f"{path.name}: baseline plan active")
            if scan:
                size = int(re.search(r"/bytes_(\d+)/", name)[1])
                require(metrics["size_bypass/op"] == int(size > 1024), f"{path.name}: inconsistent size bypass {key}")
            seen.add(key)
            all_samples[key].append({"file": path.name, "iterations": int(count), **metrics})
        require(seen == all_samples.keys(), f"{path.name}: missing {len(all_samples.keys() - seen)} benchmark rows")
    result = {}
    for (name, variant), samples in sorted(all_samples.items()):
        require(len(samples) == 6, f"{stem}: missing samples {name}/{variant}")
        require(len({s["plan_active/op"] for s in samples}) == 1, f"{stem}: unstable activation {name}/{variant}")
        aggregated = {metric: {"median": statistics.median(s[metric] for s in samples), "min": min(s[metric] for s in samples), "max": max(s[metric] for s in samples)} for metric in wanted_metrics}
        result.setdefault(name, {})[variant] = {"metrics": aggregated, "samples": samples}
    return result


def metric(row, variant, name="ns/op"):
    return row[variant]["metrics"][name]["median"]


def pairs(data, scan=False):
    result = {}
    for name, row in data.items():
        baseline, routed = metric(row, "baseline"), metric(row, "routed")
        active = bool(metric(row, "routed", "plan_active/op"))
        pair = {"baseline_ns": baseline, "routed_ns": routed, "ratio": routed / baseline, "change_pct": 100 * (routed / baseline - 1), "plan_active": active,
                "baseline_B_op": metric(row, "baseline", "B/op"), "routed_B_op": metric(row, "routed", "B/op"),
                "baseline_allocs_op": metric(row, "baseline", "allocs/op"), "routed_allocs_op": metric(row, "routed", "allocs/op")}
        pair["delta_B_op"] = pair["routed_B_op"] - pair["baseline_B_op"]
        pair["delta_allocs_op"] = pair["routed_allocs_op"] - pair["baseline_allocs_op"]
        if scan:
            bypass = bool(metric(row, "routed", "size_bypass/op"))
            pair.update(size_bypass=bypass, category="size_bypass" if bypass else "selected" if active else "declined", limit_ratio=1.10 if active and not bypass else 1.05)
            pair["within_guard_budget"] = pair["ratio"] <= pair["limit_ratio"]
        result[name] = pair
    return result


def geo(values):
    return math.exp(statistics.mean(math.log(v) for v in values))


def summarize(directory):
    machine = environment(directory)
    check_validation(directory)
    groups = {
        "frozen": read_group(directory, "scan", "BenchmarkBooleanRoutingAPI", FROZEN, machine),
        "positive": read_group(directory, "positive", "BenchmarkBooleanRoutingAPIPositive", POSITIVE, machine),
        "first_scanner": read_group(directory, "first-scanner", "BenchmarkBooleanRoutingAPIFirstScanner", STARTUP, machine, 1),
        "reused_scanner": read_group(directory, "reused-scanner", "BenchmarkBooleanRoutingAPIReusedScanner", STARTUP, machine, 100),
    }
    tables = {key: pairs(data, key in ("frozen", "positive")) for key, data in groups.items()}
    for name in STARTUP:
        require(tables["first_scanner"][name]["plan_active"] == tables["reused_scanner"][name]["plan_active"], f"startup: inconsistent first/reused activation {name}")
    frozen = tables["frozen"]
    primary = geo([frozen[n]["ratio"] for n in PRIMARY])
    families = {family: geo([frozen[n]["ratio"] for n in PRIMARY if n.startswith(family + "/")]) for family in ("literal", "conjunction", "complex")}
    # Pre-results clarification adds the conservative per-case ceiling to primary cases too.
    failures = [{"group": group, "case": name, **row} for group in ("frozen", "positive") for name, row in tables[group].items() if not row["within_guard_budget"]]
    gates = {"complete_evidence": True, "parity_44_cases": True, "primary_all_active": all(frozen[n]["plan_active"] and not frozen[n]["size_bypass"] for n in PRIMARY),
             "primary_geomean_at_least_10pct": primary <= 0.90, "each_primary_family_improves": all(v < 1 for v in families.values()), "all_case_budgets_including_primary": not failures}
    return {"status": "PASS" if all(gates.values()) else "HOLD", "machine": machine, "gates": gates,
            "primary_ratio": primary, "family_ratios": families, "guard_failures": failures, "cases": tables,
            "sample_counts": {"scan": 384, "positive": 144, "first_scanner": 108, "reused_scanner": 108},
            "coverage": {group: {category: [n for n, row in tables[group].items() if row["category"] == category] for category in ("selected", "declined", "size_bypass")} for group in ("frozen", "positive")},
            "unknown_rate": None, "unknown_note": "Not exposed by the API; fallback cost is included. No runtime rate is inferred.",
            "interpretation_note": "Before inspecting results, the root required the 10% per-case ceiling for every active non-bypassed case, including all nine primaries. This adds a conservative check and does not relax any frozen gate.",
            "statistics_note": "Strict median gates only. Six samples per variant/case; significance requires separately paired benchstat. Runs and CPUs are never pooled.",
            "startup_note": "NewScanner only; normal source compilation and Close excluded. Reused scanner uses cached plan. Startup is report-only.",
            "samples": groups}


def percent(ratio):
    return f"{100 * (ratio - 1):+.2f}%"


def markdown(summary):
    machine = summary["machine"]
    lines = [f"# Public API routing: {summary['status']}", "", f"{machine['cpu']} · {machine['go']} · `{machine['head']}`", "",
             f"Nine primary cases: **{percent(summary['primary_ratio'])} latency** versus baseline.", "",
             "; ".join(f"{name}: {percent(ratio)}" for name, ratio in summary["family_ratios"].items()) + ".", "", summary["statistics_note"], "", summary["interpretation_note"], "",
             "| Gate | Result |", "|---|---|"]
    lines += [f"| {name} | {'PASS' if passed else 'FAIL'} |" for name, passed in summary["gates"].items()]
    lines += ["", f"Guard failures: {len(summary['guard_failures'])}. Unknown rate is unavailable; API timing includes fallback.", ""]
    for group, title in (("frozen", "Original 32"), ("positive", "Supplemental 12 positive controls"), ("first_scanner", "First NewScanner"), ("reused_scanner", "Cached-plan NewScanner")):
        lines += [f"## {title}", ""]
        if group in summary["coverage"]:
            lines.append(", ".join(f"{category}: {len(names)}" for category, names in summary["coverage"][group].items()) + ".")
            lines.append("")
        lines += ["| Case | Baseline ns | Routed ns | Change | Plan/path | B/op baseline→routed (Δ) | Allocs/op baseline→routed (Δ) | Guard |", "|---|---:|---:|---:|---|---:|---:|---|"]
        for name, row in summary["cases"][group].items():
            guard = "PASS" if row.get("within_guard_budget") else "FAIL" if "within_guard_budget" in row else "report only"
            path = row.get("category", "active" if row["plan_active"] else "declined")
            lines.append(f"| {name} | {row['baseline_ns']:,.2f} | {row['routed_ns']:,.2f} | {percent(row['ratio'])} | {path} | {row['baseline_B_op']:g}→{row['routed_B_op']:g} ({row['delta_B_op']:+g}) | {row['baseline_allocs_op']:g}→{row['routed_allocs_op']:g} ({row['delta_allocs_op']:+g}) | {guard} |")
        lines.append("")
    lines += [summary["startup_note"], "", "Synthetic generated logs; large records are predominantly space-padded bypass controls. Same compiler on both paths: no inference about metadata overhead versus a prior release. No retained-heap or RSS measurement.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    try:
        summary = summarize(args.results)
        report = markdown(summary)
    except (OSError, ValueError, IndexError) as error:
        summary = {"status": "INVALID", "error": str(error), "gates": {"complete_evidence": False}}
        report = "# Public API routing: INVALID\n\n" + str(error) + "\n"
    (args.results / "api-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (args.results / "api-summary.md").write_text(report)
    print(summary["status"])
    if summary["status"] == "INVALID":
        print(summary["error"], file=sys.stderr)
        return 1
    print(f"Primary: {percent(summary['primary_ratio'])}; failed guards: {len(summary['guard_failures'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
