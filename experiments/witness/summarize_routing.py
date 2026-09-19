#!/usr/bin/env python3
"""Apply frozen routing gates to one runner's complete artifacts; no significance claims."""
import json
import math
from pathlib import Path
import re
import statistics
import sys

VARIANTS = ("baseline", "v1", "routed")
COUNTS = (24, 256, 2048)
COST = ("ns/op", "B/op", "allocs/op")
SCAN = COST + ("unknown/op", "eligible/op", "nodes/op")
MEMORY = ("program_heap_B", "compile_alloc_B", "compile_allocs", "eligible", "nodes")


def case(family, count, size=256, traffic="sparse"):
    return f"{family}/rules_{count}/bytes_{size}/{traffic}"


PRIMARY = {case(f, n) for f in ("literal", "conjunction", "complex") for n in COUNTS}
FANOUT = {case(f, n, traffic="near") for f in ("shared_tail", "shared_context") for n in COUNTS}
FRESH = PRIMARY | FANOUT | {case("shared_prefix", 256, traffic="near"), case("complex", 256, traffic="binary"), case("nocase", 256), case("irreducible", 256, traffic="near"), case("conjunction", 256, traffic="shuffled")}
FRESH |= {case("repeated", 256, 4096, t) for t in ("near", "positive")}
FRESH |= {case(f, 24, traffic=t) for f in ("short1", "short2", "mixed_short") for t in ("clean", "positive")}
FRESH |= {case("complex", 24, n, t) for n in (4096, 65536) for t in ("clean", "late")}
HISTORICAL = {"heldout/" + case("short", n, traffic=t) for n in (24, 256) for t in ("sparse", "near")}
HISTORICAL.add("heldout/" + case("complex", 256, traffic="low_entropy"))
HISTORICAL |= {f"{f}/bytes_{4096 if f == 'repeated' else 256}/positive_{p}" for f in ("short1", "short2", "mixed", "repeated") for p in ("false", "true")}
HISTORICAL |= {f"large_end/bytes_{n}/positive_{p}" for n in (4096, 65536) for p in ("false", "true")}
MEMORY_CASES = {f"{f}/rules_{n}" for f in ("complex", "shared_tail", "shared_context") for n in COUNTS}
COMPILE_CASES = MEMORY_CASES


def aggregate(raw):
    return {name: {variant: {unit: {"median": statistics.median(v for v, _ in samples), "samples": len(samples), "files": len({p for _, p in samples}), "min": min(v for v, _ in samples), "max": max(v for v, _ in samples)} for unit, samples in metrics.items()} for variant, metrics in variants.items()} for name, variants in sorted(raw.items())}


def read_bench(paths, prefix, machine):
    raw = {}
    pattern = re.compile(r"^" + re.escape(prefix) + r"/(\S+?)(?:-\d+)?\s+\d+\s+(.*)$")
    for path in paths:
        for line in path.read_text().splitlines():
            for key in ("goos", "goarch", "cpu"):
                if line.startswith(key + ":"):
                    machine.setdefault(key, set()).add(line.split(":", 1)[1].strip())
            match = pattern.match(line)
            if not match:
                continue
            name, variant = match[1].rsplit("/", 1)
            metrics = raw.setdefault(name, {}).setdefault(variant, {})
            for value, unit in re.findall(r"([\d.eE+-]+)\s+(ns/op|B/op|allocs/op|unknown/op|eligible/op|nodes/op)(?=\s|$)", match[2]):
                number = float(value)
                if math.isfinite(number):
                    metrics.setdefault(unit, []).append((number, path.name))
    return aggregate(raw)


def read_memory(paths):
    raw = {}
    for path in paths:
        current = None
        for line in path.read_text().splitlines():
            match = re.match(r"=== RUN\s+TestWitnessRoutingMemory/(\S+)", line)
            if match:
                current = match[1].rsplit("/", 1)
            if current and "program_heap_B=" in line:
                name, variant = current
                metrics = raw.setdefault(name, {}).setdefault(variant, {})
                for key, value in re.findall(r"(program_heap_B|compile_alloc_B|compile_allocs|eligible|nodes)=(-?\d+|true|false)", line):
                    number = {"true": 1, "false": 0}.get(value)
                    metrics.setdefault(key, []).append((float(value) if number is None else number, path.name))
    return aggregate(raw)


def value(data, name, variant, metric="ns/op"):
    return data.get(name, {}).get(variant, {}).get(metric, {}).get("median")


def ratio(data, name, numerator="routed", denominator="baseline", metric="ns/op"):
    a, b = value(data, name, numerator, metric), value(data, name, denominator, metric)
    return a / b if a is not None and b is not None and b > 0 else None


def geo(values):
    return math.exp(sum(math.log(v) for v in values) / len(values)) if values and all(v is not None and v > 0 for v in values) else None


def fmt(v):
    return "missing" if v is None else f"{v:,.3f}"


def check_data(data, expected, samples, section, missing, scan=False, memory=False):
    for name in sorted(expected - data.keys()):
        missing.append(f"{section}: missing case {name}")
    for name in sorted(data.keys() - expected):
        missing.append(f"{section}: unexpected case {name}")
    for name in sorted(expected & data.keys()):
        for variant in VARIANTS:
            metrics = list(MEMORY if memory else COST)
            if not scan and not memory:
                metrics += ["eligible/op", "nodes/op"]
            if scan and variant != "baseline":
                metrics.append("unknown/op")
            if scan and variant == "routed":
                metrics += ["eligible/op", "nodes/op"]
            for metric in metrics:
                item = data[name].get(variant, {}).get(metric, {})
                if item.get("samples") != samples or item.get("files") != samples:
                    missing.append(f"{section} {name}/{variant}/{metric}: expected {samples} samples from distinct files")
                elif not all(math.isfinite(item[k]) for k in ("median", "min", "max")):
                    missing.append(f"{section} {name}/{variant}/{metric}: nonfinite metric")
                elif metric in ("eligible", "eligible/op") and (item["min"] != item["max"] or item["median"] not in (0, 1)):
                    missing.append(f"{section} {name}/{variant}: inconsistent eligibility")
                elif metric == "unknown/op" and not (0 <= item["min"] <= item["max"] <= 1):
                    missing.append(f"{section} {name}/{variant}: invalid Unknown fraction")
                elif metric == "ns/op" and item["min"] <= 0:
                    missing.append(f"{section} {name}/{variant}: nonpositive latency")
                elif metric in ("nodes", "nodes/op") and (item["min"] < 0 or item["min"] != item["max"]):
                    missing.append(f"{section} {name}/{variant}: invalid node count")


def scan_table(data):
    lines = ["| Case | Variant | ns/op | B/op | allocs/op | Unknown | Eligible | Nodes | n | routed/base | routed/v1 |", "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name in sorted(data):
        for variant in VARIANTS:
            cells = [name, variant] + [fmt(value(data, name, variant, unit)) if unit in data[name].get(variant, {}) else ("—" if variant == "baseline" or variant == "v1" and unit in ("eligible/op", "nodes/op") else "missing") for unit in SCAN]
            cells += [str(data[name].get(variant, {}).get("ns/op", {}).get("samples", 0)), fmt(ratio(data, name)) if variant == "routed" else "—", fmt(ratio(data, name, denominator="v1")) if variant == "routed" else "—"]
            lines.append("| " + " | ".join(cells) + " |")
    return lines


def summarize(directory):
    machine, missing = {}, []
    paths = {kind: sorted(directory.glob(kind + "-[0-9]*.txt")) for kind in ("scan", "historical", "compile", "memory")}
    for kind, files in paths.items():
        wanted = 3 if kind == "memory" else 6
        if len(files) != wanted:
            missing.append(f"{kind}: expected {wanted} raw files; found {len(files)}")
    scans = read_bench(paths["scan"], "BenchmarkWitnessRouting", machine)
    historical = read_bench(paths["historical"], "BenchmarkWitnessRoutingHistorical", machine)
    compilation = read_bench(paths["compile"], "BenchmarkWitnessRoutingCompile", machine)
    memory = read_memory(paths["memory"])
    check_data(scans, FRESH, 6, "fresh", missing, scan=True)
    check_data(historical, HISTORICAL, 6, "historical", missing, scan=True)
    check_data(compilation, COMPILE_CASES, 6, "compile", missing)
    check_data(memory, MEMORY_CASES, 3, "memory", missing, memory=True)
    if any(len(values) != 1 for values in machine.values()) or any(key not in machine for key in ("goos", "goarch", "cpu")):
        missing.append("missing or mixed CPU/platform metadata; never pool runners")
    parity_path = directory / "parity.txt"
    parity = parity_path.read_text() if parity_path.exists() else ""
    parity_pass = parity.rstrip().endswith("PASS") and "--- FAIL" not in parity and all(re.search(r"^--- PASS: " + test + r"\s", parity, re.M) for test in ("TestWitnessRoutingParity", "TestWitnessRoutingHistoricalParity"))
    primary = {name: ratio(scans, name) for name in sorted(PRIMARY)}
    overall = geo(list(primary.values()))
    families = {f: geo([r for name, r in primary.items() if name.startswith(f + "/")]) for f in ("literal", "conjunction", "complex")}
    fanout = {name: ratio(scans, name, denominator="v1") for name in sorted(FANOUT)}
    eligible = sorted(name for name in FRESH if value(scans, name, "routed", "eligible/op") == 1)
    declined = sorted(name for name in FRESH if value(scans, name, "routed", "eligible/op") == 0)
    guard_failures = {}
    for name in sorted(FRESH):
        r = ratio(scans, name)
        threshold = 1.10 if name in eligible else 1.05 if name in declined else None
        if r is None or threshold is None or r > threshold:
            guard_failures[name] = {"ratio": r, "limit": threshold}
    memory_ratios, memory_failures = {}, {}
    for name in sorted(MEMORY_CASES):
        eligibility = value(memory, name, "routed", "eligible")
        family, count = name.split("/")
        scan_case = name + "/bytes_256/" + ("sparse" if family == "complex" else "near")
        if eligibility != value(scans, scan_case, "routed", "eligible/op"):
            missing.append(f"memory {name}: eligibility differs from scan")
        for source, label, eligible_unit, node_unit in ((memory, "memory", "eligible", "nodes"), (compilation, "compile", "eligible/op", "nodes/op")):
            if value(source, name, "routed", eligible_unit) != value(scans, scan_case, "routed", "eligible/op") or value(source, name, "routed", node_unit) != value(scans, scan_case, "routed", "nodes/op"):
                missing.append(f"{label} {name}: eligibility/nodes differs from scan")
        r = ratio(memory, name, denominator="v1", metric="program_heap_B") if eligibility == 1 else None
        memory_ratios[name] = r
        if eligibility == 1 and (r is None or r <= 0 or r > 2):
            memory_failures[name] = r
    gates = {"all_primaries_eligible": PRIMARY <= set(eligible), "fanout_eligible_with_nodes": all(name in eligible and (value(scans, name, "routed", "nodes/op") or 0) > 0 for name in FANOUT), "parity": bool(parity_pass), "complete_evidence": not missing, "primary_geomean": overall is not None and overall <= .9, "each_primary_family_improves": all(r is not None and r < 1 for r in families.values()), "each_fanout_halved": all(r is not None and r <= .5 for r in fanout.values()), "fresh_guardrails": not guard_failures, "eligible_memory_limit": not memory_failures}
    report = {"decision": "PASS" if all(gates.values()) else "HOLD", "gates": gates, "incomplete": missing, "machine": {key: sorted(values) for key, values in machine.items()}, "primary_ratio": overall, "primary_family_ratios": families, "fanout_geomean": geo(list(fanout.values())), "fanout_ratios": fanout, "coverage": {"eligible": eligible, "declined": declined, "unknown": sorted(FRESH - set(eligible) - set(declined))}, "fresh_guard_failures": guard_failures, "memory_ratios": memory_ratios, "memory_failures": memory_failures, "scan": scans, "historical": historical, "compile": compilation, "memory": memory}
    lines = ["# Witness routing study", "", f"Decision: **{report['decision']}**. Fresh eligibility {len(eligible)}/32; declined {len(declined)}/32. Historical controls are separate from fresh performance gates.", "", "Medians only; no statistical significance claim. Both v1 and routed include exact fallback. Unknown is the fixed corpus fraction; declined routed portfolios execute baseline directly. Nodes are actual routing nodes, not estimated work. Ratios below 1 are faster/smaller.", "", f"Primary routed/base geomean: {fmt(overall)}. Fanout routed/v1 geomean: {fmt(report['fanout_geomean'])} (each case must also pass).", ""]
    lines += [f"- {key}: {'PASS' if passed else 'HOLD'}" for key, passed in gates.items()]
    lines += [f"- Primary {key} ratio: {fmt(r)}" for key, r in families.items()]
    if missing:
        lines += ["", "Incomplete evidence:", ""] + [f"- {item}" for item in missing]
    for label, data in (("Fresh cases", scans), ("Historical controls", historical)):
        lines += ["", f"## {label}", ""] + scan_table(data)
    lines += ["", "## Compilation (report only)", "", "Baseline includes YARA parsing; candidates receive prebuilt IR.", "", "| Case | Variant | ns/op | B/op | allocs/op | Eligible | Nodes | n |", "|---|---|---:|---:|---:|---:|---:|---:|"]
    for name, variants in compilation.items():
        for variant in VARIANTS:
            lines.append("| " + " | ".join([name, variant] + [fmt(value(compilation, name, variant, m)) for m in COST + ("eligible/op", "nodes/op")] + [str(variants.get(variant, {}).get("ns/op", {}).get("samples", 0))]) + " |")
    lines += ["", "## Memory", "", "Incremental retained program heap from three processes; excludes source IR, scanner state and process RSS. Hybrid retains baseline plus candidate. Declined zero-byte candidates are not savings.", "", "| Case | Variant | Heap B | Compile B | Compile allocs | Eligible | Nodes | n | routed/v1 heap |", "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for name, variants in memory.items():
        for variant in VARIANTS:
            lines.append("| " + " | ".join([name, variant] + [fmt(value(memory, name, variant, m)) for m in MEMORY] + [str(variants.get(variant, {}).get("program_heap_B", {}).get("samples", 0)), fmt(memory_ratios.get(name)) if variant == "routed" else "—"]) + " |")
    (directory / "routing-summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    (directory / "routing-summary.md").write_text("\n".join(lines) + "\n")
    print(f"{report['decision']}: primary={fmt(overall)} fanout={fmt(report['fanout_geomean'])} eligible={len(eligible)}/32 incomplete={len(missing)}")
    return report


if __name__ == "__main__":
    summarize(Path(sys.argv[1] if len(sys.argv) > 1 else "results"))
