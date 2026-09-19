#!/usr/bin/env python3
import json
from pathlib import Path
import re
import subprocess
import sys

import analyze_api as api


def compare(old, new):
    rows = {}
    for name in old:
        a, b = old[name], new[name]
        rows[name] = {
            "old_ns": a["routed_ns"], "new_ns": b["routed_ns"],
            "ratio": b["routed_ns"] / a["routed_ns"],
            "old_bytes": a["routed_B_op"], "new_bytes": b["routed_B_op"],
            "old_allocs": a["routed_allocs_op"], "new_allocs": b["routed_allocs_op"],
            "same_activation": a["plan_active"] == b["plan_active"],
        }
    return rows


def summarize(root):
    reports = {}
    for revision in ("old", "new"):
        reports[revision] = api.summarize(root / revision)
        (root / revision / "api-summary.json").write_text(json.dumps(reports[revision], indent=2) + "\n")
        (root / revision / "api-summary.md").write_text("Within-revision ordinary/routed attribution only. Construction acceptance is in ../build-summary.md.\n\n" + api.markdown(reports[revision]))
    old, new = reports["old"], reports["new"]
    api.require(old["machine"]["head"] == "bf6c3e4af2ae8d7df70a305513caee32a6fecfbc", "wrong baseline")
    api.require(old["machine"]["cpu"] == new["machine"]["cpu"], "different CPUs")
    order = re.findall(r"^round=(\d+) revisions=(old new|new old) reverse=(\d+) start=\S+$", (root / "order.txt").read_text(), re.M)
    api.require(order == [(str(i), "old new" if i % 2 else "new old", str((i - 1) % 2)) for i in range(1, 7)], "missing paired order")
    groups = {group: compare(old["cases"][group], new["cases"][group]) for group in old["cases"]}
    startup = groups["first_scanner"]
    startup_ratio = api.geo(row["ratio"] for row in startup.values())
    bytes_ratio = api.geo(row["new_bytes"] / row["old_bytes"] for row in startup.values())
    scans = groups["frozen"] | groups["positive"]
    failures = {name: row for name, row in scans.items() if row["ratio"] > 1.05}
    gates = {
        "complete_paired_evidence": True,
        "startup_latency_at_least_50pct_lower": startup_ratio <= .50,
        "startup_bytes_at_least_30pct_lower": bytes_ratio <= .70,
        "no_startup_regression": all(row["ratio"] <= 1 for row in startup.values()),
        "activation_unchanged": all(row["same_activation"] for rows in groups.values() for row in rows.values()),
        "all_startup_plans_active": all(row["plan_active"] for report in reports.values() for row in report["cases"]["first_scanner"].values()),
        "scan_within_5pct": not failures,
        "no_new_scan_allocations": all(row["new_allocs"] <= row["old_allocs"] for row in scans.values()),
        "candidate_retains_ordinary_benefit": all(new["gates"].values()),
    }
    return {"status": "PASS" if all(gates.values()) else "HOLD", "gates": gates,
            "startup_ratio": startup_ratio, "startup_bytes_ratio": bytes_ratio,
            "scan_failures": failures, "groups": groups,
            "old_machine": old["machine"], "new_machine": new["machine"],
            "candidate_primary_ratio": new["primary_ratio"]}


def benchstat(root):
    for stem in ("scan", "positive", "first-scanner", "reused-scanner"):
        inputs = []
        for revision in ("old", "new"):
            rows = []
            for path in sorted((root / revision).glob(stem + "-[1-6].txt")):
                for line in path.read_text().splitlines():
                    if line.startswith(("goos:", "goarch:", "pkg:", "cpu:")) and path.name.endswith("-1.txt"):
                        rows.append(line)
                    elif line.startswith("Benchmark") and "/routed-2" in line:
                        rows.append(line.replace("/routed-2", "-2"))
            path = root / (stem + "-" + revision + ".txt")
            path.write_text("\n".join(rows) + "\n")
            inputs.append(str(path))
        with (root / (stem + "-benchstat.txt")).open("w") as output:
            subprocess.run(["benchstat", *inputs], stdout=output, check=True)


def markdown(result):
    lines = [f"# Construction study: {result['status']}", "",
             f"Startup latency: {api.percent(result['startup_ratio'])}; allocated bytes: {api.percent(result['startup_bytes_ratio'])}.", "",
             "Six samples per variant/revision/case; strict median gates. Consult benchstat separately for significance.", "",
             "| Gate | Result |", "|---|---|"]
    lines += [f"| {name} | {'PASS' if passed else 'FAIL'} |" for name, passed in result["gates"].items()]
    for group, rows in result["groups"].items():
        lines += ["", f"## {group}", "", "| Case | Old ns | New ns | Change | Old B/op | New B/op |", "|---|---:|---:|---:|---:|---:|"]
        for name, row in rows.items():
            lines.append(f"| {name} | {row['old_ns']:,.2f} | {row['new_ns']:,.2f} | {api.percent(row['ratio'])} | {row['old_bytes']:g} | {row['new_bytes']:g} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    root = Path(sys.argv[1])
    try:
        result = summarize(root)
        report = markdown(result)
        benchstat(root)
    except (OSError, ValueError, KeyError, IndexError) as error:
        result = {"status": "INVALID", "error": str(error)}
        report = f"# Construction study: INVALID\n\n{error}\n"
    (root / "build-summary.json").write_text(json.dumps(result, indent=2) + "\n")
    (root / "build-summary.md").write_text(report)
    print(report.split("\n\n", 2)[0:2])
    sys.exit(0 if result["status"] == "PASS" else 1)
