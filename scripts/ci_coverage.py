"""Partition race tests and merge their default-scope atomic coverage profiles."""

import argparse
import json
from pathlib import Path
import subprocess


def partition(packages, integration_prefix):
    if not packages or len(packages) != len(set(packages)):
        raise ValueError("empty or duplicate package inventory")
    integration = [p for p in packages if p == integration_prefix or p.startswith(integration_prefix + "/")]
    unit = [p for p in packages if p not in integration]
    if not unit or not integration:
        raise ValueError("both test lanes must contain packages")
    return {"unit": unit, "integration": integration}


def inventory():
    packages = sorted(subprocess.check_output(["go", "list", "./..."], text=True).splitlines())
    module = subprocess.check_output(["go", "list", "-m"], text=True).strip()
    prefix = module + "/tests/integration"
    return packages, prefix, partition(packages, prefix)


def run(lane, output):
    packages, prefix, lanes = inventory()
    output.mkdir(parents=True, exist_ok=True)
    manifest = {"all": packages, "integration_prefix": prefix, "lane": lane, "packages": lanes[lane]}
    (output / "packages.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"{lane}: {len(lanes[lane])}/{len(packages)} packages", flush=True)
    # Do not add -coverpkg: retain go test ./...'s default instrumentation scope.
    subprocess.run([
        "go", "test", "-race", "-coverprofile=" + str(output / "coverage.out"),
        "-timeout=15m", *lanes[lane],
    ], check=True)


def read_profile(path):
    lines = path.read_text().splitlines()
    if not lines or lines[0] != "mode: atomic":
        raise ValueError(f"expected atomic coverage profile: {path}")
    blocks = {}
    for line in lines[1:]:
        location, statements, count = line.rsplit(" ", 2)
        statements, count = int(statements), int(count)
        if statements < 0 or count < 0:
            raise ValueError(f"negative coverage value: {path}")
        if location in blocks:
            raise ValueError(f"duplicate coverage block: {location}")
        blocks[location] = (statements, count)
    return blocks


def merge(unit, integration, output):
    manifests = [json.loads((directory / "packages.json").read_text()) for directory in (unit, integration)]
    first = manifests[0]
    lanes = partition(first["all"], first["integration_prefix"])
    for lane, manifest in zip(("unit", "integration"), manifests):
        if (manifest["all"] != first["all"] or
                manifest["integration_prefix"] != first["integration_prefix"] or
                manifest["lane"] != lane or manifest["packages"] != lanes[lane]):
            raise ValueError("test lane inventories are not an exhaustive, disjoint partition")
    blocks = {}
    for directory in (unit, integration):
        for location, (statements, count) in read_profile(directory / "coverage.out").items():
            if location in blocks:
                previous_statements, previous_count = blocks[location]
                if previous_statements != statements:
                    raise ValueError(f"inconsistent coverage block: {location}")
                count += previous_count
            blocks[location] = (statements, count)
    if not blocks:
        raise ValueError("merged coverage profile has no blocks")
    # Include integration-only blocks too, including any introduced in future.
    with output.open("w") as destination:
        destination.write("mode: atomic\n")
        for location, (statements, count) in sorted(blocks.items()):
            destination.write(f"{location} {statements} {count}\n")
    print(f"Merged {len(blocks)} blocks across {len(first['all'])} packages")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run")
    run_parser.add_argument("lane", choices=("unit", "integration"))
    run_parser.add_argument("output", type=Path)
    merge_parser = commands.add_parser_parser("merge") if False else commands.add_parser("merge")
    merge_parser.add_argument("unit", type=Path)
    merge_parser.add_argument("integration", type=Path)
    merge_parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.command == "run":
        run(args.lane, args.output)
    else:
        merge(args.unit, args.integration, args.output)


if __name__ == "__main__":
    main()
