"""Build a disposable browser/WASI spike against an explicit published release."""
import argparse
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ref', required=True, help='Published module version, e.g. v0.8.0')
parser.add_argument('--out', required=True, type=Path, help='New directory outside the repository')
args = parser.parse_args()
source = Path(__file__).resolve().parent
output = args.out.resolve()
if output.is_relative_to(source.parents[2]):
    raise SystemExit('Use an output directory outside the repository')
output.mkdir(parents=True, exist_ok=False)

def run(command, **kwargs):
    return subprocess.check_output(command, text=True, **kwargs).strip()

with tempfile.TemporaryDirectory(prefix='go-yara-wasm-build-') as temp:
    build = Path(temp)
    for directory in ['engine', 'browser', 'command', 'reactor']:
        shutil.copytree(source / directory, build / directory)
    (build / 'go.mod').write_text('module github.com/cawalch/go-yara/site/spikes/wasm\n\ngo 1.26.0\n\nrequire github.com/cawalch/go-yara ' + args.ref + '\n')
    run(['go', 'mod', 'tidy'], cwd=build)
    print(run(['go', 'run', './command'], cwd=build))
    for target, package, name, flags in [('js', 'browser', 'scanner', []), ('wasip1', 'command', 'command', []), ('wasip1', 'reactor', 'reactor', ['-buildmode=c-shared'])]:
        run(['go', 'build', '-trimpath', '-ldflags=-s -w', *flags, '-o', str(output / (name + '.wasm')), './' + package], cwd=build, env={**os.environ, 'GOOS': target, 'GOARCH': 'wasm', 'GOEXPERIMENT': ''})
    shutil.copy(build / 'go.sum', output / 'go.sum')
goroot = Path(run(['go', 'env', 'GOROOT']))
shutil.copy(goroot / 'lib/wasm/wasm_exec.js', output)
for file in ['index.html', 'worker.js', 'client.mjs', 'wasi.mjs']:
    shutil.copy(source / file, output)
shutil.copy(source / 'engine/fixtures.json', output / 'fixtures.json')
metadata = {'release': args.ref, 'go': run(['go', 'version']), 'node': run(['node', '--version']), 'sizes': {}}
for file in output.glob('*.wasm'):
    data = file.read_bytes()
    metadata['sizes'][file.name] = {'bytes': len(data), 'gzipBytes': len(gzip.compress(data, mtime=0))}
(output / 'build.json').write_text(json.dumps(metadata, indent=2) + '\n')
print(json.dumps(metadata, indent=2))
print(run(['node', str(output / 'wasi.mjs')]))
print(f'Serve with: python3 -m http.server 4322 --bind 127.0.0.1 --directory {output}')
