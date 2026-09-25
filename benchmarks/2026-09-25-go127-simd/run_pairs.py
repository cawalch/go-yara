#!/usr/bin/env python3
"""Run prebuilt benchmark binaries sequentially, alternating order per pair."""
import argparse
import pathlib
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--baseline', required=True)
parser.add_argument('--candidate', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--bench', required=True)
parser.add_argument('--benchtime', default='200ms')
parser.add_argument('--count', type=int, default=6)
args = parser.parse_args()
out = pathlib.Path(args.output)
out.mkdir(parents=True, exist_ok=True)
paths = {'original': args.baseline, 'simd': args.candidate}
for label in paths:
    (out / (label + '.txt')).write_text('')
for pair in range(args.count):
    order = ['original', 'simd'] if pair % 2 == 0 else ['simd', 'original']
    for label in order:
        with (out / (label + '.txt')).open('a') as log:
            subprocess.run([paths[label], '-test.run', '^$', '-test.bench', args.bench,
                            '-test.benchtime=' + args.benchtime, '-test.count=1'],
                           stdout=log, stderr=subprocess.STDOUT, check=True)
    print('Completed pair', pair + 1, 'of', args.count, flush=True)
with (out / 'benchstat.txt').open('w') as log:
    subprocess.run(['benchstat', str(out/'original.txt'), str(out/'simd.txt')], stdout=log, check=True)
