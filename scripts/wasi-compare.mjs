import { readFileSync } from 'node:fs';
import { WASI } from 'node:wasi';

const [binary, fixtures, ...args] = process.argv.slice(2);
const start = performance.now();
const wasi = new WASI({version: 'preview1', args: ['compare', ...args], preopens: {'/fixtures': fixtures}});
const bytes = readFileSync(binary);
const imports = wasi.getImportObject();
const fs = imports.wasi_snapshot_preview1;
const open = fs.path_open;
// Go requests more descriptor rights than it uses for a read. Give Node
// only FD_READ, FD_SEEK, FD_TELL and FD_FILESTAT_GET on the staged fixtures.
const readOnly = (1n << 1n) | (1n << 2n) | (1n << 5n) | (1n << 21n);
fs.path_open = (fd, lookup, path, length, flags, rights, inherited, fdFlags, result) =>
  open(fd, lookup, path, length, flags, rights & readOnly, inherited & readOnly, fdFlags, result);
const instance = await WebAssembly.instantiate(await WebAssembly.compile(bytes), imports);
const started = performance.now();
const code = wasi.start(instance);
console.error(JSON.stringify({
  node: process.versions.node, stripped_bytes: bytes.length,
  startup_ms: started - start, wall_ms: performance.now() - start,
  peak_linear_bytes: instance.exports.memory.buffer.byteLength,
  host_peak_rss_kib: process.resourceUsage().maxRSS,
}));
process.exitCode = code;
