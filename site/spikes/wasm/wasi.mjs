import { readFile } from 'node:fs/promises';
import { WASI } from 'node:wasi';
const directory = new URL('./', import.meta.url);
for (const reactor of [false, true]) {
  const wasi = new WASI({ version: 'preview1', args: [], env: {}, preopens: {} });
  const name = reactor ? 'reactor.wasm' : 'command.wasm';
  const module = await WebAssembly.compile(await readFile(new URL(name, directory)));
  const instance = await WebAssembly.instantiate(module, wasi.getImportObject());
  if (reactor) {
    wasi.initialize(instance);
    for (let i = 0; i < 3; i++) {
      if (instance.exports.check() !== 12) throw new Error('reactor fixture failure');
    }
    console.log('PASS: WASI reactor called three times after initialization');
  } else { wasi.start(instance); }
}
