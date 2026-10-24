// Classic worker: wasm_exec.js comes from the exact Go toolchain used to build.
importScripts('./wasm_exec.js');
const started = performance.now();
const go = new Go();
let instance;
const ready = new Promise(resolve => { self.goYaraReady = resolve; });
async function boot() {
  const response = await fetch('./scanner.wasm');
  if (!response.ok) throw new Error(`Wasm download: HTTP ${response.status}`);
  ({ instance } = await WebAssembly.instantiateStreaming(response, go.importObject));
  go.run(instance).catch(error => postMessage({ fatal: String(error) }));
  await ready;
  postMessage({ ready: true, startupMs: performance.now() - started, memoryBytes: instance.exports.mem.buffer.byteLength });
}
boot().catch(error => postMessage({ fatal: String(error) }));
self.onmessage = async ({ data: { id, operation, value } }) => {
  await ready;
  postMessage({ started: id });
  try {
    const result = JSON.parse(self.goYaraCall(operation, operation === 'scan' ? new Uint8Array(value) : value));
    postMessage({ id, ...result, memoryBytes: instance.exports.mem.buffer.byteLength });
  } catch (error) {
    postMessage({ id, error: String(error) });
  }
};
