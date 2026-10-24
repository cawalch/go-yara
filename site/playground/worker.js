/* Configuration is inserted by the release builder. This file is not served raw. */
const config = __CONFIG__;
importScripts('./wasm_exec.js');
const go = new Go();
let instance;
let busy = false;
const ready = new Promise(resolve => { self.goYaraReady = resolve; });
function fatal() {
  postMessage({ fatal: 'The scanner stopped before completing. It may have reached the memory limit. No complete result is available.' });
  self.close();
}
// Do not forward unbounded Go stderr (for example a fatal heap dump) to the UI.
go.exit = () => fatal();
self.fs.writeSync = (_fd, bytes) => bytes.length;
async function boot() {
  const response = await fetch('./scanner.wasm');
  if (!response.ok) throw new Error('Scanner download failed. Reload the page and try again.');
  // arrayBuffer also works with hosts that omit application/wasm.
  ({ instance } = await WebAssembly.instantiate(await response.arrayBuffer(), go.importObject));
  go.run(instance).then(fatal, fatal);
  await ready;
  postMessage({ ready: true, version: config.version });
}
boot().catch(() => { postMessage({ fatal: 'Could not load the scanner. Reload the page and try again.' }); self.close(); });
self.onmessage = async ({ data }) => {
  if (busy) return;
  busy = true;
  await ready;
  if (typeof data.rules !== 'string' || !(data.input instanceof ArrayBuffer) ||
      data.rules.length > config.limits.rulesBytes || new TextEncoder().encode(data.rules).length > config.limits.rulesBytes || data.input.byteLength > config.limits.inputBytes) {
    postMessage({ error: 'Rule source or input exceeds the playground limit.' }); return;
  }
  try {
    const encoded = self.goYaraRun(data.rules, new Uint8Array(data.input));
    if (new TextEncoder().encode(encoded).length > config.limits.outputBytes) throw new Error('output budget');
    postMessage({ result: JSON.parse(encoded), version: config.version, memoryBytes: instance.exports.mem.buffer.byteLength });
  } catch { fatal(); }
};
