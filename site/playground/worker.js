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

function validRules(rules) {
  return typeof rules === 'string' && rules.length <= config.limits.rulesBytes &&
    new TextEncoder().encode(rules).length <= config.limits.rulesBytes;
}

async function runPCAP(data) {
  const size = data.input instanceof Blob ? data.input.size : data.input instanceof ArrayBuffer ? data.input.byteLength : -1;
  if (size < 0 || size > config.limits.inputBytes) return { error: 'Capture exceeds the playground input limit.' };
  if (data.kind === 'pcap-probe') {
    if (typeof self.goYaraProbe !== 'function' || !(data.input instanceof Blob) ||
        !['whole', 'seekable'].includes(data.strategy)) return { error: 'Invalid reader probe request.' };
    return { encoded: self.goYaraProbe(data.input, data.strategy === 'seekable') };
  }
  if (typeof self.goYaraCompare !== 'function' || !validRules(data.baseline) || !validRules(data.candidate) ||
      typeof data.rule !== 'string' || data.rule.length > 128 ||
      typeof data.fixture !== 'string' || data.fixture.length > 128) {
    return { error: 'Invalid comparison or rule source exceeds the playground limit.' };
  }
  const bytes = data.input instanceof Blob ? await data.input.arrayBuffer() : data.input;
  return { encoded: self.goYaraCompare(data.baseline, data.candidate, data.rule, data.fixture, new Uint8Array(bytes)) };
}

self.onmessage = async ({ data }) => {
  if (busy) return;
  busy = true;
  await ready;
  try {
    let encoded;
    if (data.kind === 'pcap' || data.kind === 'pcap-probe') {
      const result = await runPCAP(data);
      if (result.error) { postMessage({ error: result.error }); return; }
      encoded = result.encoded;
    } else {
      if (typeof data.evidence !== 'boolean' || !validRules(data.rules) || !(data.input instanceof ArrayBuffer) ||
          data.input.byteLength > config.limits.inputBytes) {
        postMessage({ error: 'Rule source or input exceeds the playground limit.' }); return;
      }
      encoded = self.goYaraRun(data.rules, new Uint8Array(data.input), data.evidence);
    }
    if (new TextEncoder().encode(encoded).length > config.limits.outputBytes) {
      postMessage({ error: 'Result exceeds the output budget.' }); return;
    }
    postMessage({ result: JSON.parse(encoded), version: config.version, memoryBytes: instance.exports.mem.buffer.byteLength });
  } catch { fatal(); }
};
