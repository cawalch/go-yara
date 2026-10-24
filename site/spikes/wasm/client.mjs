export class ScannerWorker {
  constructor() {
    this.worker = new Worker('./worker.js');
    this.sequence = 0;
    this.pending = new Map();
    this.ready = new Promise((resolve, reject) => {
      this.rejectReady = reject;
      this.bootTimer = setTimeout(() => this.stop('runtime startup timed out'), 15000);
      this.worker.onmessage = ({ data }) => {
        if (data.ready) { clearTimeout(this.bootTimer); resolve(data); }
        if (data.fatal) this.stop(data.fatal);
        if (data.started) this.pending.get(data.started)?.onStart?.();
        const request = this.pending.get(data.id);
        if (request) {
          clearTimeout(request.timer);
          this.pending.delete(data.id);
          request.resolve(data);
        }
      };
      this.worker.onerror = event => this.stop(event.message);
    });
  }
  async call(operation, value, { timeout = 3000, onStart } = {}) {
    await this.ready;
    if (this.stopped) throw new Error('worker stopped');
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.stop('operation timed out'), timeout);
      this.pending.set(id, { resolve, reject, timer, onStart });
      this.worker.postMessage({ id, operation, value }, operation === 'scan' ? [value] : []);
    });
  }
  stop(message = 'cancelled') {
    this.stopped = true;
    clearTimeout(this.bootTimer);
    this.worker.terminate();
    this.rejectReady(new Error(message));
    for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(new Error(message)); }
    this.pending.clear();
  }
}

export async function runSuite() {
  const fixtures = await (await fetch('./fixtures.json')).json();
  let client = new ScannerWorker();
  const measurements = { environment: navigator.userAgent, startup: await client.ready, cases: [] };
  const assert = (ok, message) => { if (!ok) throw new Error(message); };
  try {
    assert((await client.call('scan', new ArrayBuffer(0))).error === 'compile rules first', 'scan before compile');
    for (const fixture of fixtures) {
      const compiled = await client.call('compile', fixture.rules);
      if (fixture.error) { assert(Boolean(compiled.error), fixture.name); continue; }
      assert(!compiled.error, `${fixture.name}: ${compiled.error}`);
      for (let i = 0; i < 3; i++) {
        const bytes = Uint8Array.from(fixture.hex.match(/../g) || [], h => parseInt(h, 16));
        const result = await client.call('scan', bytes.buffer);
        assert(!result.error && JSON.stringify(result.matches) === JSON.stringify(fixture.want), `${fixture.name}: ${JSON.stringify(result)}`);
      }
      measurements.cases.push(fixture.name);
    }
    assert((await client.call('scan', new ArrayBuffer(0))).error === 'compile rules first', 'failed compile must clear stale rules');
    assert(Boolean((await client.call('compile', ' '.repeat(32769))).error), 'rule limit');
    await client.call('compile', 'rule r { strings: $a = "marker" condition: $a }');
    assert(Boolean((await client.call('scan', new ArrayBuffer(8 * 1024 * 1024 + 1))).error), 'input limit');
    measurements.scan1MiB = [];
    for (let i = 0; i < 6; i++) {
      const bytes = new Uint8Array(1024 * 1024).fill(120);
      bytes.set(new TextEncoder().encode('marker'), bytes.length - 6);
      const start = performance.now();
      const result = await client.call('scan', bytes.buffer);
      assert(JSON.stringify(result.matches) === JSON.stringify(['r/$a@1048570+6', 'rule:r']), 'large buffer result');
      measurements.scan1MiB.push({ engineAndResultMs: result.ms, roundTripMs: performance.now() - start, memoryBytes: result.memoryBytes });
    }
    const memory = [];
    for (let i = 0; i < 50; i++) {
      const result = await client.call('scan', new Uint8Array(1024 * 1024).fill(120).buffer);
      assert(!result.error && result.matches.length === 0, 'repeated reject');
      memory.push(result.memoryBytes);
    }
    measurements.repeatedRejects = { scans: 50, firstMemoryBytes: memory[0], lastMemoryBytes: memory.at(-1), peakMemoryBytes: Math.max(...memory) };
    // Terminate actual scanner work, not a synthetic JavaScript busy loop.
    await client.call('compile', 'rule slow { strings: $a = /a.*b/ condition: $a }');
    let ticks = 0;
    const ticker = setInterval(() => ticks++, 5);
    const start = performance.now();
    try {
      await client.call('scan', new Uint8Array(8 * 1024 * 1024).fill(97).buffer, {
        onStart: () => setTimeout(() => client.stop('cancelled busy scan'), 50),
      });
      throw new Error('scan finished before cancellation probe');
    } catch (error) {
      assert(error.message === 'cancelled busy scan', error.message);
      measurements.cancellation = { elapsedMs: performance.now() - start, uiTicks: ticks };
      assert(ticks > 0, 'main thread did not tick during scanning');
    } finally { clearInterval(ticker); }
    client = new ScannerWorker();
    measurements.restart = await client.ready;
    await client.call('compile', 'rule r { condition: true }');
    assert((await client.call('scan', new ArrayBuffer(0))).matches.includes('rule:r'), 'restart after cancellation');
    await client.call('compile', 'rule slow { strings: $a = /a.*b/ condition: $a }');
    let scanStarted = false;
    try {
      await client.call('scan', new Uint8Array(8 * 1024 * 1024).fill(97).buffer, {
        timeout: 100, onStart: () => { scanStarted = true; },
      });
      throw new Error('scan finished before timeout probe');
    } catch (error) {
      assert(error.message === 'operation timed out' && scanStarted, 'automatic timeout failed: ' + error.message);
      measurements.automaticTimeout = true;
    }
    measurements.pass = true;
    return measurements;
  } finally { client.stop(); }
}
