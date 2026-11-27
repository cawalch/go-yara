import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';

const references = JSON.parse(readFileSync(new URL('../../src/generated/pcap-references.json', import.meta.url)));

function preview(page) {
  return page.getByRole('region', {name:'PCAP rule comparison'});
}

test('HTTP evidence agrees with the native corpus', async ({page}) => {
  await page.addInitScript(() => {
    const OriginalWorker = window.Worker;
    window.pcapReports = [];
    window.Worker = class extends OriginalWorker {
      constructor(...args) {
        super(...args);
        this.addEventListener('message', ({data}) => {
          if (data.result?.schema_version === 1) window.pcapReports.push(data.result);
        });
      }
    };
  });
  await page.goto('/go-yara/modules/');
  const region = preview(page);
  for (const [label, id] of [
    ['Control with unrelated marker', 'control'],
    ['Matching update response', 'positive'],
    ['Resegmented update request', 'split'],
    ['Clipped update response', 'unavailable'],
    ['Same rule, different response', 'different'],
  ]) {
    await region.getByLabel('Capture', {exact:true}).selectOption({label});
    await region.getByRole('button', {name:'Compare rules'}).click();
    await expect(region.getByRole('table')).toBeVisible();
    const report = await page.evaluate(() => window.pcapReports.at(-1));
    const native = id === 'different' ? references.different : references.corpus;
    expect(report.parser).toBe(native.parser);
    expect(report.baseline_compiled_sha256).toBe(native.baseline_compiled_sha256);
    expect(report.candidate_compiled_sha256).toBe(native.candidate_compiled_sha256);
    expect(report.fixtures).toEqual([native.fixtures.find(row => row.fixture === id)]);
  }
  await expect(region.getByRole('status')).toContainText('Candidate matches: revoked_update. Added: none. Removed: none.');
  await expect(region.getByText('The supporting response changed.')).toBeVisible();
  await expect(region.getByRole('row', {name:/Baseline/})).toContainText('response 3:0');
  await expect(region.getByRole('row', {name:/Candidate/})).toContainText('response 7:0');
});

test('local PCAP input stays in the worker and failures clear the comparison', async ({page}) => {
  await page.addInitScript(() => {
    File.prototype.arrayBuffer = () => { throw new Error('Capture bytes were read on the main thread.'); };
  });
  const posts = [];
  page.on('request', request => { if (request.method() === 'POST') posts.push(request.url()); });
  await page.goto('/go-yara/modules/');
  const region = preview(page);
  const capture = region.getByLabel('Capture', {exact:true});
  await capture.selectOption({label:'Matching update response'});
  const source = Buffer.from((await capture.inputValue()).split(',')[1], 'base64');
  await capture.selectOption('local');
  const input = region.getByLabel('Local capture (up to 1 MiB)');
  const compare = region.getByRole('button', {name:'Compare rules'});
  const status = region.getByRole('status');
  const table = region.getByRole('table');
  await input.setInputFiles({name:'valid.pcap', mimeType:'application/octet-stream', buffer:source});
  await compare.click();
  await expect(table).toBeVisible();
  await input.setInputFiles({name:'large.pcap', mimeType:'application/octet-stream', buffer:Buffer.alloc(1048577)});
  await compare.click();
  await expect(status).toHaveText('Input exceeds 1 MiB.');
  await expect(table).toBeHidden();
  await input.setInputFiles({name:'invalid.pcap', mimeType:'application/octet-stream', buffer:Buffer.from('invalid')});
  await compare.click();
  await expect(status).toHaveText('fixture is not a readable capture');
  await expect(table).toBeHidden();
  expect(posts).toEqual([]);
});

test('cancelling a PCAP comparison leaves no verdict', async ({page}) => {
  let release;
  const hold = new Promise(resolve => { release = resolve; });
  await page.route('**/scanner.wasm', async route => {
    await hold;
    await route.continue().catch(() => {});
  });
  try {
    await page.goto('/go-yara/modules/');
    const region = preview(page);
    await region.getByRole('button', {name:'Compare rules'}).click();
    await region.getByRole('button', {name:'Cancel'}).click();
    await expect(region.getByRole('status')).toHaveText('Comparison cancelled. No complete result is available.');
    await expect(region.getByRole('table')).toBeHidden();
    await expect(region.getByRole('button', {name:'Compare rules'})).toBeEnabled();
  } finally {
    release();
  }
});

test('worker-local seekable and whole reads recover the same late response', async ({page, browserName}) => {
  await page.goto('/go-yara/modules/');
  const region = preview(page);
  const capture = region.getByLabel('Capture', {exact:true});
  await capture.selectOption({label:'Matching update response'});
  const positive = Buffer.from((await capture.inputValue()).split(',')[1], 'base64');
  // Ethernet padding on an unrelated DNS frame separates the record header
  // from the next packet. The original IP and UDP datagram remain intact.
  const header = Buffer.from(positive.subarray(24, 40));
  const padding = Buffer.alloc(16 << 10);
  positive.copy(padding, 0, 40, 40 + header.readUInt32LE(8));
  header.writeUInt32LE(padding.length, 8);
  header.writeUInt32LE(padding.length, 12);
  const record = Buffer.concat([header, padding]);
  const sparse = Buffer.concat([positive.subarray(0, 24), ...Array(54).fill(record), positive.subarray(24)]);
  const results = await region.evaluate(async (element, bytes) => {
    const config = JSON.parse(element.dataset.config);
    const capture = new File([Uint8Array.from(atob(bytes), char => char.charCodeAt(0))], 'sparse.pcap');
    const run = (strategy) => new Promise((resolve, reject) => {
      const worker = new Worker(config.workerURL);
      const timer = setTimeout(() => finish(reject, new Error('Probe timed out')), config.limits.startupMs);
      const finish = (complete, value) => {
        clearTimeout(timer);
        worker.terminate();
        complete(value);
      };
      worker.onerror = () => finish(reject, new Error('Probe worker failed'));
      worker.onmessage = ({data}) => {
        if (data.ready) worker.postMessage({kind:'pcap-probe', input:capture, strategy});
        else if (data.error || data.fatal || data.result?.error) finish(reject, new Error(data.error ?? data.fatal ?? data.result.error));
        else finish(resolve, {...data.result, peak_linear_bytes:data.memoryBytes});
      };
    });
    return {whole:await run('whole'), seekable:await run('seekable')};
  }, sparse.toString('base64'));
  expect(results.whole.artifacts).toEqual([{request_packet:58, response_packet:59, decoded_bytes:30}]);
  expect(results.seekable.artifacts).toEqual(results.whole.artifacts);
  expect(results.whole.bytes_read).toBe(sparse.length);
  expect(results.whole.reads).toBe(1);
  expect(results.seekable.bytes_read).toBeLessThan(sparse.length / 4);
  expect(results.seekable.reads).toBeGreaterThan(1);
  console.log(`${browserName} sparse input ${sparse.length} bytes: ${JSON.stringify(results)}`);
});
