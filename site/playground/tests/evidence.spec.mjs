import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
const examples = JSON.parse(readFileSync(new URL('../engine/examples.json', import.meta.url)));
const route = '/go-yara/quickstart/';
const run = page => page.getByRole('button', {name:'Compile and scan',exact:true}).click();
const done = page => expect(page.locator('.playground .status')).toContainText('Scan complete');
const preset = (page, id) => page.locator('#playground-example').selectOption(id);
async function recordReplies(page) {
  await page.addInitScript(() => {
    window.workerReplies = [];
    const NativeWorker = window.Worker;
    window.Worker = class extends NativeWorker {
      constructor(...args) {
        super(...args);
        this.addEventListener('message', event => window.workerReplies.push(event.data));
      }
    };
  });
}

test('all selectable examples match native expectations without running on selection', async ({page}) => {
  const downloads = [];
  page.on('request', request => { if (/scanner\.wasm|wasm_exec\.js|\/worker\.js/.test(request.url())) downloads.push(request.url()); });
  await recordReplies(page);
  await page.goto(route);
  for (const example of examples) {
    const before = downloads.length;
    await preset(page, example.id);
    await expect(page.locator('#playground-rules')).toHaveValue(example.rules);
    await expect(page.locator('#playground-text')).toHaveValue(example.input);
    await expect(page.locator('.results')).toBeHidden();
    await expect(page.locator('.status')).toHaveText('Example loaded. Compile and scan to see results.');
    expect(downloads).toHaveLength(before);
    await run(page);
    await done(page);
    const result = await page.evaluate(() => window.workerReplies.filter(x=>x.result).at(-1).result);
    expect(result.rules, example.id).toEqual(example.expectedRules);
    expect(result.evidence.map(x=>x.status), example.id).toEqual(example.expectedStatuses);
    expect(result.evidenceEnabled, example.id).toBe(example.evidence);
    if (example.evidence) {
      await expect(page.locator('.evidence-results')).toBeVisible();
      await expect(page.locator('.evidence-findings')).toContainText('[redacted]');
    } else await expect(page.locator('.evidence-results')).toBeHidden();
    if (example.id === 'evidence-partial') await expect(page.locator('.evidence-findings')).toContainText('missing');
    if (example.id === 'evidence-truncated') {
      expect(result.evidence[0].fields.some(x=>x.dataTruncated)).toBeTruthy();
      await expect(page.locator('.evidence-findings')).toContainText('truncated');
    }
  }
});

test('redacts captured values before worker replies and keeps input local', async ({page}) => {
  await recordReplies(page);
  const requests = [], consoleMessages = [];
  page.on('request', r => requests.push({url:r.url(),method:r.method(),body:r.postData()}));
  page.on('console', msg=>consoleMessages.push(msg.text()));
  page.on('pageerror', error=>consoleMessages.push(error.message));
  await page.goto(route);
  await preset(page, 'evidence-ready');
  const sentinels = ['endpoint_PRIVATE_9271', 'username_PRIVATE_3268', 'password_PRIVATE_6127'];
  const input = `endpoint=${sentinels[0]} username=${sentinels[1]} password=${sentinels[2]}`;
  await page.locator('#playground-text').fill(input);
  await run(page);
  await done(page);
  await expect(page.locator('.evidence-findings h4')).toContainText('ready');
  await expect(page.locator('.evidence-findings td').filter({hasText:'[redacted]'})).toHaveCount(3);
  await expect(page.locator('#playground-text')).toHaveValue(input);
  const surfaces = await page.evaluate(() => ({
    replies:window.workerReplies,
    results:document.querySelector('.results').textContent,
    storage:[{...localStorage},{...sessionStorage}],
    url:location.href,
  }));
  for (const value of sentinels) {
    expect(JSON.stringify(surfaces)).not.toContain(value);
    expect(JSON.stringify(requests)).not.toContain(value);
    expect(JSON.stringify(consoleMessages)).not.toContain(value);
  }
  expect(requests.every(r=>r.method === 'GET' && !r.body && new URL(r.url).origin === 'http://127.0.0.1:4333')).toBeTruthy();
  const result = surfaces.replies.filter(x=>x.result).at(-1).result;
  expect(result.evidence[0].fields.map(x=>x.offset)).toEqual(sentinels.map(value=>input.indexOf(value)));
  expect(result.evidence[0].fields.every(x=>!('data' in x))).toBeTruthy();
  await page.locator('#playground-evidence').uncheck();
  await expect(page.locator('.results')).toBeHidden();
  await run(page);
  await done(page);
  await expect(page.locator('.evidence-results')).toBeHidden();
  expect(await page.evaluate(()=>window.workerReplies.filter(x=>x.result).at(-1).result.evidence)).toEqual([]);
});

test('preset changes clear files and stale results; edits select custom input', async ({page}) => {
  await page.goto(route);
  await page.locator('#playground-mode').selectOption('file');
  await page.locator('#playground-file').setInputFiles({name:'sample.txt',mimeType:'text/plain',buffer:Buffer.from('hello')});
  await preset(page,'evidence-ready');
  await expect(page.locator('#playground-mode')).toHaveValue('text');
  expect(await page.locator('#playground-file').evaluate(input=>input.files.length)).toBe(0);
  await run(page); await done(page);
  await page.locator('#playground-rules').fill('rule invalid { condition: "PRIVATE_SOURCE_5930" + }');
  await expect(page.locator('#playground-example')).toHaveValue('custom');
  await expect(page.locator('.results')).toBeHidden();
  await run(page);
  await expect(page.locator('.status')).toContainText('Compilation failed');
  await expect(page.locator('.status')).not.toContainText('PRIVATE_SOURCE_5930');
  await preset(page,'greeting');
  await expect(page.locator('#playground-evidence')).not.toBeChecked();
  await run(page); await done(page);
  await expect(page.locator('.matched-rules')).toContainText('greeting');
});

test('example and evidence controls are locked during work and restored on cancellation', async ({page}) => {
  await page.route('**/scanner.wasm', async route => { await new Promise(resolve=>setTimeout(resolve,1000)); await route.continue().catch(()=>{}); });
  await page.goto(route);
  await preset(page,'evidence-ready');
  await run(page);
  await expect(page.locator('#playground-example')).toBeDisabled();
  await expect(page.locator('#playground-evidence')).toBeDisabled();
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await expect(page.locator('.status')).toContainText('cancelled');
  await expect(page.locator('#playground-example')).toBeEnabled();
  await expect(page.locator('#playground-evidence')).toBeEnabled();
  await expect(page.locator('.results')).toBeHidden();
});

test('evidence display caps preserve full conditions, finding statuses, and total counts', async ({page}) => {
  await recordReplies(page);
  await page.goto(route);
  await preset(page,'evidence-ambiguous');
  const record = 'endpoint=db username=alice username=bob username=carol password=demo';
  await page.locator('#playground-text').fill(Array(30).fill(record).join('\n'+'#'.repeat(128)+'\n'));
  await run(page); await done(page);
  let result = await page.evaluate(()=>window.workerReplies.filter(x=>x.result).at(-1).result);
  expect(result.evidenceCount).toBe(30);
  expect(result.evidenceRowCount).toBe(150);
  expect(result.evidence).toHaveLength(20);
  expect(result.evidence.reduce((n,x)=>n+x.fields.length,0)).toBe(80);
  expect(result.evidence.every(x=>x.status === 'ambiguous')).toBeTruthy();
  await expect(page.locator('.evidence-counts')).toContainText('20 of 30 findings and 80 of 150');
  await expect(page.locator('.truncation')).toBeVisible();
  const name = 'r'+'x'.repeat(4000);
  await page.locator('#playground-rules').fill(`rule ${name} { strings: $a=/(a)/ capture(secret=1) evidence: account=(secret) within 0 of secret condition: #a == 300 and @a[300] == 299 }`);
  await page.locator('#playground-text').fill('a'.repeat(300));
  await run(page); await done(page);
  result = await page.evaluate(()=>window.workerReplies.filter(x=>x.result).at(-1).result);
  expect(result.rules).toEqual([name]);
  expect(result.evidenceCount).toBe(300);
  expect(result.evidence.length).toBeLessThan(20);
  expect(Buffer.byteLength(JSON.stringify(result))).toBeLessThanOrEqual(65536);
  expect(result.truncated).toBeTruthy();
});

test('redacted evidence tables fit mobile dark layout', async ({page}) => {
  await page.setViewportSize({width:375,height:812});
  await page.goto(route);
  await page.evaluate(()=>document.documentElement.dataset.theme='dark');
  await preset(page,'evidence-ambiguous');
  await run(page); await done(page);
  await expect(page.locator('.evidence-findings h4')).toContainText('ambiguous');
  await page.locator('.evidence-results').scrollIntoViewIfNeeded();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await expect(page.locator('.evidence-findings td').filter({hasText:'[redacted]'})).toHaveCount(4);
});
