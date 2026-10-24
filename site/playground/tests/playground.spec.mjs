import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
const fixtures = JSON.parse(readFileSync(new URL('./fixtures.json', import.meta.url)));
const route = '/go-yara/quickstart/';
const run = page => page.getByRole('button', { name: 'Compile and scan', exact:true }).click();

test('loads on demand, scans locally, and reports the documented release', async ({page, browserName, browser}) => {
  const requests = [];
  page.on('request', r => requests.push({url:r.url(), method:r.method(), body:r.postData()}));
  await page.goto(route);
  const version = await page.locator('.release-stamp').innerText();
  await expect(page.locator('.playground .status')).toHaveText('Scanner not loaded.');
  expect(requests.filter(r => /scanner\.wasm|wasm_exec\.js|\/worker\.js/.test(r.url))).toHaveLength(0);
  await run(page);
  await expect(page.locator('.playground .status')).toContainText('Scan complete');
  const config = await page.locator('.playground').getAttribute('data-config');
  expect(version).toContain(JSON.parse(config).version);
  await expect(page.locator('.matched-rules')).toContainText('greeting');
  await expect(page.locator('.playground tbody tr')).toHaveCount(1);
  expect(requests.some(r => r.url.endsWith('/scanner.wasm'))).toBeTruthy();
  expect(requests.every(r => r.method === 'GET' && !r.body)).toBeTruthy();
  console.log(`${browserName}: ${browser.version()}`);
});

test('fixture rules and byte offsets agree with native expectations', async ({page}) => {
  await page.goto(route);
  await page.locator('#playground-mode').selectOption('file');
  for (const f of fixtures) {
    await page.locator('#playground-rules').fill(f.rules);
    await page.locator('#playground-file').setInputFiles({name:'fixture.bin', mimeType:'application/octet-stream', buffer:Buffer.from(f.hex,'hex')});
    await run(page);
    if (f.error) {
      await expect(page.locator('.playground .status')).toContainText('Compilation failed');
      await expect(page.locator('.playground .results')).toBeHidden();
      continue;
    }
    await expect(page.locator('.playground .status')).toContainText('Scan complete');
    const got = await page.locator('.playground .results').evaluate(element => {
      const rules = [...element.querySelectorAll('.matched-rules li')].map(e=>e.textContent).filter(x=>x !== 'No rules matched.').map(x=>'rule:'+x);
      const occurrences = [...element.querySelectorAll('tbody tr')].map(row=>{const [r,p,o,l]=[...row.cells].map(c=>c.textContent);return `${r}/${p}@${o}+${l}`;});
      return [...rules,...occurrences].sort();
    });
    expect(got, f.name).toEqual(f.want);
  }
});

test('display caps preserve counts and offsets, including false rule occurrences', async ({page}) => {
  await page.goto(route);
  await page.locator('#playground-rules').fill('rule yes { strings: $a="a" condition: #a == 300 and @a[300] == 299 } rule no { strings: $a="a" condition: #a == 200 }');
  await page.locator('#playground-text').fill('a'.repeat(300));
  await run(page);
  await expect(page.locator('.playground .status')).toContainText('Scan complete');
  await expect(page.locator('.matched-rules li')).toHaveText(['yes']);
  await expect(page.locator('.playground tbody tr')).toHaveCount(200);
  await expect(page.locator('.truncation')).toContainText('200 of 600');
});

test('validates byte limits before loading a worker and recovers from compile errors', async ({page}) => {
  const downloads = [];
  page.on('request', r=>{if (r.url().endsWith('/scanner.wasm')) downloads.push(r.url());});
  await page.goto(route);
  await page.locator('#playground-mode').selectOption('file');
  await page.locator('#playground-file').setInputFiles({name:'too-large.bin',mimeType:'application/octet-stream',buffer:Buffer.alloc(1048577)});
  await run(page);
  await expect(page.locator('.status')).toContainText('Input exceeds');
  expect(downloads).toHaveLength(0);
  await page.locator('#playground-mode').selectOption('text');
  await page.locator('#playground-rules').fill('é'.repeat(9000));
  await run(page);
  await expect(page.locator('.status')).toContainText('Rule source exceeds');
  expect(downloads).toHaveLength(0);
  await page.locator('#playground-rules').fill('rule r { condition: }');
  await run(page);
  await expect(page.locator('.status')).toContainText('Compilation failed');
  await page.locator('#playground-rules').fill('rule recovered { condition: true }');
  await run(page);
  await expect(page.locator('.matched-rules')).toContainText('recovered');
});

test('caps long-name output by bytes and caps the rule list', async ({page}) => {
  await page.goto(route);
  const name = 'r' + 'x'.repeat(1000);
  await page.locator('#playground-rules').fill(`rule ${name} { strings: $a="a" condition: #a == 300 }`);
  await page.locator('#playground-text').fill('a'.repeat(300));
  await run(page);
  await expect(page.locator('.status')).toContainText('Scan complete');
  expect(await page.locator('.playground tbody tr').count()).toBeLessThan(200);
  await expect(page.locator('.matched-rules li')).toHaveText([name]);
  await expect(page.locator('.truncation')).toBeVisible();
  await page.locator('#playground-rules').fill(Array.from({length:110},(_,i)=>`rule r${i} { condition: true }`).join('\n'));
  await run(page);
  await expect(page.locator('.status')).toContainText('Scan complete');
  await expect(page.locator('.matched-rules li')).toHaveCount(100);
  await expect(page.locator('.truncation')).toContainText('100 of 110');
});

test('cancels startup, handles download failures, and can retry', async ({page}) => {
  await page.route('**/scanner.wasm', async route => { await new Promise(resolve=>setTimeout(resolve,1000)); await route.continue().catch(()=>{}); });
  await page.goto(route);
  await run(page);
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await expect(page.locator('.status')).toContainText('cancelled');
  await expect(page.locator('.results')).toBeHidden();
  await page.unroute('**/scanner.wasm');
  await page.route('**/scanner.wasm', route=>route.fulfill({status:503,body:'Unavailable'}));
  await run(page);
  await expect(page.locator('.status')).toContainText('Could not load');
  await page.unroute('**/scanner.wasm');
  await run(page);
  await expect(page.locator('.status')).toContainText('Scan complete');
});

test('stops an expensive scan without a partial result and restarts', async ({page}) => {
  await page.goto(route);
  await page.locator('#playground-rules').fill('rule slow { strings: $a=/a.*b/ condition: $a }');
  await page.locator('#playground-mode').selectOption('file');
  await page.locator('#playground-file').setInputFiles({name:'costly.bin',mimeType:'application/octet-stream',buffer:Buffer.alloc(1048576,97)});
  await run(page);
  await expect(page.locator('.status')).toContainText('three-second scan limit');
  await expect(page.locator('.results')).toBeHidden();
  await page.locator('#playground-rules').fill('rule recovered { condition: true }');
  await run(page);
  await expect(page.locator('.matched-rules')).toContainText('recovered');
});

test('cancel interrupts active scanner work while the page remains responsive', async ({page}) => {
  await page.goto(route);
  await page.locator('#playground-rules').fill('rule slow { strings: $a=/a.*b/ condition: $a }');
  await page.locator('#playground-mode').selectOption('file');
  await page.locator('#playground-file').setInputFiles({name:'costly.bin',mimeType:'application/octet-stream',buffer:Buffer.alloc(1048576,97)});
  await run(page);
  await expect(page.locator('.status')).toHaveText('Compiling and scanning…');
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await expect(page.locator('.status')).toContainText('cancelled');
  await expect(page.locator('.results')).toBeHidden();
});

test('actual Wasm memory cannot grow past the configured ceiling', async ({page}) => {
  await page.goto(route);
  const config = JSON.parse(await page.locator('.playground').getAttribute('data-config'));
  const answer = await page.evaluate(async config => {
    const base = new URL('.', location.origin + config.workerURL).href;
    const source = `importScripts(${JSON.stringify(base+'wasm_exec.js')}); (async()=>{const go=new Go();const {instance}=await WebAssembly.instantiate(await (await fetch(${JSON.stringify(base+'scanner.wasm')})).arrayBuffer(),go.importObject);const memory=instance.exports.mem;let blocked=false;try{memory.grow(${config.limits.memoryBytes/65536});}catch(e){blocked=e instanceof RangeError;}postMessage({blocked,bytes:memory.buffer.byteLength});})().catch(e=>postMessage({error:String(e)}));`;
    const url = URL.createObjectURL(new Blob([source],{type:'text/javascript'}));
    const worker = new Worker(url);
    try { return await new Promise((resolve,reject)=>{worker.onmessage=e=>resolve(e.data);worker.onerror=e=>reject(new Error(e.message));}); }
    finally {worker.terminate();URL.revokeObjectURL(url);}
  }, config);
  expect(answer.blocked).toBeTruthy();
  expect(answer.bytes).toBeLessThanOrEqual(config.limits.memoryBytes);
});

test('match explosion fails safely and leaves the next scan usable', async ({page}) => {
  await page.goto(route);
  await page.locator('#playground-rules').fill('rule many { strings: $a="a" $b="aa" $c="aaa" condition: all of them }');
  await page.locator('#playground-mode').selectOption('file');
  await page.locator('#playground-file').setInputFiles({name:'many.bin',mimeType:'application/octet-stream',buffer:Buffer.alloc(1048576,97)});
  await run(page);
  await expect(page.locator('.status')).toContainText(/stopped before completing|three-second scan limit/);
  await expect(page.locator('.results')).toBeHidden();
  await page.locator('#playground-rules').fill('rule recovered { condition: true }');
  await run(page);
  await expect(page.locator('.matched-rules')).toContainText('recovered');
});

test('mobile layout, dark theme, and literal rendering of hostile text', async ({page}) => {
  await page.setViewportSize({width:375,height:812});
  await page.goto(route);
  await page.evaluate(()=>document.documentElement.dataset.theme='dark');
  await page.locator('#playground-text').fill('<img src=x onerror="window.bad=1"> hello');
  await run(page);
  await expect(page.locator('.status')).toContainText('Scan complete');
  expect(await page.evaluate(()=>Boolean(window.bad))).toBeFalsy();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await expect(page.getByRole('button',{name:'Compile and scan',exact:true})).toBeEnabled();
});
