import { test, expect } from '@playwright/test';

for (const layout of [
  {name:'desktop light', width:1280, height:900, theme:'light'},
  {name:'mobile dark', width:375, height:812, theme:'dark'},
]) {
  test(`documentation examples and diagrams remain readable: ${layout.name}`, async ({page}) => {
    await page.setViewportSize({width:layout.width,height:layout.height});
    for (const sample of [
      {path:'scanning', summary:'scan sparse regions and supply an overlapping window', code:'SetFileSize', diagram:'Supplied address space'},
      {path:'modules', summary:'register a function and restore it after loading', code:'UnmarshalCompiledProgram'},
      {path:'quickstart', summary:'inspect omitted rules and their dependents', code:'GetIgnoredRules'},
      {path:'compatibility', summary:'compare text, hex, and regex conditions', code:'text_count'},
      {path:'releases', diagram:'Persisted artifact'},
      {path:'quickstart', summary:'inspect semantic diagnostics and runtime undefined values', code:'semantic.Error', diagram:'Compile-time checks'},
      {path:'performance', summary:'collect scan metrics and hook events', code:'ScanTelemetry', diagram:'One scanner and telemetry sink'},
      {path:'scanning', summary:'distinguish stop-on-match from a poll abort', code:'ErrScanAborted'},
    ]) {
      await page.goto(`/go-yara/${sample.path}/`);
      await page.evaluate(theme=>document.documentElement.dataset.theme=theme, layout.theme);
      if (sample.summary) {
        const details = page.locator('details').filter({has:page.locator('summary').filter({hasText:sample.summary})});
        await details.locator('summary').click();
        await expect(details.locator('pre')).toBeVisible();
        await expect(details.locator('pre')).toContainText(sample.code);
      }
      if (sample.diagram) {
        const diagram = page.locator('figure').filter({hasText:sample.diagram});
        await diagram.scrollIntoViewIfNeeded();
        await expect(diagram).toBeVisible();
        const bounds = await diagram.boundingBox();
        expect(bounds.x).toBeGreaterThanOrEqual(0);
        expect(bounds.x + bounds.width).toBeLessThanOrEqual(layout.width);
      }
      expect(await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    }
  });
}

test('PCAP preview compares actual HTTP transaction rules in Wasm', async ({page}) => {
  const requests = [];
  page.on('request', request => {
    if (request.url().includes('scanner.wasm')) requests.push(request.url());
  });
  await page.goto('/go-yara/modules/');
  await expect(page.getByRole('heading', {name:'Check what an app received over HTTP'})).toBeVisible();
  await expect(page.locator('pre').filter({hasText:'tampered_config_response'})).toBeVisible();
  const preview = page.getByRole('region', {name:'PCAP rule comparison'});
  await expect(preview).toBeHidden();
  await page.locator('summary').filter({hasText:'Advanced walkthrough: review an update detection rule'}).click();
  const status = preview.getByRole('status');
  expect(requests).toEqual([]);
  await preview.getByRole('button', {name:'Compare rules'}).click();
  await expect(status).toContainText('Candidate matches: observed_update_dns. Added: none. Removed: revoked_update.');
  expect(requests.length).toBeGreaterThan(0);
  await preview.getByLabel('Capture', {exact:true}).selectOption({label:'Matching update response'});
  await preview.getByRole('button', {name:'Compare rules'}).click();
  await expect(status).toContainText('Candidate matches: observed_update_dns, revoked_update. Added: none. Removed: none.');
  const source = await preview.getByLabel('Capture', {exact:true}).inputValue();
  await preview.getByLabel('Capture', {exact:true}).selectOption('local');
  await preview.locator('summary').click();
  const baseline = await preview.getByLabel('Baseline', {exact:true}).inputValue();
  await preview.getByLabel('Candidate', {exact:true}).fill(baseline + '\nrule local_change { condition: defined pcap.http[0].request_packet }');
  await preview.getByLabel('Local capture (up to 1 MiB)').setInputFiles({
    name: 'local.pcap', mimeType: 'application/vnd.tcpdump.pcap', buffer: Buffer.from(source.split(',')[1], 'base64'),
  });
  await preview.getByRole('button', {name:'Compare rules'}).click();
  await expect(status).toContainText('Added: local_change. Removed: none.');
});
