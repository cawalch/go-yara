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
