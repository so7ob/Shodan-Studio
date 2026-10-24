/* Real browser acceptance against the isolated Debian service; no mocked API. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');
const { AxeBuilder } = require('@axe-core/playwright');

(async () => {
  const [base, jobId] = process.argv.slice(2);
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 1000 }, reducedMotion: 'reduce' });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.route('**/*', route => route.request().url().startsWith(base + '/') ? route.continue() : route.abort());
  try {
    await page.goto(base);
    await page.locator('#auth-user').fill('acceptance');
    await page.locator('#auth-password').fill('local-fixture-password-123!');
    await page.locator('#auth-submit').click();
    const row = page.locator(`[data-job="${jobId}"]`);
    await row.waitFor();
    assert.match(await row.innerText(), /512 من أصل نحو 782 عنوان IP/);
    assert.match(await row.innerText(), /16 \/ 77/);
    assert.equal(await row.locator('[role="progressbar"]').getAttribute('aria-valuenow'), '65');
    await row.focus();
    await page.keyboard.press('Enter');
    await page.locator('#detail-ip-progress [role="progressbar"]').waitFor();
    assert.equal(await page.locator('#detail-ip-progress [role="progressbar"]').getAttribute('aria-valuenow'), '65');
    const folder = path.join(__dirname, '../docs/ip-progress-evidence');
    fs.mkdirSync(folder, { recursive: true });
    const report = [];
    for (const width of [1280, 375]) {
      await page.setViewportSize({ width, height: 1000 });
      await page.locator('#detail-ip-progress').scrollIntoViewIfNeeded();
      await page.screenshot({ path: path.join(folder, `rtl-${width}.png`), fullPage: true });
      assert.equal(await page.locator('html').getAttribute('dir'), 'rtl');
      const layout = await page.evaluate(() => ({ width: innerWidth, scrollWidth: document.documentElement.scrollWidth,
        overflow: [...document.querySelectorAll('body *')].filter(el => !el.closest('#sidebar')).map(el => ({ tag: el.tagName, id: el.id, cls: el.className,
          left: el.getBoundingClientRect().left, right: el.getBoundingClientRect().right }))
          .filter(el => el.right > innerWidth + 1 || el.left < -1).sort((a,b) => a.left-b.left).slice(0, 15) }));
      assert.equal(layout.scrollWidth <= width, true, JSON.stringify(layout));
      assert.equal(await page.locator('#detail-ip-progress .ip-progress__fill').evaluate(el => el.style.width), '65%');
      const scan = await new AxeBuilder({ page }).include('#detail-ip-progress').include('.job-ip-progress').analyze();
      assert.deepEqual(scan.violations, []);
      const focus = await page.evaluate(() => document.activeElement?.tagName);
      await page.screenshot({ path: path.join(folder, `rtl-${width}.png`), fullPage: true });
      report.push({ width, axeViolationsInProgressWidgets: scan.violations.length, focus });
    }
    // Exercise unknown, failed, and successful-zero render states using the
    // production component, without changing the running service's fixture.
    const states = await page.evaluate(() => {
      const el = document.createElement('div');
      document.body.append(el);
      const unknown = ShodanIPProgress.render(el, { extracted_unique_ips: 12, estimated_total_ips: null, progress_percent: null });
      const noNumericAria = !el.querySelector('[aria-valuenow]');
      const failed = ShodanIPProgress.render(el, { extracted_unique_ips: 12, estimated_total_ips: 12, progress_percent: 100, job_finished_successfully: false });
      const zero = ShodanIPProgress.render(el, { extracted_unique_ips: 0, estimated_total_ips: 0, progress_percent: 100, job_finished_successfully: true });
      el.remove();
      return { unknown: unknown.percent, noNumericAria, failed: failed.percent, zero: zero.percent };
    });
    assert.deepEqual(states, { unknown: null, noNumericAria: true, failed: 99, zero: 100 });
    assert.deepEqual(errors, []);
    fs.writeFileSync(path.join(folder, 'browser.json'), JSON.stringify({ report, states, browserErrors: errors }, null, 2) + '\n');
    console.log('PASS: browser login, keyboard detail, list/detail 65%, RTL 1280/375, widget axe, unknown/failed/zero states.');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
