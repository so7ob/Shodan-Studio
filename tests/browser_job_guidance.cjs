/* Local synthetic server only; checks that presentation never submits a retry. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
(async () => {
  const [base, info, output] = process.argv.slice(2);
  const ids = JSON.parse(fs.readFileSync(info));
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 1000 }, reducedMotion: 'reduce' });
    const errors = [], mutations = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => { if (request.method() === 'POST' && !request.url().endsWith('/api/login')) mutations.push(request.url()); });
    await page.route('**/*', route => route.request().url().startsWith(base + '/') ? route.continue() : route.abort());
    await page.goto(base);
    await page.locator('#auth-user').fill('fixture');
    await page.locator('#auth-password').fill('local-fixture-password-123!');
    await page.locator('#auth-submit').click();
    async function select(name) {
      const row = page.locator(`[data-job="${ids[name]}"]`);
      await row.waitFor(); await row.focus(); await page.keyboard.press('Enter');
      await page.waitForFunction(title => document.getElementById('detail-title').textContent === title, 'Fixture · ' + name);
    }
    await select('future');
    assert.ok(await page.locator('#wait-countdown').isVisible());
    assert.match(await page.locator('#job-alert-message').innerText(), /موعد المحاولة المحفوظ/);
    assert.match(await page.locator('#job-checkpoint-status').innerText(), /نقطة حفظ متاحة/);
    for (let i = 0; i < 3; i++) {
      await page.locator('#detail-actions [data-action="resume"]').click();
      assert.match(await page.locator('#resume-description').innerText(), /لا تقصّر الانتظار/);
      await page.keyboard.press('Escape');
      await page.waitForFunction(() => !document.getElementById('resume-dialog').open);
    }
    await page.reload(); await select('future');
    assert.match(await page.locator('#job-alert-message').innerText(), /موعد المحاولة المحفوظ/);
    await select('expired');
    assert.ok(await page.locator('#wait-countdown').isHidden());
    assert.match(await page.locator('#job-alert-title').innerText(), /انتهت مهلة/);
    assert.match(await page.locator('#job-alert-message').innerText(), /لم تُرسل اللوحة/);
    await select('malformed');
    assert.match(await page.locator('#job-alert-message').innerText(), /لا يوجد موعد انتظار صالح/);
    assert.ok(await page.locator('#wait-countdown').isHidden());
    await page.reload(); await select('malformed');
    assert.match(await page.locator('#job-alert-message').innerText(), /لا يوجد موعد انتظار صالح/);
    assert.ok(await page.locator('#wait-countdown').isHidden());
    await select('missing');
    assert.match(await page.locator('#job-checkpoint-status').innerText(), /لا توجد نقطة حفظ/);
    await select('denied');
    assert.match(await page.locator('#job-alert-title').innerText(), /لم يسمح/);
    const summary = page.locator('#job-technical-error summary');
    await summary.focus(); await page.keyboard.press('Enter');
    assert.match(await page.locator('#job-technical-error-text').innerText(), /<img/);
    assert.equal(await page.locator('[data-fixture-injected]').count(), 0);
    for (const width of [1280, 375]) {
      await page.setViewportSize({ width, height: 1000 });
      await select('future');
      if (width === 375) assert.ok(await page.locator('#job-alert-message').evaluate(el => el.getBoundingClientRect().width > 200));
      await page.locator('#job-alert').screenshot({ path: path.join(output, `deadline-${width}.png`), animations: 'disabled' });
      await select('manual');
      assert.match(await page.locator('#job-alert-message').innerText(), /تكرار الاستكمال لا يرفع الحظر/);
      assert.ok(await page.locator('#wait-countdown').isHidden());
      assert.equal(await page.locator('html').getAttribute('dir'), 'rtl');
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      if (width === 375) await page.waitForFunction(() => document.getElementById('sidebar').getBoundingClientRect().left >= innerWidth - 1);
      await page.screenshot({ path: path.join(output, `manual-hold-${width}.png`), fullPage: true, animations: 'disabled' });
      await page.locator('#job-alert').screenshot({ path: path.join(output, `guidance-${width}.png`), animations: 'disabled' });
    }
    assert.deepEqual(mutations, []);
    assert.deepEqual(errors, []);
    fs.writeFileSync(path.join(output, 'acceptance.json'), JSON.stringify({ states: Object.keys(ids), widths: [1280,375], mutations, errors, reload: true, repeatedDialogCancel: 3, keyboard: true }, null, 2));
    console.log('PASS: persisted wait, elapsed/manual/denied/missing-checkpoint states, reload, repeated dialog cancel, literal errors, RTL 1280/375, zero mutation requests or browser errors.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
