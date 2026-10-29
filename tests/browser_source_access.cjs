/* Local HTTP fixture only: network health and website access are separate. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {chromium} = require('playwright');
const {AxeBuilder} = require('@axe-core/playwright');
(async () => {
  const base = process.argv[2] || 'http://127.0.0.1:8793';
  const browser = await chromium.launch({headless:true});
  const context = await browser.newContext({viewport:{width:1280,height:1000},reducedMotion:'reduce'});
  const page = await context.newPage();
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/*',r=>r.request().url().startsWith(base+'/')?r.continue():r.abort());
  const widths=[];
  try {
    await page.goto(base);await page.locator('#auth-user').fill('acceptance');
    await page.locator('#auth-password').fill('local-browser-fixture-123!');await page.locator('#auth-submit').click();
    await page.locator('#jobs-body tr[data-job]').first().focus();await page.keyboard.press('Enter');
    await page.locator('#job-network-error').filter({hasText:'بسبب تحقق متصفح تفاعلي'}).waitFor();
    assert.match(await page.locator('#job-network-error').textContent(),/نقطة الاستكمال محفوظة/);
    await page.locator('#job-network-resume').click();
    assert.equal(await page.locator('#resume-mode').inputValue(),'html');
    await page.keyboard.press('Escape');
    await page.locator('[data-network-view="diagnostics"]').click();
    await page.locator('#diagnostics-view [data-diagnose="worker"]').click();
    await page.locator('#diagnostic-worker').filter({hasText:'HTTP 403'}).waitFor();
    assert.match(await page.locator('#diagnostic-worker').textContent(),/نجحت الفحوص/);
    assert.match(await page.locator('#diagnostic-worker').textContent(),/جمع HTML متوقف/);
    for(const width of [1280,375]) {
      await page.setViewportSize({width,height:1000});
      assert.equal(await page.locator('html').getAttribute('dir'),'rtl');
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
      const scan=await new AxeBuilder({page}).include('#diagnostics-view').analyze();assert.deepEqual(scan.violations,[]);
      widths.push({width,axeViolations:0,noOverflow:true});
    }
    assert.deepEqual(errors,[]);
    fs.writeFileSync('docs/vpn-evidence/source-access-browser.json',JSON.stringify({provider:'simulated',htmlPreserved:true,challengeShown:true,healthyTunnelAndBlockedWebsite:true,keyboardJobEntry:true,widths,errors},null,2)+'\n');
    console.log('PASS: HTML retained, challenge distinct from healthy tunnel, RTL/axe 375/1280.');
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
