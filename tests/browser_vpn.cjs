/* Real HTTP/browser, simulated provider; never contacts Shodan or Premium. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const {AxeBuilder} = require('@axe-core/playwright');
(async () => {
  const base = process.argv[2] || 'http://127.0.0.1:8791';
  const evidenceDir = process.env.STUDIO_VPN_EVIDENCE_DIR || path.join(__dirname,'../docs/vpn-evidence');
  fs.mkdirSync(evidenceDir,{recursive:true});
  const browser = await chromium.launch({headless:true,...(process.env.STUDIO_TEST_CHROMIUM ? {executablePath:process.env.STUDIO_TEST_CHROMIUM}:{})});
  const context = await browser.newContext({viewport:{width:1280,height:1000},reducedMotion:'reduce'});
  const page = await context.newPage();
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/*',route=>route.request().url().startsWith(base+'/')?route.continue():route.abort());
  const evidence=[];
  try {
    await page.goto(base);await page.locator('#auth-user').fill('acceptance');
    await page.locator('#auth-password').fill('local-browser-fixture-123!');await page.locator('#auth-submit').click();
    await page.locator('[data-network-view="vpn"]').waitFor();
    await page.locator('[data-network-view="vpn"]').click();
    await page.locator('#vpn-profiles tr').first().waitFor();
    for (const width of [1280,375]) {
      await page.setViewportSize({width,height:1000});
      assert.equal(await page.locator('html').getAttribute('dir'),'rtl');
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
      const scan=await new AxeBuilder({page}).include('#vpn-view').analyze();
      assert.deepEqual(scan.violations,[]);
      await page.screenshot({path:path.join(evidenceDir,`vpn-rtl-${width}.png`),fullPage:true});
      evidence.push({width,axeViolations:scan.violations.length,noPageOverflow:true});
    }
    await page.setViewportSize({width:1280,height:1000});
    await page.locator('#vpn-add').click();await page.locator('#vpn-profile-name').fill('Local fixture');
    await page.locator('#vpn-profile-country').fill('DE');
    await page.locator('#vpn-profile-file').setInputFiles({name:'bad.conf',mimeType:'text/plain',buffer:Buffer.from('[Interface]\nPostUp = id')});
    await page.locator('#vpn-profile-submit').click();await page.locator('#vpn-profile-error').filter({hasText:'ملف غير مدعوم'}).waitFor();
    await page.keyboard.press('Escape');
    await page.locator('[data-vpn-connect]').first().click();
    await page.locator('#vpn-current').filter({hasText:'تم التحقق'}).waitFor();
    await page.locator('[data-network-view="diagnostics"]').click();
    await page.locator('#diagnostics-view [data-diagnose="worker"]').click();
    await page.locator('#diagnostic-worker').filter({hasText:'نجحت الفحوص'}).waitFor();
    const diagnostics=await new AxeBuilder({page}).include('#diagnostics-view').analyze();assert.deepEqual(diagnostics.violations,[]);
    await page.locator('[data-view="all"]').click();
    const row=page.locator('#jobs-body tr[data-job]').first();await row.focus();await page.keyboard.press('Enter');
    await page.locator('#job-network').waitFor();
    await page.locator('#job-network-edit').click();
    await page.locator('#job-net-mode').selectOption('failover');await page.locator('#job-net-profile').selectOption('1'.repeat(32));
    await page.locator('#job-net-allowed').selectOption(['1'.repeat(32),'2'.repeat(32)]);
    await page.locator('#job-net-enabled').check();await page.locator('#job-net-max').fill('100');
    await page.locator('#job-network-submit').click();
    await page.locator('#job-network-state').filter({hasText:'failover'}).waitFor();
    assert.match(await page.locator('#job-network-count').innerText(),/0 \/ 100/);
    const jobScan=await new AxeBuilder({page}).include('#job-network').analyze();assert.deepEqual(jobScan.violations,[]);
    await page.locator('#create-button').click();await page.locator('#create-net-mode').selectOption('failover');
    await page.locator('#create-net-profile').selectOption('1'.repeat(32));await page.locator('#create-net-allowed').selectOption(['1'.repeat(32),'2'.repeat(32)]);
    await page.locator('#create-net-enabled').check();
    assert.equal(await page.locator('#create-net-max').getAttribute('max'),'100');
    assert.equal(await page.locator('#create-net-max').inputValue(),'20');
    const policyScan=await new AxeBuilder({page}).include('#create-network').analyze();assert.deepEqual(policyScan.violations,[]);
    for (const width of [1280,375]) {
      await page.setViewportSize({width,height:1000});
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
      const scan=await new AxeBuilder({page}).include('#create-network').analyze();assert.deepEqual(scan.violations,[]);
      await page.screenshot({path:path.join(evidenceDir,`failover-policy-rtl-${width}.png`),fullPage:true});
    }
    assert.deepEqual(errors,[]);
    fs.writeFileSync(path.join(evidenceDir,'browser.json'),JSON.stringify({provider:'simulated',evidence,diagnosticsAxe:0,jobCardAxe:0,policyAxe:0,invalidProfileRejected:true,keyboardJobEntry:true,defaultFailovers:20,maxFailovers:100,browserErrors:errors},null,2)+'\n');
    console.log('PASS: RTL 375/1280, no overflow, VPN/diagnostics/job/policy axe, invalid import, verified connect, keyboard job, persisted network policy.');
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
