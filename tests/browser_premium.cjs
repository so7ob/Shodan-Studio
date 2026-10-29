/* Authenticated HTTP UI, simulated Premium account; no real subscription calls. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const {chromium} = require('playwright');
const {AxeBuilder} = require('@axe-core/playwright');
(async () => {
  const base = process.argv[2] || 'http://127.0.0.1:8792';
  const browser = await chromium.launch({headless:true});
  const context = await browser.newContext({viewport:{width:1280,height:1000},reducedMotion:'reduce'});
  const page = await context.newPage();
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/*',r=>r.request().url().startsWith(base+'/')?r.continue():r.abort());
  const evidence=[];
  try {
    await page.goto(base);await page.locator('#auth-user').fill('acceptance');
    await page.locator('#auth-password').fill('local-browser-fixture-123!');await page.locator('#auth-submit').click();
    await page.locator('[data-network-view="vpn"]').click();
    await page.locator('#premium-enroll').click();
    const raw = JSON.stringify({config_version:2,api_config:{service_type:'amnezia-premium',user_country_code:'ru'},auth_data:{api_key:'browser-fixture-secret'}});
    const key='vpn://'+Buffer.concat([Buffer.from([0,0,0,255]),zlib.deflateSync(Buffer.from(raw))]).toString('base64url');
    await page.locator('#premium-key').fill(key);
    assert.equal(await page.locator('#premium-key').getAttribute('type'),'password');
    const dialogScan=await new AxeBuilder({page}).include('#premium-dialog').analyze();assert.deepEqual(dialogScan.violations,[]);
    await page.locator('#premium-submit').click();
    await page.locator('#premium-dialog').waitFor({state:'hidden'});
    assert.equal(await page.locator('#premium-key').inputValue(),'');
    await page.locator('#premium-status').filter({hasText:'الاشتراك مرتبط'}).waitFor();
    assert.equal(await page.locator('#vpn-profiles tr').count(),55);
    await page.locator('#vpn-filter').fill('us-east');
    assert.equal(await page.locator('#vpn-profiles tr').count(),1);
    await page.locator('[data-vpn-edit]').click();
    assert.equal(await page.locator('#vpn-profile-country').evaluate(e=>e.readOnly),true);
    await page.keyboard.press('Escape');
    const connected=page.waitForResponse(r=>r.url().endsWith('/api/vpn/actions')&&r.request().method()==='POST');
    await page.locator('[data-vpn-connect]').click();assert.equal((await connected).status(),200);
    await page.locator('#vpn-current').filter({hasText:'تم التحقق'}).waitFor();
    const refreshed=page.waitForResponse(r=>r.url().endsWith('/api/vpn/premium')&&r.request().method()==='POST');
    await page.locator('#premium-refresh').click();assert.equal((await refreshed).status(),200);
    await page.waitForFunction(()=>document.querySelectorAll('#toasts > *').length===0);
    for(const width of [1280,375]) {
      await page.setViewportSize({width,height:1000});
      assert.equal(await page.locator('html').getAttribute('dir'),'rtl');
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
      const scan=await new AxeBuilder({page}).include('#vpn-view').analyze();assert.deepEqual(scan.violations,[]);
      await page.screenshot({path:path.join(__dirname,`../docs/vpn-evidence/premium-rtl-${width}.png`),fullPage:true});
      evidence.push({width,axeViolations:0,noOverflow:true});
    }
    assert.deepEqual(errors,[]);
    fs.writeFileSync(path.join(__dirname,'../docs/vpn-evidence/premium-browser.json'),JSON.stringify({provider:'simulated',locations:55,enrollment:true,keyCleared:true,filter:true,immutableCountry:true,verifiedConnection:true,evidence,errors},null,2)+'\n');
    console.log('PASS: Premium enrollment, 55-location filter, immutable country, key clearing, verified connection, RTL/axe 375/1280.');
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
