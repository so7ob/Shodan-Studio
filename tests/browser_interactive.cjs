const assert=require('node:assert/strict');
const fs=require('node:fs');
const {chromium}=require('playwright');
const {AxeBuilder}=require('@axe-core/playwright');
(async()=>{
 const base=process.argv[2]||'http://127.0.0.1:8794';
 const browser=await chromium.launch({headless:true});
 const context=await browser.newContext({viewport:{width:1280,height:1000},reducedMotion:'reduce'});
 const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',r=>r.request().url().startsWith(base+'/')?r.continue():r.abort());
 try {
  await page.goto(base);await page.locator('#auth-user').fill('acceptance');await page.locator('#auth-password').fill('local-browser-fixture-123!');await page.locator('#auth-submit').click();
  await page.locator('#jobs-body tr[data-job]').first().focus();await page.keyboard.press('Enter');
  await page.locator('#job-browser-open').click();await page.waitForFunction(()=>document.querySelector('#browser-frame').src.startsWith('data:'));
  assert.equal(await page.locator('#browser-resume').isDisabled(),true);
  const input=page.waitForRequest(r=>r.url().endsWith('/browser')&&r.postDataJSON().action==='text');
  await page.locator('#browser-text').fill('fixture-private-text');await page.locator('#browser-text-form button').click();assert.equal((await input).postDataJSON().text,'fixture-private-text');
  assert.equal(await page.locator('#browser-text').inputValue(),'');
  await page.locator('[data-browser-key="Tab"]').click();
  await page.locator('#browser-verify').click();await page.locator('#browser-status').filter({hasText:'الصفحة الحالية ليست نتائج المهمة'}).waitFor();
  assert.equal(await page.locator('#browser-resume').isDisabled(),true);
  await page.waitForFunction(()=>!document.querySelector('#browser-return').disabled);
  const returning=page.waitForRequest(r=>r.url().endsWith('/browser')&&r.postDataJSON().return_to_results===true);
  await page.locator('#browser-return').focus();await page.keyboard.press('Enter');
  assert.deepEqual((await returning).postDataJSON(),{action:'verify',return_to_results:true});
  await page.waitForFunction(()=>document.querySelector('#browser-return').disabled);
  assert.equal(await page.locator('#browser-resume').isDisabled(),true);
  await page.locator('#browser-verify').click();await page.locator('#browser-status').filter({hasText:'صفحة نتائج صالحة'}).waitFor();
  await page.waitForTimeout(2200);assert.equal(await page.locator('#browser-resume').isEnabled(),true);
  for(const width of [1280,375]){
   await page.setViewportSize({width,height:1000});
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   assert.ok(await page.locator('#browser-dialog').evaluate(dialog=>dialog.scrollWidth<=dialog.clientWidth+1));
   for(const id of ['browser-end','browser-return','browser-verify','browser-resume']){
    const bounds=await page.locator('#'+id).boundingBox();assert.ok(bounds.x>=0&&bounds.x+bounds.width<=width);
   }
   const scan=await new AxeBuilder({page}).include('#browser-dialog').analyze();assert.deepEqual(scan.violations,[]);
   await page.screenshot({path:`docs/vpn-evidence/browser-login-return-${width}.png`,fullPage:true});
  }
  await page.locator('#browser-resume').click();await page.locator('#browser-dialog').waitFor({state:'hidden'});
  assert.equal(await page.locator('#browser-text').inputValue(),'');assert.deepEqual(errors,[]);
  fs.writeFileSync('docs/vpn-evidence/browser-login-return-ui.json',JSON.stringify({provider:'simulated',loginLandingBlocked:true,explicitReturn:true,keyboardReturn:true,manualInput:true,textCleared:true,verifiedResume:true,rtlWidths:[375,1280],axeViolations:0,errors},null,2)+'\n');
  console.log('PASS interactive browser UI: login landing blocked, explicit return, manual input, verified resume, RTL/axe 375/1280.');
 } finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
