/* Authenticated UI acceptance against the simulated browser RPC, no Shodan traffic. */
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {chromium}=require('playwright');
const {AxeBuilder}=require('@axe-core/playwright');
(async()=>{
 const base=process.argv[2]||'http://127.0.0.1:8795';
 const browser=await chromium.launch({headless:true,executablePath:process.env.STUDIO_UI_BROWSER||undefined});
 const context=await browser.newContext({viewport:{width:1280,height:1000},reducedMotion:'reduce'});
 const page=await context.newPage();
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 await page.route('**/*',route=>route.request().url().startsWith(base+'/')?route.continue():route.abort());
 try {
  await page.goto(base);await page.locator('#auth-user').fill('acceptance');
  await page.locator('#auth-password').fill('local-browser-fixture-123!');await page.locator('#auth-submit').click();
  await page.locator('#jobs-body tr[data-job]').first().focus();await page.keyboard.press('Enter');
  await page.locator('#job-browser-state').filter({hasText:'patchright'}).waitFor();
  assert.equal(await page.locator('#browser-dialog').evaluate(node=>node.open),false);
  assert.equal(await page.locator('#job-browser-open').innerText(),'عرض جلسة المتصفح');
  assert.equal(await page.locator('#job-browser-policy').isDisabled(),true);
  await page.locator('#job-browser-open').click();
  await page.waitForFunction(()=>document.querySelector('#browser-frame').src.startsWith('data:'));
  assert.equal(await page.locator('#browser-resume').isDisabled(),true);
  await page.locator('#browser-return').focus();await page.keyboard.press('Enter');
  await page.waitForFunction(()=>document.querySelector('#browser-return').disabled);
  await page.locator('#browser-verify').click();
  await page.waitForFunction(()=>!document.querySelector('#browser-resume').disabled);
  for(const width of [1280,375]){
   await page.setViewportSize({width,height:1000});
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   const scan=await new AxeBuilder({page}).include('#browser-dialog').include('#job-network').analyze();
   assert.deepEqual(scan.violations,[]);
   await page.screenshot({path:`docs/patchright-evidence/ui-${width}.png`,fullPage:true});
  }
  await page.locator('#browser-end').click();await page.locator('#browser-dialog').waitFor({state:'hidden'});
  await page.locator('#job-browser-policy').selectOption('manual');
  await page.waitForFunction(()=>document.querySelector('#job-browser-policy').value==='manual');
  assert.deepEqual(errors,[]);
  fs.writeFileSync('docs/patchright-evidence/ui.json',JSON.stringify({provider:'simulated',autoSessionDoesNotOpenModal:true,
   attachedSession:true,explicitVerifiedResume:true,policyOptOut:true,rtlWidths:[375,1280],axeViolations:0,errors},null,2)+'\n');
  console.log('PASS automatic recovery UI, manual verification, opt-out, keyboard and axe at 375/1280.');
 } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
