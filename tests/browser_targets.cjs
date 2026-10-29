const assert=require('node:assert/strict');
const fs=require('node:fs');
const {chromium}=require('playwright');
const {AxeBuilder}=require('@axe-core/playwright');
(async()=>{
 const base=process.argv[2]||'http://127.0.0.1:8813',out='docs/target-repository-evidence';fs.mkdirSync(out,{recursive:true});
 const browser=await chromium.launch({headless:true,executablePath:process.env.STUDIO_TEST_CHROMIUM||undefined});
 const context=await browser.newContext({viewport:{width:1280,height:1000},reducedMotion:'reduce'});
 const page=await context.newPage();const errors=[];
 page.on('pageerror',e=>errors.push(e.message));await page.route('**/*',r=>r.request().url().startsWith(base+'/')?r.continue():r.abort());
 try{
  await page.goto(base);await page.locator('#auth-user').fill('acceptance');await page.locator('#auth-password').fill('local-browser-fixture-123!');await page.locator('#auth-submit').click();
  await page.locator('#targets-nav').waitFor({state:'visible'});await page.locator('#targets-nav').focus();await page.keyboard.press('Enter');await page.locator('#targets-body tr').first().waitFor();
  assert.equal(await page.locator('#targets-total').innerText(),'120');
  await page.locator('#targets-next').click();await page.waitForFunction(()=>document.getElementById('targets-range').textContent.startsWith('51'));
  await page.locator('#targets-prev').click();await page.waitForFunction(()=>document.getElementById('targets-range').textContent.startsWith('1–'));
  const form=page.locator('#targets-filter-form');await form.locator('[name=country]').fill('US');await form.locator('button[type=submit]').click();
  await page.waitForFunction(()=>Number(document.getElementById('targets-total').textContent)<80);
  await page.locator('#targets-body [data-target-select]').first().check();
  const selected=await page.locator('#targets-body [data-target-select]').first().getAttribute('data-target-select');
  await page.locator(`[data-target-select="${selected}"]`).focus();
  await page.waitForTimeout(2300);assert.equal(await page.locator(`[data-target-select="${selected}"]`).isChecked(),true);
  assert.equal(await page.evaluate(()=>document.activeElement.dataset.targetId),selected);
  const focusedTarget=await page.locator('#targets-body [data-target-open]').first().getAttribute('data-target-open');
  await page.locator(`[data-target-open="${focusedTarget}"]`).focus();
  await page.route('**/api/targets?**',async route=>{
   const response=await route.fetch(),data=await response.json();data.items[0].org+=' updated fixture';
   await route.fulfill({response,json:data});
  },{times:1});
  await page.evaluate(()=>ShodanTargets.refresh());
  await page.waitForFunction(()=>document.getElementById('targets-body').textContent.includes('updated fixture'));
  assert.equal(await page.evaluate(()=>document.activeElement.dataset.targetOpen),focusedTarget);
  assert.equal(await page.locator('#targets-body img').count(),0);
  await page.locator('#targets-body [data-target-open]').first().focus();await page.keyboard.press('Enter');await page.locator('#target-dialog').waitFor({state:'visible'});
  assert.match(await page.locator('#target-detail').innerText(),/استعلام الفرع/);assert.match(await page.locator('#target-detail').innerText(),/رصد Shodan/);
  assert.deepEqual((await new AxeBuilder({page}).include('#target-dialog').analyze()).violations,[]);
  await page.locator('#target-dialog [data-target-close]').first().click();
  for(const width of [1280,375]){
   await page.setViewportSize({width,height:1000});
   if(width===375){await page.locator('#menu-button').click();await page.locator('#targets-nav').click();}
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   const audit=await new AxeBuilder({page}).include('#targets-view').analyze();assert.deepEqual(audit.violations,[]);
   await page.screenshot({path:`${out}/targets-${width}.png`,fullPage:true});
  }
  await page.locator('#targets-settings').click();await page.locator('#target-settings-dialog').waitFor({state:'visible'});
  await page.locator('#target-settings-form [name=api_key]').fill('UI_FIXTURE_NOT_A_REAL_SECRET');
  assert.deepEqual((await new AxeBuilder({page}).include('#target-settings-dialog').analyze()).violations,[]);
  await page.keyboard.press('Escape');assert.equal(await page.locator('#target-settings-form [name=api_key]').inputValue(),'');
  await page.locator('#targets-enrich').click();await page.locator('#create-dialog').waitFor({state:'visible'});
  assert.match(await page.locator('#create-title').innerText(),/إثراء/);
  assert.deepEqual((await new AxeBuilder({page}).include('#create-dialog').analyze()).violations,[]);
  await page.locator('#create-form [name=delay]').fill('0');await page.locator('#create-submit').click();await page.locator('#create-dialog').waitFor({state:'hidden'});
  await page.locator('#job-kind-filter').selectOption('enrichment');await page.locator('#jobs-body tr').first().waitFor();
  assert.match(await page.locator('#jobs-body').innerText(),/إثراء/);assert.match(await page.locator('#detail-ip-progress').innerText(),/عنوان عولج/);
  await page.locator('#detail-actions [data-action=configure]').click();await page.locator('#job-runtime-dialog').waitFor({state:'visible'});
  await page.locator('#job-runtime-form [name=priority]').fill('10');await page.locator('#job-runtime-form [name=delay]').fill('3');
  await page.locator('#job-runtime-form [name=scheduled_at]').fill('2099-01-01T12:00');
  assert.deepEqual((await new AxeBuilder({page}).include('#job-runtime-dialog').analyze()).violations,[]);
  await page.locator('#job-runtime-save').click();await page.locator('#job-runtime-dialog').waitFor({state:'hidden'});
  await page.locator('#detail-actions [data-action=configure]').click();assert.equal(await page.locator('#job-runtime-form [name=priority]').inputValue(),'10');
  assert.equal(await page.locator('#job-runtime-form [name=delay]').inputValue(),'3');await page.keyboard.press('Escape');
  await page.reload();await page.locator('#jobs-body tr').first().waitFor();
  assert.deepEqual(errors,[]);
  fs.writeFileSync(`${out}/browser.json`,JSON.stringify({fixture:true,externalRequests:0,rtlWidths:[375,1280],pagination:true,filters:true,keyboard:true,selectionAndFocusRetained:true,details:true,enrichmentCreation:true,runtimeSettings:true,secretFieldClearedOnClose:true,axeScopes:['inventory','target details','enrichment settings','create job','runtime settings'],axeViolations:0,manualScreenReader:false,errors},null,2)+'\n');
  console.log('PASS targets UI: filtered inventory, pagination, retained selection, details, enrichment jobs, RTL and axe.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
