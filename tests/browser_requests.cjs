const assert=require('node:assert/strict');
const fs=require('node:fs');
const {chromium}=require('playwright');
const {AxeBuilder}=require('@axe-core/playwright');
(async()=>{
 const base=process.argv[2]||'http://127.0.0.1:8801';
 const out='docs/request-history-evidence';fs.mkdirSync(out,{recursive:true});
 const browser=await chromium.launch({headless:true,executablePath:process.env.STUDIO_TEST_CHROMIUM||undefined});
 const context=await browser.newContext({viewport:{width:1280,height:1000},reducedMotion:'reduce'});
 const page=await context.newPage();
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',r=>r.request().url().startsWith(base+'/')?r.continue():r.abort());
 try{
  await page.goto(base);await page.locator('#auth-user').fill('acceptance');
  await page.locator('#auth-password').fill('local-browser-fixture-123!');await page.locator('#auth-submit').click();
  await page.locator('#jobs-body tr[data-job]').first().focus();await page.keyboard.press('Enter');
  await page.locator('#latest-request').waitFor({state:'visible'});
  assert.match(await page.locator('#latest-request-query').innerText(),/http.component:"php"/);
  assert.match(await page.locator('#latest-request-state').innerText(),/جارٍ/);
  await page.locator('#tab-events').click();
  const first=page.locator('#request-list details').first();await first.waitFor();
  assert.equal(await page.locator('#request-view').inputValue(),'requests');
  await first.locator('summary').focus();await page.keyboard.press('Enter');
  assert.equal(await first.getAttribute('open'),'');
  await page.waitForFunction(()=>document.querySelector('#latest-request-state').textContent==='نجح');
  await page.waitForFunction(()=>document.querySelector('#request-list details tbody').children.length===100);
  assert.equal(await first.getAttribute('open'),'');
  assert.equal(await first.locator('img').count(),0);
  assert.match(await first.locator('tbody').innerText(),/<img src=x onerror=alert\(1\)>/);
  await first.getByRole('button',{name:'تحميل مزيد من القيم'}).click();
  await page.waitForFunction(()=>document.querySelector('#request-list details tbody').children.length===200);
  const button=first.getByRole('button',{name:'تحميل مزيد من القيم'});
  await button.focus();await page.waitForTimeout(2500);
  assert.equal(await button.evaluate(el=>el===document.activeElement),true);
  assert.equal(await first.locator('tbody tr').count(),200);
  await button.click();await page.waitForFunction(()=>document.querySelector('#request-list details tbody').children.length===250);
  assert.equal(await page.locator('#request-list details').count(),50);
  await page.locator('#requests-older').click();
  await page.waitForFunction(()=>document.querySelectorAll('#request-list details').length===70);
  await page.locator('#request-view').selectOption('all');
  await page.locator('#event-log').waitFor({state:'visible'});
  assert.match(await page.locator('#event-log').innerText(),/إجمالي السجلات: 579/);
  await page.locator('#request-view').selectOption('requests');
  assert.equal(await first.getAttribute('open'),'');
  for(const width of [1280,375]){
   await page.setViewportSize({width,height:1000});
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   const audit=await new AxeBuilder({page}).include('#job-detail').analyze();assert.deepEqual(audit.violations,[]);
   await first.screenshot({path:`${out}/requests-${width}.png`});
   await page.locator('#tab-overview').click();
   await page.locator('#latest-request').screenshot({path:`${out}/latest-${width}.png`});
   await page.locator('#tab-events').click();
  }
  await page.reload();
  await page.locator('#tab-events').click();
  await page.locator('#request-list details').first().waitFor();
  assert.match(await page.locator('#request-list details').first().innerText(),/نجح/);
  assert.deepEqual(errors,[]);
  fs.writeFileSync(`${out}/browser.json`,JSON.stringify({fixture:true,rtlWidths:[375,1280],
   attempts:70,facetValues:250,expandedStateStable:true,focusStable:true,reload:true,
   rawEvents:true,unsafeMarkupRenderedAsText:true,axeViolations:0,manualScreenReader:false,shodanRequests:0,errors},null,2)+'\n');
  console.log('PASS request UI: live transition, retained details/focus, pagination, raw log, reload, RTL and axe.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
