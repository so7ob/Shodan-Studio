const assert=require('node:assert/strict');
const fs=require('node:fs');
const {chromium}=require('playwright');
const {AxeBuilder}=require('@axe-core/playwright');
(async()=>{
 const base=process.argv[2]||'http://127.0.0.1:8797';
 const browser=await chromium.launch({headless:true,executablePath:process.env.STUDIO_TEST_CHROMIUM||undefined});
 const pacing=process.env.STUDIO_TEST_PACING==='1';
 const context=await browser.newContext({viewport:{width:1280,height:1000},reducedMotion:'reduce'});
 const page=await context.newPage();
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',r=>r.request().url().startsWith(base+'/')?r.continue():r.abort());
 fs.mkdirSync('docs/planner-evidence',{recursive:true});
 try {
  await page.goto(base);await page.locator('#auth-user').fill('acceptance');await page.locator('#auth-password').fill('local-browser-fixture-123!');await page.locator('#auth-submit').click();
  await page.locator('#jobs-body tr[data-job]').first().focus();await page.keyboard.press('Enter');
  await page.locator('#detail-planner').filter({hasText:'اختار المخطط port'}).waitFor();
  assert.ok((await page.locator('#stat-completed').innerText()).includes(pacing?'0 / 2':'2 / 2'));
  assert.match(await page.locator('#detail-source-total').innerText(),/إجمالي سجلات Shodan المعلن: 160/);
  assert.match(await page.locator('#detail-planner').innerText(),/جُمعت 52 قيمة في 2 فروع/);
  if(pacing){
   const timer=page.locator('#wait-countdown');
   assert.match(await timer.innerText(),/فاصل الطلبات/);
   const before=await timer.innerText();
   await page.waitForTimeout(1200);
   assert.notEqual(await timer.innerText(),before);
   await page.reload();
   await page.locator('#jobs-body tr[data-job]').first().focus();await page.keyboard.press('Enter');
   await timer.waitFor({state:'visible'});
   assert.match(await timer.innerText(),/فاصل الطلبات/);
  }
  for(const width of [1280,375]){
   await page.setViewportSize({width,height:1000});
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   const scan=await new AxeBuilder({page}).include('#job-detail').analyze();assert.deepEqual(scan.violations,[]);
   await page.screenshot({path:`docs/planner-evidence/issue23-${pacing?'pacing':'completed'}-${width}.png`,fullPage:true});
  }
  await page.locator('#create-button').click();
  const form=page.locator('#create-form');await form.locator('details summary').click();
  const strategy=form.locator('[name=strategy]');
  assert.equal(await strategy.inputValue(),'adaptive');assert.equal(await form.locator('[name=always_asn]').isDisabled(),true);
  assert.equal(await form.locator('[name=split_facets]').isVisible(),false);
  assert.equal(await page.locator('#automatic-planner-help').isVisible(),true);
  await strategy.selectOption('priority');assert.equal(await form.locator('[name=always_asn]').isEnabled(),true);
  assert.equal(await form.locator('[name=split_facets]').isVisible(),true);
  assert.equal(await form.locator('[name=split_facets]').inputValue(),'asn,port,version,product');
  await strategy.selectOption('adaptive');assert.equal(await form.locator('[name=always_asn]').isDisabled(),true);
  for(const width of [1280,375]){
   await page.setViewportSize({width,height:1000});
   assert.ok(await form.evaluate(el=>el.scrollWidth<=el.clientWidth+1));
   const scan=await new AxeBuilder({page}).include('#create-dialog').analyze();assert.deepEqual(scan.violations,[]);
  }
  await form.locator('[name=query]').fill('synthetic fixture');
  await form.locator('[name=mode]').selectOption('html');
  const response=page.waitForResponse(r=>r.url().endsWith('/api/jobs')&&r.request().method()==='POST');
  await form.locator('button[type=submit]').click();
  const created=await response;assert.equal(created.status(),201);
  const body=await created.json();const job=body.job||body;
  assert.equal(job.settings.strategy,'adaptive');assert.equal(job.settings.always_asn,false);
  assert.deepEqual(job.settings.split_facets,['port','version','asn','country','product','org','os','city']);
  assert.deepEqual(errors,[]);
  fs.writeFileSync(`docs/planner-evidence/issue23-${pacing?'pacing':'completed'}-ui.json`,JSON.stringify({fixture:true,newJobDefault:'adaptive',legacySelectable:true,decisionVisible:true,sourceTotalVisible:true,pacingCountdown:pacing,automaticCandidates:true,rtlWidths:[375,1280],axeViolations:0,errors},null,2)+'\n');
  console.log('PASS adaptive UI: default, legacy choice, API creation, decision summary, RTL 375/1280, axe.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
