/* Real browser/HTTP; state fixtures only. Concurrent workers are tested in Python. */
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {chromium}=require('playwright');
const {AxeBuilder}=require('@axe-core/playwright');
(async()=>{
 const base=process.argv[2]||'http://127.0.0.1:8813',out='docs/enrichment-spaces-evidence';fs.mkdirSync(out,{recursive:true});
 const browser=await chromium.launch({headless:true,executablePath:process.env.STUDIO_TEST_CHROMIUM||undefined});
 const context=await browser.newContext({viewport:{width:1280,height:1000},reducedMotion:'reduce'});
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',r=>r.request().url().startsWith(base+'/')?r.continue():r.abort());
 try{
  await page.goto(base+'/enrichment');await page.locator('#auth-user').fill('acceptance');await page.locator('#auth-password').fill('local-browser-fixture-123!');await page.locator('#auth-submit').click();
  await page.locator('#workspace-view').waitFor({state:'visible'});
  const ids=await page.evaluate(async()=>{
   const session=await (await fetch('/api/session')).json();
   const targets=await (await fetch('/api/targets?limit=1')).json();
   const response=await fetch('/api/enrichment/jobs',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrf_token},body:JSON.stringify({title:'Independent enrichment fixture',target_ids:[targets.items[0].id],mode:'html'})});
   const created=await response.json();if(!response.ok)throw Error(JSON.stringify(created));
   const jobs=await (await fetch('/api/jobs')).json();return {enrichment:created.job.id,extraction:jobs.jobs.find(j=>j.kind==='extraction').id};
  });
  await page.route('**/api/jobs',async r=>{
   const response=await r.fetch(),data=await response.json();
   for(const j of data.jobs){if(j.id===ids.extraction)j.status='running';if(j.id===ids.enrichment)j.status='waiting_input';}
   data.lanes={extraction:{active_job_id:ids.extraction,browser_job_id:null,queued:data.jobs.filter(j=>j.kind==='extraction'&&j.status==='queued').length},enrichment:{active_job_id:null,browser_job_id:ids.enrichment,queued:data.jobs.filter(j=>j.kind==='enrichment'&&j.status==='queued').length}};
   await r.fulfill({response,json:data});
  });
  await page.locator('#refresh-button').click();await page.locator('#execution-spaces-status').filter({hasText:'بانتظار المتصفح'}).waitFor();
  for(const width of [1280,375]){
   await page.setViewportSize({width,height:1000});
   for(const kind of ['extraction','enrichment']){
    if(width===375)await page.locator('#menu-button').click();
    await page.locator(`[data-space="${kind}"]`).focus();await page.keyboard.press('Enter');
    await page.waitForURL(`**/${kind}`);await page.locator('#jobs-body tr').first().waitFor();
    const rows=await page.locator('#jobs-body tr').first().getAttribute('data-job');assert.ok(rows);
    if(kind==='enrichment')assert.equal(await page.locator(`#jobs-body [data-job="${ids.extraction}"]`).count(),0);
    else assert.equal(await page.locator(`#jobs-body [data-job="${ids.enrichment}"]`).count(),0);
    assert.equal(await page.locator(`[data-space="${kind}"]`).getAttribute('aria-current'),'page');
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    const audit=await new AxeBuilder({page}).include('#workspace-view').analyze();assert.deepEqual(audit.violations,[]);
    await page.screenshot({path:`${out}/${kind}-${width}.png`,fullPage:true});
   }
  }
  await page.reload();await page.locator('#space-heading').filter({hasText:'مهام الإثراء'}).waitFor();
  await page.setViewportSize({width:1280,height:1000});await page.locator('[data-network-view="vpn"]').click();
  await page.locator('#vpn-space').selectOption('enrichment');
  await page.locator('#vpn-current').filter({hasText:'الإثراء'}).waitFor();
  assert.deepEqual((await new AxeBuilder({page}).include('#vpn-view').analyze()).violations,[]);
  await page.locator('[data-network-view="diagnostics"]').click();assert.equal(await page.locator('#vpn-space').isVisible(),true);
  assert.deepEqual((await new AxeBuilder({page}).include('#diagnostics-view').analyze()).violations,[]);
  assert.deepEqual(errors,[]);
  fs.writeFileSync(`${out}/spaces-browser.json`,JSON.stringify({fixture:true,externalRequests:0,concurrentStatusesSimulated:true,backendConcurrency:'test_execution_spaces.py uses two real offline worker processes',routes:['/extraction','/enrichment'],widths:[375,1280],keyboard:true,independentTables:true,reload:true,vpnSpaceSelector:true,axeViolations:0,errors},null,2)+'\n');
  console.log('PASS independent execution spaces: routes, keyboard, RTL 375/1280, VPN selector, zero axe.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
