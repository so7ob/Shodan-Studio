// Synthetic loopback acceptance: no Shodan, VPN or subscription requests.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {chromium}=require('playwright');
const {AxeBuilder}=require('@axe-core/playwright');
(async()=>{
 const base=process.argv[2]||'http://127.0.0.1:8799';
 const output='docs/pacing-progress-evidence';
 const browser=await chromium.launch({headless:true,executablePath:process.env.STUDIO_TEST_CHROMIUM||undefined});
 const context=await browser.newContext({viewport:{width:1280,height:1000},reducedMotion:'reduce'});
 // Reproduce a client clock five seconds behind, then change it while running.
 await context.addInitScript(()=>{
  const originalNow=Date.now;
  window.fixtureClockSkew=-5000;
  Date.now=()=>originalNow()+window.fixtureClockSkew;
 });
 const page=await context.newPage();
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',r=>r.request().url().startsWith(base+'/')?r.continue():r.abort());
 fs.mkdirSync(output,{recursive:true});
 try{
  await page.goto(base);
  await page.locator('#auth-user').fill('acceptance');
  await page.locator('#auth-password').fill('local-browser-fixture-123!');
  await page.locator('#auth-submit').click();
  const openJob=async()=>{
   await page.locator('#jobs-body tr[data-job]').first().focus();
   await page.keyboard.press('Enter');
   await page.locator('#wait-countdown').waitFor({state:'visible'});
  };
  await openJob();
  const timer=page.locator('#wait-countdown');
  const seconds=async()=>{
   const text=await timer.innerText();
   assert.match(text,/فاصل الطلبات \(18 ثانية\)/);
   const match=text.match(/00:(\d{2})/);
   return match?Number(match[1]):null;
  };
  const first=await seconds();
  assert.ok(first>=15&&first<=18,`initial countdown: ${first}`);
  await page.waitForTimeout(2100);
  await page.evaluate(()=>{window.fixtureClockSkew=3600000;});
  await page.waitForTimeout(1100);
  const shifted=await seconds();
  assert.ok(shifted<first&&shifted>=first-5,`clock changed: ${first} -> ${shifted}`);
  await page.reload();await openJob();
  const reloaded=await seconds();
  assert.ok(reloaded<=shifted&&reloaded>=shifted-3,`reload: ${shifted} -> ${reloaded}`);
  await page.evaluate(()=>{window.fixtureClockSkew=-7200000;});
  for(const width of [1280,375]){
   await page.setViewportSize({width,height:1000});
   const progress=page.locator('#detail-ip-progress [role=progressbar]');
   assert.equal(await progress.getAttribute('aria-valuenow'),'17');
   assert.equal(await page.locator('#jobs-body [role=progressbar]').first().getAttribute('aria-valuenow'),'17');
   assert.match(await page.locator('#detail-ip-progress').innerText(),/100 عنوان IP مستخرج \/ 579 سجل متوقع/);
   assert.equal(await page.locator('#detail-ip-progress .ip-progress__fill').evaluate(el=>el.style.width),'17%');
   assert.equal(await page.locator('#detail-ip-progress .ip-progress__track--unknown').count(),0);
   assert.match(await page.locator('#stat-completed').innerText(),/0 \/ 1/);
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   const scan=await new AxeBuilder({page}).include('#job-detail').analyze();
   assert.deepEqual(scan.violations,[]);
   await page.screenshot({path:`${output}/issue29-${width}.png`,fullPage:true});
  }
  const samples=[];
  for(let i=0;i<24;i++){
   assert.equal(await timer.isVisible(),true);
   samples.push(await seconds());
   if(samples.at(-1)===null) break;
   await page.waitForTimeout(1000);
  }
  assert.ok(samples.includes(0),'countdown reaches zero');
  assert.equal(samples.at(-1),null,'configured interval remains after worker clears wait');
  for(let i=1;i<samples.length;i++) if(samples[i]!==null) assert.ok(samples[i]<=samples[i-1]);
  assert.equal(await timer.innerText(),'فاصل الطلبات (18 ثانية)');
  assert.deepEqual(errors,[]);
  fs.writeFileSync(`${output}/issue29-ui.json`,JSON.stringify({fixture:true,configuredDelay:18,
   initialSeconds:first,afterClockChange:shifted,afterReload:reloaded,samples,
   extractedUniqueIPs:100,sourceRecords:579,displayedPercent:17,rtlWidths:[375,1280],
   keyboardEntry:true,axeViolations:0,manualScreenReader:false,shodanRequests:0,errors},null,2)+'\n');
  console.log('PASS pacing/progress: server clock, reload, countdown to zero, 17% bar, RTL 375/1280, keyboard and axe.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
