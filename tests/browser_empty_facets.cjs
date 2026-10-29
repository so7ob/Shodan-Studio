/* Synthetic UI replies; real browser parsing is covered by the runtime smoke. */
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {chromium}=require('playwright');
const {AxeBuilder}=require('@axe-core/playwright');
(async()=>{
 const base=process.argv[2]||'http://127.0.0.1:8799';
 const browser=await chromium.launch({headless:true,executablePath:process.env.STUDIO_TEST_CHROMIUM||undefined});
 const context=await browser.newContext({viewport:{width:1280,height:1000},reducedMotion:'reduce'});
 const page=await context.newPage();
 const errors=[],actions=[];let state=null;
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',r=>r.request().url().startsWith(base+'/')?r.continue():r.abort());
 await page.route('**/api/jobs/*/browser',async r=>{
  const input=r.request().postDataJSON();actions.push(input);
  const response=await r.fetch();const data=await response.json();
  if(state&&input.action==='frame')data.state=state;
  await r.fulfill({response,json:data});
 });
 try{
  await page.goto(base);await page.locator('#auth-user').fill('acceptance');
  await page.locator('#auth-password').fill('local-browser-fixture-123!');await page.locator('#auth-submit').click();
  await page.locator('#jobs-body tr[data-job]').first().focus();await page.keyboard.press('Enter');
  await page.locator('#job-browser-open').click();
  await page.waitForFunction(()=>!document.querySelector('#browser-return').disabled);
  await page.locator('#browser-return').focus();await page.keyboard.press('Enter');
  await page.waitForFunction(()=>!document.querySelector('#browser-resume').disabled);
  assert.equal(actions.filter(a=>a.action==='verify'&&!a.return_to_results).length,0);
  assert.match(await page.locator('#browser-status').innerText(),/صفحة المرشح جاهزة/);
  assert.equal(await page.locator('#browser-login-status').innerText(),'');
  const folder='dist/issue27-ui';fs.mkdirSync(folder,{recursive:true});
  for(const width of [1280,375]){
   await page.setViewportSize({width,height:1000});
   assert.ok(await page.locator('#browser-dialog').evaluate(el=>el.scrollWidth<=el.clientWidth+1));
   assert.deepEqual((await new AxeBuilder({page}).include('#browser-dialog').analyze()).violations,[]);
   await page.screenshot({path:`${folder}/empty-ready-${width}.png`,fullPage:true});
  }
  for(const [next,text] of [['invalid_page','تعذر قراءة تنسيق'],['login_required','لم يكتمل تسجيل الدخول'],['browser_challenge','ظهر اختبار أمان'],['rate_limited','قيّد Shodan']]){
   state=next;await page.locator('#browser-status').filter({hasText:text}).waitFor();
   assert.equal(await page.locator('#browser-resume').isDisabled(),true);
   if(next==='invalid_page')assert.doesNotMatch(await page.locator('#browser-status').innerText(),/اختبار أمان|تسجيل الدخول|افحص/);
  }
  assert.deepEqual(errors,[]);
  fs.writeFileSync(`${folder}/ui.json`,JSON.stringify({synthetic:true,liveShodanRequests:false,automaticReady:true,verifyClicks:0,
   separateBarrierMessages:true,rtlWidths:[375,1280],axeViolations:0,pageErrors:errors},null,2)+'\n');
  console.log('PASS automatic readiness, distinct page states, keyboard, RTL 375/1280 and axe.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
