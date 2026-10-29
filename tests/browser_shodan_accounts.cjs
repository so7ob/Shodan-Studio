const assert=require('node:assert/strict');
const fs=require('node:fs');
const {chromium}=require('playwright');
const {AxeBuilder}=require('@axe-core/playwright');
(async()=>{
 const base=process.argv[2]||'http://127.0.0.1:8799';
 const browser=await chromium.launch({headless:true,executablePath:process.env.STUDIO_TEST_CHROMIUM||undefined});
 const context=await browser.newContext({viewport:{width:1280,height:1000},reducedMotion:'reduce'});
 const page=await context.newPage();
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',r=>r.request().url().startsWith(base+'/')?r.continue():r.abort());
 const folder=process.env.STUDIO_ACCOUNT_EVIDENCE||'docs/shodan-accounts-evidence';fs.mkdirSync(folder,{recursive:true});
 try{
  await page.goto(base);await page.locator('#auth-user').fill('acceptance');await page.locator('#auth-password').fill('local-browser-fixture-123!');await page.locator('#auth-submit').click();
  await page.locator('#jobs-body tr[data-job]').first().focus();await page.keyboard.press('Enter');
  await page.locator('#job-network [data-shodan-accounts]').click();
  const form=page.locator('#shodan-account-form');
  await form.locator('[name=label]').fill('حساب اختباري');await form.locator('[name=username]').fill('fixture-user');await form.locator('[name=password]').fill('fixture-account-password');
  const save=page.waitForResponse(r=>r.url().endsWith('/api/shodan/accounts')&&r.request().method()==='POST');
  await page.locator('#account-save').click();const response=await save;assert.equal(response.status(),201);
  const saved=await response.json();assert.ok(!JSON.stringify(saved).includes('fixture-account-password'));
  await page.locator('#shodan-account-list .shodan-account-row').waitFor();assert.equal(await form.locator('[name=password]').inputValue(),'');
  for(const width of [1280,375]){
   await page.setViewportSize({width,height:1000});
   assert.ok(await page.locator('#shodan-accounts-dialog').evaluate(el=>el.scrollWidth<=el.clientWidth+1));
   assert.deepEqual((await new AxeBuilder({page}).include('#shodan-accounts-dialog').analyze()).violations,[]);
   await page.screenshot({path:`${folder}/accounts-${width}.png`,fullPage:true});
  }
  await page.locator('#shodan-accounts-dialog [data-close]').click();
  await page.locator('#job-shodan-account').selectOption(saved.account.id);
  await page.waitForFunction(()=>!document.querySelector('#job-browser-open').disabled);
  await page.locator('#job-browser-open').click();
  await page.waitForFunction(()=>!document.querySelector('#browser-login').disabled);
  assert.match(await page.locator('#browser-account-name').innerText(),/fixture-user/);
  const login=page.waitForRequest(r=>r.url().endsWith('/browser')&&r.postDataJSON().action==='login');
  await page.locator('#browser-login').focus();await page.keyboard.press('Enter');assert.deepEqual((await login).postDataJSON(),{action:'login'});
  await page.locator('#browser-login-status').filter({hasText:'أُرسلت بيانات الدخول'}).waitFor();
  assert.equal(await page.locator('#browser-resume').isDisabled(),true);
  for(const width of [1280,375]){
   await page.setViewportSize({width,height:1000});
   assert.deepEqual((await new AxeBuilder({page}).include('#browser-dialog').analyze()).violations,[]);
   await page.screenshot({path:`${folder}/login-${width}.png`,fullPage:true});
  }
  await page.locator('#browser-end').click();
  await page.locator('#job-network [data-shodan-accounts]').click();
  await page.locator('#shodan-account-list button').filter({hasText:'تعديل'}).click();
  assert.equal(await form.locator('[name=password]').inputValue(),'');await form.locator('[name=label]').fill('حساب معدل');
  await page.locator('#account-save').click();await page.locator('#shodan-account-list strong').filter({hasText:'حساب معدل'}).waitFor();
  page.on('dialog',d=>d.accept());await page.locator('#shodan-account-list button').filter({hasText:'حذف'}).click();
  await page.locator('#shodan-account-list').filter({hasText:'لا توجد حسابات'}).waitFor();
  assert.deepEqual(errors,[]);
  fs.writeFileSync(`${folder}/ui.json`,JSON.stringify({synthetic:true,liveShodanRequests:false,crud:true,passwordNotReturned:true,selectedAccountLogin:true,keyboard:true,rtlWidths:[375,1280],axeViolations:0,pageErrors:errors},null,2)+'\n');
  console.log('PASS account CRUD, selected login, secret omission, keyboard, RTL and axe.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
