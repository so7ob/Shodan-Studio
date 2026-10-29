/* Local intercepted pages only: no Shodan credentials or network requests. */
const assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
const {chromium}=require('playwright');
const source=execFileSync('python3',['-c','from studio.shodan_login import LOGIN_FUNCTION; print(LOGIN_FUNCTION)'],{encoding:'utf8'});
const loginFunction=eval('('+source+')');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.STUDIO_TEST_CHROMIUM||undefined});
 const page=await browser.newPage();let posts=[],markup='';
 await page.route('**/*',async route=>{
  if(route.request().method()==='POST'){posts.push(route.request().postData());await route.fulfill({body:'<h1>Submitted fixture</h1>'});}
  else await route.fulfill({contentType:'text/html',body:markup});
 });
 const form=(action='/login',method='post')=>`<form action="${action}" method="${method}"><input name="username"><input name="password" type="password"><input name="csrf_token" type="hidden" value="fixture-token"><button type="submit" formaction="https://evil.test/">Submit override</button></form>`;
 try{
  markup=form();await page.goto('https://account.shodan.io/login');
  const secret='fixture-";window.injected=true;//';
  assert.equal(await page.evaluate(loginFunction,{username:'test-user',password:secret}),'submitted');
  await page.waitForURL('https://account.shodan.io/login');await page.waitForFunction(()=>document.querySelector('h1'));
  assert.equal(posts.length,1);let fields=new URLSearchParams(posts[0]);assert.equal(fields.get('password'),secret);assert.equal(fields.get('username'),'test-user');assert.equal(fields.get('csrf_token'),'fixture-token');
  assert.equal(await page.evaluate('window.injected'),undefined);
  for(const [url,html,expected] of [
   ['https://evil.test/login',form(),'not_login_page'],
   ['https://account.shodan.io/profile',form(),'not_login_page'],
   ['https://account.shodan.io/login',form('https://evil.test/'),'unsafe_form'],
   ['https://account.shodan.io/login',form('/login','get'),'unsafe_form'],
   ['https://account.shodan.io/login','<h1>Complete verification</h1>','verification_required']
  ]){
   markup=html;await page.goto(url);assert.equal(await page.evaluate(loginFunction,{username:'test-user',password:secret}),expected);
   assert.equal(posts.length,1);
   assert.equal(await page.locator('input[type=password]').count()?await page.locator('input[type=password]').inputValue():'','');
  }
  console.log('PASS official-origin form guard, CSRF preservation, POST-only credentials, no submitter override, verification and injection checks.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
