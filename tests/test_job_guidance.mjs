import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const { viewModel, validatedDeadlineMs, countdown, createServerClock } = createRequire(import.meta.url)('../studio/static/job_guidance.js');
const now = 1700000000000;
const format = value => new Date(value).toISOString();
const job = { status: 'waiting_input', has_checkpoint: true, input_reason: 'rate_limit' };

test('persisted future deadline survives a cloned/reloaded job and is explicit', () => {
  const value = { ...job, stats: { wait_until: now / 1000 + 3600 } };
  const vm = viewModel(value, now, format);
  assert.equal(vm.kind, 'waiting');
  assert.equal(vm.deadlineMs, now + 3600000);
  assert.match(vm.message, /2023-11-14T23:13:20.000Z/);
  assert.match(vm.checkpoint, /نقطة حفظ متاحة/);
  assert.deepEqual(viewModel(JSON.parse(JSON.stringify(value)), now, format), vm);
});
test('expired deadline remains visible without promising acceptance or automatic resume', () => {
  const vm = viewModel({ ...job, stats: { wait_until: now / 1000 } }, now, format);
  assert.equal(vm.kind, 'elapsed');
  assert.match(vm.message, /لم تُرسل اللوحة طلب استكمال تلقائيًا/);
  assert.match(vm.message, /لا يضمن قبول المصدر/);
  assert.equal(vm.deadlineMs, now);
});
test('unbounded wait takes precedence even if an old deadline has elapsed', () => {
  const vm = viewModel({ ...job, stats: { wait_unbounded: true, wait_until: 1 } }, now, format);
  assert.equal(vm.kind, 'manual_hold');
  assert.match(vm.message, /تكرار الاستكمال لا يرفع الحظر/);
  assert.doesNotMatch(vm.message, /1970/);
});
test('invalid deadlines never become an expired wait', () => {
  for (const wait_until of [null, false, '1700000000', '2099-01-01T00:00:00Z', -1, 0, NaN, Infinity, 1e100]) {
    const vm = viewModel({ ...job, stats: { wait_until } }, now, format);
    assert.equal(vm.kind, 'rate_limit');
    assert.equal(vm.deadlineMs, null);
    assert.match(vm.message, /لا يوجد موعد/);
  }
});
test('countdown and guidance share validation with unbounded-hold precedence', () => {
  for (const stats of [{}, { wait_until: now / 1000 + 1 }, { wait_until: now / 1000 - 1 },
    { wait_until: '2099-01-01T00:00:00Z' }, { wait_until: 1e100 },
    { wait_until: now / 1000 + 1, wait_unbounded: true }]) {
    assert.equal(validatedDeadlineMs(stats), viewModel({ ...job, stats }, now, format).deadlineMs);
  }
  assert.equal(validatedDeadlineMs({ wait_until: now / 1000 + 1 }), now + 1000);
  assert.equal(validatedDeadlineMs({ wait_until: now / 1000 + 1, wait_unbounded: true }), null);
});
test('missing checkpoint is not described as a saved restart point', () => {
  for (const has_checkpoint of [false, undefined, 'true']) {
    const vm = viewModel({ ...job, has_checkpoint }, now, format);
    assert.match(vm.checkpoint, /لا توجد نقطة حفظ متاحة/);
  }
});
test('access refusals explain manual review without claiming a retry solves access', () => {
  for (const error of ['[BROWSER_CHALLENGE] blocked', '[HTTP_403] forbidden', '[API_HTTP_401] denied']) {
    const vm = viewModel({ ...job, input_reason: 'source_error', error }, now, format);
    assert.equal(vm.kind, 'access_denied');
    assert.match(vm.message, /لا يضمن قبول المصدر/);
    assert.equal(vm.technicalError, error);
  }
});
test('technical markup stays a literal string for textContent rendering', () => {
  const error = '<img src=x onerror=alert(1)>';
  assert.equal(viewModel({ error }).technicalError, error);
  assert.doesNotMatch(viewModel({ error }).message, /<img/);
});
test('layout errors never ask the user to solve a security challenge', () => {
  const vm = viewModel({ status:'waiting_input', input_reason:'source_error', error:'[HTML_PARSE] unrecognized facet' });
  assert.equal(vm.kind,'response_error');
  assert.doesNotMatch(vm.message,/تحقق|تسجيل الدخول|اختبار أمان/);
});
test('login and permission guidance are distinct from a detected challenge', () => {
  assert.match(viewModel({error:'[BROWSER_LOGIN] login form'}).title,/تسجيل الدخول/);
  assert.match(viewModel({error:'[BROWSER_CHALLENGE] detected'}).message,/اختبار أمان/);
  assert.doesNotMatch(viewModel({error:'[HTTP_403] denied'}).message,/تحقق|اختبار أمان/);
});
test('view model does not mutate saved state or require browser/network globals', () => {
  const input = Object.freeze({ ...job, stats: Object.freeze({ wait_until: now / 1000 + 1 }) });
  assert.equal(viewModel(input, now, format).kind, 'waiting');
  assert.equal(input.stats.wait_until, now / 1000 + 1);
  assert.equal(viewModel().kind, 'paused');
});

test('request delay counts down from an absolute deadline across refreshes', () => {
  const { countdown } = createRequire(import.meta.url)('../studio/static/job_guidance.js');
  const value = { status: 'running', stats: { request_wait: { reason: 'request_delay', until: now/1000+30 } } };
  assert.equal(countdown(value, now).seconds, 30);
  const reloaded = JSON.parse(JSON.stringify(value));
  assert.equal(countdown(reloaded, now+1100).seconds, 29);
  assert.match(countdown(reloaded, now+1100).text, /فاصل الطلبات.*00:29/);
  assert.equal(countdown(value, now+30000).seconds, 0);
  assert.match(countdown(value, now+30000).text, /حان موعد الطلب التالي.*00:00/);
  for (const status of ['paused','pause_requested','cancel_requested','interrupted','waiting_input','completed','cancelled']) {
    assert.equal(countdown({ ...value, status }, now), null);
  }
});

test('server clock ignores browser skew, wall clock changes and page reloads', () => {
  const value = {status:'running',settings:{delay:18},stats:{request_wait:{reason:'request_delay',until:now/1000+18}}};
  for (const skew of [-3600000,-5000,5000,3600000]) {
    let mono=100,wall=now+skew;
    const clock=createServerClock(()=>mono,()=>wall);
    assert.equal(clock.observe(String(now/1000),90),true);
    assert.equal(countdown(value,clock.now()).seconds,18);
    mono+=4000;wall+=7200000;
    assert.equal(countdown(value,clock.now()).seconds,14);
    const reloaded=createServerClock(()=>mono,()=>wall);
    assert.equal(reloaded.observe(String(now/1000+4),mono),true);
    assert.equal(countdown(JSON.parse(JSON.stringify(value)),reloaded.now()).seconds,14);
  }
});

test('clock rejects invalid, stale and slow response samples', () => {
  let mono=100;
  const clock=createServerClock(()=>mono,()=>now+3600000);
  for (const value of [null,'','0','NaN','-1','1e100',String(1e18)]) assert.equal(clock.observe(value,90),false);
  assert.equal(clock.observe(String(now/1000),90),true);
  mono=200;
  assert.equal(clock.observe(String(now/1000-10),80),false);
  assert.equal(clock.now(),now+100);
  assert.equal(clock.observe(String((now+50)/1000),150),true);
  assert.equal(clock.now(),now+100);
  mono=4000;
  assert.equal(clock.observe(String(now/1000),200),false);
  assert.equal(clock.now(),now+3900);
});

test('configured interval stays visible between waits and never resets a countdown', () => {
  const value={status:'running',settings:{delay:18},stats:{request_wait:{reason:'request_delay',until:now/1000+18}}};
  assert.match(countdown(value,now).text,/\(18 ثانية\).*00:18/);
  assert.equal(countdown(value,now-5000).seconds,18);
  assert.equal(countdown(value,now+16000).seconds,2);
  assert.equal(countdown(value,now+20000).seconds,0);
  value.stats.request_wait=null;
  assert.deepEqual(countdown(value,now+20000),{reason:'configured_delay',seconds:null,text:'فاصل الطلبات (18 ثانية)'});
  value.stats.request_wait={reason:'request_delay',until:now/1000+38};
  assert.equal(countdown(value,now+21000).seconds,17);
  value.stats.wait_until=now/1000+120;
  assert.equal(countdown(value,now).seconds,120);
  assert.equal(countdown(value,now).reason,'rate_limit');
  assert.equal(countdown({...value,status:'cancelled'},now),null);
});
test('rate limit deadline takes precedence and is distinct from ordinary pacing', () => {
  const { countdown } = createRequire(import.meta.url)('../studio/static/job_guidance.js');
  const value = { status: 'running', stats: { wait_until: now/1000+60, request_wait: { reason:'request_delay', until:now/1000+30 } } };
  assert.equal(countdown(value, now).reason, 'rate_limit');
  assert.equal(countdown(value, now).seconds, 60);
  assert.match(countdown(value, now).text, /مهلة تقييد الطلبات/);
  assert.equal(countdown({ ...value, stats:{ ...value.stats, wait_unbounded:true } }, now), null);
  assert.equal(countdown({ ...value, status:'completed_warnings' }, now), null);
  for (const until of [null,NaN,Infinity,1e100,'1700000000',-1]) {
    assert.equal(countdown({status:'running',stats:{request_wait:{reason:'request_delay',until}}}, now), null);
  }
});
