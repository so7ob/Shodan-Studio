import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const { viewModel } = createRequire(import.meta.url)('../studio/static/job_guidance.js');
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
  for (const wait_until of [null, false, '1700000000', -1, 0, NaN, Infinity, 1e100]) {
    const vm = viewModel({ ...job, stats: { wait_until } }, now, format);
    assert.equal(vm.kind, 'rate_limit');
    assert.equal(vm.deadlineMs, null);
    assert.match(vm.message, /لا يوجد موعد/);
  }
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
test('view model does not mutate saved state or require browser/network globals', () => {
  const input = Object.freeze({ ...job, stats: Object.freeze({ wait_until: now / 1000 + 1 }) });
  assert.equal(viewModel(input, now, format).kind, 'waiting');
  assert.equal(input.stats.wait_until, now / 1000 + 1);
  assert.equal(viewModel().kind, 'paused');
});
