import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { viewModel } = require('../studio/static/ip_progress.js');

test('example 512 of estimated 782 displays 65%', () => {
  const vm = viewModel({ extracted_unique_ips: 512, estimated_total_ips: 782,
    remaining_estimated_ips: 270, progress_percent: 65,
    planning_complete: true, completed_leaves: 16, total_leaves: 77, is_estimate: true });
  assert.equal(vm.percentLabel, '65% تقديري');
  assert.match(vm.headline, /512/);
  assert.match(vm.headline, /782/);
  assert.match(vm.branchDescription, /16 \/ 77/);
});

test('no estimate is not presented as zero percent or 100%', () => {
  const vm = viewModel({ extracted_unique_ips: 512, estimated_total_ips: null,
    progress_percent: null, planning_complete: false });
  assert.equal(vm.percent, null);
  assert.equal(vm.percentLabel, '—');
  assert.match(vm.description, /تخطيط/);
});

test('source records give provisional numeric progress while unique total is unknown', () => {
  const input={extracted_unique_ips:100,estimated_total_ips:null,progress_percent:null,
    planning_complete:false,source_record_reference:{total_records:579,progress_percent:17}};
  const vm=viewModel(input);
  assert.equal(vm.percent,17);
  assert.equal(vm.total,null);
  assert.match(vm.headline,/100 عنوان IP مستخرج \/ 579 سجل متوقع/);
  assert.match(vm.percentLabel,/تقديري/);
  assert.match(vm.description,/قد تتكرر/);
  assert.equal(viewModel({...input,extracted_unique_ips:600}).percent,99);
  assert.equal(viewModel({...input,extracted_unique_ips:0}).percent,0);
  for (const total_records of [0,-1,false,'579',Infinity,1.5]) {
    assert.equal(viewModel({...input,source_record_reference:{total_records}}).percent,null);
  }
  assert.equal(viewModel({...input,estimated_total_ips:200,progress_percent:50}).percent,50);
  assert.equal(viewModel({...input,estimated_total_ips:100,progress_percent:100,job_finished_successfully:true}).percent,100);
});

test('completed zero-IP job can show 100% without fabricated totals', () => {
  const vm = viewModel({ extracted_unique_ips: 0, estimated_total_ips: 0,
    progress_percent: 100, job_finished_successfully: true, is_estimate: false });
  assert.equal(vm.percentLabel, '100%');
  assert.match(vm.headline, /اكتملت/);
});

test('error condition with known count remains estimated', () => {
  const vm = viewModel({ extracted_unique_ips: 5, estimated_total_ips: 12,
    remaining_estimated_ips: 7, progress_percent: 42, is_estimate: true });
  assert.equal(vm.percentLabel, '42% تقديري');
});

test('large numbers formatted safely', () => {
  const vm = viewModel({ extracted_unique_ips: 1000000, estimated_total_ips: 1200000,
    remaining_estimated_ips: 200000, progress_percent: 83 });
  assert.match(vm.headline, /1,000,000/);
});

test('invalid percent is treated as unknown', () => {
  const vm = viewModel({ extracted_unique_ips: 1, estimated_total_ips: 2,
    progress_percent: null });
  assert.equal(vm.percent, null);
});

test('rounding or malformed payload cannot display 100 before success', () => {
  for (const progress_percent of [99.99, 100, 150]) {
    assert.equal(viewModel({ extracted_unique_ips: 512, estimated_total_ips: 512,
      progress_percent, job_finished_successfully: false }).percent, 99);
  }
  assert.equal(viewModel({ progress_percent: 80 }).percent, null);
});

test('missing progress never falls back to a branch percentage', () => {
  const vm = viewModel({ completed_leaves: 77, total_leaves: 77, planning_complete: true });
  assert.equal(vm.percent, null);
  assert.match(vm.headline, /الإجمالي الفريد قيد التقدير/);
});

class FakeElement {
  constructor(tag = 'div') {
    this.tag = tag;
    this.dataset = {};
    this.children = [];
    this.attributes = {};
    this.style = { width: '' };
    this.className = '';
    this.classList = {
      add: (...classes) => { this.className += ' ' + classes.join(' '); },
    };
  }
  setAttribute(name, value) { this.attributes[name] = value; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = [...nodes]; }
  getAttribute(name) { return this.attributes[name]; }
}

test('render creates accessible determinate progressbar', () => {
  const api = require('../studio/static/ip_progress.js');
  globalThis.document = { createElement: tag => new FakeElement(tag) };
  const container = new FakeElement();
  container.dataset.variant = 'detail';
  api.render(container, { extracted_unique_ips: 512, estimated_total_ips: 782,
    remaining_estimated_ips: 270, progress_percent: 65, is_estimate: true,
    planning_complete: true, completed_leaves:16, total_leaves:77 });
  const bar = container.children[2];
  assert.equal(bar.getAttribute('role'), 'progressbar');
  assert.equal(bar.getAttribute('aria-valuenow'), '65');
  assert.equal(bar.children[0].style.width, '65%');
  assert.equal(container.children.at(-1).textContent, 'الفروع (مؤشر ثانوي): \u206616 / 77\u2069');
});

test('render unknown estimate as non-numeric status', () => {
  const api = require('../studio/static/ip_progress.js');
  globalThis.document = { createElement: tag => new FakeElement(tag) };
  const container = new FakeElement();
  api.render(container, { extracted_unique_ips: 194, progress_percent: null,
    estimated_total_ips: null, planning_complete: false });
  const bar = container.children[2];
  assert.equal(bar.getAttribute('role'), 'status');
  assert.equal(bar.getAttribute('aria-valuenow'), undefined);
});

test('compact list retains secondary branch counts and safely renders text', () => {
  const api = require('../studio/static/ip_progress.js');
  globalThis.document = { createElement: tag => new FakeElement(tag) };
  const container = new FakeElement();
  container.dataset.variant = 'compact';
  api.render(container, { extracted_unique_ips: 512, estimated_total_ips: 782,
    progress_percent: 65, planning_complete: true, completed_leaves: 16, total_leaves: 77 });
  assert.equal(container.children[2].children[0].style.width, '65%');
  assert.match(container.children.at(-1).textContent, /16 \/ 77/);
});

test('enrichment progress counts processed targets and keeps outcomes separate', () => {
  const api = require('../studio/static/ip_progress.js');
  const view = api.viewModel({enrichment:{total:10,processed:10,success:6,partial:2,not_found:1,failed:1}});
  assert.equal(view.percent,100);assert.equal(view.isEstimated,false);
  assert.match(view.headline,/10 \/ 10/);assert.match(view.description,/لا يعني توفر/);
  assert.match(view.branchDescription,/جزئي: 2/);
});
