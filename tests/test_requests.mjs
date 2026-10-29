import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const {describe,formatMessage}=createRequire(import.meta.url)('../studio/static/requests.js');
test('host lookup results report services independently of discovery counts',()=>{
 const d=describe({status:'success',facet:'host',source:'html',row_count:0,duration_ms:10});
 assert.match(d.meta,/تفاصيل المضيف/);assert.match(d.result,/الخدمات في الاستجابة: 0/);
 assert.doesNotMatch(d.result,/عناوين IP جديدة/);
});
test('request results distinguish records, page items and newly stored unique IPs',()=>{
 const d=describe({status:'success',facet:'ip',source:'api',api_page:2,total_records:579,row_count:100,new_unique_ips:80,duration_ms:1500});
 assert.equal(d.status,'نجح');assert.match(d.meta,/صفحة 2/);
 assert.match(d.result,/إجمالي السجلات: 579/);assert.match(d.result,/عناصر الصفحة: 100/);
 assert.match(d.result,/عناوين IP جديدة: 80/);assert.match(d.result,/1.5 ثانية/);
});
test('missing historic data is not zero, and a saved snapshot is not a new request',()=>{
 const d=describe({status:'snapshot',origin:'snapshot'});
 assert.match(d.meta,/ليست محاولة جديدة/);assert.match(d.result,/غير متاح/);assert.doesNotMatch(d.result,/: 0/);
 assert.equal(describe({status:'unavailable'}).status,'المرشح بلا معلومات');
 assert.equal(describe({status:'empty'}).status,'لا توجد نتائج');
 assert.match(describe({status:'cached',origin:'cache'}).meta,/بدون طلب شبكة/);
});
test('security, login, throttling and ambiguous attempts remain distinct',()=>{
 for(const status of ['challenge','login_required','rate_limited','connection_failed','uncertain']){
  assert.notEqual(describe({status}).status,'فشل الطلب');
 }
 const query='<img src=x onerror=alert(1)>';
 assert.ok(formatMessage({query,status:'failed'}).includes(query)); // DOM renderer uses textContent.
});
