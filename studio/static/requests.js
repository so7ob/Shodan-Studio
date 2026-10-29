/* Request history is independent of progress events and never sends Shodan queries. */
(function(root){
 'use strict';
 const labels={requesting:'جارٍ إرسال الاستعلام',processing:'جارٍ تحليل النتيجة',success:'نجح',empty:'لا توجد نتائج',
  unavailable:'المرشح بلا معلومات',failed:'فشل الطلب',rate_limited:'تقييد الطلبات 429',challenge:'اختبار أمان Cloudflare',
  login_required:'يلزم تسجيل الدخول',connection_failed:'فشل الاتصال',uncertain:'النتيجة غير مؤكدة',cached:'من الذاكرة المؤقتة',snapshot:'لقطة محفوظة'};
 const origins={legacy:'سجل مستعاد',snapshot:'نتيجة محفوظة؛ ليست محاولة جديدة',cache:'بدون طلب شبكة جديد'};
 const count=x=>typeof x==='number'&&Number.isFinite(x)?new Intl.NumberFormat('en-US').format(x):'غير متاح';
 function describe(r){
  const duration=typeof r.duration_ms==='number'?`${count(Math.round(r.duration_ms)/1000)} ثانية`:'غير متاحة';
  return {status:labels[r.status]||labels.uncertain,
   meta:[r.facet||'مرشح غير معروف',r.source==='api'?'Shodan API':r.source==='html'?'Shodan HTML':'مصدر غير معروف',
    r.api_page!=null?`صفحة ${count(r.api_page)}`:'',r.http_status!=null?`HTTP ${r.http_status}`:'',origins[r.origin]||''].filter(Boolean).join(' · '),
   result:`إجمالي السجلات: ${count(r.total_records)} · عناصر الصفحة: ${count(r.row_count)}${r.facet==='ip'?` · عناوين IP جديدة: ${count(r.new_unique_ips)}`:''} · المدة: ${duration}`};
 }
 function formatMessage(r){const d=describe(r);return `${d.status} | ${d.meta} | ${r.query||'استعلام غير متاح'} | ${d.result}${r.error?' | '+r.error:''}`;}
 let api,copy,jobId=null,epoch=0,busy=false,cursor=null,loaded=false,mode='requests';
 const rows=new Map();
 const $=id=>document.getElementById(id);
 function el(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!=null)n.textContent=text;return n;}
 function url(id){return `/api/jobs/${encodeURIComponent(jobId)}/requests${id?'/'+encodeURIComponent(id):''}`;}
 function select(id){
  if(jobId===id)return;
  jobId=id;epoch++;busy=false;cursor=null;loaded=false;rows.clear();
  $('request-list').replaceChildren();$('request-notice').textContent='لم تُحمّل الطلبات بعد.';
  $('requests-older').hidden=true;
 }
 function renderLatest(job){
  select(job.id);
  const r=job.latest_request;
  $('latest-request').hidden=false;
  $('latest-request-title').textContent=r&&['requesting','processing'].includes(r.status)?'الطلب الجاري':'آخر طلب / قراءة';
  $('latest-request-copy').hidden=!r;
  $('latest-request-copy').onclick=()=>copy(r?.query||'');
  if(!r){
   $('latest-request-query').textContent='لا يوجد طلب مسجل بعد.';
   for(const id of ['latest-request-state','latest-request-meta','latest-request-result','latest-request-error'])$(id).textContent='';
   return;
  }
  const d=describe(r);
  $('latest-request-query').textContent=r.query||'الاستعلام غير متاح';
  $('latest-request-state').textContent=d.status;
  $('latest-request-meta').textContent=d.meta;
  $('latest-request-result').textContent=d.result;
  $('latest-request-error').textContent=r.error||'';
 }
 async function detail(row,more=false){
  if(row.loading)return;
  const version=epoch,id=row.entry.request_id;
  row.loading=true;row.more.disabled=true;
  try{
   const offset=more?row.offset:0;
   const data=await api(`${url(id)}?offset=${offset}&limit=100`);
   if(version!==epoch)return;
   if(!more)row.body.replaceChildren();
   for(const item of data.items){
    const tr=el('tr');
    tr.append(el('td','request-value',(item.label||item.value)+(item.truncated?'… (قيمة طويلة مختصرة)':'')),el('td','request-count',count(item.count)));
    row.body.append(tr);
   }
   row.offset=offset+data.items.length;
   row.more.hidden=!data.has_more;
   row.notice.textContent=data.total?`عرض ${count(row.offset)} من ${count(data.total)} قيمة`:
    ['requesting','processing'].includes(row.entry.status)?'بانتظار قيم النتيجة.':'لا توجد قيم مرشحات محفوظة لهذه المحاولة.';
   row.table.hidden=!data.total;
   row.wrapper.hidden=!data.total;
   row.loaded=true;
  }catch(e){if(version===epoch){row.notice.textContent=e.message;row.more.hidden=false;row.more.textContent='إعادة تحميل التفاصيل';row.loaded=false;}}
  finally{row.loading=false;row.more.disabled=false;}
 }
 function makeRow(entry){
  const node=el('details','request-row'),head=el('summary'),state=el('strong','request-state'),meta=el('span','muted small-text'),query=el('code','request-query'),result=el('p','small-text');
  head.append(state,meta,query,result);node.append(head);
  const controls=el('div','request-controls'),button=el('button','button small secondary','نسخ الاستعلام');button.type='button';
  const stamp=el('span','muted small-text');controls.append(button,stamp);
  const error=el('p','request-error'),notice=el('p','muted small-text');
  const wrapper=el('div','request-values-scroll'),table=el('table','request-values');
  wrapper.tabIndex=0;wrapper.setAttribute('role','region');wrapper.setAttribute('aria-label',`قيم المرشح ${entry.facet||''}`);
  wrapper.hidden=true;
  table.append(el('caption',null,'قيم المرشح وأعداد سجلاتها'));
  const thead=el('thead'),tr=el('tr');
  for(const text of ['القيمة','عدد السجلات']){const th=el('th',null,text);th.scope='col';tr.append(th);}
  thead.append(tr);const body=el('tbody');table.append(thead,body);wrapper.append(table);table.hidden=true;
  const more=el('button','button small secondary','تحميل مزيد من القيم');more.type='button';more.hidden=true;
  const panel=el('div','request-detail');panel.append(controls,error,notice,wrapper,more);node.append(panel);
  const row={node,state,meta,query,result,stamp,error,notice,wrapper,table,body,more,entry,offset:0,loaded:false,loading:false};
  button.onclick=()=>copy(row.entry.query||'');
  more.onclick=()=>detail(row,row.loaded);
  node.addEventListener('toggle',()=>{if(node.open&&!row.loaded)detail(row);});
  return row;
 }
 function update(entry){
  let row=rows.get(entry.request_id);
  if(!row){
   row=makeRow(entry);rows.set(entry.request_id,row);
   const following=[...$('request-list').children].find(n=>Number(n.dataset.seq)<entry.seq);
   row.node.dataset.seq=entry.seq;row.node.dataset.requestId=entry.request_id;
   $('request-list').insertBefore(row.node,following||null);
  }
  const changed=row.entry.status!==entry.status||row.entry.details_count!==entry.details_count;
  row.entry=entry;const d=describe(entry);
  row.state.textContent=d.status;row.meta.textContent=d.meta;row.query.textContent=entry.query||'الاستعلام غير متاح';row.result.textContent=d.result;
  row.error.textContent=entry.error||'';
  const date=entry.started_at?new Date(entry.started_at):null;
  row.stamp.textContent=date&&Number.isFinite(date.getTime())?`بدأ: ${date.toLocaleString('ar')}`:'وقت بدء الطلب غير متاح';
  if(changed&&row.node.open&&!row.loading)detail(row);
 }
 async function refresh(id,visible=false,older=false){
  if(id!==jobId)select(id);
  if(!id||!visible||mode!=='requests'||busy)return;
  const version=epoch;busy=true;$('requests-older').disabled=true;
  try{
   const data=await api(`${url()}?limit=50${older&&cursor?'&before='+cursor:''}`);
   if(version!==epoch)return;
   const overlaps=data.items.some(entry=>rows.has(entry.request_id));
   for(const entry of data.items)update(entry);
   if(older||!loaded||!overlaps)cursor=data.next_cursor;
   loaded=true;
   $('requests-older').hidden=!cursor;
   $('request-notice').textContent=rows.size?'':'لا توجد طلبات محفوظة لهذه المهمة بعد.';
  }catch(e){if(version===epoch)$('request-notice').textContent=e.message;}
  finally{if(version===epoch){busy=false;$('requests-older').disabled=false;}}
 }
 function init(options){
  api=options.api;copy=options.copyText;
  $('request-view').onchange=()=>{
   mode=$('request-view').value;
   $('request-history').hidden=mode!=='requests';$('event-log').hidden=mode==='requests';
   $('raw-log-controls').hidden=mode==='requests';
   refresh(jobId,true);
  };
  $('requests-older').onclick=()=>refresh(jobId,true,true);
 }
 const exported={describe,formatMessage,init,select,renderLatest,refresh};
 if(typeof module==='object'&&module.exports)module.exports=exported;
 else root.ShodanRequests=exported;
})(typeof globalThis!=='undefined'?globalThis:this);
