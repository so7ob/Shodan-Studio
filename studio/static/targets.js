/* The inventory reads local evidence; enrichment always enters the job queue. */
'use strict';
window.ShodanTargets = (() => {
  const $ = id => document.getElementById(id);
  const esc = v => String(v ?? 'غير معروف').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const number = v => new Intl.NumberFormat('en-US').format(v || 0);
  const time = v => v ? new Intl.DateTimeFormat('ar', {timeZone:'Asia/Aden',dateStyle:'medium',timeStyle:'medium'}).format(new Date(v)) : 'غير معروف';
  const statuses = {pending:'بانتظار الإثراء',success:'تفاصيل مكتملة',partial:'تفاصيل جزئية',not_found:'غير موجود لدى المصدر',failed:'متعثر'};
  const specs = [
    ['q','IP / CIDR / اسم مضيف'],['country','رمز الدولة'],['city','المدينة'],['port','البورت'],['protocol','البروتوكول', ['', 'tcp','udp','unknown']],
    ['asn','ASN'],['org','المؤسسة'],['product','المنتج'],['job_id','المهمة المصدرية'],['query','الاستعلام'],
    ['source','مصدر الاكتشاف',['','html','api']],['enrichment_source','مصدر التفاصيل',['','html','api']],
    ['status','حالة الإثراء',['',...Object.keys(statuses)]],['from','من تاريخ / وقت عدن'],['to','إلى تاريخ / وقت عدن'],
    ['demo','مجموعة البيانات',['0','1']]
  ];
  let ctx, visible = false, filters = {}, offset = 0, total = 0, busy = false, generation = 0, signature = '', options = {};
  let detailId = null, detailOffset = 0;
  let configuringJob = null;
  const runtimeFields = [
    ['max_requests','حد الطلبات للجولة',1,100000,1],['delay','فاصل الطلبات · ثانية',0,3600,0.1],
    ['timeout','مهلة الاتصال · ثانية',1,180,1],['rate_limit_retries','محاولات 429',0,10,1],
    ['retry_base_delay','الانتظار الأولي · ثانية',1,3600,1],['max_retry_wait','أقصى انتظار · ثانية',0,86400,1]
  ];
  const selected = new Set();
  function field([name,label,choices]) {
    const control = choices ? `<select name="${name}">${choices.map(v => `<option value="${v}">${esc(name==='demo'?(v==='1'?'تجريبية':'حقيقية'):v===''?'الكل':statuses[v] || v)}</option>`).join('')}</select>`
      : `<input name="${name}" ${['from','to'].includes(name)?'type="datetime-local"':'type="search" maxlength="512"'} ${['q','asn','port','country','job_id'].includes(name)?'dir="ltr"':''}>`;
    return `<label class="field"><span>${label}</span>${control}</label>`;
  }
  function mount() {
    const nav = document.createElement('button'); nav.id='targets-nav'; nav.className='nav-item'; nav.type='button';
    nav.innerHTML='<svg class="icon" aria-hidden="true"><use href="#i-globe"/></svg><span>مستودع الأهداف</span>';
    document.querySelector('nav[aria-label="التنقل الرئيسي"]').insertBefore(nav, document.querySelector('[data-shodan-accounts]'));
    const section = document.createElement('section'); section.id='targets-view'; section.hidden=true; section.setAttribute('aria-labelledby','targets-heading');
    section.innerHTML=`<div class="page-heading"><div><div class="eyebrow">سجل الاكتشافات</div><h1 id="targets-heading" tabindex="-1">مستودع الأهداف</h1><p class="muted">عنوان واحد، كل مصادره وخدماته وأوقات العثور عليه. الأوقات بتوقيت عدن.</p></div><div class="heading-actions"><button id="targets-settings" class="button secondary">إعدادات الإثراء</button><button id="targets-enrich" class="button primary">إنشاء مهمة إثراء</button></div></div>
      <section class="targets-metrics" aria-label="إحصاءات الأهداف المطابقة"><div><span>عناوين فريدة بين المهام</span><strong id="targets-total">—</strong></div><div><span>خدمات الأهداف المطابقة</span><strong id="targets-services">—</strong></div><div><span>المهام المصدرية</span><strong id="targets-jobs">—</strong></div><div><span>أهداف ذات تفاصيل مكتملة</span><strong id="targets-complete">—</strong></div></section>
      <section class="panel targets-filters" aria-labelledby="targets-filter-heading"><h2 id="targets-filter-heading">الفلاتر</h2><form id="targets-filter-form"><div class="targets-filter-grid">${specs.map(field).join('')}</div><div class="targets-actions"><button class="button primary" type="submit">تطبيق الفلاتر</button><button id="targets-reset" class="button secondary" type="button">مسح الفلاتر</button><span class="muted small-text">المهمة والاستعلام والفترة تتطابق مع واقعة الاكتشاف نفسها. «إلى» لا يشمل اللحظة المحددة.</span></div></form></section>
      <p id="targets-error" class="form-error" role="alert" hidden></p><p id="targets-loading" class="muted" role="status" hidden>جارٍ تحميل المستودع…</p>
      <div class="targets-charts"><section class="panel"><h2>الدول</h2><div id="targets-countries"></div></section><section class="panel"><h2>المدن</h2><div id="targets-cities"></div></section><section class="panel"><h2>البورتات</h2><div id="targets-ports"></div></section><section class="panel"><h2>حالات الإثراء</h2><div id="targets-statuses"></div></section></div>
      <section class="panel targets-timeline"><details><summary>العناوين المشاهدة يوميًا · أوقات موثقة فقط</summary><div id="targets-timeline"></div></details></section>
      <section class="panel"><div class="panel-heading targets-table-tools"><div><h2>الأهداف المطابقة</h2><span id="targets-selection" class="muted">0 محددة</span></div><div class="button-group"><button id="targets-clear-selection" class="button small secondary" type="button">مسح التحديد</button><button class="button small secondary" data-target-export="txt">TXT</button><button class="button small secondary" data-target-export="csv">CSV</button><button class="button small secondary" data-target-export="json">JSON</button></div></div>
      <div class="table-scroll targets-scroll" tabindex="0" role="region" aria-label="جدول الأهداف"><table class="targets-table"><thead><tr><th><span class="sr-only">التحديد</span></th><th>العنوان / أسماء المضيف</th><th>الدولة / المدينة</th><th>الخدمات</th><th>المؤسسة / ASN</th><th>أقدم / آخر اكتشاف موثق</th><th>الإثراء</th><th>المصادر</th></tr></thead><tbody id="targets-body"></tbody></table></div><p id="targets-empty" class="empty-state compact" hidden>لا توجد أهداف مطابقة. غيّر الفلاتر، أو ابدأ مهمة استخراج.</p>
      <div class="panel-footer"><span id="targets-range">—</span><div class="button-group"><button id="targets-prev" class="button small secondary">السابق</button><button id="targets-next" class="button small secondary">التالي</button></div></div></section>`;
    $('main').insertBefore(section,$('workspace-view'));
    const dialogs=document.createElement('div'); dialogs.innerHTML=`
      <dialog id="target-dialog" class="modal large-modal" aria-labelledby="target-detail-heading"><div class="modal-heading"><h2 id="target-detail-heading" dir="ltr">تفاصيل الهدف</h2><button type="button" class="icon-button" data-target-close aria-label="إغلاق">×</button></div><div class="modal-body" id="target-detail"></div><div class="modal-footer"><button id="target-enrich-one" class="button primary">إثراء هذا الهدف</button><button data-target-close class="button secondary">إغلاق</button></div></dialog>
      <dialog id="target-settings-dialog" class="modal" aria-labelledby="target-settings-heading"><form id="target-settings-form"><div class="modal-heading"><h2 id="target-settings-heading">إعدادات إثراء الأهداف</h2><button type="button" class="icon-button" data-target-close aria-label="إغلاق">×</button></div><div class="modal-body"><label class="check-label"><input name="automatic" type="checkbox">إنشاء مهام إثراء تلقائيًا للأهداف القديمة والجديدة</label><label class="field"><span>المصدر الافتراضي</span><select name="source_mode"><option value="auto">تلقائي · API عند توفر مفتاح ثم HTML عند الحاجة</option><option value="html">HTML</option><option value="api">API</option></select></label><label class="field"><span>مفتاح Shodan API اختياري · محفوظ مشفرًا</span><input name="api_key" type="password" autocomplete="off" dir="ltr"><small id="target-key-status"></small></label><label class="check-label"><input name="clear_key" type="checkbox">مسح المفتاح المحفوظ</label><p class="muted">تعمل كل عملية إثراء كمهمة مستقلة لها إعداداتها واتصالها ومتصفحها ونقطة استكمالها.</p><p id="target-settings-error" class="form-error" role="alert"></p></div><div class="modal-footer"><button id="target-settings-save" class="button primary" type="submit">حفظ الإعدادات</button><button type="button" class="button secondary" data-target-close>إلغاء</button></div></form></dialog>`;
    document.body.append(dialogs);
    const runDialog = document.createElement('dialog'); runDialog.id='job-runtime-dialog';runDialog.className='modal large-modal';runDialog.setAttribute('aria-labelledby','job-runtime-heading');
    runDialog.innerHTML=`<form id="job-runtime-form"><div class="modal-heading"><h2 id="job-runtime-heading">إعدادات تشغيل المهمة</h2><button type="button" class="icon-button" data-target-close aria-label="إغلاق">×</button></div><div class="modal-body"><div class="form-grid"><label class="field"><span>أولوية الطابور · 0 منخفضة إلى 10 مرتفعة</span><input name="priority" type="number" min="0" max="10" required></label><label class="field"><span>موعد البدء · بتوقيت جهازك، فارغ للبدء عند توفر العامل</span><input name="scheduled_at" type="datetime-local"></label>${runtimeFields.map(([key,label,min,max,step])=>`<label class="field"><span>${label}</span><input name="${key}" type="number" min="${min}" max="${max}" step="${step}" required></label>`).join('')}<label class="field"><span>عميل الاتصال</span><select name="transport"><option value="curl">curl</option><option value="python">Python</option></select></label><label class="field"><span>عند تعذّر API</span><select name="api_fallback"><option value="html">محاولة HTML</option><option value="stop">انتظار المتابعة</option></select></label><label class="field"><span>عند استمرار تقييد المعدّل</span><select name="on_rate_limit"><option value="pause">انتظار المتابعة</option><option value="stop">توقف</option></select></label><label class="field"><span>فتح متصفح التحقق</span><select name="browser_recovery"><option value="on_challenge">تلقائيًا عند التحقق</option><option value="manual">يدويًا</option></select></label></div><label class="field"><span>User-Agent اختياري</span><input name="user_agent" maxlength="512" dir="ltr"></label><label class="check-label"><input name="rotate_user_agents" type="checkbox">تدوير User-Agent لطلبات HTTP</label><p id="job-runtime-error" class="form-error" role="alert"></p></div><div class="modal-footer"><button id="job-runtime-save" class="button primary" type="submit">حفظ</button><button type="button" class="button secondary" data-target-close>إلغاء</button></div></form>`;
    document.body.append(runDialog);
    const summary=document.createElement('p'); summary.id='create-target-summary'; summary.className='notice'; summary.hidden=true;
    $('create-form').querySelector('.modal-body').prepend(summary);
    const schedule=document.createElement('label'); schedule.className='field'; schedule.innerHTML='<span>موعد بدء المهمة · اختياري، بتوقيت جهازك</span><input name="scheduled_at" type="datetime-local">';
    $('create-form').querySelector('.modal-body').append(schedule);
    const kind=document.createElement('select'); kind.id='job-kind-filter'; kind.setAttribute('aria-label','نوع المهمة');
    kind.innerHTML='<option value="all">كل الأنواع</option><option value="extraction">استخراج</option><option value="enrichment">إثراء</option>';
    $('job-filter').before(kind);
  }
  function filterValues() {
    const result={}, data=new FormData($('targets-filter-form'));
    for(const [key,raw] of data) {
      if(!raw)continue;
      result[key]=['from','to'].includes(key)?new Date(`${raw}+03:00`).toISOString():String(raw).trim();
    }
    return result;
  }
  function urlParams(extra={}) { return new URLSearchParams({...filters,...extra}); }
  function show() {
    ShodanVPN.workspace(); visible=true; $('workspace-view').hidden=true; $('targets-view').hidden=false;
    document.querySelectorAll('[data-view],[data-network-view]').forEach(x=>x.classList.remove('active'));
    $('targets-nav').classList.add('active'); $('breadcrumb-current').textContent='مستودع الأهداف';
    $('targets-heading').focus(); ctx.closeSidebar();
    history.replaceState(null,'',`#view=targets&${urlParams()}`); refresh();
  }
  function workspace() { visible=false; $('targets-view').hidden=true; $('targets-nav').classList.remove('active'); }
  function chart(id, rows, filter) {
    const target=$(id), sig=JSON.stringify(rows); if(target.dataset.signature===sig)return;
    const focused=target.contains(document.activeElement)?document.activeElement.dataset.chartValue:null;
    target.dataset.signature=sig; target.replaceChildren();
    if(!rows.length){target.textContent='لا توجد بيانات موثقة.';return;}
    const max=Math.max(1,...rows.map(x=>x.count));
    for(const row of (filter ? rows.slice(0,10) : rows)) {
      const line=document.createElement('div'); line.className='target-bar';
      const label=document.createElement(filter&&row.value!=='غير معروف'?'button':'span');
      label.textContent=statuses[row.value]||row.value; if(label.tagName==='BUTTON') {
        label.type='button'; label.className='target-filter-link';
        label.dataset.chartValue=String(row.value);
        label.setAttribute('aria-label',`${label.textContent}: ${number(row.count)}، تصفية`);
        label.onclick=()=>{ $('targets-filter-form').elements[filter].value=row.value; applyFilters(); };
      }
      const meter=document.createElement('meter'); meter.min=0; meter.max=max; meter.value=row.count;
      meter.setAttribute('aria-label',`${label.textContent}: ${number(row.count)}`);
      const count=document.createElement('span');count.textContent=number(row.count);line.append(label,meter,count);target.append(line);
    }
    if(focused!==null)Array.from(target.querySelectorAll('button')).find(b=>b.dataset.chartValue===focused)?.focus({preventScroll:true});
  }
  function render(data, stats) {
    total=data.total; $('targets-total').textContent=number(total);$('targets-services').textContent=number(stats.services);
    $('targets-jobs').textContent=number(stats.jobs);$('targets-complete').textContent=number(stats.status.find(x=>x.value==='success')?.count);
    chart('targets-countries',stats.country,'country');chart('targets-cities',stats.city,'city');chart('targets-ports',stats.ports,'port');
    chart('targets-statuses',stats.status,'status');chart('targets-timeline',[...stats.timeline].reverse());
    const sig=JSON.stringify(data);
    if(sig!==signature) {
      signature=sig; const active=document.activeElement;
      const focusAttribute=active?.dataset?.targetSelect?'data-target-select':active?.dataset?.targetOpen?'data-target-open':null;
      const focus=focusAttribute?active.getAttribute(focusAttribute):null;
      $('targets-body').innerHTML=data.items.map(x=>`<tr><td><input type="checkbox" data-target-select="${x.id}" data-target-id="${x.id}" aria-label="تحديد ${esc(x.ip)}" ${selected.has(x.id)?'checked':''}></td>
        <td><button class="target-ip" data-target-open="${x.id}" dir="ltr">${esc(x.ip)}</button><small dir="ltr">${esc((x.hostnames||[]).join(', '))}</small></td>
        <td>${esc(x.country_name||x.country)}<small>${esc(x.city)}</small></td><td dir="ltr">${x.services.slice(0,8).map(s=>`${s.port}/${esc(s.transport)}`).join(' · ')||'—'}${x.services.length>8?` +${x.services.length-8}`:''}</td>
        <td>${esc(x.org)}<small dir="ltr">${esc(x.asn)}</small></td><td>${esc(time(x.first_found_at))}<small>${esc(time(x.last_found_at))}${x.unknown_discovery_times?' · توجد أوقات قديمة مجهولة':''}</small></td>
        <td>${esc(statuses[x.status]||x.status)}<small>${esc(time(x.enriched_at))}</small></td><td>${number(x.job_count)} مهام<small>${number(x.discovery_count)} سجلات</small></td></tr>`).join('');
      if(focus)$('targets-body').querySelector(`[${focusAttribute}="${focus}"]`)?.focus({preventScroll:true});
    }
    $('targets-empty').hidden=!!data.items.length; $('targets-range').textContent=total?`${number(offset+1)}–${number(offset+data.items.length)} من ${number(total)}`:'0 هدف';
    $('targets-prev').disabled=offset===0;$('targets-next').disabled=offset+50>=total;
  }
  async function refresh() {
    if(!visible||busy)return; busy=true;const own=generation;
    $('targets-loading').hidden=!!signature;
    try {
      const [data,stats,savedOptions]=await Promise.all([ctx.api(`/api/targets?${urlParams({offset,limit:50})}`),ctx.api(`/api/targets/stats?${urlParams()}`),options.source_mode?Promise.resolve(options):ctx.api('/api/enrichment/settings')]);
      if(own!==generation)return;
      options=savedOptions;
      render(data,stats);$('targets-error').hidden=true;
    } catch(error) { if(own===generation){$('targets-error').textContent=error.message;$('targets-error').hidden=false;} }
    finally {busy=false;$('targets-loading').hidden=true;if(own!==generation&&visible)refresh();}
  }
  function applyFilters() { filters=filterValues();offset=0;generation++;signature='';history.replaceState(null,'',`#view=targets&${urlParams()}`);refresh(); }
  async function detail(id, more=false) {
    detailId=id; if(!more)detailOffset=0;
    const {target:x}=await ctx.api(`/api/targets/${id}?offset=${detailOffset}&limit=50`);
    if(detailId!==id)return;
    $('target-detail-heading').textContent=x.ip;
    if(!more) {
      $('target-detail').innerHTML=`<dl class="target-facts">${[['الدولة',x.country_name||x.country],['المدينة',x.city],['المؤسسة',x.org],['ASN',x.asn],['ISP',x.isp],['أسماء المضيف',(x.hostnames||[]).join(', ')],['النطاقات',(x.domains||[]).join(', ')],['أقدم اكتشاف موثق',time(x.first_found_at)],['آخر اكتشاف موثق',time(x.last_found_at)],['آخر إثراء',time(x.enriched_at)],['آخر رصد Shodan',time(x.last_seen)]].map(([k,v])=>`<div><dt>${k}</dt><dd dir="auto">${esc(v)}</dd></div>`).join('')}</dl>
        ${x.unknown_discovery_times?'<p class="notice">بعض المصادر القديمة لا تتضمن وقت اكتشاف موثقًا. لم يُستخدم وقت الترحيل بديلًا له.</p>':''}
        <h3>خدمات المضيف المسجلة</h3><p class="muted small-text">تفاصيل الإثراء قد تتضمن خدمات أخرى للمضيف. لا تُنسب هذه الخدمات تلقائيًا إلى استعلام الاكتشاف.</p>
        <div class="table-scroll" tabindex="0" role="region" aria-label="خدمات الهدف"><table><thead><tr><th>الخدمة</th><th>المنتج / الإصدار</th><th>المصدر</th><th>رصد Shodan</th><th>جلب التفاصيل</th></tr></thead><tbody>${x.services.map(s=>`<tr><td dir="ltr">${s.port}/${esc(s.transport)}</td><td dir="auto">${esc(s.product)} ${esc(s.version||'')}</td><td>${esc(s.source)}</td><td>${esc(time(s.observed_at))}</td><td>${esc(time(s.fetched_at))}</td></tr>`).join('')||'<tr><td colspan="5">غير متاحة بعد.</td></tr>'}</tbody></table></div>
        <h3>مهام إثراء هذا الهدف</h3><div>${(x.enrichment_jobs||[]).map(j=>`<p><button class="button small secondary" data-target-job="${j.id}">${esc(j.title)}</button> · ${esc(j.status)} · ${esc(statuses[j.target_status]||j.target_status)}</p>`).join('')||'<p class="muted">لم تُنشأ مهمة إثراء لهذا الهدف بعد.</p>'}</div>
        <h3>سجل العثور على الهدف</h3><div id="target-discoveries"></div><button id="target-more-discoveries" class="button small secondary" type="button">تحميل سجلات أقدم</button>
        <h3>مصدر كل معلومة</h3><div class="table-scroll"><table><thead><tr><th>المعلومة</th><th>المصدر</th><th>وقت الجلب</th></tr></thead><tbody>${Object.entries(x.provenance||{}).map(([field,p])=>`<tr><td dir="ltr">${esc(field)}</td><td>${esc(p.source)}</td><td>${esc(time(p.fetched_at))}</td></tr>`).join('')}</tbody></table></div>
        <details><summary>لقطات التفاصيل التاريخية · آخر 100</summary><div>${x.snapshots.map(s=>`<details><summary>${esc(s.source)} · ${esc(time(s.fetched_at))}</summary><pre class="target-json" dir="ltr">${esc(JSON.stringify(s.document,null,2))}</pre></details>`).join('')||'<p>لا توجد لقطات بعد.</p>'}</div></details>`;
      $('target-more-discoveries').onclick=()=>detail(id,true).catch(e=>ctx.toast(e.message,'error'));
    }
    $('target-discoveries').insertAdjacentHTML('beforeend',x.discoveries.map(d=>`<article class="target-discovery"><strong>${esc(d.context.title||d.job_id)}${d.job_deleted?' · المهمة محذوفة':''}</strong><p>${esc(time(d.found_at))} · ${esc(d.source)} · ${d.time_quality==='recovered'?'وقت مستعاد من سجل الطلب':d.time_quality==='unknown'?'الوقت غير معروف':'وقت استجابة مسجل'}</p><span class="muted small-text">الاستعلام الأصلي</span><code dir="ltr">${esc(d.original_query)}</code><span class="muted small-text">استعلام الفرع</span><code dir="ltr">${esc(d.query)}</code>${!d.job_deleted?`<button class="button small secondary" data-target-job="${d.job_id}">فتح المهمة</button>`:''}</article>`).join(''));
    detailOffset+=x.discoveries.length;$('target-more-discoveries').hidden=!x.has_more_discoveries;
    if(!$('target-dialog').open)$('target-dialog').showModal();
  }
  function enrich(ids=null) {
    const enrichment=ids?{target_ids:ids}:selected.size?{target_ids:[...selected]}:{filters:{...filters}};
    $('target-dialog').close();ctx.openCreate({enrichment,mode:options.source_mode||'auto',demo:filters.demo==='1',count:ids?.length||selected.size||total});
  }
  async function settings() {
    options=await ctx.api('/api/enrichment/settings');const f=$('target-settings-form');f.reset();f.elements.automatic.checked=options.automatic;
    f.elements.source_mode.value=options.source_mode;$('target-key-status').textContent=options.has_key?'يوجد مفتاح محفوظ. اترك الحقل فارغًا للاحتفاظ به.':'HTML متاح دون مفتاح API.';
    $('target-settings-error').textContent='';$('target-settings-dialog').showModal();
  }
  async function download(format) {
    try {
      const response=await ctx.api(`/api/targets/download?${urlParams({format})}`,{raw:true});
      const blob=await response.blob(), url=URL.createObjectURL(blob), a=document.createElement('a');a.href=url;a.download=`shodan-targets.${format}`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    } catch(error){ctx.toast(error.message,'error');}
  }
  function configureJob(job) {
    if(!job)return;configuringJob=job.id;const f=$('job-runtime-form').elements;
    f.priority.value=job.priority;f.scheduled_at.value=job.scheduled_at?new Date(new Date(job.scheduled_at).getTime()-new Date().getTimezoneOffset()*60000).toISOString().slice(0,16):'';
    for(const [key] of runtimeFields)f[key].value=job.settings[key];
    for(const key of ['transport','api_fallback','on_rate_limit','browser_recovery','user_agent'])f[key].value=job.settings[key]||'';
    f.rotate_user_agents.checked=!!job.settings.rotate_user_agents;$('job-runtime-error').textContent='';$('job-runtime-dialog').showModal();
  }
  function init(context) {
    ctx=context;mount();
    $('targets-nav').onclick=show;$('targets-filter-form').onsubmit=e=>{e.preventDefault();applyFilters();};
    $('targets-reset').onclick=()=>{$('targets-filter-form').reset();applyFilters();};
    $('targets-prev').onclick=()=>{offset=Math.max(0,offset-50);generation++;refresh();};
    $('targets-next').onclick=()=>{offset+=50;generation++;refresh();};
    $('targets-enrich').onclick=()=>{if(total||selected.size)enrich();else ctx.toast('لا توجد أهداف مطابقة للإثراء.');};
    $('target-enrich-one').onclick=()=>enrich([detailId]);$('targets-settings').onclick=()=>settings().catch(e=>ctx.toast(e.message,'error'));
    $('targets-clear-selection').onclick=()=>{selected.clear();signature='';$('targets-selection').textContent='0 محددة';refresh();};
    $('targets-body').onchange=e=>{const id=e.target.dataset.targetSelect;if(!id)return;e.target.checked?selected.add(id):selected.delete(id);$('targets-selection').textContent=`${number(selected.size)} محددة`;};
    document.addEventListener('click',e=>{
      const open=e.target.closest('[data-target-open]');if(open)detail(open.dataset.targetOpen).catch(x=>ctx.toast(x.message,'error'));
      const job=e.target.closest('[data-target-job]');if(job){$('target-dialog').close();workspace();ctx.setView('all');ctx.selectJob(job.dataset.targetJob);}
      const close=e.target.closest('[data-target-close]');if(close)close.closest('dialog').close();
      const exp=e.target.closest('[data-target-export]');if(exp)download(exp.dataset.targetExport);
    });
    $('target-settings-form').onsubmit=async e=>{
      e.preventDefault();const f=e.currentTarget.elements;$('target-settings-save').disabled=true;
      try{options=await ctx.api('/api/enrichment/settings',{method:'POST',body:JSON.stringify({source_mode:f.source_mode.value,automatic:f.automatic.checked,api_key:f.api_key.value,clear_key:f.clear_key.checked})});$('target-settings-dialog').close();ctx.toast('حُفظت إعدادات الإثراء.');await ctx.refreshAll();}
      catch(error){$('target-settings-error').textContent=error.message;}finally{f.api_key.value='';$('target-settings-save').disabled=false;}
    };
    $('target-settings-dialog').addEventListener('close',()=>{$('target-settings-form').elements.api_key.value='';});
    $('job-runtime-form').onsubmit=async e=>{
      e.preventDefault();const f=e.currentTarget.elements,settings={};for(const [key] of runtimeFields)settings[key]=Number(f[key].value);
      for(const key of ['transport','api_fallback','on_rate_limit','browser_recovery','user_agent'])settings[key]=f[key].value;
      settings.rotate_user_agents=f.rotate_user_agents.checked;$('job-runtime-save').disabled=true;
      try{await ctx.api(`/api/jobs/${configuringJob}/actions`,{method:'POST',body:JSON.stringify({action:'configure',priority:Number(f.priority.value),scheduled_at:f.scheduled_at.value?new Date(f.scheduled_at.value).toISOString():null,settings})});$('job-runtime-dialog').close();await ctx.refreshAll();ctx.toast('حُفظت إعدادات التشغيل.');}
      catch(error){$('job-runtime-error').textContent=error.message;}finally{$('job-runtime-save').disabled=false;}
    };
    const hash=new URLSearchParams(location.hash.slice(1));
    if(hash.get('view')==='targets') {
      for(const [key,value] of hash)if(specs.some(s=>s[0]===key)) {
        filters[key]=value;const field=$('targets-filter-form').elements[key];
        field.value=['from','to'].includes(key)?new Date(new Date(value).getTime()+3*3600000).toISOString().slice(0,16):value;
      }
      visible=true;$('workspace-view').hidden=true;$('targets-view').hidden=false;$('targets-nav').classList.add('active');
      document.querySelectorAll('[data-view]').forEach(x=>x.classList.remove('active'));$('breadcrumb-current').textContent='مستودع الأهداف';
    }
  }
  return {init,refresh,workspace,configureJob,statusLabel:s=>statuses[s]||s};
})();
