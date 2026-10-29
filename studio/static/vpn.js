/* VPN operations use the existing authenticated, CSRF-protected API and polling. */
'use strict';
window.ShodanVPN = (() => {
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '—').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const phases = {completed:'اكتملت المهمة',paused:'متوقفة مؤقتًا',waiting_input:'بانتظار المراجعة',preparing_job:'تجهيز المهمة',checking_network:'فحص الشبكة',connecting_vpn:'الاتصال بـ VPN',verifying_tunnel:'التحقق من النفق',connection_lost:'فُقد الاتصال',retry_scheduled:'إعادة المحاولة مجدولة',switching_vpn:'تبديل ملف VPN',resuming_extraction:'استكمال الاستخراج'};
  const health = {healthy:'سليم',unhealthy:'غير سليم',unknown:'غير مختبر',host_route:'مسار الخادم'};
  const statuses = {connected:'متصل ومتحقق',disconnected:'غير متصل',unverified:'لم يُتحقق',unknown:'غير معروف'};
  let ctx, snapshot = {profiles:[],status:{}}, editing = null, job = null, loading = false, view = null;
  let reports = {}, pending = false;
  const country = code => { try { return code ? new Intl.DisplayNames(['ar'], {type:'region'}).of(code) : 'غير محددة'; } catch { return code || 'غير محددة'; } };
  const time = value => value ? new Date(typeof value === 'number' ? value * 1000 : value).toLocaleString('ar') : '—';
  const profile = id => snapshot.profiles.find(p => p.id === id);
  const post = (url, body) => ctx.api(url, {method:'POST', body:JSON.stringify(body)});
  async function perform(button, fn) {
    if (pending) return;
    pending = true;
    if (button) button.disabled = true;
    render();
    try { await fn(); await refresh(); }
    catch (error) { ctx.toast(error.message, 'error'); }
    finally { pending = false; if (button) button.disabled = false; render(); }
  }
  function fields(prefix) {
    return `<label class="field"><span>سياسة الاتصال</span><select id="${prefix}-mode"><option value="direct">Direct — مسار الخادم الحالي</option><option value="preferred">Preferred VPN — ملف محدد</option><option value="failover">VPN Failover — تبديل محدود</option><option value="manual">Manual — اتصال يدوي</option></select></label>
      <div id="${prefix}-vpn" hidden><label class="field"><span>ملف الاتصال المفضل</span><select id="${prefix}-profile"></select></label><label class="field"><span>الملفات المسموحة للتبديل (Ctrl أو ⌘ لاختيار عدة ملفات)</span><select id="${prefix}-allowed" multiple size="3"></select></label><label class="field"><span>أقصى محاولات التبديل طوال المهمة</span><input id="${prefix}-max" type="number" min="0" max="100" value="20"></label><label class="check-label"><input id="${prefix}-enabled" type="checkbox">تبديل تلقائي عند 429 أو فشل الاتصال بـ Shodan</label></div>
      <p class="muted small-text">Direct يتبع شبكة الخادم الحالية، وقد تكون متصلة بـ Amnezia. Failover يبدّل بعد حفظ التقدم، ويحتفظ بمهلة انتظار المصدر.</p>`;
  }
  function fillOptions(prefix, values) {
    const options = snapshot.profiles.filter(p => p.enabled);
    const single = $(`${prefix}-profile`), multi = $(`${prefix}-allowed`);
    const selected = values?.preferred_vpn_profile ?? single.value ?? '';
    const allowed = values?.allowed_vpn_profiles ?? [...multi.selectedOptions].map(x => x.value);
    single.innerHTML = '<option value="">اختر ملفًا</option>' + options.map(p => `<option value="${p.id}">${esc(p.name)} · ${esc(country(p.country))}</option>`).join('');
    multi.innerHTML = options.map(p => `<option value="${p.id}">${esc(p.name)} · ${esc(country(p.country))}</option>`).join('');
    single.value = selected || snapshot.preferred_profile || '';
    for (const option of multi.options) option.selected = allowed.includes(option.value);
    if (values) {
      $(`${prefix}-mode`).value = values.network_mode || 'direct';
      $(`${prefix}-enabled`).checked = !!values.vpn_failover_enabled;
      $(`${prefix}-max`).value = values.max_failovers ?? 20;
    }
    togglePolicy(prefix);
  }
  function togglePolicy(prefix) {
    const mode = $(`${prefix}-mode`).value;
    $(`${prefix}-vpn`).hidden = mode === 'direct';
    $(`${prefix}-enabled`).disabled = mode !== 'failover';
    $(`${prefix}-allowed`).disabled = mode !== 'failover';
    $(`${prefix}-max`).disabled = mode !== 'failover';
  }
  function getPolicy(prefix) {
    const mode = $(`${prefix}-mode`).value;
    return {network_mode:mode, preferred_vpn_profile:mode === 'direct' ? null : $(`${prefix}-profile`).value || null,
      allowed_vpn_profiles:mode === 'failover' ? [...$(`${prefix}-allowed`).selectedOptions].map(x => x.value) : [],
      vpn_failover_enabled:mode === 'failover' && $(`${prefix}-enabled`).checked,
      max_failovers:Number($(`${prefix}-max`).value)};
  }
  function navigate(next) {
    view = next;
    $('workspace-view').hidden = !!next;
    $('vpn-view').hidden = next !== 'vpn';
    $('diagnostics-view').hidden = next !== 'diagnostics';
    document.querySelectorAll('[data-network-view]').forEach(el => el.classList.toggle('active', el.dataset.networkView === next));
    if (next) {
      document.querySelectorAll('[data-view]').forEach(el => el.classList.remove('active'));
      $('breadcrumb-current').textContent = next === 'vpn' ? 'إدارة اتصالات VPN' : 'تشخيص الشبكة';
      $(next === 'vpn' ? 'vpn-heading' : 'diagnostics-heading').focus();
      ctx.closeSidebar();
    }
  }
  function render() {
    const status = snapshot.status || {}, active = profile(status.active_profile), check = status.last_check || {};
    const premium = status.premium || {}, account = premium.account || {};
    $('premium-status').textContent = premium.configured ? (premium.last_error ? `تعذرت آخر عملية Premium: ${premium.last_error}` : 'الاشتراك مرتبط؛ حالة النفق تظهر بعد التحقق من الاتصال.') : 'لم يُربط اشتراك Premium بعد.';
    $('premium-summary').innerHTML = [
      ['المواقع المتاحة في القائمة',premium.location_count ?? 0],
      ['مصدر القائمة',premium.catalog_source === 'gateway' ? 'بوابة الاشتراك' : premium.catalog_source === 'installed_client' ? 'قائمة مخزنة من العميل المثبت' : 'غير متاح'],
      ['آخر تحديث للبيانات',time(premium.last_refresh)],['جهاز العامل',premium.device_tag || 'لم يُنشأ'],
      ['الجهاز مسجل لدى Premium',premium.registered ? 'نعم' : 'لم يُثبت بعد'],
      ['خانات الحساب المستخدمة / المتاحة',`${account.active_device_count ?? '—'} / ${account.max_device_count ?? '—'}`],
      ['الملفات المصدّرة في الحساب',account.issued_config_count ?? '—']
    ].map(([k,v]) => `<div><dt>${esc(k)}</dt><dd dir="auto">${esc(v)}</dd></div>`).join('');
    $('premium-enroll').disabled = !!premium.configured || !!status.running_job || !!status.busy || pending;
    $('premium-refresh').disabled = !premium.configured || !!status.running_job || !!status.busy || pending;
    $('vpn-error').textContent = snapshot.error || '';
    $('vpn-error').hidden = !snapshot.error;
    $('vpn-current').innerHTML = [
      ['الاتصال الحالي', active?.name || 'لا يوجد نفق مُدار'], ['الدولة المعرّفة',country(active?.country)],
      ['عنوان الخروج (آخر تحقق)',check.egress_ip], ['البروتوكول',active?.protocol],
      ['حالة النفق',status.verified ? 'تم التحقق' : 'غير متحقق'], ['زمن الاختبار',check.latency_ms != null ? `${check.latency_ms} ms` : '—'],
      ['آخر تغيير',time(status.last_change)],['آخر اختبار',time(check.checked_at)],
      ['حماية التسرب',status.leak_protection ? 'فعالة داخل العزل' : 'غير مثبتة'],
      ['المهمة الحالية',status.running_job], ['تغييرات المهمة',ctx.currentJob(status.running_job)?.failover_count ?? '—']
    ].map(([k,v]) => `<div><dt>${esc(k)}</dt><dd dir="auto">${esc(v)}</dd></div>`).join('');
    const focused = document.activeElement?.closest('#vpn-profiles button');
    const focusData = focused ? {...focused.dataset} : null;
    const filter = $('vpn-filter').value.trim().toLocaleLowerCase();
    const shown = snapshot.profiles.filter(p => `${p.name} ${p.country} ${country(p.country)} ${p.location || ''}`.toLocaleLowerCase().includes(filter));
    $('vpn-profiles').innerHTML = shown.length ? shown.map(p => `<tr><td>${esc(p.name)}${snapshot.preferred_profile === p.id ? ' · مفضّل' : ''}<small>${p.provider === 'amnezia-premium' ? 'اشتراك Premium · '+esc(p.location) : 'ملف مستورد'}</small><small class="mono">${p.id.slice(0,8)}</small></td><td>${esc(country(p.country))}</td><td>${esc(p.protocol)}</td><td>${esc(statuses[p.status] || p.status)}<small>${p.available === false ? 'غير مدعوم أو غير متاح' : p.enabled ? 'مفعّل':'معطّل'}</small></td><td>${esc(health[p.health] || p.health)}<small>${esc(time(p.last_check))}</small></td><td dir="ltr">${esc(p.egress_ip)}</td><td>${p.failure_count || 0}<small>${p.cooldown_until > Date.now()/1000 ? `انتظار حتى ${esc(time(p.cooldown_until))}`:'—'}</small></td><td><div class="vpn-actions"><button class="button small secondary" data-vpn-connect="${p.id}" ${!p.enabled || status.running_job || status.busy || pending ? 'disabled':''}>اتصال</button><button class="button small secondary" data-vpn-edit="${p.id}">تعديل</button><button class="button small secondary" data-vpn-prefer="${p.id}" ${!p.enabled?'disabled':''}>تفضيل</button></div></td></tr>`).join('') : '<tr><td colspan="8">لا توجد اتصالات مطابقة. اربط اشتراك Premium أو أضف ملف اتصال.</td></tr>';
    if (focusData) {
      const [key,value] = Object.entries(focusData)[0] || [];
      [...$('vpn-profiles').querySelectorAll('button')].find(b => b.dataset[key] === value)?.focus({preventScroll:true});
    }
    $('vpn-audit').innerHTML = (snapshot.events || []).map(item => `<tr><td>${esc(time(item.at))}</td><td>${esc(item.job_id?.slice(0,8))}</td><td>${esc(profile(item.previous_profile)?.name || item.previous_profile)}</td><td>${esc(profile(item.new_profile)?.name || item.new_profile)}</td><td>${esc(item.reason || item.action)}</td><td>${item.verified ? 'تم التحقق' : 'لم يُثبت'} · ${esc(item.status)}</td><td>${item.duration_ms} ms</td></tr>`).join('') || '<tr><td colspan="7">لا توجد أحداث اتصال بعد.</td></tr>';
    $('vpn-disconnect').disabled = !status.active_profile || !!status.running_job || !!status.busy || pending;
    $('vpn-restore').disabled = !status.previous_profile || !!status.running_job || !!status.busy || pending;
    for (const prefix of ['create-net','job-net']) {
      if (!$(prefix + '-mode').closest('dialog')?.open) fillOptions(prefix);
    }
    if (job) renderJob(job);
  }
  async function refresh() {
    if (loading) return;
    loading = true;
    try { snapshot = await ctx.api('/api/vpn'); render(); }
    catch (error) { $('vpn-error').textContent = error.message; $('vpn-error').hidden = false; }
    finally { loading = false; }
  }
  function renderJob(value) {
    job = value;
    ShodanBrowser.render(value);
    const p = profile(job.active_vpn_profile || job.preferred_vpn_profile);
    $('job-network-state').textContent = `${job.network_mode || 'direct'} · ${p?.name || (job.network_mode && job.network_mode !== 'direct' ? 'ملف VPN غير متاح' : 'مسار الخادم')} · ${country(p?.country)} · ${job.current_egress_ip || 'عنوان الخروج غير متحقق'} · ${health[job.network_health] || 'غير مختبر'}`;
    $('job-network-phase').textContent = phases[job.network_phase] || '';
    $('job-network-count').textContent = `محاولات التبديل: ${job.failover_count || 0} / ${job.max_failovers ?? 20}`;
    const sourceDenied = /\[HTTP_(401|403)\]/.test(job.error || '') && job.mode === 'html';
    $('job-network-error').textContent = sourceDenied
      ? 'رفض Shodan طلب HTML' + ((job.error || '').includes('[BROWSER_CHALLENGE]') ? ' بسبب تحقق متصفح تفاعلي' : ' (HTTP 401/403)') + '. نجاح النفق لا يثبت السماح بالبحث. بقيت النتائج ونقطة الاستكمال محفوظة. افحص وصول الموقع من صفحة التشخيص؛ إعادة الاستكمال ستعيد الطلب وقد تُرفض مجددًا.'
      : job.last_network_error || '';
    $('job-network-error').hidden = !sourceDenied && !job.last_network_error;
    const busy = job.network_busy || ['running','queued','pause_requested','cancel_requested'].includes(job.status);
    $('job-network-edit').disabled = busy;
    $('job-network-restore').disabled = busy || !job.previous_vpn_profile;
    $('job-network-resume').disabled = !!job.network_busy || !['paused','waiting_input','interrupted','failed'].includes(job.status);
    $('job-network-stop').disabled = ['completed','completed_warnings','cancelled'].includes(job.status);
  }
  function editProfile(ident = null) {
    editing = ident;
    const p = profile(ident);
    $('vpn-profile-form').reset();
    $('vpn-profile-name').value = p?.name || '';
    $('vpn-profile-country').value = p?.country || '';
    $('vpn-profile-country').readOnly = p?.provider === 'amnezia-premium';
    $('vpn-profile-enabled').checked = p?.enabled ?? true;
    $('vpn-file-field').hidden = !!ident;
    $('vpn-source-field').hidden = !!ident;
    $('vpn-profile-error').textContent = '';
    $('vpn-profile-dialog').showModal();
  }
  async function diagnose(scope, button) {
    await perform(button, async () => {
      const report = await post('/api/vpn/diagnostics', {scope});
      reports[scope] = report;
      const labels = {dns:'DNS',tcp:'TCP',tls:'TLS',http:'HTTP (خدمة عنوان الخروج)',interface_up:'الواجهة',route_verified:'المسار',handshake:'VPN Handshake',leak_protection:'حماية التسرب'};
      const access = {not_tested:'لم يُختبر',browser_challenge:'يتطلب تحققًا تفاعليًا من المتصفح؛ جمع HTML متوقف',access_denied:'رفض الموقع الوصول',rate_limited:'حدّ الطلبات',website_reachable:'الصفحة الرئيسية متاحة؛ صلاحية الاستعلام لم تُختبر',other_http_status:'استجابة أخرى من الموقع',check_failed:'تعذر إكمال فحص الموقع'};
      const target = $('diagnostic-' + scope);
      target.innerHTML = `<h3>${scope === 'host' ? 'الخادم — المسار الحالي':'العامل — Namespace معزول'}</h3><p>${report.healthy ? 'نجحت الفحوص المطلوبة':'فحص غير ناجح أو غير متاح'} · ${esc(time(report.checked_at))}</p><dl class="vpn-kv">${Object.entries(labels).map(([key,label]) => `<div><dt>${label}</dt><dd>${report[key] === true ? 'ناجح':report[key] === false ? 'فشل':'غير منطبق'}</dd></div>`).join('')}<div><dt>عنوان الخروج</dt><dd dir="ltr">${esc(report.egress_ip)}</dd></div><div><dt>الخطأ</dt><dd>${esc(report.error)}</dd></div></dl>`;
      $('diagnostic-export').disabled = false;
      const source = document.createElement('p');
      source.textContent = `وصول Shodan: ${access[report.source_access] || 'لم يُختبر'}${report.source_http_status ? ' · HTTP ' + report.source_http_status : ''}. فحص الشبكة مستقل عن صلاحية البحث.`;
      target.append(source);
      navigate('diagnostics');
    });
  }
  function init(context) {
    ctx = context;
    ShodanBrowser.init(context);
    $('create-network').innerHTML = fields('create-net');
    $('job-network-fields').innerHTML = fields('job-net');
    ['create-net','job-net'].forEach(prefix => $(prefix+'-mode').addEventListener('change', () => togglePolicy(prefix)));
    document.querySelectorAll('[data-network-view]').forEach(el => el.addEventListener('click', () => navigate(el.dataset.networkView)));
    $('vpn-add').addEventListener('click', () => editProfile());
    $('vpn-filter').addEventListener('input', render);
    $('premium-enroll').addEventListener('click', () => {
      $('premium-form').reset(); $('premium-form-error').textContent = ''; $('premium-dialog').showModal();
    });
    $('premium-dialog').addEventListener('close', () => $('premium-form').reset());
    $('premium-refresh').addEventListener('click', event => perform(event.target, async () => {
      await post('/api/vpn/premium', {action:'refresh'}); ctx.toast('تم تحديث بيانات الاشتراك؛ لم يُغيّر اتصال العامل.');
    }));
    $('premium-form').addEventListener('submit', async event => {
      event.preventDefault(); $('premium-submit').disabled = true;
      const key = $('premium-key').value.trim(); $('premium-key').value = '';
      try {
        await post('/api/vpn/premium', {action:'enroll',key});
        $('premium-dialog').close(); ctx.toast('رُبط الاشتراك. اختر موقعًا للتحقق من الاتصال.');
      } catch (error) { $('premium-form-error').textContent = error.message; }
      finally { $('premium-submit').disabled = false; await refresh(); }
    });
    $('vpn-discover').addEventListener('click', event => perform(event.target, async () => {
      const result = await ctx.api('/api/vpn/discover');
      $('vpn-profile-source').innerHTML = '<option value="">رفع ملف من جهازك</option>' + result.candidates.map(p => `<option value="${esc(p.source)}">${esc(p.name)}</option>`).join('');
      editProfile();
      if (!result.candidates.length) $('vpn-profile-error').textContent = 'لم يعثر الخادم على ملفات مرشحة. يمكنك رفع ملف Premium مُصدّر.';
    }));
    $('vpn-profiles').addEventListener('click', event => {
      const b = event.target.closest('button'); if (!b) return;
      if (b.dataset.vpnEdit) return editProfile(b.dataset.vpnEdit);
      perform(b, async () => {
        const prefer = b.dataset.vpnPrefer;
        await post('/api/vpn/actions', {action:prefer ? 'prefer':'connect',profile_id:prefer || b.dataset.vpnConnect});
        ctx.toast(prefer ? 'حُفظ الملف المفضل.' : 'نجح التحقق من النفق وعنوان الخروج.');
      });
    });
    ['disconnect','restore'].forEach(action => $('vpn-'+action).addEventListener('click', event => perform(event.target, async () => {
      await post('/api/vpn/actions', {action}); ctx.toast(action === 'restore' ? 'نجح التحقق من الاتصال السابق.' : 'فُصل النفق المُدار.');
    })));
    $('vpn-profile-form').addEventListener('submit', async event => {
      event.preventDefault();
      const button = $('vpn-profile-submit'); button.disabled = true;
      try {
        const metadata = {name:$('vpn-profile-name').value,country:$('vpn-profile-country').value.toUpperCase(),enabled:$('vpn-profile-enabled').checked};
        if (editing) await post('/api/vpn/profiles/'+editing, metadata);
        else {
          const source = $('vpn-profile-source').value, file = $('vpn-profile-file').files[0];
          if (!source && (!file || file.size > 16384)) throw new Error('اختر ملف .conf لا يتجاوز 16 KiB.');
          await post('/api/vpn/profiles', source ? {source, metadata} : {config:await file.text(), metadata});
        }
        $('vpn-profile-form').reset(); $('vpn-profile-dialog').close();
        ctx.toast('حُفظ الملف. لم يتم الاتصال به بعد.'); await refresh();
      } catch (error) { $('vpn-profile-error').textContent = error.message; }
      finally { button.disabled = false; }
    });
    $('job-network-edit').addEventListener('click', () => {fillOptions('job-net',job); $('job-network-dialog').showModal();});
    $('job-network-form').addEventListener('submit', event => {event.preventDefault(); perform($('job-network-submit'), async () => {
      await post(`/api/jobs/${job.id}/network`, getPolicy('job-net')); $('job-network-dialog').close(); await ctx.refreshAll();
    });});
    $('job-network-resume').addEventListener('click', () => ctx.openResume(job.id));
    $('job-network-stop').addEventListener('click', event => perform(event.target, () => ctx.runAction(job.id,'cancel')));
    $('job-network-restore').addEventListener('click', event => perform(event.target, async () => {
      const cfg = {network_mode:job.network_mode,preferred_vpn_profile:job.previous_vpn_profile,allowed_vpn_profiles:job.allowed_vpn_profiles,vpn_failover_enabled:job.vpn_failover_enabled,max_failovers:job.max_failovers};
      await post(`/api/jobs/${job.id}/network`,cfg); await ctx.refreshAll(); ctx.toast('حُفظ اختيار الاتصال السابق؛ استكمل المهمة للتحقق منه.');
    }));
    $('job-network-check').addEventListener('click', event => diagnose(job.network_mode === 'direct' ? 'host':'worker',event.target));
    document.querySelectorAll('[data-diagnose]').forEach(el => el.addEventListener('click', () => diagnose(el.dataset.diagnose,el)));
    $('diagnostic-export').addEventListener('click', () => {
      const url = URL.createObjectURL(new Blob([JSON.stringify({generated_at:new Date().toISOString(),reports},null,2)],{type:'application/json'}));
      const link = document.createElement('a'); link.href=url; link.download='shodan-network-diagnostics.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url),1000);
    });
  }
  return {init, refresh, renderJob, workspace:() => navigate(null), createPolicy:() => getPolicy('create-net'), prepareCreate:() => fillOptions('create-net',{network_mode:'direct'})};
})();
