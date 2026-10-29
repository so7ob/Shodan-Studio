/* Account passwords are write-only; never retain them in browser storage. */
window.ShodanAccounts=(()=>{
  'use strict';
  const $=id=>document.getElementById(id);
  let ctx, accounts=[], job=null, editing=null, loading=null, lastLoad=0;
  const post=(path,payload)=>ctx.api(path,{method:'POST',body:JSON.stringify(payload)});
  function reset(){editing=null;$('shodan-account-form').reset();$('account-form-title').textContent='إضافة حساب';$('account-password').required=true;$('account-password-help').textContent='تُحفظ مشفّرة على الخادم ولا تُعرض بعد الحفظ.';}
  function renderJob(value){
    job=value;const select=$('job-shodan-account');
    const signature=JSON.stringify([accounts.map(a=>[a.id,a.label,a.username]),job?.shodan_account_id]);
    if(select.dataset.signature!==signature){
      select.replaceChildren(new Option('دون حساب محفوظ — تسجيل دخول يدوي',''));
      for(const a of accounts)select.add(new Option(`${a.label} · ${a.username}`,a.id));
      if(job?.shodan_account_id&&!accounts.some(a=>a.id===job.shodan_account_id))select.add(new Option('الحساب المحفوظ غير متاح',job.shodan_account_id));
      select.value=job?.shodan_account_id||'';select.dataset.signature=signature;
    }
    select.disabled=!job||job.mode!=='html'||!['paused','waiting_input','interrupted','failed'].includes(job.status)||job.browser_session_open||job.network_busy;
    $('job-shodan-account-help').textContent=job?.browser_session_open?'أغلق جلسة المتصفح قبل تغيير الحساب.':'اختر الحساب، افتح متصفح المهمة، ثم اضغط تسجيل الدخول بالحساب.';
  }
  function renderList(){
    const list=$('shodan-account-list');list.replaceChildren();
    if(!accounts.length){const p=document.createElement('p');p.className='muted';p.textContent='لا توجد حسابات Shodan محفوظة.';list.append(p);}
    for(const a of accounts){
      const row=document.createElement('div');row.className='shodan-account-row';
      const info=document.createElement('div'),label=document.createElement('strong'),username=document.createElement('span');
      label.textContent=a.label;username.textContent=a.username;username.dir='ltr';info.append(label,username);
      const actions=document.createElement('div');actions.className='button-group';
      const edit=document.createElement('button');edit.type='button';edit.className='button small secondary';edit.textContent='تعديل';edit.setAttribute('aria-label',`تعديل ${a.label}`);
      edit.addEventListener('click',()=>{editing=a.id;const f=$('shodan-account-form').elements;f.label.value=a.label;f.username.value=a.username;f.password.value='';f.password.required=false;$('account-form-title').textContent='تعديل الحساب';$('account-password-help').textContent='اتركها فارغة للاحتفاظ بكلمة المرور الحالية. تغيير بيانات الدخول ينشئ جلسة جديدة.';f.label.focus();});
      const remove=document.createElement('button');remove.type='button';remove.className='button small secondary';remove.textContent='حذف';remove.setAttribute('aria-label',`حذف ${a.label}`);
      remove.addEventListener('click',async()=>{
        if(!confirm('حذف حساب Shodan وبيانات دخوله وجلساته المحفوظة؟ سيُلغى ربطه بالمهام.'))return;
        remove.disabled=true;
        try{await post(`/api/shodan/accounts/${a.id}`,{action:'delete'});reset();await refresh(true);await ctx.refreshAll();}
        catch(e){$('accounts-error').textContent=e.message;}
        finally{remove.disabled=false;}
      });
      actions.append(edit,remove);row.append(info,actions);list.append(row);
    }
    renderJob(job);
  }
  async function refresh(force=false){
    if(loading)return loading;
    if(!force&&Date.now()-lastLoad<15000)return;
    loading=(async()=>{try{const data=await ctx.api('/api/shodan/accounts');accounts=data.accounts;lastLoad=Date.now();renderList();}catch(error){lastLoad=Date.now();$('accounts-error').textContent=error.message;if(force)throw error;}finally{loading=null;}})();return loading;
  }
  async function open(){ctx.closeSidebar();reset();$('accounts-error').textContent='';$('shodan-accounts-dialog').showModal();try{await refresh(true);}catch(e){$('accounts-error').textContent=e.message;}}
  function init(context){
    ctx=context;
    document.querySelectorAll('[data-shodan-accounts]').forEach(b=>b.addEventListener('click',open));
    $('account-reset').addEventListener('click',reset);
    $('shodan-accounts-dialog').addEventListener('close',reset);
    $('job-shodan-account').addEventListener('change',async()=>{
      const selected=job;$('job-shodan-account').disabled=true;$('job-shodan-account-error').textContent='';
      try{await post(`/api/jobs/${selected.id}/shodan-account`,{account_id:$('job-shodan-account').value||null});await ctx.refreshAll();}
      catch(e){$('job-shodan-account-error').textContent=e.message;$('job-shodan-account').value=selected.shodan_account_id||'';}
      finally{renderJob(job);}
    });
    $('shodan-account-form').addEventListener('submit',async e=>{
      e.preventDefault();const f=e.currentTarget.elements;
      const payload={label:f.label.value.trim(),username:f.username.value.trim(),password:f.password.value};f.password.value='';
      if(editing)payload.action='update';$('account-save').disabled=true;$('accounts-error').textContent='';
      try{await post(editing?`/api/shodan/accounts/${editing}`:'/api/shodan/accounts',payload);reset();await refresh(true);await ctx.refreshAll();ctx.toast('حُفظ حساب Shodan.');}
      catch(error){$('accounts-error').textContent=error.message;}
      finally{$('account-save').disabled=false;}
    });
  }
  function label(id){const a=accounts.find(item=>item.id===id);return a?`${a.label} · ${a.username}`:'حساب Shodan المختار';}
  return {init,refresh,renderJob,label};
})();
