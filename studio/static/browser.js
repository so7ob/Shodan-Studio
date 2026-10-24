/* Manual input only. Images and text remain in the authenticated session. */
window.ShodanBrowser = (() => {
  const $ = id => document.getElementById(id);
  let ctx, job, activeJob, timer, busy=false, inputBusy=false, opening=false, queue=Promise.resolve(), generation=0, lastResult={};
  const states={closed:'الجلسة مغلقة',awaiting_verification:'أكمل التحقق أو تسجيل الدخول، ثم افحص الصفحة.',browser_challenge:'يطلب Shodan تحققًا يدويًا. إذا استمر في تكراره، أنهِ الجلسة واحتفظ بالمهمة للمحاولة لاحقًا.',rate_limited:'قيّد Shodan عدد الطلبات (429). انتظر موعد الاستكمال المحفوظ؛ لا حاجة إلى تكرار الضغط على التحقق.',access_denied:'رفض Shodan الوصول. راجع الصفحة.',ready:'تم التحقق من صفحة نتائج صالحة؛ يمكنك الاستكمال.'};
  async function send(input) {return ctx.api(`/api/jobs/${activeJob}/browser`,{method:'POST',body:JSON.stringify(input)});}
  states.off_task_page='الصفحة الحالية ليست نتائج المهمة. بعد إتمام تسجيل الدخول اضغط «العودة إلى نتائج المهمة»، ثم «فحص الصفحة».';
  function controls() {
    $('browser-resume').disabled=inputBusy||opening||lastResult.state!=='ready';
    $('browser-return').disabled=inputBusy||opening||!lastResult.can_return_to_results;
    $('browser-verify').disabled=inputBusy||opening;
  }
  function show(result) {
    lastResult=result;
    $('browser-status').textContent=(states[result.state]||'جارٍ التحقق')+(result.http_status ? ` · HTTP ${result.http_status}`:'');
    controls();
    if(result.image)$('browser-frame').src=result.image;
  }
  function action(input) {
    if(opening || (input.action==='frame' && busy))return Promise.resolve();
    const version=generation;
    const work=queue.then(async()=>{
      if(version!==generation)return;
      busy=true;inputBusy=input.action!=='frame';controls();$('browser-error').textContent='';
      try {const result=await send(input);if(version===generation)show(result);return result;}
      catch(error){if(version===generation){$('browser-error').textContent=error.message;lastResult={};}}
      finally{busy=false;inputBusy=false;controls();}
    });
    queue=work.catch(()=>{});return work;
  }
  function schedule() {
    clearTimeout(timer);
    if(!$('browser-dialog').open)return;
    timer=setTimeout(async()=>{if(!busy&&!opening)await action({action:'frame'});schedule();},1800);
  }
  async function open() {
    if(!job||opening)return;
    activeJob=job.id;generation++;opening=true;lastResult={};controls();$('job-browser-open').disabled=true;
    $('browser-error').textContent='';$('browser-status').textContent='جارٍ فتح المتصفح عبر اتصال المهمة…';
    $('browser-frame').removeAttribute('src');$('browser-resume').disabled=true;$('browser-dialog').showModal();
    try{show(await send({action:'start'}));await ctx.refreshAll();}
    catch(error){$('browser-error').textContent=error.message;}
    finally{opening=false;controls();render(job);schedule();}
  }
  function render(value){job=value;$('job-browser-open').disabled=!job||job.mode!=='html'||job.network_mode==='direct'||!job.network_mode||!['paused','waiting_input','interrupted','failed'].includes(job.status)||opening;}
  function init(context){
    ctx=context;$('job-browser-open').addEventListener('click',open);
    $('browser-dialog').addEventListener('close',()=>{generation++;clearTimeout(timer);$('browser-text').value='';$('browser-frame').removeAttribute('src');});
    $('browser-frame').addEventListener('click',event=>{
      const rect=event.target.getBoundingClientRect();
      action({action:'click',x:Math.min(1099,Math.max(0,Math.floor((event.clientX-rect.left)*1100/rect.width))),y:Math.min(759,Math.max(0,Math.floor((event.clientY-rect.top)*760/rect.height)))});
    });
    $('browser-frame').addEventListener('keydown',event=>{
      if(event.ctrlKey||event.altKey||event.metaKey||event.key==='Tab')return;
      if(['Enter','Backspace','Delete','Escape','ArrowLeft','ArrowRight','ArrowUp','ArrowDown','Home','End',' '].includes(event.key)){event.preventDefault();action({action:'key',key:event.key});}
      else if(event.key.length===1){event.preventDefault();action({action:'text',text:event.key});}
    });
    $('browser-text-form').addEventListener('submit',event=>{event.preventDefault();if(opening)return;const text=$('browser-text').value;$('browser-text').value='';if(text)action({action:'text',text});});
    document.querySelectorAll('[data-browser-key]').forEach(b=>b.addEventListener('click',()=>action({action:'key',key:b.dataset.browserKey})));
    document.querySelectorAll('[data-browser-scroll]').forEach(b=>b.addEventListener('click',()=>action({action:'scroll',delta:Number(b.dataset.browserScroll)})));
    $('browser-verify').addEventListener('click',()=>action({action:'verify'}));
    $('browser-return').addEventListener('click',()=>action({action:'verify',return_to_results:true}));
    $('browser-end').addEventListener('click',async()=>{if(await action({action:'stop'})){$('browser-dialog').close();await ctx.refreshAll();}});
    $('browser-resume').addEventListener('click',async()=>{
      if(busy)return;busy=true;inputBusy=true;controls();
      try{await ctx.runAction(activeJob,'resume',{mode:'html'});$('browser-dialog').close();}
      catch(error){$('browser-error').textContent=error.message;}
      finally{busy=false;inputBusy=false;controls();}
    });
  }
  return {init,render};
})();
