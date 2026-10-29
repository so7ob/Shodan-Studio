/* Presentation only: no requests, timers, credentials or retry decisions. */
(function (root) {
  "use strict";
  function validatedDeadlineMs(stats = {}) {
    if (stats.wait_unbounded === true) return null;
    const seconds = stats.wait_until;
    if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds <= 0) return null;
    const deadline = seconds * 1000;
    return Number.isFinite(new Date(deadline).getTime()) ? deadline : null;
  }
  function createServerClock(monotonic = () => performance.now(), wall = () => Date.now()) {
    let anchor = null, lastRequest = -Infinity;
    return {
      observe(value, requestStarted, received = monotonic()) {
        if (typeof value !== "string" || !/^\d+(?:\.\d+)?$/.test(value)) return false;
        const server = Number(value) * 1000;
        if (!Number.isFinite(server) || !Number.isFinite(new Date(server).getTime()) || server <= 0 ||
            !Number.isFinite(requestStarted) || !Number.isFinite(received) || received < requestStarted ||
            requestStarted < lastRequest) return false;
        // Slow responses can carry a stale timestamp. Keep the existing anchor.
        if (anchor && received - requestStarted > 2000) return false;
        // Network jitter must not make the countdown run backwards on a poll.
        const projected = anchor ? anchor.server + Math.max(0, received - anchor.received) : server;
        anchor = { server:Math.max(server, projected), received }; lastRequest = requestStarted;
        return true;
      },
      now() { return anchor ? anchor.server + Math.max(0, monotonic() - anchor.received) : wall(); },
    };
  }
  function viewModel(job = {}, now = Date.now(), formatDate = value => new Date(value).toLocaleString("ar")) {
    const stats = job.stats || {};
    const raw = typeof job.error === "string" ? job.error : job.error?.message || job.error?.detail || "";
    const checkpoint = job.has_checkpoint === true
      ? "نقطة حفظ متاحة؛ يمكن متابعة التقدم المحفوظ عندما يسمح المصدر."
      : "لا توجد نقطة حفظ متاحة بعد؛ لا يمكن تأكيد استعادة الطلب الأخير.";
    const deadlineMs = validatedDeadlineMs(stats);
    let kind = "paused", title = "التنفيذ متوقف", message = "راجع حالة المهمة ثم اختر الاستكمال يدويًا عند الاستعداد.";
    if (stats.wait_unbounded === true) {
      kind = "manual_hold"; title = "حظر انتظار بلا موعد قابل للعرض";
      message = "مدة الانتظار التي طلبها المصدر تتجاوز المجال المدعوم. يلزم مراجعة الحالة يدويًا؛ تكرار الاستكمال لا يرفع الحظر ولا توجد محاولة تلقائية من هذه اللوحة.";
    } else if (deadlineMs !== null) {
      const when = formatDate(deadlineMs);
      if (deadlineMs > now) {
        kind = "waiting"; title = "بانتظار مهلة المصدر";
        message = `موعد المحاولة المحفوظ: ${when} (بالتوقيت المحلي). الاستكمال المبكر لا يختصر مهلة المصدر؛ إعادة التحميل أو الضغط المتكرر لا تقصّر الانتظار.`;
      } else {
        kind = "elapsed"; title = "انتهت مهلة الانتظار المحفوظة";
        message = `الموعد المحفوظ: ${when} (بالتوقيت المحلي). لم تُرسل اللوحة طلب استكمال تلقائيًا. راجع الحالة قبل الاستكمال؛ انتهاء المهلة لا يضمن قبول المصدر.`;
      }
    } else if (/BROWSER_CHALLENGE/.test(raw)) {
      kind = "access_denied"; title = "المصدر لم يسمح بالوصول";
      message = "ظهر اختبار أمان. أكمله داخل الجلسة المتاحة؛ تكرار الاستكمال لا يضمن قبول المصدر.";
    } else if (/BROWSER_LOGIN|\[(?:API_)?HTTP_401\]/.test(raw)) {
      kind = "access_denied"; title = "يلزم تسجيل الدخول";
      message = "راجع بيانات الدخول أو صلاحية مفتاح API بحسب مصدر المهمة. تكرار الاستكمال لا يضمن قبول المصدر.";
    } else if (/\[(?:API_)?HTTP_403\]/.test(raw)) {
      kind = "access_denied"; title = "المصدر لم يسمح بالوصول";
      message = "راجع صلاحيات الحساب للوصول إلى هذا المصدر. تكرار الاستكمال لا يضمن قبول المصدر.";
    } else if (/\[HTML_PARSE\]/.test(raw)) {
      kind = "response_error"; title = "تعذر قراءة صفحة المرشح";
      message = "تعذر التعرف على تنسيق استجابة المصدر. راجع تفاصيل الخطأ أو أعد محاولة الطلب مع حفظ نقطة الاستكمال.";
    } else if (job.input_reason === "rate_limit") {
      kind = "rate_limit"; title = "تقييد طلبات المصدر";
      message = "لا يوجد موعد انتظار صالح للعرض. راجع تفاصيل الخطأ قبل الاستكمال؛ لا تفترض أن الانتظار انتهى.";
    } else if (job.input_reason === "request_budget") {
      title = "انتهى حد طلبات هذه الجولة";
      message = "راجع التقدم المحفوظ قبل بدء جولة استكمال جديدة. لن تبدأ الجولة من هذه اللوحة دون طلبك.";
    } else if (job.status === "interrupted") {
      title = "توقفت المهمة مع الخادم";
      message = "لم تُستكمل المهمة تلقائيًا. راجع نقطة الحفظ والمصدر قبل طلب الاستكمال.";
    } else if (job.status === "failed") {
      title = "تعذّر إكمال التنفيذ";
      message = "راجع تفاصيل الخطأ وحالة نقطة الحفظ قبل إعادة طلب الاستكمال.";
    } else if (job.input_reason === "api_key") {
      title = "يلزم مفتاح API للاستكمال";
      message = "أدخل المفتاح في نافذة الاستكمال؛ لا يُحفظ المفتاح في بيانات المهمة.";
    }
    return { kind, title, message, checkpoint, deadlineMs, technicalError: String(raw) };
  }
  function countdown(job = {}, now = Date.now()) {
    const stats = job.stats || {};
    if (stats.wait_unbounded || ["completed", "completed_warnings", "cancelled", "failed"].includes(job.status)) return null;
    const configured = job.settings?.delay;
    const hasDelay = typeof configured === "number" && Number.isFinite(configured) && configured > 0;
    const settingLabel = hasDelay ? `فاصل الطلبات (${configured} ثانية)` : "فاصل الطلبات";
    let deadline = validatedDeadlineMs(stats), reason = "rate_limit";
    if (!(deadline > now)) {
      const wait = stats.request_wait;
      if (job.status !== "running") return null;
      if (!wait || !["request_delay", "rate_limit"].includes(wait.reason)) {
        return hasDelay ? { seconds:null, reason:"configured_delay", text:settingLabel } : null;
      }
      deadline = validatedDeadlineMs({ wait_until: wait.until }); reason = wait.reason;
      if (deadline === null) return hasDelay ? { seconds:null, reason:"configured_delay", text:settingLabel } : null;
    }
    let seconds = Math.max(0, Math.ceil((deadline - now) / 1000));
    // A normal delay can never exceed the job setting. Retry-After is separate.
    if (reason === "request_delay" && hasDelay) seconds = Math.min(seconds, Math.ceil(configured));
    const clock = `${Math.floor(seconds / 3600) ? `${Math.floor(seconds / 3600)}:` : ""}${String(Math.floor(seconds / 60) % 60).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
    const label = reason === "request_delay" ? `${settingLabel} — ${seconds ? 'الطلب التالي بعد' : 'حان موعد الطلب التالي'}` : "مهلة تقييد الطلبات — المتبقي";
    return { seconds, reason, text: `${label} \u2066${clock}\u2069` };
  }
  if (typeof module === "object" && module.exports) module.exports = { viewModel, validatedDeadlineMs, countdown, createServerClock };
  else root.ShodanJobGuidance = { viewModel, validatedDeadlineMs, countdown, createServerClock };
})(typeof globalThis !== "undefined" ? globalThis : this);
