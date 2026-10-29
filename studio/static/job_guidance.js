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
    let deadline = validatedDeadlineMs(stats), reason = "rate_limit";
    if (!(deadline > now)) {
      const wait = stats.request_wait;
      if (job.status !== "running" || !wait || !["request_delay", "rate_limit"].includes(wait.reason)) return null;
      deadline = validatedDeadlineMs({ wait_until: wait.until }); reason = wait.reason;
    }
    if (!(deadline > now)) return null;
    const seconds = Math.ceil((deadline - now) / 1000);
    const clock = `${Math.floor(seconds / 3600) ? `${Math.floor(seconds / 3600)}:` : ""}${String(Math.floor(seconds / 60) % 60).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
    const label = reason === "request_delay" ? "فاصل الطلبات — الطلب التالي بعد" : "مهلة تقييد الطلبات — المتبقي";
    return { seconds, reason, text: `${label} \u2066${clock}\u2069` };
  }
  if (typeof module === "object" && module.exports) module.exports = { viewModel, validatedDeadlineMs, countdown };
  else root.ShodanJobGuidance = { viewModel, validatedDeadlineMs, countdown };
})(typeof globalThis !== "undefined" ? globalThis : this);
