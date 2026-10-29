/* Shodan Studio: self-contained browser client. No credentials are persisted here. */
"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const state = {
    session: null, jobs: [], selectedId: null, selectedJob: null,
    view: "all", tab: "overview", lastEvent: 0, events: [],
    results: { items: [], total: 0, offset: 0, limit: 100, q: "" },
    polling: false, connected: true, tableSignature: "", actionSignature: "",
    settingsSignature: "", resultsCount: -1, resumeId: null, cancelId: null,
    eventRequest: false, resultRequest: 0, logWarning: false, logoutBusy: false,
  };
  const number = new Intl.NumberFormat("en-US");
  const STATUS = {
    queued: ["في الطابور", "slate"], running: ["قيد التنفيذ", "cyan"],
    pause_requested: ["جارٍ الإيقاف المؤقت", "amber"], paused: ["متوقفة مؤقتًا", "amber"],
    waiting_input: ["تحتاج إلى متابعتك", "amber"], interrupted: ["توقفت مع الخادم", "amber"],
    cancel_requested: ["جارٍ الإلغاء", "amber"], cancelled: ["ملغاة", "slate"],
    completed: ["مكتملة", "green"], completed_warnings: ["مكتملة مع تحذيرات", "amber"],
    failed: ["تعذّر التنفيذ", "red"],
  };
  const PHASE = {
    queued: "بانتظار عامل التنفيذ", starting: "تهيئة المهمة", planning: "بناء خطة البحث",
    discovering: "استكشاف الدول والمدن", partitioning: "تقسيم الفروع الكبيرة",
    extracting: "استخراج العناوين", completed: "اكتمل التنفيذ", finished: "اكتمل التنفيذ",
    waiting: "انتظار السماح بالمتابعة", rate_limited: "انتظار انتهاء تقييد المعدّل",
    paused: "التقدم محفوظ", waiting_input: "بانتظار متابعتك", failed: "تعذّر إكمال التنفيذ",
    country: "استعراض الدول", city: "استعراض المدن", asn: "التقسيم بحسب ASN",
    port: "التقسيم بحسب المنفذ", version: "التقسيم بحسب الإصدار", product: "التقسيم بحسب المنتج",
  };
  const activeStatuses = new Set(["running", "pause_requested", "cancel_requested"]);
  const attentionStatuses = new Set(["paused", "waiting_input", "interrupted"]);
  const finishedStatuses = new Set(["completed", "completed_warnings"]);
  const resumableStatuses = new Set(["paused", "waiting_input", "interrupted", "failed"]);
  const escapeHTML = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const icon = (name, css = "") => `<svg class="icon ${css}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
  const fmt = (value) => number.format(Number.isFinite(Number(value)) ? Number(value) : 0);
  const text = (id, value) => { $(id).textContent = value; };
  const show = (id, visible) => { $(id).hidden = !visible; };
  const safeNum = (value, fallback = 0) => Number.isFinite(Number(value)) ? Number(value) : fallback;
  const isPlainObject = (value) => !!value && typeof value === "object" && !Array.isArray(value);
  const jobURL = (id, tail = "") => `/api/jobs/${encodeURIComponent(id)}${tail}`;
  const errorMessage = (value) => {
    if (typeof value === "string") return value;
    if (value && typeof value.message === "string") return value.message;
    if (value && typeof value.detail === "string") return value.detail;
    return "تعذّر تنفيذ الطلب. راجع اتصال الخادم وحاول مرة أخرى.";
  };
  const getStats = (job) => isPlainObject(job?.stats) ? job.stats : {};
  const warningCount = (stats) => Array.isArray(stats.warnings) ? stats.warnings.length : safeNum(stats.warnings);
  function dateValue(value) {
    if (!value) return null;
    const date = new Date(typeof value === "number" && value < 1e12 ? value * 1000 : value);
    return Number.isNaN(date.getTime()) ? null : date;
  }
  function dateText(value, short = false) {
    const date = dateValue(value);
    if (!date) return "—";
    return date.toLocaleString("ar", short
      ? { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }
      : { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }
  function badge(status) {
    const item = STATUS[status] || [status || "غير معروفة", "slate"];
    return `<span class="badge ${item[1]}"><span class="status-dot"></span>${escapeHTML(item[0])}</span>`;
  }
  function sourceText(mode) {
    return mode === "api" ? "Shodan API" : mode === "html" ? "Shodan HTML" : mode === "demo" ? "تجريبي محلي" : "تلقائي";
  }
  function jobTitle(job) { return job.title || job.query || "مهمة بحث"; }
  function toast(message, type = "success") {
    const node = document.createElement("div");
    node.className = `toast ${type}`;
    node.innerHTML = icon(type === "success" ? "check" : "info") + `<span>${escapeHTML(message)}</span>`;
    $("toasts").append(node);
    window.setTimeout(() => node.remove(), type === "error" ? 8500 : 5000);
  }
  function setFormError(id, message) {
    text(id, message || "");
    show(id, !!message);
  }
  async function api(path, options = {}) {
    const headers = { Accept: "application/json", ...options.headers };
    const method = options.method || "GET";
    if (method !== "GET" && method !== "HEAD") {
      headers["Content-Type"] = "application/json";
      if (state.session?.csrf_token) headers["X-CSRF-Token"] = state.session.csrf_token;
    }
    let response;
    try {
      response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...options, headers });
    } catch (_) {
      const err = new Error("تعذّر الاتصال بالخادم. تحقق من الشبكة وعنوان خادم Debian.");
      err.network = true;
      throw err;
    }
    let data;
    try { data = await response.json(); }
    catch (_) { throw new Error(`أعاد الخادم استجابة غير متوقعة (${response.status}).`); }
    if (!response.ok) {
      const err = new Error(errorMessage(data.error || data.detail || data.message || data));
      err.status = response.status;
      err.code = data.code;
      const expired = response.status === 401 && state.session?.authenticated && !path.endsWith("/login");
      if ((expired || data.code === "invalid_csrf") && path !== "/api/session") {
        try { state.session = await api("/api/session"); }
        catch (_) { if (expired && state.session) state.session.authenticated = false; }
        if (!state.session?.authenticated) {
          showAuth();
          toast("انتهت جلسة الدخول. سجّل الدخول للمتابعة.", "warning");
        }
      }
      throw err;
    }
    return data;
  }
  const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body) });

  function setConnected(connected) {
    state.connected = connected;
    show("network-banner", !connected);
    $("connection-badge").innerHTML = `<span class="status-dot${connected ? "" : " offline"}"></span><span>${connected ? "متصل" : "إعادة اتصال"}</span>`;
    $("sidebar-status-dot").classList.toggle("offline", !connected);
    text("sidebar-status-text", connected ? "الخادم متصل" : "تعذّر الاتصال");
  }
  function showAuth() {
    show("boot", false); show("app", false); show("auth-screen", true);
    const setup = !!state.session?.setup_required;
    show("setup-token-field", setup); show("password-help", setup);
    $("setup-token").required = setup;
    $("auth-password").minLength = setup ? 12 : 1;
    $("auth-password").autocomplete = setup ? "new-password" : "current-password";
    text("auth-eyebrow", setup ? "إعداد مساحة العمل" : "مساحة العمل الخاصة بك");
    text("auth-title", setup ? "لنجهّز مساحة العمل." : "مرحبًا بعودتك");
    text("auth-description", setup ? "أنشئ حساب الإدارة للدخول إلى لوحة التحكم على خادمك." : "سجّل الدخول لمتابعة مهام البحث ونتائجها.");
    $("auth-submit").querySelector("span").textContent = setup ? "إنشاء الحساب والدخول" : "دخول مساحة العمل";
    document.querySelectorAll("dialog[open]").forEach((dialog) => dialog.close());
  }
  async function loadSession() {
    try {
      state.session = await api("/api/session");
      show("boot", false);
      if (!state.session.authenticated) { showAuth(); return; }
      show("auth-screen", false); show("app", true);
      const username = typeof state.session.user === "string" ? state.session.user : state.session.user?.username || "المستخدم";
      text("username", username); text("user-avatar", username.charAt(0).toUpperCase());
      show("demo-badge", !!state.session.demo); show("demo-option", !!state.session.demo);
      setConnected(true);
      await refreshAll();
    } catch (err) {
      if (!state.session) {
        $("boot").querySelector("span:not(.spinner)").textContent = err.message;
        $("boot").querySelector(".spinner").hidden = true;
        show("boot-retry", true);
      } else { setFormError("auth-error", err.message); }
    }
  }
  function matchesView(job, view) {
    if (view === "active") return activeStatuses.has(job.status) || job.status === "queued";
    if (view === "attention") return attentionStatuses.has(job.status);
    if (view === "completed") return finishedStatuses.has(job.status);
    if (view === "failed") return ["failed", "cancelled"].includes(job.status);
    return true;
  }
  function renderMetrics() {
    const jobs = state.jobs;
    text("metric-jobs", fmt(jobs.length));
    text("metric-ips", fmt(jobs.reduce((sum, j) => sum + safeNum(getStats(j).unique_ips), 0)));
    text("metric-running", fmt(jobs.filter((j) => activeStatuses.has(j.status)).length));
    text("metric-requests", fmt(jobs.reduce((sum, j) => sum + safeNum(getStats(j).requests), 0)));
    text("metric-completed", `${fmt(jobs.filter((j) => finishedStatuses.has(j.status)).length)} مكتملة`);
    text("metric-queued", `${fmt(jobs.filter((j) => j.status === "queued").length)} في الطابور`);
    text("nav-total", fmt(jobs.length));
    text("nav-active", fmt(jobs.filter((j) => matchesView(j, "active")).length));
    text("nav-attention", fmt(jobs.filter((j) => matchesView(j, "attention")).length));
  }
  function renderJobs(force = false) {
    const query = $("job-search").value.trim().toLocaleLowerCase();
    const jobs = state.jobs.filter((job) => matchesView(job, state.view) && (!query || `${job.title || ""} ${job.query || ""}`.toLocaleLowerCase().includes(query)));
    text("jobs-count", fmt(jobs.length));
    show("jobs-empty", state.jobs.length === 0);
    show("jobs-no-match", state.jobs.length > 0 && jobs.length === 0);
    show("jobs-table-wrap", jobs.length > 0);
    const signature = JSON.stringify([state.selectedId, jobs]);
    if (!force && signature === state.tableSignature) return;
    state.tableSignature = signature;
    const focusId = document.activeElement?.closest?.("[data-job]")?.dataset.job;
    $("jobs-body").innerHTML = jobs.map((job) => {
      const s = getStats(job);
      const name = jobTitle(job);
      return `<tr data-job="${escapeHTML(job.id)}" class="${job.id === state.selectedId ? "selected" : ""}" tabindex="0" aria-label="${escapeHTML(`تفاصيل ${name}`)}" aria-selected="${job.id === state.selectedId}"><td><span class="job-name">${escapeHTML(name)}</span><code class="job-query">${escapeHTML(job.query || "")}</code>${job.settings?.demo ? '<span class="job-subtitle">بيانات تجريبية محلية</span>' : ""}</td><td>${badge(job.status)}</td><td><div class="job-ip-progress" data-variant="compact"></div></td><td class="job-number">${fmt(s.unique_ips)}</td><td class="job-number">${fmt(s.requests)}</td><td class="job-date">${escapeHTML(dateText(job.updated_at, true))}</td><td><button class="icon-button" data-open-job="${escapeHTML(job.id)}" aria-label="عرض التفاصيل">${icon("arrow")}</button></td></tr>`;
    }).join("");
    $("jobs-body").querySelectorAll(".job-ip-progress").forEach((node, index) => {
      ShodanIPProgress.updateFromJob(node, jobs[index]);
    });
    if (focusId) Array.from($("jobs-body").querySelectorAll("[data-job]")).find((node) => node.dataset.job === focusId)?.focus({ preventScroll: true });
  }
  function setView(view) {
    ShodanVPN.workspace();
    state.view = view;
    $("job-filter").value = view;
    document.querySelectorAll("[data-view]").forEach((node) => node.classList.toggle("active", node.dataset.view === view));
    const labels = { all: "لوحة التحكم", active: "المهام النشطة", attention: "بانتظار المتابعة", completed: "المهام المكتملة", failed: "المهام المتعثرة والملغاة" };
    text("breadcrumb-current", labels[view]);
    renderJobs(true);
    closeSidebar();
  }
  async function refreshAll(manual = false) {
    if (state.polling || !state.session?.authenticated) return;
    state.polling = true;
    try {
      const data = await api("/api/jobs");
      state.jobs = Array.isArray(data.jobs) ? data.jobs : [];
      renderMetrics(); renderJobs(); setConnected(true);
      await ShodanVPN.refresh();
      await ShodanAccounts.refresh();
      text("last-sync", `آخر تحديث ${new Date().toLocaleTimeString("ar", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`);
      if (state.selectedId) await refreshDetail();
      else {
        const idFromHash = new URLSearchParams(location.hash.slice(1)).get("job");
        if (idFromHash && state.jobs.some((job) => job.id === idFromHash)) await selectJob(idFromHash, false);
      }
      if (manual) toast("تم تحديث مساحة العمل.");
    } catch (err) {
      if (err.status !== 401) { setConnected(false); if (manual) toast(err.message, "error"); }
    } finally { state.polling = false; }
  }
  async function selectJob(id, scroll = true) {
    if (id !== state.selectedId) {
      state.selectedId = id; state.selectedJob = null; state.lastEvent = 0; state.events = [];
      state.results = { items: [], total: 0, offset: 0, limit: 100, q: "" };
      state.resultsCount = -1; state.actionSignature = ""; state.settingsSignature = "";
      state.logWarning = false; state.eventRequest = false;
      $("result-search").value = "";
      $("event-log").innerHTML = '<p class="log-empty">جارٍ تحميل سجل المهمة…</p>';
      history.replaceState(null, "", `${location.pathname}${location.search}#job=${encodeURIComponent(id)}`);
    }
    renderJobs(true); show("job-detail", true);
    try { await refreshDetail(); }
    catch (err) { toast(err.message, "error"); }
    if (scroll) $("job-detail").scrollIntoView({ block: "start", behavior: "smooth" });
  }
  async function refreshDetail() {
    const id = state.selectedId;
    if (!id) return;
    const data = await api(jobURL(id));
    if (id !== state.selectedId) return;
    state.selectedJob = data.job || data;
    renderDetail(state.selectedJob);
    await loadEvents(id);
    if (state.tab === "results") {
      const count = safeNum(getStats(state.selectedJob).unique_ips);
      if (count !== state.resultsCount) { state.resultsCount = count; await loadResults(); }
    }
  }
  function actionButton(action, label, iconName, css = "secondary", disabled = false) {
    return `<button class="button small ${css}" data-action="${action}"${disabled ? " disabled" : ""}>${icon(iconName)}${label}</button>`;
  }
  function renderDetail(job) {
    ShodanVPN.renderJob(job);
    const s = getStats(job);
    text("detail-title", jobTitle(job)); text("detail-query", job.query || "");
    $("detail-status").innerHTML = badge(job.status);
    text("results-tab-count", fmt(s.unique_ips));
    const phase = !activeStatuses.has(job.status)
      ? PHASE[job.status] || STATUS[job.status]?.[0] || "بانتظار البدء"
      : PHASE[s.phase] || (s.phase ? String(s.phase) : PHASE[job.status] || STATUS[job.status]?.[0] || "بانتظار البدء");
    text("detail-phase", phase);
    const adaptive = job.settings?.strategy === "adaptive";
    show("detail-planner", adaptive);
    const decision = s.last_partition;
    text("detail-planner", decision ? `اختار المخطط ${decision.facet}: ${fmt(decision.children)} فروع، نحو ${fmt(decision.estimated_requests)} طلبات استخراج. ${decision.raw_children > decision.children ? `جُمعت ${fmt(decision.raw_children)} قيمة في ${fmt(decision.children)} فروع. ` : ""}فحوص التقسيم: ${fmt(s.facet_probes)}.` : "يفحص IP مباشرة، ويقارن كلفة التقسيم فقط عند الحاجة. قد تتغير الخطة مع النتائج.");
    const sourceTotal = s.source_total_records;
    const sourceKnown = Number.isSafeInteger(sourceTotal) && sourceTotal >= 0;
    show("detail-source-total", sourceKnown);
    text("detail-source-total", sourceKnown ? `إجمالي سجلات Shodan المعلن: ${fmt(sourceTotal)}. قد تتغيّر الأعداد أثناء التنفيذ؛ قد تتكرر عناوين IP بين السجلات.` : "");
    ShodanIPProgress.updateFromJob($("detail-ip-progress"), job);
    text("detail-current-query", s.current_query || job.query || "—");
    text("stat-completed", s.plan_known ? `${fmt(s.completed_branches)} / ${fmt(s.ready_branches)}` : "—");
    text("stat-remaining", s.plan_known ? fmt(s.remaining_branches) : "—");
    text("stat-ips", fmt(s.unique_ips)); text("stat-requests", `${fmt(s.requests_this_run ?? s.requests)} / ${fmt(s.request_budget ?? job.settings?.max_requests ?? 500)}`);
    text("detail-total-requests", fmt(s.requests));
    text("detail-source", sourceText(s.source || job.mode)); text("detail-started", dateText(job.started_at));
    text("detail-warning-count", fmt(warningCount(s))); show("detail-demo", !!job.settings?.demo);
    updateCountdown();
    const aSignature = JSON.stringify([job.id, job.status]);
    if (aSignature !== state.actionSignature) {
      state.actionSignature = aSignature;
      let actions = "";
      if (job.status === "running") actions += actionButton("pause", "إيقاف مؤقت", "pause");
      if (job.status === "queued") actions += actionButton("pause", "تعليق في الطابور", "pause");
      if (resumableStatuses.has(job.status)) actions += actionButton("resume", "استكمال", "play", "primary");
      if (["pause_requested", "cancel_requested"].includes(job.status)) actions += actionButton("wait", "جارٍ حفظ التقدم…", "clock", "secondary", true);
      actions += actionButton("duplicate", "نسخ المهمة", "copy");
      if (!finishedStatuses.has(job.status) && !["cancelled", "failed", "cancel_requested"].includes(job.status)) actions += `<button class="icon-button" data-action="cancel" title="إلغاء المهمة" aria-label="إلغاء المهمة">${icon("stop")}</button>`;
      $("detail-actions").innerHTML = actions;
    }
    const alert = attentionStatuses.has(job.status) || job.status === "failed" || job.status === "completed_warnings";
    show("job-alert", alert);
    if (alert) {
      const guidance = ShodanJobGuidance.viewModel(job);
      text("job-alert-title", job.status === "completed_warnings" ? "انتهى التنفيذ مع ملاحظات على التغطية" : guidance.title);
      text("job-alert-message", job.status === "completed_warnings" ? "يمكنك تنزيل النتائج والتقرير لفهم الفروع والتحذيرات المسجلة." : guidance.message);
      text("job-checkpoint-status", guidance.checkpoint);
      show("job-technical-error", !!guidance.technicalError);
      text("job-technical-error-text", guidance.technicalError);
      show("attention-action", resumableStatuses.has(job.status));
    }
    const settingsSignature = JSON.stringify([job.id, job.settings, job.mode, job.created_at, job.priority]);
    if (settingsSignature !== state.settingsSignature) { state.settingsSignature = settingsSignature; renderSettings(job); }
    $("download-txt").href = jobURL(job.id, "/download?format=txt");
  }
  function updateCountdown() {
    const timer = ShodanJobGuidance.countdown(state.selectedJob || {});
    show("wait-countdown", !!timer);
    text("wait-countdown", timer?.text || "");
  }

  function renderSettings(job) {
    const s = job.settings || {};
    const entries = [
      ["المصدر المحدد", sourceText(job.mode)], ["الاستراتيجية", s.strategy === "adaptive" ? "تقليل الاستعلامات · Adaptive" : s.strategy === "tree" ? "Tree" : "Priority"],
      ["عميل الاتصال", s.transport || "curl"], ["نوع العناوين", s.ip_version === "all" ? "IPv4 + IPv6" : `IPv${s.ip_version || "4"}`],
      ["حد الطلبات للجولة", fmt(s.max_requests ?? 500)], ["فاصل الطلبات", `${s.delay ?? 2} s`],
      ["اختيار التقسيم", s.strategy === "adaptive" ? "تلقائي بحسب كلفة الطلبات والفروع" : Array.isArray(s.split_facets) ? s.split_facets.join(" → ") : s.split_facets || "asn → port → version → product"],
      ["عند تعذّر API", s.api_fallback === "stop" ? "التوقف" : "محاولة HTML"],
      ["أولوية الطابور", String(job.priority ?? 0)], ["تاريخ الإنشاء", dateText(job.created_at)],
    ];
    $("detail-settings").innerHTML = entries.map(([label, value]) => `<div><dt>${escapeHTML(label)}</dt><dd>${escapeHTML(value)}</dd></div>`).join("");
    const downloads = [
      ["txt", "قائمة العناوين", "عنوان واحد في كل سطر", "TXT"],
      ["csv", "نتائج بصيغة جدول", "للاستعمال في أدوات التحليل", "CSV"],
      ["json", "بيانات النتائج", "العناوين بصيغة JSON", "JSON"],
      ["report", "تقرير التنفيذ", "الفروع والطلبات وتحذيرات التغطية", "JSON"],
      ["checkpoint", "نقطة الحفظ", "للاستكمال لاحقًا أو نقل المهمة", "JSON"],
    ];
    $("download-links").innerHTML = downloads.map(([format, title, description, ext]) => `<a href="${jobURL(job.id, `/download?format=${format}`)}" class="download-link" data-download="${format}">${icon("download")}<div>${title}<small>${description}</small></div><span class="file-kind">${ext}</span></a>`).join("");
  }
  async function loadEvents(id) {
    if (state.eventRequest) return;
    state.eventRequest = true;
    try {
      const data = await api(jobURL(id, `/events?after=${state.lastEvent}`));
      if (id !== state.selectedId) return;
      const events = Array.isArray(data.events) ? data.events : [];
      if (events.length) {
        state.events.push(...events);
        if (state.events.length > 2000) state.events.splice(0, state.events.length - 2000);
        state.lastEvent = Math.max(state.lastEvent, safeNum(data.last_id), ...events.map((event) => safeNum(event.id)));
        renderEvents(events);
      } else if (state.events.length === 0) {
        $("event-log").innerHTML = '<p class="log-empty">لم تُسجّل أحداث لهذه المهمة بعد.</p>';
      }
      text("log-count", fmt(state.events.length));
    } finally { if (id === state.selectedId) state.eventRequest = false; }
  }
  function renderEvents(newEvents) {
    const container = $("event-log");
    container.querySelector(".log-empty")?.remove();
    const fragment = document.createDocumentFragment();
    newEvents.forEach((event) => {
      const kind = event.kind || event.type || "log";
      const level = event.level || (kind === "warning" ? "warning" : "info");
      if (["warning", "error"].includes(level)) state.logWarning = true;
      const line = document.createElement("div");
      line.className = `log-line ${["warning", "error"].includes(level) ? level : ""}`;
      const stamp = dateValue(event.at || event.timestamp);
      const time = stamp ? stamp.toLocaleTimeString("en-GB") : "—";
      let message = event.message;
      if (!message && kind === "state") message = STATUS[event.status]?.[0] || event.status;
      if (!message && kind === "progress") {
        const s = event.stats || {};
        message = [PHASE[s.phase] || s.phase, s.current_query, s.unique_ips == null ? "" : `IPs: ${fmt(s.unique_ips)}`].filter(Boolean).join(" | ");
      }
      if (!message && typeof event.detail === "string") message = event.detail;
      if (!message) message = kind;
      const timeNode = document.createElement("time"); timeNode.textContent = time;
      const labelNode = document.createElement("span"); labelNode.className = "log-level"; labelNode.textContent = String(level).toUpperCase();
      const messageNode = document.createElement("span"); messageNode.className = "log-message"; messageNode.textContent = String(message);
      line.append(timeNode, labelNode, messageNode); fragment.append(line);
    });
    container.append(fragment);
    while (container.children.length > 2000) container.firstElementChild.remove();
    show("log-warning-dot", state.logWarning);
    if ($("log-autoscroll").checked) container.scrollTop = container.scrollHeight;
  }
  async function loadResults(reset = false) {
    const id = state.selectedId;
    if (!id) return;
    if (reset) state.results.offset = 0;
    const requestId = ++state.resultRequest;
    const params = new URLSearchParams({ offset: String(state.results.offset), limit: String(state.results.limit), q: state.results.q });
    try {
      const data = await api(jobURL(id, `/results?${params}`));
      if (id !== state.selectedId || requestId !== state.resultRequest) return;
      state.results.items = (Array.isArray(data.items) ? data.items : []).map((item) => typeof item === "string" ? item : item.ip || item.address || item.ip_str || "").filter(Boolean);
      state.results.total = safeNum(data.total); state.results.offset = safeNum(data.offset, state.results.offset);
      renderResults();
    } catch (err) { if (requestId === state.resultRequest && err.status !== 401) toast(err.message, "error"); }
  }
  function renderResults() {
    const r = state.results;
    show("results-empty", r.items.length === 0);
    $("results-empty").querySelector("h3").textContent = r.q ? "لا توجد عناوين مطابقة" : "لا توجد عناوين محفوظة بعد";
    $("results-empty").querySelector("p").textContent = r.q ? "غيّر نص البحث لعرض نتائج أخرى." : "ستظهر النتائج عند حفظ أول مجموعة من العناوين.";
    $("results-grid").innerHTML = r.items.map((ip) => `<div class="ip-item"><span>${escapeHTML(ip)}</span><button data-copy-ip="${escapeHTML(ip)}" title="نسخ العنوان" aria-label="${escapeHTML(`نسخ ${ip}`)}">${icon("copy")}</button></div>`).join("");
    text("results-range", r.items.length ? `${fmt(r.offset + 1)}–${fmt(r.offset + r.items.length)} من ${fmt(r.total)} عنوان` : `${fmt(r.total)} عنوان`);
    $("results-prev").disabled = r.offset === 0;
    $("results-next").disabled = r.offset + r.limit >= r.total;
    $("copy-results").disabled = r.items.length === 0;
  }
  function switchTab(tab) {
    state.tab = tab;
    document.querySelectorAll("[data-tab]").forEach((button) => {
      const selected = button.dataset.tab === tab;
      button.setAttribute("aria-selected", String(selected)); button.tabIndex = selected ? 0 : -1;
      show(`pane-${button.dataset.tab}`, selected);
    });
    if (tab === "results") loadResults();
    if (tab === "events" && $("log-autoscroll").checked) $("event-log").scrollTop = $("event-log").scrollHeight;
  }
  function openDialog(id) {
    const dialog = $(id);
    if (!dialog.open) dialog.showModal();
  }
  function openCreate() {
    $("create-form").reset(); ShodanVPN.prepareCreate(); setFormError("create-error", "");
    $("create-form").elements.demo.checked = !!state.session?.demo;
    updatePlannerFields(); updateKeyField("create"); openDialog("create-dialog");
  }
  function updatePlannerFields(resetCandidates = false) {
    const fields = $("create-form").elements;
    const adaptive = fields.strategy.value === "adaptive";
    show("split-facets-field", !adaptive);
    show("automatic-planner-help", adaptive);
    fields.split_facets.disabled = adaptive;
    fields.always_asn.disabled = adaptive;
    if (adaptive) fields.always_asn.checked = false;
    if (resetCandidates) fields.split_facets.value = adaptive ? "port,version,asn,country,product,org,os,city" : "asn,port,version,product";
  }
  function updateKeyField(prefix) {
    const mode = $(`${prefix}-mode`).value;
    show(`${prefix}-key-field`, mode !== "html");
    const keyInput = $(`${prefix}-key-field`).querySelector("input");
    if (mode === "html") keyInput.value = "";
  }
  function openResume(id) {
    state.resumeId = id;
    const job = state.jobs.find((item) => item.id === id) || state.selectedJob;
    $("resume-form").reset(); setFormError("resume-error", "");
    const guidance = ShodanJobGuidance.viewModel(job);
    text("resume-description", `${guidance.message} ${guidance.checkpoint}`);
    $("resume-mode").value = ["api", "html", "auto"].includes(job?.mode) ? job.mode : "html";
    updateKeyField("resume"); openDialog("resume-dialog");
  }
  async function runAction(id, action, body = {}) {
    try {
      const result = await post(jobURL(id, "/actions"), { action, ...body });
      const job = result.job || result;
      toast(action === "pause" ? "طُلب الإيقاف المؤقت. سيحفظ العامل التقدم عند نقطة آمنة." : action === "cancel" ? "طُلب إلغاء المهمة." : action === "duplicate" ? "أُنشئت نسخة جديدة من المهمة." : "أُعيدت المهمة إلى طابور التنفيذ.");
      await refreshAll();
      if (action === "duplicate" && job.id) await selectJob(job.id);
      return job;
    } catch (err) { toast(err.message, "error"); throw err; }
  }
  async function copyText(value) {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(value);
      else {
        const area = document.createElement("textarea");
        area.value = value; area.className = "sr-only";
        document.body.append(area); area.select();
        const success = document.execCommand("copy"); area.remove();
        if (!success) throw new Error("copy");
      }
      toast("تم النسخ.");
    } catch (_) { toast("لم يسمح المتصفح بالنسخ. حدّد النص وانسخه يدويًا.", "warning"); }
  }
  async function downloadFile(format) {
    if (!state.selectedId) return;
    try {
      const response = await fetch(jobURL(state.selectedId, `/download?format=${encodeURIComponent(format)}`), { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) {
        let data = {};
        try { data = await response.json(); } catch (_) { /* Use status below. */ }
        throw new Error(errorMessage(data.error || data.detail || `تعذّر تنزيل الملف (${response.status}).`));
      }
      const blob = await response.blob(); const url = URL.createObjectURL(blob);
      const disposition = response.headers.get("Content-Disposition") || "";
      const match = disposition.match(/filename="?([^";]+)"?/i);
      const fileName = match ? match[1].replace(/[\\/]/g, "_") : `shodan-${state.selectedId}.${["report", "checkpoint"].includes(format) ? `${format}.json` : format}`;
      const anchor = document.createElement("a"); anchor.href = url; anchor.download = fileName;
      document.body.append(anchor); anchor.click(); anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) { toast(err.message || "تعذّر تنزيل الملف.", "error"); }
  }
  function closeSidebar() {
    $("sidebar").classList.remove("open"); show("sidebar-backdrop", false);
    $("menu-button").setAttribute("aria-expanded", "false");
  }
  function bindEvents() {
    $("boot-retry").addEventListener("click", () => { show("boot-retry", false); $("boot").querySelector(".spinner").hidden = false; loadSession(); });
    $("auth-form").addEventListener("submit", async (event) => {
      event.preventDefault(); setFormError("auth-error", "");
      $("auth-submit").disabled = true;
      const payload = { username: $("auth-user").value.trim(), password: $("auth-password").value };
      if (state.session?.setup_required) payload.setup_token = $("setup-token").value.trim();
      try {
        await post(state.session?.setup_required ? "/api/setup" : "/api/login", payload);
        $("auth-password").value = ""; $("setup-token").value = "";
        await loadSession();
      } catch (err) { setFormError("auth-error", err.message); }
      finally { payload.password = ""; if (payload.setup_token) payload.setup_token = ""; $("auth-submit").disabled = false; }
    });
    $("logout").addEventListener("click", async () => {
      if (state.logoutBusy) return; state.logoutBusy = true;
      try { await post("/api/logout", {}); state.jobs = []; state.selectedJob = null; state.selectedId = null; show("job-detail", false); await loadSession(); }
      catch (err) { toast(err.message, "error"); }
      finally { state.logoutBusy = false; }
    });
    $("menu-button").addEventListener("click", () => { $("sidebar").classList.add("open"); show("sidebar-backdrop", true); $("menu-button").setAttribute("aria-expanded", "true"); });
    $("sidebar-backdrop").addEventListener("click", closeSidebar);
    document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
    $("job-filter").addEventListener("change", () => setView($("job-filter").value));
    $("job-search").addEventListener("input", () => renderJobs(true));
    $("refresh-button").addEventListener("click", () => refreshAll(true));
    ["create-button", "empty-create"].forEach((id) => $(id).addEventListener("click", openCreate));
    $("jobs-body").addEventListener("click", (event) => { const row = event.target.closest("[data-job]"); if (row) selectJob(row.dataset.job); });
    $("jobs-body").addEventListener("keydown", (event) => { if (["Enter", " "].includes(event.key) && event.target.matches("tr[data-job]")) { event.preventDefault(); selectJob(event.target.dataset.job); } });
    document.querySelectorAll("[data-tab]").forEach((button) => {
      button.addEventListener("click", () => switchTab(button.dataset.tab));
      button.addEventListener("keydown", (event) => {
        const tabs = Array.from(document.querySelectorAll("[data-tab]")); const index = tabs.indexOf(button);
        let next = null;
        if (event.key === "ArrowLeft") next = tabs[(index + 1) % tabs.length];
        if (event.key === "ArrowRight") next = tabs[(index - 1 + tabs.length) % tabs.length];
        if (event.key === "Home") next = tabs[0]; if (event.key === "End") next = tabs[tabs.length - 1];
        if (next) { event.preventDefault(); switchTab(next.dataset.tab); next.focus(); }
      });
    });
    document.querySelectorAll("dialog").forEach((dialog) => {
      dialog.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => dialog.close()));
      dialog.addEventListener("click", (event) => { if (event.target === dialog) { const r = dialog.getBoundingClientRect(); if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) dialog.close(); } });
      dialog.addEventListener("close", () => dialog.querySelectorAll('input[type="password"]').forEach((input) => { input.value = ""; }));
    });
    ["create", "resume", "import"].forEach((prefix) => $(`${prefix}-mode`).addEventListener("change", () => updateKeyField(prefix)));
    $("create-form").elements.strategy.addEventListener("change", () => updatePlannerFields(true));
    $("create-form").addEventListener("submit", async (event) => {
      event.preventDefault(); setFormError("create-error", "");
      const form = event.currentTarget; const fields = form.elements;
      const n = (name) => Number(fields[name].value);
      const key = fields.api_key.value.trim();
      const payload = {
        title: fields.title.value.trim(), query: fields.query.value.trim(), mode: fields.mode.value, priority: n("priority"),
        settings: { browser_recovery: fields.browser_recovery.value, transport: fields.transport.value, ip_version: fields.ip_version.value, strategy: fields.strategy.value,
          split_facets: fields.strategy.value === "adaptive" ? ["port","version","asn","country","product","org","os","city"] : fields.split_facets.value.split(",").map((v) => v.trim()).filter(Boolean),
          max_requests: n("max_requests"), delay: n("delay"), timeout: n("timeout"),
          rate_limit_retries: n("rate_limit_retries"), retry_base_delay: n("retry_base_delay"), max_retry_wait: n("max_retry_wait"),
          always_asn: fields.always_asn.checked, rotate_user_agents: fields.rotate_user_agents.checked,
          include_non_global: fields.include_non_global.checked, user_agent: fields.user_agent.value.trim(),
          api_fallback: fields.api_fallback.value, on_rate_limit: fields.on_rate_limit.value,
          demo: !!state.session?.demo && fields.demo.checked,
        },
      };
      if (key && payload.mode !== "html") payload.api_key = key;
      $("create-submit").disabled = true;
      try {
        const data = await post("/api/jobs", {...payload, network:ShodanVPN.createPolicy()}); fields.api_key.value = "";
        $("create-dialog").close(); toast("أُضيفت المهمة إلى طابور التنفيذ.");
        setView("all"); $("job-search").value = "";
        await refreshAll(); const job = data.job || data; if (job.id) await selectJob(job.id);
      } catch (err) { setFormError("create-error", err.message); }
      finally { delete payload.api_key; $("create-submit").disabled = false; }
    });
    $("detail-actions").addEventListener("click", async (event) => {
      const button = event.target.closest("[data-action]"); if (!button || !state.selectedId) return;
      const action = button.dataset.action;
      if (action === "resume") { openResume(state.selectedId); return; }
      if (action === "cancel") { state.cancelId = state.selectedId; openDialog("confirm-dialog"); return; }
      button.disabled = true;
      try { await runAction(state.selectedId, action); } catch (_) { /* Toast already displayed. */ }
      finally { if (button.isConnected) button.disabled = false; }
    });
    $("attention-action").addEventListener("click", () => { if (state.selectedId) openResume(state.selectedId); });
    $("resume-form").addEventListener("submit", async (event) => {
      event.preventDefault(); setFormError("resume-error", ""); $("resume-submit").disabled = true;
      const fields = event.currentTarget.elements;
      const payload = { action: "resume", mode: fields.mode.value };
      if (fields.api_key.value.trim() && payload.mode !== "html") payload.api_key = fields.api_key.value.trim();
      try {
        await post(jobURL(state.resumeId, "/actions"), payload); fields.api_key.value = "";
        $("resume-dialog").close(); toast("أُعيدت المهمة إلى الطابور مع الاحتفاظ بالتقدم."); await refreshAll();
      } catch (err) { setFormError("resume-error", err.message); }
      finally { delete payload.api_key; $("resume-submit").disabled = false; }
    });
    $("confirm-cancel").addEventListener("click", async () => {
      $("confirm-cancel").disabled = true;
      try { await runAction(state.cancelId, "cancel"); $("confirm-dialog").close(); }
      catch (_) { /* Toast already displayed. */ }
      finally { $("confirm-cancel").disabled = false; }
    });
    $("import-button").addEventListener("click", () => { $("import-form").reset(); setFormError("import-error", ""); text("import-filename", "ملف JSON أو ملف حفظ بلا امتداد · حتى 32 MiB"); updateKeyField("import"); openDialog("import-dialog"); });
    $("import-file").addEventListener("change", () => { const file = $("import-file").files[0]; text("import-filename", file ? `${file.name} · ${(file.size / 1048576).toFixed(2)} MiB` : "ملف JSON أو ملف حفظ بلا امتداد · حتى 32 MiB"); });
    $("import-form").addEventListener("submit", async (event) => {
      event.preventDefault(); setFormError("import-error", "");
      const file = $("import-file").files[0]; if (!file) return;
      if (file.size > 32 * 1024 * 1024) { setFormError("import-error", "يتجاوز الملف الحد المسموح، 32 MiB."); return; }
      $("import-submit").disabled = true;
      const fields = event.currentTarget.elements;
      const payload = { title: fields.title.value.trim(), mode: fields.mode.value, filename: file.name };
      try {
        try { payload.checkpoint = JSON.parse(await file.text()); } catch (_) { throw new Error("الملف ليس JSON صالحًا. اختر ملف نقطة الحفظ نفسه."); }
        if (!isPlainObject(payload.checkpoint)) throw new Error("يجب أن يحتوي الملف على كائن نقطة حفظ صالح.");
        if (fields.api_key.value.trim() && payload.mode !== "html") payload.api_key = fields.api_key.value.trim();
        const data = await post("/api/checkpoints/import", payload);
        fields.api_key.value = ""; $("import-dialog").close(); toast("استُوردت نقطة الحفظ. راجع المهمة ثم اضغط استكمال لبدء التنفيذ.");
        setView("all"); $("job-search").value = ""; await refreshAll(); const job = data.job || data; if (job.id) await selectJob(job.id);
      } catch (err) { setFormError("import-error", err.message); }
      finally { delete payload.api_key; delete payload.checkpoint; $("import-submit").disabled = false; }
    });
    let resultTimer;
    $("result-search").addEventListener("input", () => { clearTimeout(resultTimer); resultTimer = setTimeout(() => { state.results.q = $("result-search").value.trim(); loadResults(true); }, 250); });
    $("results-prev").addEventListener("click", () => { state.results.offset = Math.max(0, state.results.offset - state.results.limit); loadResults(); });
    $("results-next").addEventListener("click", () => { state.results.offset += state.results.limit; loadResults(); });
    $("copy-results").addEventListener("click", () => copyText(state.results.items.join("\n")));
    $("results-grid").addEventListener("click", (event) => { const button = event.target.closest("[data-copy-ip]"); if (button) copyText(button.dataset.copyIp); });
    $("download-txt").addEventListener("click", (event) => { event.preventDefault(); downloadFile("txt"); });
    $("download-links").addEventListener("click", (event) => { const link = event.target.closest("[data-download]"); if (link) { event.preventDefault(); downloadFile(link.dataset.download); } });
    document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshAll(); });
    document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeSidebar(); });
    window.addEventListener("online", () => refreshAll());
  }
  ShodanAccounts.init({api,toast,closeSidebar,refreshAll});
  ShodanVPN.init({api, toast, closeSidebar, refreshAll, openResume, runAction, currentJob: id => state.jobs.find(j => j.id === id)});
  bindEvents(); loadSession();
  window.setInterval(() => { if (!document.hidden && state.session?.authenticated) refreshAll(); }, 2000);
  window.setInterval(updateCountdown, 1000);
})();
