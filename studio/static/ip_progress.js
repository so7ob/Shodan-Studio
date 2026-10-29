/* IP-centric estimated progress widget; no framework/dependencies; RTL Arabic. */
(function (root, factory) {
  'use strict';
  const exported = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = exported;
  root.ShodanIPProgress = exported;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const formatter = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });

  function finiteCount(x) {
    if (x === null || x === undefined || x === '') return null;
    if (typeof x === 'boolean') return null;
    const n = Number(x);
    return Number.isFinite(n) && n >= 0 ? Math.floor(n) : null;
  }

  function viewModel(progress) {
    const m = progress && typeof progress === 'object' ? progress : {};
    const extracted = finiteCount(m.extracted_unique_ips) ?? 0;
    const total = finiteCount(m.estimated_total_ips);
    const remaining = finiteCount(m.remaining_estimated_ips);
    const pct = finiteCount(m.progress_percent);
    const displayedPct = pct === null || total === null ? null : Math.min(m.job_finished_successfully === true ? 100 : 99, pct);
    const complete = m.job_finished_successfully === true;
    const estimate = !complete;
    const planned = Boolean(m.planning_complete);
    const completedLeaves = finiteCount(m.completed_leaves);
    const totalLeaves = finiteCount(m.total_leaves);
    const n = (x) => formatter.format(x);
    let heading = 'تقدّم استخراج عناوين IP';
    let headline, description;
    if (total === null || displayedPct === null) {
      headline = `${n(extracted)} عنوان IP مستخرج — الإجمالي الفريد قيد التقدير`;
      description = planned
        ? 'توجد فروع غير محسوبة؛ لا يمكن تحديد نسبة موثوقة حاليًا.'
        : 'جارٍ تخطيط الفروع وتحديد حجم العمل المتبقي.';
    } else if (complete) {
      headline = `${n(extracted)} عنوان IP فريد — اكتملت الفروع المخططة`;
      description = '100% من العمل المخطط؛ قد تظهر فجوات تغطية منفصلة في التقرير.';
    } else {
      headline = `${n(extracted)} من أصل نحو ${n(total)} عنوان IP`;
      description = `المتبقي تقديريًا: نحو ${n(remaining ?? Math.max(0, total - extracted))} عنوان IP. قد تتغيّر النسبة مع الاستخراج وإزالة التكرار.`;
    }
    const branchDescription = planned && totalLeaves !== null && completedLeaves !== null
      ? `الفروع (مؤشر ثانوي): \u2066${n(completedLeaves)} / ${n(totalLeaves)}\u2069`
      : 'الفروع: لم تكتمل الخطة بعد';
    return {
      title: heading,
      extracted,
      total,
      remaining,
      percent: displayedPct,
      percentLabel: displayedPct === null ? '—' : `${displayedPct}%${estimate ? ' تقديري' : ''}`,
      headline,
      description,
      branchDescription,
      isEstimated: estimate,
    };
  }

  function node(tag, className, content) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (content !== undefined) el.textContent = String(content);
    return el;
  }

  function render(element, progress) {
    if (!element || typeof element.replaceChildren !== 'function') {
      throw new TypeError('render() requires an HTML container element');
    }
    const data = viewModel(progress);
    const compact = element.dataset.variant === 'compact';
    element.classList.add('ip-progress', compact ? 'ip-progress--compact' : 'ip-progress--detail');
    element.setAttribute('dir', 'rtl');
    const top = node('div', 'ip-progress__top');
    top.append(node('span', 'ip-progress__label', data.title));
    top.append(node('strong', 'ip-progress__number', data.percentLabel));
    const headline = node('div', 'ip-progress__headline', data.headline);
    const track = node('div', 'ip-progress__track');
    const fill = node('div', 'ip-progress__fill');
    if (data.percent === null) {
      track.setAttribute('role', 'status');
      track.setAttribute('aria-label', 'الإجمالي الفريد قيد التقدير');
      track.classList.add('ip-progress__track--unknown');
      fill.style.width = '32%';
    } else {
      track.setAttribute('role', 'progressbar');
      track.setAttribute('aria-label', 'نسبة التقدّم في استخراج عناوين IP');
      track.setAttribute('aria-valuemin', '0');
      track.setAttribute('aria-valuemax', '100');
      track.setAttribute('aria-valuenow', String(data.percent));
      track.setAttribute('aria-valuetext', `${data.headline}، ${data.percentLabel}`);
      fill.style.width = `${data.percent}%`;
    }
    track.append(fill);
    const below = node('div', 'ip-progress__below', data.description);
    const branch = node('div', 'ip-progress__branches', data.branchDescription);
    if (compact) {
      element.replaceChildren(top, headline, track, branch);
    } else {
      element.replaceChildren(top, headline, track, below, branch);
    }
    return data;
  }

  function updateFromJob(container, job) {
    if (!job || typeof job !== 'object' || !job.ip_progress) {
      throw new TypeError('API job object must contain ip_progress');
    }
    return render(container, job.ip_progress);
  }

  return { viewModel, render, updateFromJob };
}));
