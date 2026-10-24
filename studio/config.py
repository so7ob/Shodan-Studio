"""Typed job inputs. No user input is interpreted as a shell command."""
from __future__ import annotations

import math
from typing import Any

from . import engine


class JobValidationError(ValueError):
    pass


DEFAULT_SETTINGS = {
    "transport": "curl", "timeout": 30.0, "delay": 2.0,
    "max_requests": 500, "ip_version": "all", "strategy": "priority",
    "split_facets": ["asn", "port", "version", "product"],
    "max_plan_nodes": 20000, "api_facet_limit": 1000, "always_asn": False,
    "api_fallback": "html", "rate_limit_retries": 3,
    "retry_base_delay": 30.0, "max_retry_wait": 600.0,
    "on_rate_limit": "pause", "user_agent": "", "rotate_user_agents": False,
    "include_non_global": False, "demo": False,
}


def bounded(value: Any, name: str, low: float, high: float, integer=False):
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise JobValidationError(f"القيمة {name} يجب أن تكون بين {low:g} و{high:g}.")
    if integer and type(value) is not int:
        raise JobValidationError(f"القيمة {name} يجب أن تكون عددًا صحيحًا.")
    return int(value) if integer else float(value)


def text(value: Any, name: str, maximum: int, empty=False) -> str:
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise JobValidationError(f"قيمة {name} غير صالحة.")
    value = value.strip()
    if not value and not empty:
        raise JobValidationError(f"أدخل {name}.")
    return value


def validate_key(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise JobValidationError("مفتاح API غير صالح.")
    try:
        engine.validate_api_key(value)
    except engine.SpiderError:
        raise JobValidationError("مفتاح API غير صالح؛ أدخل المفتاح فقط دون مسافات.") from None
    return value


def settings_from(payload: Any, *, allow_demo=False) -> dict:
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise JobValidationError("الإعدادات يجب أن تكون كائنًا.")
    unknown = set(payload) - set(DEFAULT_SETTINGS)
    if unknown:
        raise JobValidationError("يوجد إعداد غير مدعوم في المهمة.")
    result = {**DEFAULT_SETTINGS, **payload}
    result["split_facets"] = list(result["split_facets"]) if isinstance(result["split_facets"], (list, tuple)) else result["split_facets"]
    choices = {
        "transport": ("curl", "python"), "ip_version": ("4", "6", "all"),
        "strategy": ("priority", "tree"), "api_fallback": ("html", "stop"),
        "on_rate_limit": ("pause", "stop"),
    }
    for field, options in choices.items():
        if result[field] not in options:
            raise JobValidationError(f"قيمة {field} غير مدعومة.")
    ranges = {
        "timeout": (1, 180, False), "delay": (0, 3600, False),
        "max_requests": (1, 100000, True), "max_plan_nodes": (1, 100000, True),
        "api_facet_limit": (1, 10000, True), "rate_limit_retries": (0, 10, True),
        "retry_base_delay": (1, 3600, False), "max_retry_wait": (0, 86400, False),
    }
    for field, (low, high, integer) in ranges.items():
        result[field] = bounded(result[field], field, low, high, integer)
    for field in ("always_asn", "rotate_user_agents", "include_non_global", "demo"):
        if type(result[field]) is not bool:
            raise JobValidationError(f"قيمة {field} يجب أن تكون اختيارًا منطقيًا.")
    facets = result["split_facets"]
    if not isinstance(facets, list) or not facets or len(facets) > 6 or any(not isinstance(f, str) or f not in engine.SPLIT_FACETS for f in facets) or len(set(facets)) != len(facets):
        raise JobValidationError("اختر قائمة تقسيم صحيحة من asn, port, version, product, org, os دون تكرار.")
    agent = result["user_agent"]
    if not isinstance(agent, str):
        raise JobValidationError("User-Agent غير صالح.")
    if agent:
        try:
            engine.validate_user_agent(agent)
        except ValueError:
            raise JobValidationError("User-Agent يجب أن يكون نصًا قابلًا للطباعة دون أسطر جديدة.") from None
    if agent and result["rotate_user_agents"]:
        raise JobValidationError("اختر User-Agent ثابتًا أو تدوير القيم.")
    if result["demo"] and not allow_demo:
        raise JobValidationError("الوضع التجريبي غير مفعّل على هذا الخادم.")
    return result


def validate_job(payload: Any, *, allow_demo=False) -> tuple[dict, str | None]:
    if not isinstance(payload, dict):
        raise JobValidationError("المهمة يجب أن تكون كائنًا.")
    if set(payload) - {"title", "query", "mode", "api_key", "settings", "priority"}:
        raise JobValidationError("توجد حقول غير مدعومة في المهمة.")
    query = text(payload.get("query"), "استعلام Shodan", 8192)
    try:
        engine.validate_scope_query(query)
    except engine.SpiderError:
        raise JobValidationError("الاستعلام يحتوي قيود نطاق متعارضة أو غير مدعومة.") from None
    title = text(payload.get("title", ""), "اسم المهمة", 160, empty=True) or query[:80]
    key = validate_key(payload.get("api_key"))
    mode = payload.get("mode", "auto")
    if mode not in ("auto", "html", "api"):
        raise JobValidationError("اختر المصدر html أو api أو auto.")
    if mode == "auto":
        mode = "api" if key else "html"
    settings = settings_from(payload.get("settings"), allow_demo=allow_demo)
    priority = bounded(payload.get("priority", 0), "priority", 0, 10, True)
    # Catch pasted credentials in a public title/query before any persistence.
    if key and (key in query or key in title or key in settings["user_agent"]):
        raise JobValidationError("ضع مفتاح API في حقل المفتاح فقط.")
    return {"title": title, "query": query, "mode": mode, "settings": settings, "priority": priority}, key
