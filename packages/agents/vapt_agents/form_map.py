"""Authenticated form-map extractor for the webvuln phase.

For each discovered endpoint, GET the page with the admin session cookie and parse
every ``<form>`` element into structured metadata the LLM planner (and operators
reading the audit) can reason about: form action, method, enctype, and each
field's name + type + current value.

This is the deterministic input that lets the LLM derive the right probe without
hardcoded (path, field) tables. Where the old code shipped a tier like
``_ADMIN_SSTI_SINKS = (("/admin/offer", "offer"), ("/admin/announcement",
"content"), …)`` baked into engagement.py, now the map simply records that
``POST /admin/offer`` has a ``textarea[name=offer]`` and ``POST /admin/announcement``
has a ``textarea[name=content]`` — the LLM sees that and emits
``ssti_detect url=/admin/offer data=offer={{7*7}}`` on its own, no DineHub
knowledge required.

Also captures the OPTIONS Allow header + response Content-Type per endpoint —
critical for spotting XML endpoints (``Allow: OPTIONS, POST`` + a probe that
echoes an XML body is the XXE primitive signal) or JSON config dumps
(``Content-Type: application/json`` + sensitive-looking URL = secrets check).

Design notes
------------
* Pure stdlib (requests + re). No HTML parser dependency: the form-field regex is
  the same one `web_login.py` uses; both apps are small, deterministic HTML.
* Fail-safe: any network error, parse exception, or Redis miss returns an empty
  (or partial) map rather than raising. The planner degrades to "no form hints"
  (the old behaviour).
* Bounded: at most ``MAX_URLS`` endpoints, ``TIMEOUT`` per request, in-scope only.
* Argv-free: this is library code called inline from the orchestrator. The
  SUBPROCESS version (for the LLM's tool-use loop in Stage 3) is a separate
  worker binary and tool spec.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from urllib.parse import urljoin, urlparse

MAX_URLS = 50
TIMEOUT = 8

# Matches an <input ... name="…" ...> element — the type attribute is OPTIONAL
# because HTML defaults it to "text" when omitted (and real forms do omit it).
# We'll pull the type out separately from the same opening tag if present.
_INPUT_RE = re.compile(
    r"""<input\b([^>]*?)\bname\s*=\s*["']([^"']+)["']([^>]*)>""",
    re.IGNORECASE,
)
_TYPE_IN_TAG_RE = re.compile(
    r"""\btype\s*=\s*["']([^"']+)["']""", re.IGNORECASE,
)
_TEXTAREA_RE = re.compile(
    r"""<textarea\b[^>]*?\bname\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
_SELECT_RE = re.compile(
    r"""<select\b[^>]*?\bname\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
_FORM_RE = re.compile(
    r"""<form\b([^>]*)>(.*?)</form>""", re.IGNORECASE | re.DOTALL
)
_ATTR_RE = re.compile(
    r"""(\w[\w-]*)\s*=\s*["']([^"']*)["']""", re.IGNORECASE
)
_VALUE_RE_TEMPLATE = (
    r"""<input\b[^>]*?\bname\s*=\s*["']{name}["'][^>]*?\bvalue\s*=\s*["']([^"']*)["']"""
)


@dataclass
class FormField:
    name: str
    type: str = "text"
    value: str = ""


@dataclass
class FormSpec:
    """One parsed form on a page."""
    action: str                       # resolved absolute URL (or empty = post-back to self)
    method: str = "get"               # lowercase: get | post | put | ...
    enctype: str = "application/x-www-form-urlencoded"
    fields: list[FormField] = dc_field(default_factory=list)

    def field_names(self) -> list[str]:
        return [f.name for f in self.fields]

    def text_field_names(self) -> list[str]:
        return [f.name for f in self.fields
                if f.type in ("text", "textarea", "search", "email", "url")]


@dataclass
class EndpointMap:
    """What we learned about one authenticated-GET'd endpoint."""
    url: str
    status: int = 0
    content_type: str = ""
    allow: str = ""                   # OPTIONS Allow header, if we checked
    forms: list[FormSpec] = dc_field(default_factory=list)
    error: str = ""

    def summary_line(self) -> str:
        """One compact line per endpoint for the LLM prompt."""
        parts = [f"{self.url} [{self.status}]"]
        if self.content_type:
            parts.append(f"ct={self.content_type.split(';')[0]}")
        if self.allow:
            parts.append(f"allow={self.allow}")
        for i, f in enumerate(self.forms[:3]):
            fields = ",".join(f"{x.name}:{x.type}" for x in f.fields[:8])
            parts.append(f"form#{i+1}={f.method.upper()} {f.action or '(self)'} ({fields})")
        return "  ".join(parts)


def _parse_forms(html: str, page_url: str) -> list[FormSpec]:
    """Extract every <form> from the HTML. Resolves action= against page_url;
    extracts input/textarea/select fields. Deterministic, bounded."""
    out: list[FormSpec] = []
    if not html:
        return out
    for m in _FORM_RE.finditer(html):
        attrs_raw, body = m.group(1) or "", m.group(2) or ""
        attrs = {k.lower(): v for k, v in _ATTR_RE.findall(attrs_raw)}
        action = attrs.get("action", "").strip()
        if action:
            action = urljoin(page_url, action)
        method = (attrs.get("method", "get") or "get").strip().lower()
        if method not in ("get", "post", "put", "patch", "delete"):
            method = "get"
        enctype = (attrs.get("enctype", "application/x-www-form-urlencoded")
                   or "application/x-www-form-urlencoded").strip().lower()
        fields: list[FormField] = []
        _seen_names: set[str] = set()
        # <input ...> — type is OPTIONAL (HTML defaults to "text" when omitted,
        # and plenty of real admin forms use <input name="…"> bare).
        for im in _INPUT_RE.finditer(body):
            attrs = (im.group(1) or "") + (im.group(3) or "")
            name = (im.group(2) or "").strip()
            if not name or name in _seen_names:
                continue
            tm = _TYPE_IN_TAG_RE.search(attrs)
            itype = (tm.group(1) if tm else "text").strip().lower()
            vm = re.search(_VALUE_RE_TEMPLATE.format(name=re.escape(name)),
                           body, re.IGNORECASE)
            value = (vm.group(1) if vm else "").strip()
            _seen_names.add(name)
            fields.append(FormField(name=name, type=itype, value=value))
        # <textarea ...>
        for tm in _TEXTAREA_RE.finditer(body):
            name = (tm.group(1) or "").strip()
            if name and name not in _seen_names:
                _seen_names.add(name)
                fields.append(FormField(name=name, type="textarea"))
        # <select ...>
        for sm in _SELECT_RE.finditer(body):
            name = (sm.group(1) or "").strip()
            if name and name not in _seen_names:
                _seen_names.add(name)
                fields.append(FormField(name=name, type="select"))
        if fields or action:
            out.append(FormSpec(action=action, method=method, enctype=enctype,
                                fields=fields))
    return out


def build_endpoint_map(urls: list[str], cookie: str | None,
                      target_host: str) -> list[EndpointMap]:
    """GET each in-scope URL with the authenticated session cookie, parse forms,
    capture response Content-Type + OPTIONS Allow. Returns one EndpointMap per
    reachable URL (bounded). Fail-safe: any error on a URL yields an entry with
    ``.error`` set and empty forms; the walk continues.
    """
    try:
        import requests
    except Exception:
        return []
    sess = requests.Session()
    sess.headers.update({
        "User-Agent": "vapt-form-map/1.0 (authorized assessment)",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    if cookie:
        sess.headers["Cookie"] = cookie

    out: list[EndpointMap] = []
    seen: set[str] = set()
    for url in urls:
        if len(out) >= MAX_URLS:
            break
        url = (url or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        if not url.lower().startswith(("http://", "https://")):
            continue
        try:
            host = urlparse(url).hostname
        except Exception:
            continue
        if host != target_host:
            continue
        em = EndpointMap(url=url)
        try:
            r = sess.get(url, timeout=TIMEOUT, allow_redirects=True)
            em.status = r.status_code
            em.content_type = (r.headers.get("Content-Type") or "").strip()
            if r.status_code == 200 and r.text and "text/html" in em.content_type.lower():
                em.forms = _parse_forms(r.text, url)
        except Exception as e:
            em.error = f"{type(e).__name__}: {str(e)[:80]}"
        # OPTIONS fetch is cheap and reveals Allow (XML endpoints often advertise
        # POST only — useful signal for the LLM). Only run when the GET succeeded
        # or returned 405 (method-not-allowed is itself a hint we care about).
        if em.status in (200, 403, 405):
            try:
                r2 = sess.options(url, timeout=TIMEOUT)
                em.allow = (r2.headers.get("Allow") or "").strip()
            except Exception:
                pass
        out.append(em)
    return out


def summarize_for_llm(maps: list[EndpointMap]) -> str:
    """Compact multi-line summary suitable for a planner prompt. Keeps the token
    budget tight by truncating to the most informative endpoints first (forms
    present), then falling back to interesting content types (JSON/XML)."""
    scored: list[tuple[int, EndpointMap]] = []
    for em in maps:
        score = 0
        if em.forms:
            score += 10 + len(em.forms)
        ct = em.content_type.lower()
        if "json" in ct or "xml" in ct:
            score += 5
        if em.allow and "POST" in em.allow and em.status in (200, 405):
            score += 3
        if em.status == 200:
            score += 1
        # Threshold score > 1: a page with ONLY status==200 (no form, no
        # interesting content type, no POST allow) is static noise (css/js/
        # image) and gets dropped. A form, JSON/XML content type, or POST
        # allow is required to make the LLM summary.
        if score > 1:
            scored.append((score, em))
    scored.sort(key=lambda t: -t[0])
    return "\n".join(em.summary_line() for _, em in scored[:40])
