"""HTTP/WebSocket header builders for reverse-proxy requests.

All values are sanitized to ASCII-safe Latin-1 before use.
"""

import asyncio
import base64
import json
import random
import re
import string
import time
import urllib.request
import uuid
from typing import Optional
from urllib.parse import urlparse


from app.platform.logging.logger import logger
from app.platform.config.snapshot import get_config
from app.control.proxy.models import ProxyLease
from app.dataplane.proxy.adapters.profile import ProxyProfile, resolve_proxy_profile

# ---------------------------------------------------------------------------
# Unicode → ASCII normalisation map
# ---------------------------------------------------------------------------

_CHAR_MAP = str.maketrans(
    {
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2212": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u00a0": " ",
        "\u2007": " ",
        "\u202f": " ",
        "\u200b": "",
        "\u200c": "",
        "\u200d": "",
        "\ufeff": "",
    }
)


def _sanitize(value: Optional[str], *, field: str, strip_spaces: bool = False) -> str:
    raw = "" if value is None else str(value)
    out = raw.translate(_CHAR_MAP)
    out = re.sub(r"\s+", "", out) if strip_spaces else out.strip()
    out = out.encode("latin-1", errors="ignore").decode("latin-1")
    if out != raw:
        logger.debug(
            "header sanitized: field={} original_len={} sanitized_len={}",
            field,
            len(raw),
            len(out),
        )
    return out


# ---------------------------------------------------------------------------
# Statsig / request-id generation
# ---------------------------------------------------------------------------


# Client-side signature cache: {"METHOD|path": (signature, expiry_ts)}.
# Safe without locking — _statsig_id is synchronous and the asyncio event loop
# is single-threaded, so concurrent coroutines never interleave inside it.
_SIG_CACHE: dict[str, tuple[str, float]] = {}
_SIG_CACHE_MAX = 512
# Negative cache: after a signer failure, skip remote calls until this monotonic
# deadline so a dead/slow signer can't block the event loop on every request.
_SIGNER_FAIL_UNTIL: float = 0.0


def _cache_put(key: str, sig: str, exp: float) -> None:
    if len(_SIG_CACHE) >= _SIG_CACHE_MAX:
        now = time.monotonic()
        for k in [k for k, (_, e) in _SIG_CACHE.items() if e <= now]:
            _SIG_CACHE.pop(k, None)
        if len(_SIG_CACHE) >= _SIG_CACHE_MAX:
            _SIG_CACHE.clear()
    _SIG_CACHE[key] = (sig, exp)


def _fetch_remote_statsig(
    signer_url: str, path: str, method: str, timeout: float
) -> Optional[str]:
    """Request a real x-statsig-id from the signer service.

    Synchronous (briefly blocks the event loop). Returns the signature on
    success, ``None`` on any failure so the caller can fall back to the fake
    value without aborting the request.
    """
    body = json.dumps({"path": path, "method": method}).encode()
    req = urllib.request.Request(
        signer_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        sig = data.get("statsig")
        return sig if isinstance(sig, str) and sig else None
    except Exception as exc:
        logger.warning("statsig signer request failed: url={} err={}", signer_url, exc)
        return None


def _fake_statsig_id(cfg) -> str:
    # 前缀必须是 x1: —— grok 前端 Statsig 评估失败时回退到 btoa("x1:" + error)，
    # 新版反爬严格校验该格式，老的 e: 前缀已被识破直接 403。
    if cfg.get_bool("features.dynamic_statsig", False):
        if random.choice((True, False)):
            rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
            msg = f"x1:TypeError: Cannot read properties of null (reading 'children[\\'{rand}\\']')"
        else:
            rand = "".join(random.choices(string.ascii_lowercase, k=10))
            msg = f"x1:TypeError: Cannot read properties of undefined (reading '{rand}')"
        return base64.b64encode(msg.encode()).decode()
    return (
        "eDE6VHlwZUVycm9yOiBDYW5ub3QgcmVhZCBwcm9wZXJ0aWVzIG9mIHVuZGVmaW5lZCAocmVhZGluZyAn"
        "Y2hpbGROb2Rlcycp"
    )


# Per-key single-flight locks: collapse concurrent cache misses on the same
# path into one signer call. Lazily created inside the running loop. Some paths
# embed an id (e.g. asset deletes), so the key set is unbounded — cap the dict
# and evict currently-unheld locks when it grows too large.
_SIG_LOCKS: dict[str, asyncio.Lock] = {}
_SIG_LOCKS_MAX = 512


async def resolve_statsig_id(path: str = "", method: str = "POST") -> str:
    """Async counterpart of :func:`_statsig_id`.

    Same cache/cooldown semantics, but the (CPU-bound, possibly slow) signer
    request runs in a thread so it never blocks the event loop, and a per-path
    single-flight lock ensures the signer is hit at most once per TTL regardless
    of concurrency.
    """
    global _SIGNER_FAIL_UNTIL
    cfg = get_config()
    signer_url = cfg.get_str("statsig.signer_url", "").strip()
    if not (signer_url and path):
        return _fake_statsig_id(cfg)

    ttl = cfg.get_float("statsig.cache_ttl", 20.0)
    key = f"{method}|{path}"
    now = time.monotonic()
    if ttl > 0:
        cached = _SIG_CACHE.get(key)
        if cached and cached[1] > now:
            return cached[0]

    lock = _SIG_LOCKS.get(key)
    if lock is None:
        if len(_SIG_LOCKS) >= _SIG_LOCKS_MAX:
            for k in [k for k, lk in _SIG_LOCKS.items() if not lk.locked()]:
                _SIG_LOCKS.pop(k, None)
        lock = asyncio.Lock()
        _SIG_LOCKS[key] = lock

    async with lock:
        # Re-check: a prior holder of the lock may have just populated the cache.
        now = time.monotonic()
        if ttl > 0:
            cached = _SIG_CACHE.get(key)
            if cached and cached[1] > now:
                return cached[0]
        if now >= _SIGNER_FAIL_UNTIL:
            timeout = cfg.get_float("statsig.timeout", 5.0)
            loop = asyncio.get_running_loop()
            sig = await loop.run_in_executor(
                None, _fetch_remote_statsig, signer_url, path, method, timeout
            )
            if sig:
                _SIGNER_FAIL_UNTIL = 0.0
                if ttl > 0:
                    _cache_put(key, sig, now + ttl)
                return sig
            _SIGNER_FAIL_UNTIL = now + cfg.get_float("statsig.fail_cooldown", 5.0)
    return _fake_statsig_id(cfg)


# ---------------------------------------------------------------------------
# Client-hints helpers
# ---------------------------------------------------------------------------


def _major_version(browser: Optional[str], ua: Optional[str]) -> Optional[str]:
    for src in (browser or "", ua or ""):
        m = re.search(r"(\d{2,3})", src)
        if m:
            return m.group(1)
    return None


def _platform(ua: str) -> Optional[str]:
    u = ua.lower()
    if "windows" in u:
        return "Windows"
    if "mac os x" in u or "macintosh" in u:
        return "macOS"
    if "android" in u:
        return "Android"
    if "iphone" in u or "ipad" in u:
        return "iOS"
    if "linux" in u:
        return "Linux"
    return None


def _arch(ua: str) -> Optional[str]:
    u = ua.lower()
    if "aarch64" in u or "arm" in u:
        return "arm"
    if "x86_64" in u or "x64" in u or "win64" in u or "intel" in u:
        return "x86"
    return None


def _client_hints(browser: Optional[str], ua: Optional[str]) -> dict[str, str]:
    b = (browser or "").lower()
    u = (ua or "").lower()
    is_chromium = any(k in b for k in ("chrome", "chromium", "edge", "brave")) or any(
        k in u for k in ("chrome", "chromium", "edg")
    )
    if not is_chromium or "firefox" in u or ("safari" in u and "chrome" not in u):
        return {}
    ver = _major_version(browser, ua)
    if not ver:
        return {}
    if "edge" in b or "edg" in u:
        brand = "Microsoft Edge"
    elif "brave" in b:
        brand = "Brave"
    elif "chromium" in b:
        brand = "Chromium"
    else:
        brand = "Google Chrome"

    sec_ch_ua = f'"{brand}";v="{ver}", "Chromium";v="{ver}", "Not(A:Brand";v="24"'
    plat = _platform(ua or "")
    arch = _arch(ua or "")
    mobile = "?1" if ("mobile" in u or plat in ("Android", "iOS")) else "?0"

    hints: dict[str, str] = {
        "Sec-Ch-Ua": sec_ch_ua,
        "Sec-Ch-Ua-Mobile": mobile,
        "Sec-Ch-Ua-Model": "",
    }
    if plat:
        hints["Sec-Ch-Ua-Platform"] = f'"{plat}"'
    if arch:
        hints["Sec-Ch-Ua-Arch"] = arch
        hints["Sec-Ch-Ua-Bitness"] = "64"
    return hints


# ---------------------------------------------------------------------------
# Lease resolution
# ---------------------------------------------------------------------------


def _resolve_profile(lease: ProxyLease | None) -> ProxyProfile:
    return resolve_proxy_profile(lease)


# ---------------------------------------------------------------------------
# Public builders
# ---------------------------------------------------------------------------


def build_sso_cookie(
    sso_token: str,
    *,
    lease: ProxyLease | None = None,
    cf_cookies: str | None = None,
    cf_clearance: str | None = None,
) -> str:
    """Build the Cookie header value for an SSO-authenticated request.

    When *cf_clearance* is not provided, the value is resolved from the lease's
    cf_cookies profile or falls back to the config's cf_clearance (supporting
    both ``proxy.clearance.cf_clearance`` and legacy ``proxy.cf_clearance`` paths).
    Historical bug: earlier v2.0 releases silently defaulted cf_clearance to the
    empty string when not passed explicitly, causing Cookies without a CF
    clearance token and immediate 403 from Cloudflare on every grok.com call.
    """
    tok = sso_token[4:] if sso_token.startswith("sso=") else sso_token
    tok = _sanitize(tok, field="sso_token", strip_spaces=True)

    cookie = f"sso={tok}; sso-rw={tok}"
    profile = _resolve_profile(lease)
    eff_cookies = _sanitize(
        cf_cookies if cf_cookies is not None else profile.cf_cookies, field="cf_cookies"
    )
    eff_clearance = _sanitize(
        cf_clearance if cf_clearance is not None else profile.cf_clearance,
        field="cf_clearance",
        strip_spaces=True,
    )

    if eff_clearance and eff_cookies:
        if re.search(r"(?:^|;\s*)cf_clearance=", eff_cookies):
            eff_cookies = re.sub(
                r"(^|;\s*)cf_clearance=[^;]*",
                r"\1cf_clearance=" + eff_clearance,
                eff_cookies,
                count=1,
            )
        else:
            eff_cookies = f"{eff_cookies.rstrip('; ')}; cf_clearance={eff_clearance}"
    elif eff_clearance:
        eff_cookies = f"cf_clearance={eff_clearance}"

    if eff_cookies:
        cookie += f"; {eff_cookies}"
    return cookie


async def build_http_headers(
    cookie_token: str,
    *,
    content_type: Optional[str] = None,
    origin: Optional[str] = None,
    referer: Optional[str] = None,
    lease: ProxyLease | None = None,
    url: Optional[str] = None,
    method: str = "POST",
) -> dict[str, str]:
    """Build headers for a standard HTTP reverse-proxy request.

    Pass *url* (and *method*) for grok.com API endpoints so a real
    ``x-statsig-id`` can be signed for that request path; omit them for
    non-grok requests (the fake fallback value is used instead).
    """
    profile = _resolve_profile(lease)
    raw_ua = profile.user_agent
    ua = _sanitize(raw_ua, field="user_agent")
    browser = profile.browser
    org = _sanitize(origin or "https://grok.com", field="origin")
    ref = _sanitize(referer or "https://grok.com/", field="referer")

    ct = content_type or "application/json"
    if ct == "application/json":
        accept = "*/*"
        fd = "empty"
    elif ct in ("image/jpeg", "image/png", "video/mp4", "video/webm"):
        accept = (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8"
        )
        fd = "document"
    else:
        accept = "*/*"
        fd = "empty"

    org_host = urlparse(org).hostname
    ref_host = urlparse(ref).hostname
    site = "same-origin" if org_host and org_host == ref_host else "same-site"

    headers: dict[str, str] = {
        "Accept": accept,
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Baggage": (
            "sentry-environment=production,"
            "sentry-release=d6add6fb0460641fd482d767a335ef72b9b6abb8,"
            "sentry-public_key=b311e0f2690c81f25e2c4cf6d4f7ce1c"
        ),
        "Content-Type": ct,
        "Origin": org,
        "Priority": "u=1, i",
        "Referer": ref,
        "Sec-Fetch-Dest": fd,
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": site,
        "User-Agent": ua,
        "x-statsig-id": await resolve_statsig_id(
            urlparse(url).path if url else "", method
        ),
        "x-xai-request-id": str(uuid.uuid4()),
    }
    headers.update(_client_hints(browser, raw_ua))
    headers["Cookie"] = build_sso_cookie(cookie_token, lease=lease)

    logger.debug("http headers built: header_count={}", len(headers))
    return headers


def build_ws_headers(
    token: Optional[str] = None,
    *,
    origin: Optional[str] = None,
    extra: Optional[dict[str, str]] = None,
    lease: ProxyLease | None = None,
) -> dict[str, str]:
    """Build headers for a WebSocket upgrade request."""
    profile = _resolve_profile(lease)
    raw_ua = profile.user_agent
    ua = _sanitize(raw_ua, field="user_agent")
    browser = profile.browser
    org = _sanitize(origin or "https://grok.com", field="origin")

    headers: dict[str, str] = {
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Cache-Control": "no-cache",
        "Origin": org,
        "Pragma": "no-cache",
        "User-Agent": ua,
    }
    headers.update(_client_hints(browser, raw_ua))
    if token:
        headers["Cookie"] = build_sso_cookie(token, lease=lease)
    if extra:
        headers.update(extra)
    return headers


__all__ = ["build_http_headers", "build_sso_cookie", "build_ws_headers"]
