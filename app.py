import getpass
import hmac
import html
import logging
import os
import re
import secrets
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timedelta
from functools import wraps

import requests
import whois
from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("domain-checker")

app = Flask(__name__)
# Render đứng sau proxy → lấy đúng IP / scheme thật của client
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def _int_env(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _float_env(name, default):
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# ==========================================
# CẤU HÌNH
# ==========================================
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")
CF_MIN_INTERVAL = _float_env("CF_MIN_INTERVAL", 0.35)      # giây giữa 2 lần gọi CF (tránh rate limit)

IS_RENDER = bool(os.environ.get("RENDER"))
_secret = os.environ.get("SECRET_KEY", "")
if not _secret:
    _secret = secrets.token_hex(32)
    log.warning("SECRET_KEY chưa được đặt → dùng khóa ngẫu nhiên; phiên đăng nhập sẽ mất mỗi lần restart. "
                "Hãy đặt SECRET_KEY cố định trong Environment của Render.")

app.config.update(
    SECRET_KEY=_secret,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_RENDER,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=_int_env("SESSION_HOURS", 12)),
    MAX_CONTENT_LENGTH=64 * 1024,
)

API_LIMIT_PER_MIN = _int_env("API_LIMIT_PER_MIN", 120)     # số lượt /api/check mỗi user mỗi phút
LOGIN_MAX_FAILS = _int_env("LOGIN_MAX_FAILS", 5)           # số lần sai tối đa
LOGIN_WINDOW_SEC = _int_env("LOGIN_WINDOW_SEC", 600)       # trong khoảng thời gian này
LOOKUP_BUDGET_SEC = _int_env("LOOKUP_BUDGET_SEC", 22)      # tổng thời gian tối đa tra cứu 1 domain

HTTP_HEADERS = {
    "User-Agent": "DomainBuyChecker/2.0",
    "Accept": "application/rdap+json, application/json;q=0.9, */*;q=0.5",
}


# ==========================================
# ĐĂNG NHẬP / BẢO MẬT
# ==========================================
def load_users():
    """APP_USERS="user1:secret1;user2:secret2"  (secret = hash werkzeug hoặc mật khẩu thường)"""
    users = {}
    for item in os.environ.get("APP_USERS", "").split(";"):
        item = item.strip()
        if ":" not in item:
            continue
        name, secret = item.split(":", 1)
        name, secret = name.strip(), secret.strip()
        if name and secret:
            users[name] = secret
    return users


USERS = load_users()
if not USERS:
    log.warning("APP_USERS chưa được cấu hình → app sẽ từ chối mọi truy cập (fail-closed).")

_DUMMY_HASH = generate_password_hash("dummy-password")


def verify_password(username, password):
    stored = USERS.get(username)
    if stored is None:
        check_password_hash(_DUMMY_HASH, password)   # giữ thời gian xử lý gần như nhau
        return False
    if stored.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored, password)
    return hmac.compare_digest(stored.encode("utf-8"), password.encode("utf-8"))


class RateLimiter:
    """Sliding window trong RAM (đủ dùng cho 1 worker)."""

    def __init__(self):
        self._hits = {}
        self._lock = threading.Lock()

    def _prune(self, key, window, now):
        q = [t for t in self._hits.get(key, []) if now - t < window]
        if q:
            self._hits[key] = q
        else:
            self._hits.pop(key, None)
        return q

    def blocked(self, key, limit, window):
        with self._lock:
            return len(self._prune(key, window, time.monotonic())) >= limit

    def hit(self, key, window):
        with self._lock:
            now = time.monotonic()
            self._prune(key, window, now)
            self._hits.setdefault(key, []).append(now)

    def clear(self, key):
        with self._lock:
            self._hits.pop(key, None)


login_limiter = RateLimiter()
api_limiter = RateLimiter()


def _csrf_ok(token):
    expected = session.get("csrf")
    if not expected or not token:
        return False
    return hmac.compare_digest(str(expected).encode("utf-8"), str(token).encode("utf-8"))


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not USERS:
            return "Chưa cấu hình APP_USERS trên server.", 503
        if "user" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def api_guard(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if not USERS or not user:
            return jsonify(error="unauthorized", failed=True), 401
        if not _csrf_ok(request.headers.get("X-CSRF-Token", "")):
            return jsonify(error="csrf", failed=True), 403
        if api_limiter.blocked(user, API_LIMIT_PER_MIN, 60):
            return jsonify(error="rate_limited", failed=True), 429
        api_limiter.hit(user, 60)
        return view(*args, **kwargs)
    return wrapper


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data: https://cdn-icons-png.flaticon.com; "
        "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    )
    if request.path != "/healthz":
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ==========================================
# VALIDATE DOMAIN
# ==========================================
DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)

# ==========================================
# TIÊU CHÍ CẤM THEO REGISTRAR
# ==========================================
# Namecheap: .ch .li .cn .au .fr .ca .eu .eco .uk (chỉ .uk thuần)
#            + .in có chứa "india"
# GoDaddy:   TẤT CẢ .in (kể cả .co.in .net.in ...), .cz .eu .dk
# Dynadot:   .it .org
# Spaceship: .de (cho phép .uk .my)
# SAV:       chưa có lưu ý

NAMECHEAP_BANNED_TLDS = {".ch", ".li", ".cn", ".au", ".fr", ".ca", ".eu", ".eco", ".uk"}
GODADDY_BANNED_TLDS = {".cz", ".eu", ".dk"}  # + tất cả đuôi .in
DYNADOT_BANNED_TLDS = {".it", ".org"}
SPACESHIP_BANNED_TLDS = {".de"}

# Nhãn cấp 2 thường gặp dưới ccTLD (co.uk, org.uk, com.au, co.in, ...)
SECOND_LEVEL_LABELS = {
    "co", "com", "org", "net", "me", "ltd", "plc", "gov", "ac", "edu", "sch", "nic",
    "firm", "gen", "ind", "res", "mil", "info", "biz", "ne", "or", "go", "ed", "id",
    "asn", "web", "nom",
}


def get_tld_parts(domain: str):
    """Trả về (full_suffix, last_tld). Ví dụ: ('.co.uk', '.uk'), ('.in', '.in'), ('.uk', '.uk')
    Chỉ coi là suffix 2 cấp khi TLD là ccTLD 2 ký tự và nhãn liền trước thuộc SECOND_LEVEL_LABELS
    → 'blog.example.uk' vẫn được hiểu là .uk thuần."""
    parts = domain.lower().strip().rstrip(".").split(".")
    if len(parts) < 2:
        return "", ""
    last = "." + parts[-1]
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL_LABELS:
        return "." + parts[-2] + "." + parts[-1], last
    return last, last


def _match_banned(full_suffix, last_tld, banned):
    if full_suffix in banned:
        return full_suffix
    if last_tld in banned:
        return last_tld
    return None


def check_buyability(domain: str):
    """Trả về ({registrar: {"ok": bool, "reason": str}}, can_buy)
    can_buy = True nếu có ÍT NHẤT 1 registrar cho phép."""
    domain = domain.lower().strip()
    full_suffix, last_tld = get_tld_parts(domain)
    results = {}

    # ---------- Namecheap ----------
    reason = ""
    if last_tld == ".uk":
        if full_suffix == ".uk":                      # chỉ cấm .uk thuần
            reason = "Cấm đuôi .uk thuần"
    else:
        hit = _match_banned(full_suffix, last_tld, NAMECHEAP_BANNED_TLDS)
        if hit:
            reason = f"Cấm đuôi {hit}"
    if not reason and last_tld == ".in" and "india" in domain:
        reason = 'Domain .in chứa "india"'
    results["Namecheap"] = {"ok": not reason, "reason": reason}

    # ---------- GoDaddy ----------
    reason = ""
    if last_tld == ".in":
        reason = f"Cấm mọi đuôi .in ({full_suffix})"
    else:
        hit = _match_banned(full_suffix, last_tld, GODADDY_BANNED_TLDS)
        if hit:
            reason = f"Cấm đuôi {hit}"
    results["GoDaddy"] = {"ok": not reason, "reason": reason}

    # ---------- Dynadot ----------
    hit = _match_banned(full_suffix, last_tld, DYNADOT_BANNED_TLDS)
    results["Dynadot"] = {"ok": not hit, "reason": f"Cấm đuôi {hit}" if hit else ""}

    # ---------- Spaceship ----------
    hit = _match_banned(full_suffix, last_tld, SPACESHIP_BANNED_TLDS)
    results["Spaceship"] = {"ok": not hit, "reason": f"Cấm đuôi {hit}" if hit else ""}

    # ---------- SAV (luôn cho phép) ----------
    results["SAV"] = {"ok": True, "reason": ""}

    return results, any(r["ok"] for r in results.values())


def _badge(cls, text):
    return f"<span class='badge {cls}'>{text}</span>"


def format_buyability_html(results, tld_ok, state, cf=None):
    """
    Trạng thái mua cuối cùng cho SEOer:
    - registered   → ĐÃ ĐĂNG KÝ
    - restricted   → KHÔNG MUA ĐƯỢC (Registry Policy)
    - unknown      → CHƯA XÁC ĐỊNH (tra cứu lỗi, cần Retry)
    - unregistered → CÓ THỂ MUA (kèm registrar nào cho / cấm) hoặc KHÔNG MUA ĐƯỢC (CF ban / TLD cấm)
    """
    cf = cf or {}
    if state == "registered":
        return _badge("badge-muted", "ĐÃ ĐĂNG KÝ")
    if state == "restricted":
        return (_badge("badge-danger", "KHÔNG MUA ĐƯỢC")
                + "<div class='buy-reason'>⛔ Bị Registry Policy cấm đăng ký</div>")
    if state == "unknown":
        return (_badge("badge-warning", "CHƯA XÁC ĐỊNH")
                + "<div class='buy-reason'>Không tra cứu được WHOIS/RDAP — bấm Retry lỗi</div>")
    if cf.get("failed"):
        return (_badge("badge-warning", "CHƯA XÁC ĐỊNH")
                + "<div class='buy-reason'>Lỗi kiểm tra Cloudflare — bấm Retry lỗi</div>")

    banned = [(n, i["reason"] or "TLD bị cấm") for n, i in results.items() if not i["ok"]]
    allowed = [n for n, i in results.items() if i["ok"]]
    ban_tags = " ".join(
        f"<span class='ban-tag' title='{html.escape(reason, quote=True)}'>{html.escape(name)}</span>"
        for name, reason in banned
    )
    cf_blocked = bool(cf.get("blocked"))

    if tld_ok and not cf_blocked:
        out = [_badge("badge-success", "CÓ THỂ MUA")]
        if banned:
            ok_tags = " ".join(_badge("badge-success", html.escape(n)) for n in allowed)
            out.append(f"<div class='buy-detail'><span class='skipped'>Mua được tại:</span> {ok_tags}</div>")
            out.append(f"<div class='buy-reason'>⛔ Cấm tại: {ban_tags}</div>")
        else:
            out.append("<div class='buy-detail'><span class='skipped'>Mọi registrar đều cho phép</span></div>")
        return "".join(out)

    out = [_badge("badge-danger", "KHÔNG MUA ĐƯỢC")]
    if banned:
        out.append(f"<div class='buy-reason'>⛔ Cấm tại: {ban_tags}</div>")
    if cf_blocked:
        detail = {
            1097: "Cloudflare BANNED",
            1095: "Cloudflare chặn thêm domain",
            1116: "Đuôi TLD bị Cloudflare cấm",
        }.get(cf.get("code"), "Cloudflare Banned / TLD bị CF cấm")
        out.append(f"<div class='buy-reason'>⛔ {detail}</div>")
    return "".join(out)


# ==========================================
# 1. XỬ LÝ DỮ LIỆU DOMAIN
# ==========================================
def format_date_short(dt):
    """datetime / ISO string / list → DD/MM/YY"""
    if not dt:
        return None
    if isinstance(dt, (list, tuple)):
        dt = dt[0] if dt else None
    if isinstance(dt, datetime):
        return dt.strftime("%d/%m/%y")
    if isinstance(dt, str):
        m = re.search(r"(\d{4})-(\d{2})-(\d{2})", dt)
        if m:
            return f"{m.group(3)}/{m.group(2)}/{m.group(1)[2:]}"
    return None


_STATUS_KEYS = [
    "serverHold", "clientHold", "clientTransferProhibited", "serverTransferProhibited",
    "pendingTransfer", "clientUpdateProhibited", "serverUpdateProhibited",
    "clientDeleteProhibited", "serverDeleteProhibited", "redemptionPeriod", "pendingDelete",
    "addPeriod", "autoRenewPeriod", "renewPeriod", "transferPeriod",
    "pendingRestore", "pendingCreate", "pendingRenew", "pendingUpdate", "inactive",
]
# khóa dài so khớp trước (autoRenewPeriod trước renewPeriod)
_STATUS_LOOKUP = sorted(((k.lower(), k) for k in _STATUS_KEYS), key=lambda kv: -len(kv[0]))


def _normalize_status(s):
    """Chuẩn hóa 1 status string → key chuẩn (hoặc None)"""
    s = re.sub(r"[\s_\-]", "", str(s).lower())
    for lowered, key in _STATUS_LOOKUP:
        if lowered in s:
            return key
    if s.startswith(("ok", "active")):
        return "ok"
    return None


def _parse_rdap_json(data):
    """RDAP JSON → (status_set, registrar, created, expires)"""
    status_found, registrar, created, expires = set(), None, None, None
    if not isinstance(data, dict):
        return status_found, registrar, created, expires

    for s in data.get("status") or []:
        key = _normalize_status(s)
        if key:
            status_found.add(key)

    for ent in data.get("entities") or []:
        if not isinstance(ent, dict) or "registrar" not in (ent.get("roles") or []):
            continue
        vcard = ent.get("vcardArray") or []
        if len(vcard) > 1:
            for prop in vcard[1]:
                if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
                    registrar = prop[3]
                    break
        if not registrar:
            registrar = ent.get("handle") or ent.get("name")

    for ev in data.get("events") or []:
        action = str(ev.get("eventAction", "")).lower()
        date_str = ev.get("eventDate")
        if not date_str:
            continue
        if action in ("registration", "registered"):
            created = format_date_short(date_str)
        elif action in ("expiration", "expiry", "expired", "registrar expiration"):
            expires = format_date_short(date_str)
    return status_found, registrar, created, expires


def _parse_generic_json(data):
    """Parser dùng chung cho who-dat / rdap.cloud (JSON tự do + có thể lồng RDAP)."""
    status_found, registrar, created, expires = set(), None, None, None
    if not isinstance(data, dict):
        return status_found, registrar, created, expires

    reg_val = data.get("registrar")
    if isinstance(reg_val, str) and reg_val.strip():
        registrar = reg_val.strip()
    elif isinstance(reg_val, dict):
        registrar = reg_val.get("name") or reg_val.get("organization")

    statuses = data.get("status") or data.get("statuses") or []
    if isinstance(statuses, str):
        statuses = [statuses]
    for s in statuses:
        key = _normalize_status(s)
        if key:
            status_found.add(key)

    for k in ("created", "creationDate", "creation_date", "registered"):
        if data.get(k):
            created = format_date_short(data[k])
            break
    for k in ("expires", "expirationDate", "expiration_date", "expiry"):
        if data.get(k):
            expires = format_date_short(data[k])
            break

    for sub in (data, data.get("rdap")):
        st, reg, cr, exp = _parse_rdap_json(sub)
        status_found |= st
        registrar = registrar or reg
        created = created or cr
        expires = expires or exp
    return status_found, registrar, created, expires


_STATUS_LABELS = {
    "serverHold": ("serverHold", "badge-danger"),
    "clientHold": ("clientHold", "badge-danger"),
    "clientTransferProhibited": ("Khóa Transfer (Client)", "badge-warning"),
    "serverTransferProhibited": ("Khóa Transfer (Server)", "badge-warning"),
    "pendingTransfer": ("Đang chuyển Registrar", "badge-orange"),
    "clientUpdateProhibited": ("Khóa Update", "badge-muted"),
    "serverUpdateProhibited": ("Khóa Update (Server)", "badge-muted"),
    "clientDeleteProhibited": ("Khóa Delete", "badge-muted"),
    "serverDeleteProhibited": ("Khóa Delete (Server)", "badge-muted"),
    "redemptionPeriod": ("Redemption Period", "badge-danger"),
    "pendingDelete": ("Pending Delete", "badge-danger"),
    "pendingRestore": ("Pending Restore", "badge-danger"),
    "autoRenewPeriod": ("Auto-Renew Grace Period", "badge-warning"),
    "renewPeriod": ("Renew Grace Period", "badge-warning"),
    "addPeriod": ("Add Grace Period", "badge-muted"),
    "transferPeriod": ("Transfer Grace Period", "badge-muted"),
    "pendingCreate": ("Pending Create", "badge-muted"),
    "pendingRenew": ("Pending Renew", "badge-muted"),
    "pendingUpdate": ("Pending Update", "badge-muted"),
    "inactive": ("Inactive (chưa có NS)", "badge-warning"),
    "ok": ("Active", "badge-success"),
}
_STATUS_PRIORITY = [
    "serverHold", "clientHold", "pendingTransfer", "redemptionPeriod", "pendingDelete",
    "pendingRestore", "autoRenewPeriod", "renewPeriod", "inactive",
    "clientTransferProhibited", "serverTransferProhibited",
    "clientUpdateProhibited", "serverUpdateProhibited",
    "clientDeleteProhibited", "serverDeleteProhibited",
    "addPeriod", "transferPeriod", "pendingCreate", "pendingRenew", "pendingUpdate", "ok",
]


def format_status_display(status_set):
    """set status → HTML badge, mỗi trạng thái 1 dòng"""
    if not status_set:
        return _badge("badge-success", "Active / Không bị lock")
    badges = []
    for key in _STATUS_PRIORITY:
        if key in status_set:
            text, cls = _STATUS_LABELS[key]
            badges.append(_badge(cls, text))
    return "<br>".join(badges) or _badge("badge-success", "Active / Không bị lock")


# ---------- nguồn tra cứu ----------
def _looks_restricted(resp):
    try:
        data = resp.json()
    except ValueError:
        return False
    desc = data.get("description") or []
    desc_text = " ".join(str(d) for d in desc) if isinstance(desc, list) else str(desc)
    full_text = (desc_text + " " + str(data.get("title", ""))).lower()
    return any(k in full_text for k in (
        "not available for registration", "restricted by registry policy", "registry policy", "prohibited",
    ))


def _fetch_json(url, timeout=(4, 7)):
    try:
        r = requests.get(url, timeout=timeout, headers=HTTP_HEADERS)
        if r.status_code == 200:
            return r.json()
    except (requests.RequestException, ValueError) as e:
        log.info("Nguồn %s lỗi: %s", url.split("/")[2], e)
    return None


_whois_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="whois")


def _whois_lookup(domain, timeout):
    """Trả về ('data', (status, registrar, created, expires)) | ('no_match', None) | ('error', None)"""
    try:
        fut = _whois_pool.submit(whois.whois, domain)
        w = fut.result(timeout=max(1.0, timeout))
    except FuturesTimeout:
        log.info("python-whois timeout: %s", domain)
        return "error", None
    except Exception as e:  # noqa: BLE001
        msg = str(e).lower()
        if e.__class__.__name__ == "PywhoisError" or "no match" in msg or "not found" in msg:
            return "no_match", None
        log.info("python-whois lỗi %s: %s", domain, e)
        return "error", None

    status = set()
    raw_status = getattr(w, "status", None)
    if isinstance(raw_status, str):
        raw_status = [raw_status]
    for s in raw_status or []:
        key = _normalize_status(s)
        if key:
            status.add(key)
    registrar = getattr(w, "registrar", None)
    created = format_date_short(getattr(w, "creation_date", None))
    expires = format_date_short(getattr(w, "expiration_date", None))
    if not registrar and not created:
        # python-whois hay trả domain_name cả khi chưa ĐK → không có registrar/ngày = không có bằng chứng
        return "no_match", None
    return "data", (status, registrar, created, expires)


def _unregistered_info():
    ok = _badge("badge-success", "Chưa đăng ký")
    return {"state": "unregistered", "status_html": ok, "registrar": ok, "created": None, "expires": None}


def get_domain_info(domain):
    """
    Trả về dict: state ∈ {registered, unregistered, restricted, unknown}, status_html, registrar, created, expires.

    - registered   : có registrar HOẶC ngày đăng ký (bằng chứng chắc chắn)
    - unregistered : RDAP 404 / nguồn trả rỗng VÀ whois xác nhận "no match"
    - restricted   : RDAP 404 kèm nội dung Registry Policy
    - unknown      : mọi nguồn lỗi / không đủ bằng chứng → KHÔNG được coi là "chưa đăng ký"
    """
    deadline = time.monotonic() + LOOKUP_BUDGET_SEC
    remaining = lambda: deadline - time.monotonic()  # noqa: E731

    status, registrar, created, expires = set(), None, None, None
    restricted = rdap_404 = empty_ok = False

    def merge(parsed):
        nonlocal status, registrar, created, expires
        st, reg, cr, exp = parsed
        status |= st
        registrar = registrar or reg
        created = created or cr
        expires = expires or exp

    # ---- 1. rdap.org ----
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=(4, 8), headers=HTTP_HEADERS)
        if r.status_code == 200:
            merge(_parse_rdap_json(r.json()))
        elif r.status_code == 404:
            rdap_404 = True
            restricted = _looks_restricted(r)
        else:
            log.info("rdap.org %s → HTTP %s", domain, r.status_code)
    except (requests.RequestException, ValueError) as e:
        log.info("rdap.org lỗi %s: %s", domain, e)

    def need_more():
        return not restricted and not (registrar or created)

    # ---- 2. who-dat / rdap.cloud (chỉ khi rdap.org không cho kết quả & không phải 404) ----
    if need_more() and not rdap_404:
        for url in (f"https://who-dat.as93.net/{domain}", f"https://rdap.cloud/api/v1/{domain}"):
            if remaining() <= 3:
                break
            data = _fetch_json(url, timeout=(4, min(7, remaining())))
            if data is not None:
                merge(_parse_generic_json(data))
                if need_more():
                    empty_ok = True
                else:
                    break

    # ---- 3. python-whois (xác nhận cuối) ----
    whois_no_match = False
    if need_more() and remaining() > 1:
        outcome, payload = _whois_lookup(domain, remaining())
        if outcome == "data":
            merge(payload)
        elif outcome == "no_match":
            whois_no_match = True

    # ---- Kết luận ----
    if restricted:
        return {
            "state": "restricted",
            "status_html": _badge("badge-danger", "Không thể đăng ký") + "<br>"
                           + _badge("badge-warning", "Restricted by Registry Policy"),
            "registrar": "Registry Policy", "created": None, "expires": None,
        }
    if registrar or created:
        reg_text = html.escape(str(registrar).strip()) if registrar else "Không xác định"
        return {
            "state": "registered",
            "status_html": format_status_display(status),
            "registrar": reg_text, "created": created, "expires": expires,
        }
    if (rdap_404 or empty_ok) and whois_no_match:
        return _unregistered_info()
    return {
        "state": "unknown",
        "status_html": _badge("badge-warning", "Không tra cứu được"),
        "registrar": "Không xác định", "created": None, "expires": None,
    }


# ==========================================
# 2. CLOUDFLARE
# ==========================================
_cf_lock = threading.Lock()
_cf_last_call = 0.0
CF_ZONES_URL = "https://api.cloudflare.com/client/v4/zones"


def _cf_throttle():
    """Giãn cách các lần gọi CF giữa mọi thread để tránh rate limit."""
    global _cf_last_call
    with _cf_lock:
        wait = CF_MIN_INTERVAL - (time.monotonic() - _cf_last_call)
        if wait > 0:
            time.sleep(wait)
        _cf_last_call = time.monotonic()


def _cf_delete_zone(zone_id, headers):
    """Xóa zone tạm, thử lại 3 lần. Trả True nếu đã xóa (hoặc không còn tồn tại)."""
    for attempt in range(3):
        try:
            _cf_throttle()
            r = requests.delete(f"{CF_ZONES_URL}/{zone_id}", headers=headers, timeout=8)
            if r.status_code in (200, 404):
                return True
            log.warning("Xóa zone %s thất bại: HTTP %s", zone_id, r.status_code)
        except requests.RequestException as e:
            log.warning("Xóa zone %s lỗi: %s", zone_id, e)
        time.sleep(1 + attempt)
    log.error("KHÔNG xóa được zone tạm %s — hãy dọn thủ công trong dashboard Cloudflare.", zone_id)
    return False


def _cf_result(html_, code=None, blocked=False, unregistered=False, failed=False):
    return {"html": html_, "code": code, "blocked": blocked, "unregistered": unregistered, "failed": failed}


def check_cf_eligibility(domain):
    """Thử add domain vào CF (rồi xóa ngay) để biết có bị Banned không. Trả về dict kết quả."""
    if not CF_API_TOKEN or not CF_ACCOUNT_ID:
        return _cf_result(_badge("badge-muted", "Thiếu API CF"))

    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    payload = {"name": domain, "account": {"id": CF_ACCOUNT_ID}, "type": "full"}
    try:
        _cf_throttle()
        r = requests.post(CF_ZONES_URL, headers=headers, json=payload, timeout=(5, 10))
    except requests.RequestException as e:
        log.warning("CF POST lỗi %s: %s", domain, e)
        return _cf_result(_badge("badge-danger", "Lỗi Call API CF"), failed=True)

    if r.status_code == 429 or r.status_code >= 500:
        log.warning("CF HTTP %s cho %s", r.status_code, domain)
        return _cf_result(_badge("badge-warning", "CF quá tải / rate limit"), failed=True)
    try:
        resp = r.json()
    except ValueError:
        return _cf_result(_badge("badge-muted", "Lỗi CF: phản hồi không hợp lệ"), failed=True)

    if r.status_code == 200 and resp.get("success"):
        zone_id = (resp.get("result") or {}).get("id")
        html_ = _badge("badge-success", "Sạch")
        if zone_id and not _cf_delete_zone(zone_id, headers):
            html_ += "<br>" + _badge("badge-warning", "Zone tạm chưa xóa")
        return _cf_result(html_)

    errors = resp.get("errors") or []
    code = errors[0].get("code") if errors else None
    if code == 1049:
        return _cf_result(_badge("badge-info", "Sạch (Chưa ĐK)"), code, unregistered=True)
    if code == 1097:
        return _cf_result(_badge("badge-danger", "BANNED"), code, blocked=True)
    if code == 1095:
        return _cf_result(_badge("badge-danger", "Bị CF Chặn Add"), code, blocked=True)
    if code == 1116:
        return _cf_result(_badge("badge-warning", "Đuôi TLD bị CF cấm"), code, blocked=True)
    if code == 1061:
        return _cf_result(_badge("badge-success", "Sạch (Đã nằm trong CF khác)"), code)
    if code is not None:
        log.info("CF trả mã lạ %s cho %s", code, domain)
        return _cf_result(_badge("badge-muted", f"Lỗi CF: {code}"), code)
    return _cf_result(_badge("badge-muted", "Không rõ trạng thái"))


# ==========================================
# 3. GIAO DIỆN WEB
# ==========================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Buy Checker — Ares</title>
    <link rel="icon" type="image/png" href="https://cdn-icons-png.flaticon.com/512/15435/15435750.png">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0b0f19;
            --bg-card: #111827;
            --bg-elevated: #1a2234;
            --border: #1e293b;
            --border-light: #334155;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --text-dim: #64748b;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --success: #22c55e;
            --danger: #ef4444;
            --warning: #f59e0b;
            --orange: #f97316;
            --info: #06b6d4;
            --accent: #8b5cf6;
            --radius: 12px;
            --radius-sm: 8px;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            line-height: 1.5;
            background-image:
                radial-gradient(ellipse 80% 50% at 50% -20%, rgba(59, 130, 246, 0.15), transparent),
                radial-gradient(ellipse 60% 40% at 100% 100%, rgba(139, 92, 246, 0.08), transparent);
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 32px 24px 60px;
        }
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 28px;
            flex-wrap: wrap;
            gap: 16px;
        }
        .logo {
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .logo-icon {
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            box-shadow: 0 0 24px rgba(59, 130, 246, 0.35);
        }
        .logo h1 {
            font-size: 1.5rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            background: linear-gradient(90deg, #e2e8f0, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .logo p {
            font-size: 0.8rem;
            color: var(--text-dim);
            margin-top: 2px;
        }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 24px;
            margin-bottom: 16px;
            box-shadow: 0 4px 24px rgba(0,0,0,0.25);
        }
        textarea {
            width: 100%;
            height: 130px;
            padding: 14px 16px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            color: var(--text);
            font-family: 'JetBrains Mono', monospace;
            font-size: 13.5px;
            resize: vertical;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        textarea:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }
        textarea::placeholder { color: var(--text-dim); }
        .action-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 16px;
            align-items: center;
        }
        button {
            border: none;
            padding: 10px 18px;
            font-size: 14px;
            font-weight: 600;
            border-radius: var(--radius-sm);
            cursor: pointer;
            transition: all 0.2s;
            font-family: inherit;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6, #2563eb);
            color: white;
            box-shadow: 0 2px 12px rgba(59, 130, 246, 0.35);
        }
        .btn-primary:hover:not(:disabled) {
            transform: translateY(-1px);
            box-shadow: 0 4px 16px rgba(59, 130, 246, 0.45);
        }
        .btn-secondary {
            background: var(--bg-elevated);
            color: var(--text);
            border: 1px solid var(--border-light);
        }
        .btn-secondary:hover { background: #243044; }
        .btn-warning {
            background: linear-gradient(135deg, #f59e0b, #d97706);
            color: #111;
        }
        .btn-warning:hover:not(:disabled) { transform: translateY(-1px); }
        button:disabled {
            opacity: 0.45;
            cursor: not-allowed;
            transform: none !important;
            box-shadow: none !important;
        }
        .delay-box {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-left: auto;
            font-size: 13px;
            color: var(--text-muted);
        }
        .delay-box input {
            width: 80px;
            padding: 8px 10px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            font-size: 13px;
            font-family: 'JetBrains Mono', monospace;
        }
        .delay-box input:focus {
            outline: none;
            border-color: var(--primary);
        }
        .progress {
            margin-top: 14px;
            font-size: 13.5px;
            color: var(--text-muted);
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .progress-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--primary);
            animation: pulse 1.4s ease infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.85); }
        }
        /* Legend */
        .legend {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 16px 20px;
            margin-bottom: 16px;
            display: none;
        }
        .legend.show { display: block; }
        .legend-title {
            font-size: 11px;
            font-weight: 600;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 0.07em;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .legend-groups {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px 28px;
        }
        .legend-group { display: none; }
        .legend-group.show { display: block; }
        .legend-group-title {
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 8px;
            padding-bottom: 4px;
            border-bottom: 1px solid var(--border);
        }
        .legend-rows {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .legend-row {
            display: none;
            align-items: center;
            gap: 10px;
            font-size: 12.5px;
            color: var(--text-muted);
            line-height: 1.35;
        }
        .legend-row.show { display: flex; }
        .legend-row .badge {
            flex-shrink: 0;
            min-width: 148px;
            text-align: center;
        }
        @media (max-width: 780px) {
            .legend-groups { grid-template-columns: 1fr; }
            .legend-row .badge { min-width: 130px; }
        }
        /* Badges */
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11.5px;
            font-weight: 600;
            letter-spacing: 0.01em;
            white-space: nowrap;
        }
        .badge-success { background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.25); }
        .badge-danger  { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.25); }
        .badge-warning { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.25); }
        .badge-orange  { background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.25); }
        .badge-info    { background: rgba(6, 182, 212, 0.15); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.25); }
        .badge-muted   { background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.25); }
        .buy-detail {
            margin-top: 6px;
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
        }
        .buy-detail .badge { font-size: 10.5px; padding: 2px 8px; }
        .buy-reason {
            margin-top: 5px;
            font-size: 11.5px;
            color: #f87171;
            line-height: 1.5;
        }
        .ban-tag {
            display: inline-block;
            background: rgba(239, 68, 68, 0.18);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 6px;
            padding: 1px 7px;
            font-size: 11px;
            font-weight: 600;
            margin: 1px 2px;
        }
        .note-box {
            background: rgba(245, 158, 11, 0.08);
            border: 1px solid rgba(245, 158, 11, 0.25);
            border-radius: var(--radius-sm);
            padding: 12px 16px;
            margin-bottom: 16px;
            font-size: 13px;
            color: #fbbf24;
            line-height: 1.55;
            display: flex;
            gap: 10px;
            align-items: flex-start;
        }
        .note-box .note-icon {
            flex-shrink: 0;
            font-size: 16px;
            margin-top: 1px;
        }
        /* Table */
        .table-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            overflow: hidden;
            box-shadow: 0 4px 24px rgba(0,0,0,0.25);
        }
        .table-wrapper { overflow-x: auto; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13.5px;
            min-width: 900px;
        }
        th {
            background: var(--bg-elevated);
            color: var(--text-muted);
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }
        td {
            padding: 13px 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
            white-space: nowrap;
        }
        td.status-cell, td.buy-cell {
            white-space: normal;
            line-height: 1.8;
        }
        tbody tr { transition: background 0.15s; }
        tbody tr:hover { background: rgba(59, 130, 246, 0.04); }
        tbody tr:last-child td { border-bottom: none; }
        .domain-cell {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 500;
            font-size: 13px;
            color: #93c5fd;
        }
        .date-cell {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12.5px;
            color: var(--text-muted);
        }
        .skipped { color: var(--text-dim); font-style: italic; font-size: 12.5px; }
        .error-cell { color: #f87171; }
        /* Rules card */
        .rules-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 16px 20px;
            margin-bottom: 16px;
            font-size: 13px;
            color: var(--text-muted);
        }
        .rules-card h3 {
            font-size: 13px;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 10px;
        }
        .rules-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px;
        }
        .rule-item {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 12px;
        }
        .rule-item strong {
            color: var(--text);
            display: block;
            margin-bottom: 4px;
            font-size: 12.5px;
        }
        .rule-item span { font-size: 12px; line-height: 1.45; }
        /* Modal */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            inset: 0;
            background: rgba(0,0,0,0.6);
            backdrop-filter: blur(6px);
            align-items: center;
            justify-content: center;
            opacity: 0;
            transition: opacity 0.25s;
        }
        .modal.show {
            display: flex;
            opacity: 1;
        }
        .modal-content {
            background: var(--bg-card);
            border: 1px solid var(--border-light);
            padding: 28px;
            border-radius: 16px;
            width: 400px;
            max-width: 95vw;
            box-shadow: 0 20px 50px rgba(0,0,0,0.5);
            transform: translateY(12px);
            transition: transform 0.25s;
        }
        .modal.show .modal-content { transform: translateY(0); }
        .modal-content h3 {
            font-size: 1.1rem;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .close-btn {
            float: right;
            font-size: 22px;
            color: var(--text-dim);
            cursor: pointer;
            line-height: 1;
            margin-top: -4px;
            transition: color 0.15s;
        }
        .close-btn:hover { color: var(--text); }
        .settings-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 0;
            cursor: pointer;
            font-size: 14px;
        }
        .settings-item input {
            width: 17px;
            height: 17px;
            accent-color: var(--primary);
            cursor: pointer;
        }
        .settings-item label { cursor: pointer; user-select: none; }
        .footer {
            text-align: center;
            margin-top: 36px;
            font-size: 13px;
            color: var(--text-dim);
        }
        .footer span {
            background: linear-gradient(90deg, #3b82f6, #8b5cf6, #06b6d4, #3b82f6);
            background-size: 300% 100%;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 700;
            animation: gradientMove 5s linear infinite;
        }
        @keyframes gradientMove {
            0% { background-position: 0% 50%; }
            100% { background-position: 300% 50%; }
        }
        @media (max-width: 640px) {
            .container { padding: 20px 14px 40px; }
            .delay-box { margin-left: 0; width: 100%; }
        }
        .user-box { display: flex; align-items: center; gap: 12px; font-size: 13px; color: var(--text-muted); }
        .user-box form { margin: 0; }
        .user-box button { padding: 7px 14px; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <div class="logo-icon">◈</div>
                <div>
                    <h1>Domain Buy Checker</h1>
                    <p>Ares · Lọc domain mua được theo registrar</p>
                </div>
            </div>
            <div class="user-box">
                <span>👤 {{ username }}</span>
                <form method="post" action="/logout">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                    <button type="submit" class="btn-secondary">Đăng xuất</button>
                </form>
            </div>
        </div>

        <!-- Important note -->
        <div class="note-box">
            <span class="note-icon">⚠️</span>
            <div>
                <strong>Lưu ý quan trọng:</strong>
                Đây là thông tin tham khảo, có thể mua được hay không còn tùy thuộc vào thời điểm và quy định riêng của từng nhà cung cấp.
            </div>
        </div>

        <!-- Rules summary -->
        <div class="rules-card">
            <h3>◈ Tiêu chí cấm mua theo Registrar</h3>
            <div class="rules-grid">
                <div class="rule-item">
                    <strong>Namecheap</strong>
                    <span>Cấm: .ch .li .cn .au .fr .ca .eu .eco · <b>.uk thuần</b><br>
                    Mọi *.xx.uk (.co.uk .org.uk…) được phép<br>
                    Cấm .in chứa "india"</span>
                </div>
                <div class="rule-item">
                    <strong>GoDaddy</strong>
                    <span>Cấm: TẤT CẢ .in (kể cả .co.in .net.in…)<br>
                    Cấm: .cz .eu .dk</span>
                </div>
                <div class="rule-item">
                    <strong>Dynadot</strong>
                    <span>Cấm: .it · .org</span>
                </div>
                <div class="rule-item">
                    <strong>Spaceship</strong>
                    <span>Cấm: .de<br>
                    Cho phép: .uk · .my</span>
                </div>
                <div class="rule-item">
                    <strong>SAV</strong>
                    <span>Chưa có lưu ý · luôn cho phép</span>
                </div>
            </div>
        </div>

        <!-- Input -->
        <div class="card">
            <textarea id="domainList" placeholder="Nhập domain (mỗi dòng 1 domain). Hỗ trợ dán kèm giá tiền / ký tự lạ — hệ thống tự lọc.&#10;google.com&#10;example.co.uk&#10;india-shop.in&#10;test.de"></textarea>
            <div class="action-bar">
                <button id="btnCheck" class="btn-primary" onclick="startCheck(false)">▶ Bắt đầu kiểm tra</button>
                <button id="btnRetry" class="btn-warning" onclick="startCheck(true)" disabled>↻ Retry lỗi</button>
                <button class="btn-secondary" onclick="openSettings()">⚙ Cài đặt</button>
                <div class="delay-box">
                    <label for="delayMs">Delay</label>
                    <input type="number" id="delayMs" value="500" min="0" step="100" title="ms giữa mỗi domain">
                    <span>ms</span>
                </div>
            </div>
            <div class="progress" id="progressText">Sẵn sàng kiểm tra</div>
        </div>

        <!-- Legend -->
        <div class="legend" id="legendBox">
            <div class="legend-title">◈ Chú thích trạng thái (chỉ hiện những trạng thái đang có trong kết quả)</div>
            <div class="legend-groups">
                <div class="legend-group" id="legendBuyGroup">
                    <div class="legend-group-title">Khả năng mua</div>
                    <div class="legend-rows">
                        <div class="legend-row" data-key="canBuy">
                            <span class="badge badge-success">CÓ THỂ MUA</span>
                            <span>Chưa đăng ký · registrar cho phép</span>
                        </div>
                        <div class="legend-row" data-key="cannotBuy">
                            <span class="badge badge-danger">KHÔNG MUA ĐƯỢC</span>
                            <span>TLD cấm registrar · CF Banned · Registry Policy</span>
                        </div>
                        <div class="legend-row" data-key="unknownBuy">
                            <span class="badge badge-warning">CHƯA XÁC ĐỊNH</span>
                            <span>Tra cứu WHOIS/RDAP hoặc Cloudflare lỗi · cần Retry</span>
                        </div>
                        <div class="legend-row" data-key="daDK">
                            <span class="badge badge-muted">ĐÃ ĐĂNG KÝ</span>
                            <span>Domain đã có chủ · không mua được</span>
                        </div>
                    </div>
                </div>
                <div class="legend-group" id="legendDomainGroup">
                    <div class="legend-group-title">Trạng thái Domain</div>
                    <div class="legend-rows">
                        <div class="legend-row" data-key="active">
                            <span class="badge badge-success">Active / Không bị lock</span>
                            <span>Hoạt động bình thường</span>
                        </div>
                        <div class="legend-row" data-key="serverHold">
                            <span class="badge badge-danger">serverHold</span>
                            <span>Bị tạm giữ · không resolve DNS</span>
                        </div>
                        <div class="legend-row" data-key="clientHold">
                            <span class="badge badge-danger">clientHold</span>
                            <span>Bị tạm giữ · không resolve DNS</span>
                        </div>
                        <div class="legend-row" data-key="transferLock">
                            <span class="badge badge-warning">Khóa Transfer</span>
                            <span>Không chuyển registrar được</span>
                        </div>
                        <div class="legend-row" data-key="pendingTransfer">
                            <span class="badge badge-orange">Đang chuyển Registrar</span>
                            <span>Đang trong quá trình transfer</span>
                        </div>
                        <div class="legend-row" data-key="updateLock">
                            <span class="badge badge-muted">Khóa Update / Delete</span>
                            <span>Không sửa WHOIS / xóa được</span>
                        </div>
                        <div class="legend-row" data-key="redemption">
                            <span class="badge badge-danger">Redemption / Pending Delete</span>
                            <span>Sắp xóa hoặc đang chuộc</span>
                        </div>
                        <div class="legend-row" data-key="gracePeriod">
                            <span class="badge badge-warning">Grace / Pending / Inactive</span>
                            <span>Đang trong giai đoạn gia hạn, chờ xử lý hoặc chưa có NS</span>
                        </div>
                        <div class="legend-row" data-key="chuaDK">
                            <span class="badge badge-success">Chưa đăng ký</span>
                            <span>Domain chưa đăng ký · có thể mua</span>
                        </div>
                        <div class="legend-row" data-key="restricted">
                            <span class="badge badge-danger">Không thể đăng ký</span>
                            <span>Bị Registry Policy cấm</span>
                        </div>
                    </div>
                </div>
                <div class="legend-group" id="legendCfGroup">
                    <div class="legend-group-title">Cloudflare Banned</div>
                    <div class="legend-rows">
                        <div class="legend-row" data-key="cfSach">
                            <span class="badge badge-success">Sạch</span>
                            <span>Có thể add vào Cloudflare</span>
                        </div>
                        <div class="legend-row" data-key="cfBanned">
                            <span class="badge badge-danger">BANNED</span>
                            <span>Bị Cloudflare cấm thêm</span>
                        </div>
                        <div class="legend-row" data-key="cfChuaDK">
                            <span class="badge badge-info">Sạch (Chưa ĐK)</span>
                            <span>Chưa đăng ký · nên mua</span>
                        </div>
                        <div class="legend-row" data-key="cfTldCam">
                            <span class="badge badge-warning">Đuôi TLD bị CF cấm</span>
                            <span>TLD không được CF hỗ trợ</span>
                        </div>
                        <div class="legend-row" data-key="cfChanAdd">
                            <span class="badge badge-danger">Bị CF Chặn Add</span>
                            <span>Cloudflare từ chối thêm domain</span>
                        </div>
                        <div class="legend-row" data-key="cfOther">
                            <span class="badge badge-muted">Lỗi CF / Không rõ</span>
                            <span>Lỗi API hoặc trạng thái không xác định</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Results Table -->
        <div class="table-card">
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr id="tableHeader"></tr>
                    </thead>
                    <tbody id="resultBody"></tbody>
                </table>
            </div>
        </div>
        <div class="footer">
            DEV by <span>Ares</span>
        </div>
    </div>

    <!-- Settings Modal -->
    <div id="settingsModal" class="modal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeSettings()">&times;</span>
            <h3>⚙ Cài đặt kiểm tra</h3>
            <div class="settings-item">
                <input type="checkbox" id="chk_buy" checked>
                <label for="chk_buy">Khả năng mua (theo registrar)</label>
            </div>
            <div class="settings-item">
                <input type="checkbox" id="chk_registrar" checked>
                <label for="chk_registrar">Nhà đăng ký (Registrar)</label>
            </div>
            <div class="settings-item">
                <input type="checkbox" id="chk_dates" checked>
                <label for="chk_dates">Ngày đăng ký</label>
            </div>
            <div class="settings-item">
                <input type="checkbox" id="chk_cf" checked>
                <label for="chk_cf">Cloudflare Banned</label>
            </div>
            <div class="settings-item">
                <input type="checkbox" id="chk_hold" checked>
                <label for="chk_hold">Trạng thái Domain (Hold / Lock)</label>
            </div>
            <button class="btn-primary" style="margin-top: 22px; width: 100%; justify-content: center;" onclick="closeSettings()">Lưu cài đặt</button>
        </div>
    </div>

    <script>
        const CSRF_TOKEN = "{{ csrf_token }}";
        const modal = document.getElementById("settingsModal");
        function openSettings() { modal.classList.add("show"); }
        function closeSettings() { modal.classList.remove("show"); }
        window.onclick = function(e) { if (e.target === modal) closeSettings(); };

        let failedDomains = [];
        let seenLegendKeys = new Set();

        function getOptions() {
            return {
                check_buy: document.getElementById('chk_buy').checked,
                check_registrar: document.getElementById('chk_registrar').checked,
                check_dates: document.getElementById('chk_dates').checked,
                check_cf: document.getElementById('chk_cf').checked,
                check_hold: document.getElementById('chk_hold').checked
            };
        }

        function buildHeader(options) {
            const tr = document.getElementById('tableHeader');
            let html = '<th>Domain</th>';
            if (options.check_buy) html += '<th>Có thể mua?</th>';
            if (options.check_registrar) html += '<th>Nhà đăng ký</th>';
            if (options.check_dates) html += '<th>Ngày đăng ký</th>';
            if (options.check_cf) html += '<th>Cloudflare Banned</th>';
            if (options.check_hold) html += '<th>Trạng thái Domain</th>';
            tr.innerHTML = html;
        }

        function countVisibleCols(options) {
            let n = 1;
            if (options.check_buy) n++;
            if (options.check_registrar) n++;
            if (options.check_dates) n++;
            if (options.check_cf) n++;
            if (options.check_hold) n++;
            return n;
        }

        function isFailedResult(data, options) {
            // Chỉ coi là lỗi khi backend trả về lỗi thật sự (network / exception).
            // Không check được registrar / chưa đăng ký → KHÔNG tính lỗi.
            if (!data) return true;
            if (data.failed) return true;
            const reg = (data.registrar || "").toString().toLowerCase();
            const st = (data.status || "").toString().toLowerCase();
            if (reg.includes("lỗi") || st === "lỗi" || st.includes("lỗi backend")) return true;
            if (data.cf_add_status && data.cf_add_status.toString().toLowerCase().includes("lỗi call")) return true;
            return false;
        }

        function collectLegendKeysFromResult(data, options) {
            if (options.check_buy && data.buy_html) {
                const bh = data.buy_html;
                if (bh.includes("CÓ THỂ MUA")) seenLegendKeys.add("canBuy");
                else if (bh.includes("ĐÃ ĐĂNG KÝ")) seenLegendKeys.add("daDK");
                else if (bh.includes("CHƯA XÁC ĐỊNH")) seenLegendKeys.add("unknownBuy");
                else seenLegendKeys.add("cannotBuy");
            }
            if (options.check_hold && data.status) {
                const st = data.status;
                if (st.includes("Active / Không bị lock") || st.includes(">Active<")) seenLegendKeys.add("active");
                if (st.includes("serverHold")) seenLegendKeys.add("serverHold");
                if (st.includes("clientHold")) seenLegendKeys.add("clientHold");
                if (st.includes("Khóa Transfer")) seenLegendKeys.add("transferLock");
                if (st.includes("Đang chuyển Registrar")) seenLegendKeys.add("pendingTransfer");
                if (st.includes("Khóa Update") || st.includes("Khóa Delete")) seenLegendKeys.add("updateLock");
                if (st.includes("Redemption") || st.includes("Pending Delete")) seenLegendKeys.add("redemption");
                if (st.includes("Chưa đăng ký") || st.includes("Ẩn thông tin")) seenLegendKeys.add("chuaDK");
                if (/Grace|Pending (Restore|Create|Renew|Update)|Inactive/.test(st)) seenLegendKeys.add("gracePeriod");
                if (st.includes("Không thể đăng ký") || st.includes("Restricted by Registry Policy")) seenLegendKeys.add("restricted");
            }
            if (options.check_cf && data.cf_add_status) {
                const cf = data.cf_add_status;
                if (cf.includes("Sạch") && !cf.includes("Chưa ĐK") && !cf.includes("Đã nằm")) seenLegendKeys.add("cfSach");
                if (cf.includes("Sạch (Đã nằm trong CF khác)")) seenLegendKeys.add("cfSach");
                if (cf.includes("BANNED")) seenLegendKeys.add("cfBanned");
                if (cf.includes("Sạch (Chưa ĐK)")) seenLegendKeys.add("cfChuaDK");
                if (cf.includes("Đuôi TLD bị CF cấm")) seenLegendKeys.add("cfTldCam");
                if (cf.includes("Bị CF Chặn Add")) seenLegendKeys.add("cfChanAdd");
                if (cf.includes("Lỗi CF") || cf.includes("Không rõ") || cf.includes("Thiếu API")) seenLegendKeys.add("cfOther");
            }
        }

        function updateLegendVisibility() {
            const legendBox = document.getElementById('legendBox');
            if (seenLegendKeys.size === 0) {
                legendBox.classList.remove("show");
                return;
            }
            legendBox.classList.add("show");
            document.querySelectorAll(".legend-row").forEach(row => row.classList.remove("show"));
            document.querySelectorAll(".legend-group").forEach(g => g.classList.remove("show"));

            let hasBuy = false, hasDomain = false, hasCf = false;
            seenLegendKeys.forEach(key => {
                const row = document.querySelector(`.legend-row[data-key="${key}"]`);
                if (row) {
                    row.classList.add("show");
                    if (["canBuy","cannotBuy","daDK","unknownBuy"].includes(key)) hasBuy = true;
                    else if (["active","serverHold","clientHold","transferLock","pendingTransfer","updateLock","redemption","chuaDK","restricted","gracePeriod"].includes(key)) hasDomain = true;
                    else hasCf = true;
                }
            });
            if (hasBuy) document.getElementById("legendBuyGroup").classList.add("show");
            if (hasDomain) document.getElementById("legendDomainGroup").classList.add("show");
            if (hasCf) document.getElementById("legendCfGroup").classList.add("show");
        }

        async function sleep(ms) {
            return new Promise(r => setTimeout(r, ms));
        }

        async function startCheck(isRetry = false) {
            const btn = document.getElementById('btnCheck');
            const btnRetry = document.getElementById('btnRetry');
            const options = getOptions();
            const delay = Math.max(0, parseInt(document.getElementById('delayMs').value) || 500);
            let domains = [];

            if (isRetry) {
                domains = [...failedDomains];
                if (!domains.length) { alert("Không có domain lỗi để retry!"); return; }
            } else {
                const text = document.getElementById('domainList').value;
                const domainRegex = /(?:https?:\\/\\/)?(?:www\\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)/i;
                domains = text.replace(/\\r/g, "").split("\\n")
                    .map(line => {
                        const cleaned = line.trim().toLowerCase();
                        if (!cleaned) return null;
                        const firstToken = cleaned.split(/[\\s\\t,;|]+/)[0];
                        if (domainRegex.test(firstToken) && firstToken.includes(".")) {
                            const m = firstToken.match(domainRegex);
                            return m ? m[1] : null;
                        }
                        const m = cleaned.match(domainRegex);
                        return m ? m[1] : null;
                    })
                    .filter(d => d && d.includes(".") && d.length > 3);
                domains = [...new Set(domains)];
                if (!domains.length) { alert("Vui lòng nhập ít nhất 1 domain hợp lệ!"); return; }
                failedDomains = [];
                seenLegendKeys = new Set();
            }

            buildHeader(options);
            const tbody = document.getElementById('resultBody');
            if (!isRetry) tbody.innerHTML = '';

            btn.disabled = true;
            btnRetry.disabled = true;

            let completed = 0;
            const total = domains.length;
            const colspan = countVisibleCols(options) - 1;

            for (const domain of domains) {
                document.getElementById('progressText').innerHTML =
                    `<span class="progress-dot"></span> Đang xử lý ${completed + 1}/${total} — <b style="color:#93c5fd">${domain}</b>`;

                let row = document.getElementById(`row-${domain}`);
                if (!row) {
                    row = document.createElement('tr');
                    row.id = `row-${domain}`;
                    tbody.appendChild(row);
                }
                row.innerHTML = `<td class="domain-cell">${domain}</td><td colspan="${colspan}" class="skipped">Đang quét dữ liệu…</td>`;

                try {
                    const response = await fetch('/api/check', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN },
                        body: JSON.stringify({ domain, options })
                    });
                    if (response.status === 401 || response.status === 403) { window.location.href = '/login'; return; }
                    if (response.status === 429) { await sleep(5000); throw new Error("rate limited"); }
                    if (!response.ok) throw new Error("Server error");
                    const data = await response.json();

                    collectLegendKeysFromResult(data, options);

                    let registrarText = data.registrar || "";
                    // "Chưa đăng ký" đã có badge xanh từ backend → giữ nguyên
                    // Chỉ tô đỏ khi thật sự lỗi / không xác định
                    if (registrarText === "Không xác định" || registrarText === "Bỏ qua") {
                        registrarText = `<span class="error-cell">${registrarText}</span>`;
                    } else if (registrarText === "Không có dữ liệu") {
                        registrarText = `<span class="badge badge-success">Chưa đăng ký</span>`;
                    }

                    let datesText = "—";
                    if (data.created) {
                        datesText = `<span class="date-cell">${data.created}</span>`
                            + (data.expires ? `<div class="skipped">hết hạn ${data.expires}</div>` : "");
                    } else if ((data.status || "").includes("Chưa đăng ký")) {
                        datesText = '<span class="skipped">Chưa ĐK</span>';
                    }

                    let cells = `<td class="domain-cell">${domain}</td>`;
                    if (options.check_buy) cells += `<td class="buy-cell">${data.buy_html || ""}</td>`;
                    if (options.check_registrar) cells += `<td>${registrarText}</td>`;
                    if (options.check_dates) cells += `<td>${datesText}</td>`;
                    if (options.check_cf) cells += `<td>${data.cf_add_status || ""}</td>`;
                    if (options.check_hold) cells += `<td class="status-cell">${data.status || ""}</td>`;
                    row.innerHTML = cells;

                    if (isFailedResult(data, options)) {
                        if (!failedDomains.includes(domain)) failedDomains.push(domain);
                    } else {
                        failedDomains = failedDomains.filter(d => d !== domain);
                    }
                } catch (e) {
                    row.innerHTML = `
                        <td class="domain-cell">${domain}</td>
                        <td colspan="${colspan}" class="error-cell">Lỗi network / quá tải — thử lại sau</td>`;
                    if (!failedDomains.includes(domain)) failedDomains.push(domain);
                }

                completed++;
                updateLegendVisibility();
                if (completed < total && delay > 0) await sleep(delay);
            }

            document.getElementById('progressText').innerHTML =
                `✓ Hoàn thành ${completed}/${total} domain` +
                (failedDomains.length ? ` · <span style="color:#f87171">${failedDomains.length} lỗi</span>` : '');
            btn.disabled = false;
            btnRetry.disabled = failedDomains.length === 0;
            updateLegendVisibility();
        }
    </script>
</body>
</html>
"""


LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Đăng nhập — Domain Buy Checker</title>
    <meta name="robots" content="noindex,nofollow">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', system-ui, sans-serif;
            background: #0b0f19; color: #e2e8f0; min-height: 100vh;
            display: flex; align-items: center; justify-content: center; padding: 20px;
            background-image:
                radial-gradient(ellipse 80% 50% at 50% -20%, rgba(59,130,246,.15), transparent),
                radial-gradient(ellipse 60% 40% at 100% 100%, rgba(139,92,246,.08), transparent);
        }
        .box {
            width: 100%; max-width: 380px; background: #111827; border: 1px solid #1e293b;
            border-radius: 16px; padding: 32px 28px; box-shadow: 0 20px 50px rgba(0,0,0,.45);
        }
        .logo {
            width: 48px; height: 48px; border-radius: 12px; margin: 0 auto 14px;
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            display: flex; align-items: center; justify-content: center; font-size: 24px;
            box-shadow: 0 0 24px rgba(59,130,246,.35);
        }
        h1 { font-size: 1.25rem; text-align: center; margin-bottom: 4px; }
        .sub { text-align: center; font-size: .8rem; color: #64748b; margin-bottom: 22px; }
        label { display: block; font-size: 12.5px; color: #94a3b8; margin: 14px 0 6px; }
        input {
            width: 100%; padding: 11px 13px; background: #0b0f19; border: 1px solid #1e293b;
            border-radius: 8px; color: #e2e8f0; font-size: 14px; font-family: inherit;
        }
        input:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,.2); }
        button {
            width: 100%; margin-top: 22px; padding: 11px; border: none; border-radius: 8px;
            background: linear-gradient(135deg, #3b82f6, #2563eb); color: #fff;
            font-size: 14px; font-weight: 600; cursor: pointer; font-family: inherit;
        }
        button:hover { filter: brightness(1.1); }
        .err {
            margin-top: 16px; padding: 10px 12px; border-radius: 8px; font-size: 13px;
            background: rgba(239,68,68,.12); border: 1px solid rgba(239,68,68,.3); color: #f87171;
        }
    </style>
</head>
<body>
    <form class="box" method="post" action="/login" autocomplete="on">
        <div class="logo">◈</div>
        <h1>Domain Buy Checker</h1>
        <p class="sub">Đăng nhập để tiếp tục</p>
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <label for="username">Tên đăng nhập</label>
        <input id="username" name="username" type="text" autocomplete="username" required autofocus>
        <label for="password">Mật khẩu</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
        {% if error %}<div class="err">{{ error }}</div>{% endif %}
        <button type="submit">Đăng nhập</button>
    </form>
</body>
</html>
"""


# ==========================================
# 4. ROUTES
# ==========================================
@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/login", methods=["GET", "POST"])
def login():
    if not USERS:
        return "Chưa cấu hình APP_USERS trên server.", 503
    if session.get("user"):
        return redirect(url_for("index"))

    ip = request.remote_addr or "unknown"
    error, status = None, 200

    if request.method == "POST":
        if not _csrf_ok(request.form.get("csrf_token", "")):
            error, status = "Phiên đã hết hạn, vui lòng thử lại.", 400
        elif login_limiter.blocked(ip, LOGIN_MAX_FAILS, LOGIN_WINDOW_SEC):
            error, status = "Thử sai quá nhiều lần. Vui lòng đợi vài phút rồi thử lại.", 429
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if verify_password(username, password):
                login_limiter.clear(ip)
                session.clear()                                   # chống session fixation
                session["user"] = username
                session["csrf"] = secrets.token_urlsafe(32)
                session.permanent = True
                log.info("Đăng nhập thành công: %s (%s)", username, ip)
                return redirect(url_for("index"))
            login_limiter.hit(ip, LOGIN_WINDOW_SEC)
            log.warning("Đăng nhập sai: user=%r ip=%s", username[:40], ip)
            time.sleep(0.4)
            error, status = "Sai tên đăng nhập hoặc mật khẩu.", 401

    if not session.get("csrf"):
        session["csrf"] = secrets.token_urlsafe(32)
    return render_template_string(LOGIN_TEMPLATE, error=error, csrf_token=session["csrf"]), status


@app.route("/logout", methods=["POST"])
def logout():
    if _csrf_ok(request.form.get("csrf_token", "")):
        session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    if not session.get("csrf"):
        session["csrf"] = secrets.token_urlsafe(32)
    return render_template_string(HTML_TEMPLATE, username=session["user"], csrf_token=session["csrf"])


@app.route("/api/check", methods=["POST"])
@api_guard
def api_check():
    domain = ""
    try:
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        if not DOMAIN_RE.match(domain):
            return jsonify(error="Domain không hợp lệ", failed=True), 400

        options = data.get("options") or {}
        opt = lambda k: bool(options.get(k, True))  # noqa: E731
        check_buy, check_reg = opt("check_buy"), opt("check_registrar")
        check_hold, check_dates, check_cf = opt("check_hold"), opt("check_dates"), opt("check_cf")

        # ---- WHOIS / RDAP trước: cần biết đã ĐK hay chưa ----
        info = None
        if check_buy or check_reg or check_hold or check_dates:
            info = get_domain_info(domain)

        # ---- Cloudflare: bật cột CF, hoặc cần để chốt "có thể mua" (bỏ qua nếu domain đã có chủ / restricted) ----
        already_taken = bool(info) and info["state"] in ("registered", "restricted")
        cf = None
        if check_cf or (check_buy and not already_taken):
            cf = check_cf_eligibility(domain)
            # WHOIS không chắc chắn nhưng CF báo "chưa ĐK" (1049) → dùng làm bằng chứng bổ sung
            if info and info["state"] == "unknown" and cf["unregistered"]:
                info = _unregistered_info()

        # ---- Verdict mua ----
        can_buy, buy_html = False, "Bỏ qua"
        if check_buy:
            results, tld_ok = check_buyability(domain)
            state = info["state"] if info else "unknown"
            cf_ok = bool(cf) and not cf["failed"]
            can_buy = state == "unregistered" and tld_ok and cf_ok and not cf["blocked"]
            buy_html = format_buyability_html(results, tld_ok, state, cf)

        # ---- Cờ lỗi để frontend đưa vào danh sách Retry ----
        failed = False
        if info and info["state"] == "unknown":
            failed = True
        if cf and cf["failed"] and (check_cf or check_buy):
            failed = True

        return jsonify({
            "domain": domain,
            "buy_html": buy_html,
            "can_buy": can_buy,
            "cf_add_status": (cf["html"] if cf else "") if check_cf else "Bỏ qua",
            "registrar": (info["registrar"] if info else "Bỏ qua") if check_reg else "Bỏ qua",
            "status": (info["status_html"] if info else "Bỏ qua") if check_hold else "Bỏ qua",
            "created": info["created"] if (info and check_dates) else None,
            "expires": info["expires"] if (info and check_dates) else None,
            "failed": failed,
        })
    except Exception:  # noqa: BLE001
        log.exception("Lỗi khi xử lý domain %r", domain)
        return jsonify({
            "domain": domain or "Unknown",
            "buy_html": _badge("badge-danger", "Lỗi"),
            "can_buy": False,
            "cf_add_status": "Lỗi Backend",
            "registrar": "Lỗi",
            "status": "Lỗi",
            "created": None,
            "expires": None,
            "failed": True,
        }), 500


if __name__ == "__main__":
    # Tạo hash mật khẩu cho APP_USERS:  python app.py hash   (hoặc: python app.py hash "mat-khau")
    if len(sys.argv) >= 2 and sys.argv[1] == "hash":
        pw = sys.argv[2] if len(sys.argv) >= 3 else getpass.getpass("Mật khẩu: ")
        print(generate_password_hash(pw))
        sys.exit(0)
    port = _int_env("PORT", 5000)
    app.run(host="0.0.0.0", port=port)
