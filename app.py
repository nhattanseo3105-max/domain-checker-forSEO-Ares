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

# Thêm pymongo cho các tính năng database
import pymongo

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("domain-checker")

app = Flask(__name__)
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
# DATABASE CẤU HÌNH (MONGODB)
# ==========================================
MONGO_URI = "mongodb+srv://nhattanseo3105_db_user:HeSauzpD4Vn3fbfA@cluster0.lhnikju.mongodb.net/?appName=Cluster0"
try:
    mongo_client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = mongo_client["domain_checker_db"]
    users_col = db["users"]
    rules_col = db["rules"]
    hidden_domains_col = db["hidden_domains"]

    # Khởi tạo dữ liệu mặc định nếu chưa có
    if users_col.count_documents({}) == 0:
        users_col.insert_one({"username": "admin", "password": generate_password_hash("admin")})
        
    if rules_col.count_documents({}) == 0:
        rules_col.insert_many([
            {"registrar": "Namecheap", "banned": ".ch, .li, .cn, .au, .fr, .ca, .eu, .eco, .uk", "allowed": ""},
            {"registrar": "GoDaddy", "banned": ".cz, .eu, .dk, .in", "allowed": ""},
            {"registrar": "Dynadot", "banned": ".it, .org", "allowed": ""},
            {"registrar": "Spaceship", "banned": ".de", "allowed": ".uk, .my"},
            {"registrar": "SAV", "banned": "", "allowed": ""}
        ])
except Exception as e:
    log.error("Lỗi kết nối MongoDB: %s", e)

# ==========================================
# CẤU HÌNH HTTP
# ==========================================
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")
CF_MIN_INTERVAL = _float_env("CF_MIN_INTERVAL", 0.35)

IS_RENDER = bool(os.environ.get("RENDER"))
_secret = os.environ.get("SECRET_KEY", secrets.token_hex(32))

app.config.update(
    SECRET_KEY=_secret,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_RENDER,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=_int_env("SESSION_HOURS", 12)),
    MAX_CONTENT_LENGTH=64 * 1024,
)

API_LIMIT_PER_MIN = _int_env("API_LIMIT_PER_MIN", 120)
LOGIN_MAX_FAILS = _int_env("LOGIN_MAX_FAILS", 5)
LOGIN_WINDOW_SEC = _int_env("LOGIN_WINDOW_SEC", 600)
LOOKUP_BUDGET_SEC = _int_env("LOOKUP_BUDGET_SEC", 22)

HTTP_HEADERS = {
    "User-Agent": "DomainBuyChecker/2.0",
    "Accept": "application/rdap+json, application/json;q=0.9, */*;q=0.5",
}

# ==========================================
# BẢO MẬT ĐĂNG NHẬP
# ==========================================
_DUMMY_HASH = generate_password_hash("dummy-password")

def verify_password(username, password):
    try:
        user = users_col.find_one({"username": username})
    except:
        user = None
    if not user:
        check_password_hash(_DUMMY_HASH, password)
        return False
    stored = user.get("password", "")
    if stored.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored, password)
    return hmac.compare_digest(stored.encode("utf-8"), password.encode("utf-8"))

class RateLimiter:
    def __init__(self):
        self._hits = {}
        self._lock = threading.Lock()
    def _prune(self, key, window, now):
        q = [t for t in self._hits.get(key, []) if now - t < window]
        if q: self._hits[key] = q
        else: self._hits.pop(key, None)
        return q
    def blocked(self, key, limit, window):
        with self._lock: return len(self._prune(key, window, time.monotonic())) >= limit
    def hit(self, key, window):
        with self._lock:
            now = time.monotonic()
            self._prune(key, window, now)
            self._hits.setdefault(key, []).append(now)
    def clear(self, key):
        with self._lock: self._hits.pop(key, None)

login_limiter = RateLimiter()
api_limiter = RateLimiter()

def _csrf_ok(token):
    expected = session.get("csrf")
    if not expected or not token: return False
    return hmac.compare_digest(str(expected).encode("utf-8"), str(token).encode("utf-8"))

def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user" not in session: return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper

def api_guard(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if not user: return jsonify(error="unauthorized", failed=True), 401
        if not _csrf_ok(request.headers.get("X-CSRF-Token", "")): return jsonify(error="csrf", failed=True), 403
        if api_limiter.blocked(user, API_LIMIT_PER_MIN, 60): return jsonify(error="rate_limited", failed=True), 429
        api_limiter.hit(user, 60)
        return view(*args, **kwargs)
    return wrapper

# ==========================================
# RULE & CHECK BUYABILITY
# ==========================================
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
SECOND_LEVEL_LABELS = {"co", "com", "org", "net", "me", "ltd", "plc", "gov", "ac", "edu", "sch", "nic", "firm", "gen", "ind", "res", "mil", "info", "biz", "ne", "or", "go", "ed", "id", "asn", "web", "nom"}

def get_tld_parts(domain: str):
    parts = domain.lower().strip().rstrip(".").split(".")
    if len(parts) < 2: return "", ""
    last = "." + parts[-1]
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL_LABELS:
        return "." + parts[-2] + "." + parts[-1], last
    return last, last

def _match_banned(full_suffix, last_tld, banned_set):
    if full_suffix in banned_set: return full_suffix
    if last_tld in banned_set: return last_tld
    return None

def get_registrar_rules():
    rules = {
        "Namecheap": {"banned": [], "allowed": []},
        "GoDaddy": {"banned": [], "allowed": []},
        "Dynadot": {"banned": [], "allowed": []},
        "Spaceship": {"banned": [], "allowed": []},
        "SAV": {"banned": [], "allowed": []}
    }
    try:
        for doc in rules_col.find():
            r = doc["registrar"]
            if r in rules:
                b = doc.get("banned", "")
                a = doc.get("allowed", "")
                rules[r]["banned"] = [x.strip() for x in b.split(",") if x.strip()]
                rules[r]["allowed"] = [x.strip() for x in a.split(",") if x.strip()]
    except: pass
    return rules

def check_buyability(domain: str):
    domain = domain.lower().strip()
    full_suffix, last_tld = get_tld_parts(domain)
    results = {}
    rules = get_registrar_rules()
    
    try:
        hd = hidden_domains_col.find_one({"domain": domain})
        hidden_regs = hd.get("registrars", []) if hd else []
    except:
        hidden_regs = []

    for reg in ["Namecheap", "GoDaddy", "Dynadot", "Spaceship", "SAV"]:
        reason = ""
        if reg in hidden_regs:
            reason = "Bị cấm bởi Admin (Domain ẩn)"
        else:
            banned = set(rules[reg]["banned"])
            allowed = set(rules[reg]["allowed"])
            
            if reg == "Namecheap" and last_tld == ".uk" and full_suffix == ".uk" and ".uk" in banned:
                reason = "Cấm đuôi .uk thuần"
            elif reg == "Namecheap" and last_tld == ".in" and "india" in domain and ".in" not in allowed:
                reason = 'Domain .in chứa "india"'
            elif reg == "GoDaddy" and last_tld == ".in" and ".in" in banned:
                reason = f"Cấm mọi đuôi .in ({full_suffix})"
            else:
                hit = _match_banned(full_suffix, last_tld, banned)
                if hit and hit not in allowed:
                    reason = f"Cấm đuôi {hit}"
        
        results[reg] = {"ok": not reason, "reason": reason}

    return results, any(r["ok"] for r in results.values())

def _badge(cls, text): return f"<span class='badge {cls}'>{text}</span>"

def format_buyability_html(results, tld_ok, state, cf=None):
    cf = cf or {}
    if state == "registered": return _badge("badge-muted", "ĐÃ ĐĂNG KÝ")
    if state == "restricted": return _badge("badge-danger", "KHÔNG MUA ĐƯỢC") + "<div class='buy-reason'>⛔ Bị Registry Policy cấm đăng ký</div>"
    if state == "unknown": return _badge("badge-warning", "CHƯA XÁC ĐỊNH") + "<div class='buy-reason'>Không tra cứu được WHOIS/RDAP — bấm Retry lỗi</div>"
    if cf.get("failed"): return _badge("badge-warning", "CHƯA XÁC ĐỊNH") + "<div class='buy-reason'>Lỗi kiểm tra Cloudflare — bấm Retry lỗi</div>"

    banned = [(n, i["reason"] or "TLD bị cấm") for n, i in results.items() if not i["ok"]]
    ban_tags = " ".join(f"<span class='ban-tag' title='{html.escape(reason, quote=True)}'>{html.escape(name)}</span>" for name, reason in banned)
    cf_blocked = bool(cf.get("blocked"))

    if tld_ok and not cf_blocked:
        out = [_badge("badge-success", "CÓ THỂ MUA")]
        if banned: out.append(f"<div class='buy-reason'>⛔ Cấm tại: {ban_tags}</div>")
        return "".join(out)

    out = [_badge("badge-danger", "KHÔNG MUA ĐƯỢC")]
    if banned: out.append(f"<div class='buy-reason'>⛔ Cấm tại: {ban_tags}</div>")
    if cf_blocked:
        detail = {1097: "Cloudflare BANNED", 1095: "Cloudflare chặn thêm domain", 1116: "Đuôi TLD bị Cloudflare cấm"}.get(cf.get("code"), "Cloudflare Banned / TLD bị CF cấm")
        out.append(f"<div class='buy-reason'>⛔ {detail}</div>")
    return "".join(out)

# ==========================================
# (Phần core Whois, RDAP, CF giữ nguyên)
# ==========================================
def format_date_short(dt):
    if not dt: return None
    if isinstance(dt, (list, tuple)): dt = dt[0] if dt else None
    if isinstance(dt, datetime): return dt.strftime("%d/%m/%y")
    if isinstance(dt, str):
        m = re.search(r"(\d{4})-(\d{2})-(\d{2})", dt)
        if m: return f"{m.group(3)}/{m.group(2)}/{m.group(1)[2:]}"
    return None

_STATUS_KEYS = ["serverHold", "clientHold", "clientTransferProhibited", "serverTransferProhibited", "pendingTransfer", "clientUpdateProhibited", "serverUpdateProhibited", "clientDeleteProhibited", "serverDeleteProhibited", "redemptionPeriod", "pendingDelete", "addPeriod", "autoRenewPeriod", "renewPeriod", "transferPeriod", "pendingRestore", "pendingCreate", "pendingRenew", "pendingUpdate", "inactive"]
_STATUS_LOOKUP = sorted(((k.lower(), k) for k in _STATUS_KEYS), key=lambda kv: -len(kv[0]))

def _normalize_status(s):
    s = re.sub(r"[\s_\-]", "", str(s).lower())
    for lowered, key in _STATUS_LOOKUP:
        if lowered in s: return key
    if s.startswith(("ok", "active")): return "ok"
    return None

def _parse_rdap_json(data):
    status_found, registrar, created, expires = set(), None, None, None
    if not isinstance(data, dict): return status_found, registrar, created, expires
    for s in data.get("status") or []:
        key = _normalize_status(s)
        if key: status_found.add(key)
    for ent in data.get("entities") or []:
        if not isinstance(ent, dict) or "registrar" not in (ent.get("roles") or []): continue
        vcard = ent.get("vcardArray") or []
        if len(vcard) > 1:
            for prop in vcard[1]:
                if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
                    registrar = prop[3]; break
        if not registrar: registrar = ent.get("handle") or ent.get("name")
    for ev in data.get("events") or []:
        action = str(ev.get("eventAction", "")).lower()
        date_str = ev.get("eventDate")
        if not date_str: continue
        if action in ("registration", "registered"): created = format_date_short(date_str)
        elif action in ("expiration", "expiry", "expired", "registrar expiration"): expires = format_date_short(date_str)
    return status_found, registrar, created, expires

def _parse_generic_json(data):
    status_found, registrar, created, expires = set(), None, None, None
    if not isinstance(data, dict): return status_found, registrar, created, expires
    reg_val = data.get("registrar")
    if isinstance(reg_val, str) and reg_val.strip(): registrar = reg_val.strip()
    elif isinstance(reg_val, dict): registrar = reg_val.get("name") or reg_val.get("organization")
    statuses = data.get("status") or data.get("statuses") or []
    if isinstance(statuses, str): statuses = [statuses]
    for s in statuses:
        key = _normalize_status(s)
        if key: status_found.add(key)
    for k in ("created", "creationDate", "creation_date", "registered"):
        if data.get(k): created = format_date_short(data[k]); break
    for k in ("expires", "expirationDate", "expiration_date", "expiry"):
        if data.get(k): expires = format_date_short(data[k]); break
    for sub in (data, data.get("rdap")):
        st, reg, cr, exp = _parse_rdap_json(sub)
        status_found |= st; registrar = registrar or reg; created = created or cr; expires = expires or exp
    return status_found, registrar, created, expires

_STATUS_LABELS = {
    "serverHold": ("serverHold", "badge-danger"), "clientHold": ("clientHold", "badge-danger"),
    "clientTransferProhibited": ("Khóa Transfer (Client)", "badge-warning"), "serverTransferProhibited": ("Khóa Transfer (Server)", "badge-warning"),
    "pendingTransfer": ("Đang chuyển Registrar", "badge-orange"),
    "clientUpdateProhibited": ("Khóa Update", "badge-muted"), "serverUpdateProhibited": ("Khóa Update (Server)", "badge-muted"),
    "clientDeleteProhibited": ("Khóa Delete", "badge-muted"), "serverDeleteProhibited": ("Khóa Delete (Server)", "badge-muted"),
    "redemptionPeriod": ("Redemption Period", "badge-danger"), "pendingDelete": ("Pending Delete", "badge-danger"),
    "pendingRestore": ("Pending Restore", "badge-danger"), "autoRenewPeriod": ("Auto-Renew Grace Period", "badge-warning"),
    "renewPeriod": ("Renew Grace Period", "badge-warning"), "addPeriod": ("Add Grace Period", "badge-muted"),
    "transferPeriod": ("Transfer Grace Period", "badge-muted"), "pendingCreate": ("Pending Create", "badge-muted"),
    "pendingRenew": ("Pending Renew", "badge-muted"), "pendingUpdate": ("Pending Update", "badge-muted"),
    "inactive": ("Inactive (chưa có NS)", "badge-warning"), "ok": ("Active", "badge-success"),
}
_STATUS_PRIORITY = ["serverHold", "clientHold", "pendingTransfer", "redemptionPeriod", "pendingDelete", "pendingRestore", "autoRenewPeriod", "renewPeriod", "inactive", "clientTransferProhibited", "serverTransferProhibited", "clientUpdateProhibited", "serverUpdateProhibited", "clientDeleteProhibited", "serverDeleteProhibited", "addPeriod", "transferPeriod", "pendingCreate", "pendingRenew", "pendingUpdate", "ok"]

def format_status_display(status_set):
    if not status_set: return _badge("badge-success", "Active / Không bị lock")
    badges = []
    for key in _STATUS_PRIORITY:
        if key in status_set:
            text, cls = _STATUS_LABELS[key]
            badges.append(_badge(cls, text))
    return "<br>".join(badges) or _badge("badge-success", "Active / Không bị lock")

def _looks_restricted(resp):
    try: data = resp.json()
    except ValueError: return False
    desc = data.get("description") or []
    desc_text = " ".join(str(d) for d in desc) if isinstance(desc, list) else str(desc)
    return any(k in (desc_text + " " + str(data.get("title", ""))).lower() for k in ("not available for registration", "restricted by registry policy", "registry policy", "prohibited"))

def _fetch_json(url, timeout=(4, 7)):
    try:
        r = requests.get(url, timeout=timeout, headers=HTTP_HEADERS)
        if r.status_code == 200: return r.json()
    except: pass
    return None

_whois_pool = ThreadPoolExecutor(max_workers=4)

def _whois_lookup(domain, timeout):
    try: w = _whois_pool.submit(whois.whois, domain).result(timeout=max(1.0, timeout))
    except FuturesTimeout: return "error", None
    except Exception as e:
        msg = str(e).lower()
        if e.__class__.__name__ == "PywhoisError" or "no match" in msg or "not found" in msg: return "no_match", None
        return "error", None
    status = set()
    raw_status = getattr(w, "status", None)
    if isinstance(raw_status, str): raw_status = [raw_status]
    for s in raw_status or []:
        key = _normalize_status(s)
        if key: status.add(key)
    registrar = getattr(w, "registrar", None)
    created = format_date_short(getattr(w, "creation_date", None))
    expires = format_date_short(getattr(w, "expiration_date", None))
    if not registrar and not created: return "no_match", None
    return "data", (status, registrar, created, expires)

def _http_get(url, timeout=(4, 8), tries=2, **kw):
    headers = kw.pop("headers", HTTP_HEADERS)
    for i in range(tries):
        try:
            r = requests.get(url, timeout=timeout, headers=headers, **kw)
            if r.status_code in (429, 500, 502, 503, 504) and i < tries - 1: time.sleep(0.8 * (i + 1)); continue
            return r
        except:
            if i < tries - 1: time.sleep(0.5)
    return None

_IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_IANA_TTL = 24 * 3600
_bootstrap = {"map": None, "ts": 0.0, "fail_ts": -1e9}
_bootstrap_lock = threading.Lock()

def _rdap_base_for(domain):
    now = time.monotonic()
    with _bootstrap_lock:
        stale = _bootstrap["map"] is None or now - _bootstrap["ts"] > _IANA_TTL
        if stale and now - _bootstrap["fail_ts"] > 60:
            data = _fetch_json(_IANA_BOOTSTRAP_URL, timeout=(4, 8))
            mapping = {}
            try:
                for tlds, urls in (data or {}).get("services", []):
                    https = [u for u in urls if u.startswith("https://")] or urls
                    for t in tlds: mapping[t.lower()] = https[0]
            except: mapping = {}
            if mapping: _bootstrap.update(map=mapping, ts=now)
            else: _bootstrap["fail_ts"] = now
        mapping = _bootstrap["map"]
    if mapping is None: return None
    return mapping.get(domain.rsplit(".", 1)[-1].lower(), "")

def _dns_ns_check(domain, timeout=4):
    for url in ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"):
        r = _http_get(url, timeout=(timeout, timeout), tries=1, params={"name": domain, "type": "NS"}, headers={**HTTP_HEADERS, "Accept": "application/dns-json"})
        if r is None or r.status_code != 200: continue
        try: j = r.json()
        except: continue
        if j.get("Status") == 3: return "nxdomain"
        if j.get("Status") == 0:
            has_ns = any(a.get("type") == 2 for a in (j.get("Answer") or []))
            return "exists" if has_ns else "nodata"
    return None

def _unregistered_info():
    ok = _badge("badge-success", "Chưa đăng ký")
    return {"state": "unregistered", "status_html": ok, "registrar": ok, "created": None, "expires": None}

def get_domain_info(domain):
    deadline = time.monotonic() + LOOKUP_BUDGET_SEC
    remaining = lambda: deadline - time.monotonic()
    status, registrar, created, expires = set(), None, None, None
    restricted = rdap_404 = empty_ok = False
    def merge(parsed):
        nonlocal status, registrar, created, expires
        st, reg, cr, exp = parsed
        status |= st; registrar = registrar or reg; created = created or cr; expires = expires or exp

    base = _rdap_base_for(domain)
    no_rdap_tld = base == ""
    rdap_urls = []
    if base: rdap_urls.append(base.rstrip("/") + "/domain/" + domain)
    if not no_rdap_tld: rdap_urls.append(f"https://rdap.org/domain/{domain}")
    for url in rdap_urls:
        if remaining() <= 2: break
        r = _http_get(url, timeout=(4, min(8, max(2, remaining()))))
        if r is None: continue
        if r.status_code == 200:
            try: merge(_parse_rdap_json(r.json()))
            except: continue
            break
        if r.status_code == 404:
            rdap_404 = True
            restricted = _looks_restricted(r)
            break

    def need_more(): return not restricted and not (registrar or created)
    dns = _dns_ns_check(domain) if need_more() and remaining() > 3 else None

    if need_more() and not rdap_404:
        for url in (f"https://who-dat.as93.net/{domain}", f"https://rdap.cloud/api/v1/{domain}"):
            if remaining() <= 3: break
            data = _fetch_json(url, timeout=(4, min(7, remaining())))
            if data is not None:
                merge(_parse_generic_json(data))
                if need_more(): empty_ok = True
                else: break

    whois_no_match = False
    if need_more() and remaining() > 1:
        outcome, payload = _whois_lookup(domain, remaining())
        if outcome == "data": merge(payload)
        elif outcome == "no_match": whois_no_match = True

    if restricted: return {"state": "restricted", "status_html": _badge("badge-danger", "Không thể đăng ký") + "<br>" + _badge("badge-warning", "Restricted by Registry Policy"), "registrar": "Registry Policy", "created": None, "expires": None}
    if registrar or created: return {"state": "registered", "status_html": format_status_display(status), "registrar": html.escape(str(registrar).strip()) if registrar else "Không xác định", "created": created, "expires": expires}
    if dns == "exists": return {"state": "registered", "status_html": format_status_display(status), "registrar": "Không xác định (có DNS)", "created": None, "expires": None}
    if whois_no_match and (rdap_404 or empty_ok or no_rdap_tld): return _unregistered_info()
    if rdap_404 and dns == "nxdomain": return _unregistered_info()
    return {"state": "unknown", "status_html": _badge("badge-warning", "Không tra cứu được"), "registrar": "Không xác định", "created": None, "expires": None}

_cf_lock = threading.Lock()
_cf_last_call = 0.0
CF_ZONES_URL = "https://api.cloudflare.com/client/v4/zones"
def _cf_throttle():
    global _cf_last_call
    with _cf_lock:
        wait = CF_MIN_INTERVAL - (time.monotonic() - _cf_last_call)
        if wait > 0: time.sleep(wait)
        _cf_last_call = time.monotonic()
def _cf_delete_zone(zone_id, headers):
    for attempt in range(3):
        try:
            _cf_throttle()
            r = requests.delete(f"{CF_ZONES_URL}/{zone_id}", headers=headers, timeout=8)
            if r.status_code in (200, 404): return True
        except: pass
        time.sleep(1 + attempt)
    return False
def _cf_result(html_, code=None, blocked=False, unregistered=False, failed=False): return {"html": html_, "code": code, "blocked": blocked, "unregistered": unregistered, "failed": failed}

def check_cf_eligibility(domain):
    if not CF_API_TOKEN or not CF_ACCOUNT_ID: return _cf_result(_badge("badge-muted", "Thiếu API CF"))
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}
    payload = {"name": domain, "account": {"id": CF_ACCOUNT_ID}, "type": "full"}
    try:
        _cf_throttle()
        r = requests.post(CF_ZONES_URL, headers=headers, json=payload, timeout=(5, 10))
    except: return _cf_result(_badge("badge-danger", "Lỗi Call API CF"), failed=True)
    if r.status_code == 429 or r.status_code >= 500: return _cf_result(_badge("badge-warning", "CF quá tải / rate limit"), failed=True)
    try: resp = r.json()
    except ValueError: return _cf_result(_badge("badge-muted", "Lỗi CF: phản hồi không hợp lệ"), failed=True)
    if r.status_code == 200 and resp.get("success"):
        zone_id = (resp.get("result") or {}).get("id")
        html_ = _badge("badge-success", "Sạch")
        if zone_id and not _cf_delete_zone(zone_id, headers): html_ += "<br>" + _badge("badge-warning", "Zone tạm chưa xóa")
        return _cf_result(html_)
    errors = resp.get("errors") or []
    code = errors[0].get("code") if errors else None
    if code == 1049: return _cf_result(_badge("badge-info", "Sạch (Chưa ĐK)"), code, unregistered=True)
    if code == 1097: return _cf_result(_badge("badge-danger", "BANNED"), code, blocked=True)
    if code == 1095: return _cf_result(_badge("badge-danger", "Bị CF Chặn Add"), code, blocked=True)
    if code == 1116: return _cf_result(_badge("badge-warning", "Đuôi TLD bị CF cấm"), code, blocked=True)
    if code == 1061: return _cf_result(_badge("badge-success", "Sạch (Đã nằm trong CF khác)"), code)
    if code is not None: return _cf_result(_badge("badge-muted", f"Lỗi CF: {code}"), code)
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
    <title>Domain Checker — Ares</title>
    <link rel="icon" type="image/png" href="https://cdn-icons-png.flaticon.com/512/15435/15435750.png">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root { --bg: #0b0f19; --bg-card: #111827; --bg-elevated: #1a2234; --border: #1e293b; --text: #e2e8f0; --text-muted: #94a3b8; --text-dim: #64748b; --primary: #3b82f6; --success: #22c55e; --danger: #ef4444; --warning: #f59e0b; --orange: #f97316; --info: #06b6d4; --radius: 12px; --radius-sm: 8px; }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; line-height: 1.5; padding-bottom: 60px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 32px 24px; }
        .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 28px; flex-wrap: wrap; gap: 16px; }
        .logo h1 { font-size: 1.5rem; font-weight: 700; color: #fff; }
        .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); padding: 24px; margin-bottom: 16px; box-shadow: 0 4px 24px rgba(0,0,0,0.25); }
        .nav-tabs { display: flex; gap: 8px; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 12px; overflow-x: auto; }
        .nav-tab { background: transparent; border: 1px solid var(--border); color: var(--text-muted); padding: 8px 16px; border-radius: 8px; cursor: pointer; transition: 0.2s; font-weight: 500; font-size: 14px; white-space: nowrap; }
        .nav-tab:hover { background: var(--bg-elevated); color: var(--text); }
        .nav-tab.active { background: var(--primary); color: white; border-color: var(--primary); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        textarea { width: 100%; height: 130px; padding: 14px 16px; background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-sm); color: var(--text); font-family: 'JetBrains Mono', monospace; font-size: 13.5px; resize: vertical; margin-bottom: 16px; }
        textarea:focus { outline: none; border-color: var(--primary); }
        button.btn-primary, button.btn-warning, button.btn-secondary { border: none; padding: 10px 18px; font-size: 14px; font-weight: 600; border-radius: var(--radius-sm); cursor: pointer; color: #fff; }
        .btn-primary { background: linear-gradient(135deg, #3b82f6, #2563eb); }
        .btn-warning { background: linear-gradient(135deg, #f59e0b, #d97706); color: #111; }
        .btn-secondary { background: var(--bg-elevated); border: 1px solid var(--border); color: var(--text); }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        
        table { width: 100%; border-collapse: collapse; font-size: 13.5px; min-width: 900px; }
        th { background: var(--bg-elevated); color: var(--text-muted); font-weight: 600; padding: 14px 16px; text-align: left; border-bottom: 1px solid var(--border); }
        td { padding: 13px 16px; border-bottom: 1px solid var(--border); }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11.5px; font-weight: 600; white-space: nowrap; }
        .badge-success { background: rgba(34, 197, 94, 0.15); color: #4ade80; }
        .badge-danger  { background: rgba(239, 68, 68, 0.15); color: #f87171; }
        .badge-warning { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
        .badge-muted   { background: rgba(100, 116, 139, 0.15); color: #94a3b8; }
        .buy-reason { margin-top: 5px; font-size: 11.5px; color: #f87171; }
        
        .note-box { background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: var(--radius-sm); padding: 12px 16px; font-size: 13px; color: #fbbf24; display: flex; gap: 10px; }
        .input-group { display: flex; gap: 8px; margin-bottom: 12px; }
        .input-text { flex: 1; padding: 8px 12px; background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: var(--radius-sm); }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <h1>Domain Checker</h1>
                <p style="color:var(--text-dim); font-size: 13px;">Quản lý và kiểm tra tên miền</p>
            </div>
            <div style="display:flex; gap: 12px; align-items:center;">
                <span style="font-size: 13px; color: var(--text-muted);">👤 {{ username }}</span>
                <form method="post" action="/logout" style="margin:0;"><input type="hidden" name="csrf_token" value="{{ csrf_token }}"><button type="submit" class="btn-secondary" style="padding: 6px 12px;">Đăng xuất</button></form>
            </div>
        </div>

        <div class="nav-tabs">
            <button class="nav-tab active" onclick="switchTab('tab-check', this, 'buy')">Kiểm tra Mua</button>
            <button class="nav-tab" onclick="switchTab('tab-check', this, 'transfer')">Kiểm tra Transfer</button>
            <button class="nav-tab" onclick="switchTab('tab-godaddy', this, null)">Giá GoDaddy</button>
            {% if username == 'admin' %}
            <button class="nav-tab" onclick="switchTab('tab-admin', this, null)">Quản trị (Admin)</button>
            {% endif %}
        </div>

        <!-- MAIN CHECK TAB (Buy & Transfer share this) -->
        <div id="tab-check" class="tab-content active">
            <input type="hidden" id="checkMode" value="buy">
            <div class="card">
                <textarea id="domainList" placeholder="Nhập danh sách domain, mỗi dòng 1 domain..."></textarea>
                <div style="display: flex; gap: 10px; align-items: center;">
                    <button id="btnCheck" class="btn-primary" onclick="startCheck(false)">▶ Bắt đầu kiểm tra</button>
                    <button id="btnRetry" class="btn-warning" onclick="startCheck(true)" disabled>↻ Retry lỗi</button>
                    <div style="margin-left: auto; font-size: 13px; color: var(--text-muted);">
                        Delay: <input type="number" id="delayMs" value="500" style="width:60px; padding:4px; background:var(--bg); border:1px solid var(--border); color:#fff; border-radius:4px;"> ms
                    </div>
                </div>
                <div id="progressText" style="margin-top: 14px; font-size: 13px; color: var(--text-muted);">Sẵn sàng kiểm tra</div>
            </div>
            <div class="card" style="padding:0; overflow-x:auto;">
                <table>
                    <thead>
                        <tr id="tableHeader"></tr>
                    </thead>
                    <tbody id="resultBody"></tbody>
                </table>
            </div>
        </div>

        <!-- GODADDY TAB -->
        <div id="tab-godaddy" class="tab-content card">
            <h3 style="margin-bottom: 12px;">Kiểm tra giá GoDaddy</h3>
            <p style="font-size: 13px; color: var(--text-dim); margin-bottom: 16px;">
                <strong style="color: var(--warning);">LƯU Ý:</strong> CHỨC NĂNG NÀY CHỈ LÀ DẪN LINK MỞ GODADDY, KHÔNG PHẢI THỰC HIỆN TRÊN WEBSITE
            </p>
            <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                <a href="https://www.godaddy.com/en/domains/bulk-domain-search" target="_blank" class="btn-primary" style="text-decoration: none;">🔍 Kiểm tra giá mua mới GoDaddy</a>
                <a href="https://www.godaddy.com/en/domains/domain-transfer" target="_blank" class="btn-secondary" style="text-decoration: none;">🔄 Kiểm tra giá Transfer to GoDaddy</a>
            </div>
            <div class="note-box" style="margin-top: 20px;">
                <span class="note-icon">⚠️</span>
                <div>Nếu giá domain rẻ bất thường, vui lòng liên hệ IT mua domain để được hỗ trợ kiểm tra giá.</div>
            </div>
        </div>

        <!-- ADMIN TAB -->
        {% if username == 'admin' %}
        <div id="tab-admin" class="tab-content card">
            <h3 style="margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 10px;">Quản trị Hệ thống</h3>
            
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px;">
                <!-- Quản lý User -->
                <div style="background: var(--bg); padding: 16px; border-radius: var(--radius-sm); border: 1px solid var(--border);">
                    <h4 style="margin-bottom: 12px; color: var(--text-muted);">👤 Tạo / Sửa Users</h4>
                    <div class="input-group">
                        <input type="text" id="admUser" class="input-text" placeholder="Tên đăng nhập">
                        <input type="password" id="admPass" class="input-text" placeholder="Mật khẩu (mới)">
                        <button class="btn-primary" onclick="adminAction('save_user')">Lưu</button>
                    </div>
                    <ul id="admUserList" style="list-style:none; font-size: 13px; color: var(--text-muted); max-height: 120px; overflow-y: auto;"></ul>
                </div>

                <!-- Domain Cấm Ẩn -->
                <div style="background: var(--bg); padding: 16px; border-radius: var(--radius-sm); border: 1px solid var(--border);">
                    <h4 style="margin-bottom: 12px; color: var(--text-muted);">🚫 Domain Cấm (Ẩn)</h4>
                    <div class="input-group">
                        <input type="text" id="admHiddenDomain" class="input-text" placeholder="Nhập domain cấm...">
                        <button class="btn-primary" onclick="adminAction('add_hidden')">Thêm</button>
                    </div>
                    <div style="font-size: 12px; margin-bottom: 12px; display:flex; gap: 10px; flex-wrap: wrap; color: var(--text-muted);">
                        <label><input type="checkbox" class="chk-reg" value="Namecheap"> Namecheap</label>
                        <label><input type="checkbox" class="chk-reg" value="GoDaddy"> GoDaddy</label>
                        <label><input type="checkbox" class="chk-reg" value="Dynadot"> Dynadot</label>
                        <label><input type="checkbox" class="chk-reg" value="Spaceship"> Spaceship</label>
                        <label><input type="checkbox" class="chk-reg" value="SAV"> SAV</label>
                    </div>
                    <ul id="admHiddenList" style="list-style:none; font-size: 13px; color: var(--text-muted); max-height: 120px; overflow-y: auto;"></ul>
                </div>
            </div>

            <!-- Cấu hình Đuôi Cấm / Cho phép -->
            <div style="background: var(--bg); padding: 16px; border-radius: var(--radius-sm); border: 1px solid var(--border);">
                <h4 style="margin-bottom: 12px; color: var(--text-muted);">⚙ Cấu hình đuôi cấm/cho phép (ngăn cách bằng dấu phẩy)</h4>
                <div id="admRulesList" style="display: flex; flex-direction: column; gap: 12px;"></div>
            </div>
        </div>
        {% endif %}
    </div>

    <script>
        const CSRF_TOKEN = "{{ csrf_token }}";
        let failedDomains = [];

        function switchTab(tabId, btnElement, mode) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.nav-tab').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            btnElement.classList.add('active');
            if(mode) document.getElementById('checkMode').value = mode;
            if(tabId === 'tab-admin') loadAdminData();
            
            // Build header
            if(tabId === 'tab-check') {
                const tr = document.getElementById('tableHeader');
                if (mode === 'buy') {
                    tr.innerHTML = '<th>Domain</th><th>Có thể mua?</th><th>Nhà đăng ký</th><th>Ngày đăng ký</th><th>Cloudflare Banned</th><th>Trạng thái Domain</th>';
                } else {
                    tr.innerHTML = '<th>Domain</th><th>Đ.kiện Transfer?</th><th>Nhà đăng ký</th><th>Ngày đăng ký</th><th>Trạng thái Domain</th>';
                }
            }
        }

        // Initialize header
        switchTab('tab-check', document.querySelector('.nav-tab'), 'buy');

        async function startCheck(isRetry = false) {
            const mode = document.getElementById('checkMode').value;
            const btn = document.getElementById('btnCheck');
            const delay = Math.max(0, parseInt(document.getElementById('delayMs').value) || 500);
            let domains = [];
            
            if (isRetry) {
                domains = [...failedDomains];
            } else {
                const text = document.getElementById('domainList').value;
                domains = text.split("\\n").map(d => d.trim().toLowerCase()).filter(d => d.includes(".") && d.length > 3);
                domains = [...new Set(domains)];
                failedDomains = [];
            }
            if(!domains.length) return alert("Vui lòng nhập domain!");
            
            const tbody = document.getElementById('resultBody');
            if (!isRetry) tbody.innerHTML = '';
            btn.disabled = true;

            for (let i = 0; i < domains.length; i++) {
                const domain = domains[i];
                document.getElementById('progressText').innerHTML = `Đang xử lý ${i+1}/${domains.length}: ${domain}`;
                let row = document.getElementById(`row-${domain}`);
                if (!row) { row = document.createElement('tr'); row.id = `row-${domain}`; tbody.appendChild(row); }
                row.innerHTML = `<td style="color:#93c5fd">${domain}</td><td colspan="5" style="color:#64748b">Đang quét...</td>`;

                try {
                    const response = await fetch('/api/check', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN },
                        body: JSON.stringify({ domain, mode })
                    });
                    const data = await response.json();
                    
                    let cells = `<td style="color:#93c5fd">${domain}</td>`;
                    cells += `<td>${data.result_html || ""}</td>`;
                    cells += `<td>${data.registrar || ""}</td>`;
                    cells += `<td>${data.created || "—"}${data.expires ? `<br><small style="color:#64748b">hết: ${data.expires}</small>` : ''}</td>`;
                    if (mode === 'buy') cells += `<td>${data.cf_add_status || ""}</td>`;
                    cells += `<td>${data.status || ""}</td>`;
                    row.innerHTML = cells;

                    if (data.failed && !failedDomains.includes(domain)) failedDomains.push(domain);
                    else failedDomains = failedDomains.filter(d => d !== domain);
                } catch (e) {
                    row.innerHTML = `<td style="color:#93c5fd">${domain}</td><td colspan="5" style="color:#f87171">Lỗi server</td>`;
                    if (!failedDomains.includes(domain)) failedDomains.push(domain);
                }
                if (i < domains.length - 1 && delay > 0) await new Promise(r => setTimeout(r, delay));
            }
            document.getElementById('progressText').innerHTML = `✓ Hoàn thành ${domains.length} domain`;
            btn.disabled = false;
            document.getElementById('btnRetry').disabled = failedDomains.length === 0;
        }

        async function loadAdminData() {
            const res = await fetch('/admin/api', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN },
                body: JSON.stringify({ action: 'get_data' })
            });
            const data = await res.json();
            
            // Users
            document.getElementById('admUserList').innerHTML = data.users.map(u => `<li>👤 ${u}</li>`).join('');
            
            // Rules
            const rDiv = document.getElementById('admRulesList');
            rDiv.innerHTML = data.rules.map(r => `
                <div style="display:flex; gap: 8px; align-items:center;">
                    <div style="width: 100px; font-weight: 500; color:#fff;">${r.registrar}</div>
                    <input type="text" id="ban_${r.registrar}" value="${r.banned}" class="input-text" placeholder="Đuôi cấm (VD: .vn, .com.vn)" title="Đuôi bị cấm">
                    <input type="text" id="allow_${r.registrar}" value="${r.allowed}" class="input-text" placeholder="Đuôi cho phép (VD: .uk)" title="Đuôi ngoại lệ cho phép">
                    <button class="btn-primary" onclick="adminAction('save_rule', '${r.registrar}')" style="padding: 6px 12px; font-size: 12px;">Lưu</button>
                </div>
            `).join('');

            // Hidden Domains
            document.getElementById('admHiddenList').innerHTML = data.hidden.map(h => `
                <li style="display:flex; justify-content:space-between; margin-bottom:6px; padding-bottom:6px; border-bottom:1px solid #1e293b;">
                    <span><strong style="color:#fff;">${h.domain}</strong> <small>(${h.registrars.join(', ')})</small></span>
                    <button onclick="adminAction('del_hidden', '${h.domain}')" style="background:transparent; border:none; color:#ef4444; cursor:pointer;">Xóa</button>
                </li>
            `).join('');
        }

        async function adminAction(action, param) {
            let payload = { action };
            if (action === 'save_user') {
                payload.username = document.getElementById('admUser').value;
                payload.password = document.getElementById('admPass').value;
                if(!payload.username || !payload.password) return alert("Nhập đủ user/pass!");
            } else if (action === 'save_rule') {
                payload.registrar = param;
                payload.banned = document.getElementById(`ban_${param}`).value;
                payload.allowed = document.getElementById(`allow_${param}`).value;
            } else if (action === 'add_hidden') {
                payload.domain = document.getElementById('admHiddenDomain').value;
                payload.registrars = Array.from(document.querySelectorAll('.chk-reg:checked')).map(el => el.value);
                if(!payload.domain || !payload.registrars.length) return alert("Nhập domain và chọn ít nhất 1 nhà cung cấp!");
            } else if (action === 'del_hidden') {
                payload.domain = param;
            }

            const res = await fetch('/admin/api', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN },
                body: JSON.stringify(payload)
            });
            if(res.ok) {
                if(action==='save_user') { document.getElementById('admUser').value=''; document.getElementById('admPass').value=''; }
                if(action==='add_hidden') { document.getElementById('admHiddenDomain').value=''; }
                loadAdminData();
                alert("Thành công!");
            } else alert("Lỗi hệ thống hoặc quyền truy cập");
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
    <title>Đăng nhập</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #0b0f19; color: #fff; display: flex; align-items: center; justify-content: center; height: 100vh; margin:0;}
        .box { background: #111827; padding: 32px; border-radius: 12px; width: 340px; border: 1px solid #1e293b; }
        input { width: 100%; padding: 10px; margin: 10px 0 20px; background: #0b0f19; border: 1px solid #1e293b; color: #fff; border-radius: 6px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #3b82f6; border: none; color: #fff; border-radius: 6px; cursor: pointer; font-weight: 600; }
        .err { color: #f87171; font-size: 13px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <form class="box" method="post" action="/login">
        <h2 style="text-align:center; margin-bottom:20px;">Đăng nhập</h2>
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <label>Username</label><input type="text" name="username" required autofocus>
        <label>Password</label><input type="password" name="password" required>
        {% if error %}<div class="err">{{ error }}</div>{% endif %}
        <button type="submit">Đăng nhập</button>
    </form>
</body>
</html>
"""

# ==========================================
# 4. ROUTES
# ==========================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"): return redirect(url_for("index"))
    ip = request.remote_addr or "unknown"
    error = None
    if request.method == "POST":
        if not _csrf_ok(request.form.get("csrf_token", "")): error = "Phiên hết hạn"
        elif login_limiter.blocked(ip, LOGIN_MAX_FAILS, LOGIN_WINDOW_SEC): error = "Thử sai quá nhiều"
        else:
            u = request.form.get("username", "").strip()
            p = request.form.get("password", "")
            if verify_password(u, p):
                login_limiter.clear(ip)
                session.clear()
                session["user"] = u
                session["csrf"] = secrets.token_urlsafe(32)
                session.permanent = True
                return redirect(url_for("index"))
            login_limiter.hit(ip, LOGIN_WINDOW_SEC)
            error = "Sai thông tin"
    if not session.get("csrf"): session["csrf"] = secrets.token_urlsafe(32)
    return render_template_string(LOGIN_TEMPLATE, error=error, csrf_token=session["csrf"])

@app.route("/logout", methods=["POST"])
def logout():
    if _csrf_ok(request.form.get("csrf_token", "")): session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    if not session.get("csrf"): session["csrf"] = secrets.token_urlsafe(32)
    return render_template_string(HTML_TEMPLATE, username=session["user"], csrf_token=session["csrf"])

@app.route("/admin/api", methods=["POST"])
@api_guard
def admin_api():
    if session.get("user") != "admin": return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    action = data.get("action")
    if action == "save_user":
        u = data["username"].strip()
        p = generate_password_hash(data["password"].strip())
        users_col.update_one({"username": u}, {"$set": {"password": p}}, upsert=True)
        return jsonify({"success": True})
    if action == "save_rule":
        rules_col.update_one({"registrar": data["registrar"]}, {"$set": {"banned": data["banned"], "allowed": data["allowed"]}}, upsert=True)
        return jsonify({"success": True})
    if action == "add_hidden":
        hidden_domains_col.update_one({"domain": data["domain"].strip().lower()}, {"$set": {"registrars": data["registrars"]}}, upsert=True)
        return jsonify({"success": True})
    if action == "del_hidden":
        hidden_domains_col.delete_one({"domain": data["domain"].strip().lower()})
        return jsonify({"success": True})
    if action == "get_data":
        return jsonify({
            "users": [u["username"] for u in users_col.find()],
            "rules": list(rules_col.find({}, {"_id": 0})),
            "hidden": list(hidden_domains_col.find({}, {"_id": 0}))
        })
    return jsonify({"error": "Unknown"}), 400

@app.route("/api/check", methods=["POST"])
@api_guard
def api_check():
    try:
        data = request.json or {}
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        mode = data.get("mode", "buy")
        if not DOMAIN_RE.match(domain): return jsonify(error="Lỗi domain", failed=True), 400

        info = get_domain_info(domain)
        state = info["state"]
        failed = state == "unknown"
        result_html = ""
        cf_html = "Bỏ qua"

        if mode == "buy":
            cf = None
            if state not in ("registered", "restricted"): cf = check_cf_eligibility(domain)
            if info and state == "unknown" and cf and cf["unregistered"]:
                info = _unregistered_info()
                state = "unregistered"
                failed = False
            
            results, tld_ok = check_buyability(domain)
            cf_ok = bool(cf) and not cf["failed"]
            result_html = format_buyability_html(results, tld_ok, state, cf)
            if cf: cf_html = cf["html"]
            if cf and cf["failed"]: failed = True
        
        else: # Transfer check
            if state == "unregistered": result_html = _badge("badge-danger", "Không đủ Đ.kiện (Chưa ĐK)")
            elif state == "unknown": result_html = _badge("badge-warning", "Chưa xác định")
            elif state == "restricted": result_html = _badge("badge-danger", "Bị cấm (Restricted)")
            else:
                st = info["status_html"]
                is_locked = any(x in st for x in ["Khóa Transfer", "Đang chuyển", "serverHold", "clientHold"])
                created = info.get("created")
                days_old = 999
                if created:
                    try: days_old = (datetime.now() - datetime.strptime(created, "%d/%m/%y")).days
                    except: pass
                
                result_html = ""
                if is_locked: result_html += _badge("badge-warning", "Đang bị khóa Transfer") + "<br>"
                if days_old < 60: result_html += _badge("badge-danger", f"Chưa đủ 60 ngày ({days_old}d)") + "<br>"
                if not is_locked and days_old >= 60: result_html = _badge("badge-success", "Đủ điều kiện Transfer")

        return jsonify({
            "domain": domain,
            "result_html": result_html,
            "cf_add_status": cf_html,
            "registrar": info["registrar"],
            "status": info["status_html"],
            "created": info["created"],
            "expires": info["expires"],
            "failed": failed,
        })
    except Exception as e:
        log.exception("Lỗi %r", e)
        return jsonify(failed=True), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=_int_env("PORT", 5000))
