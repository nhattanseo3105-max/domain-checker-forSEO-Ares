import copy
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
from datetime import date, datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from functools import wraps

import requests
import whois
from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from bson import ObjectId
    from pymongo import MongoClient, UpdateOne
    from pymongo.errors import DuplicateKeyError, PyMongoError
except ImportError:  # chưa cài pymongo → chỉ dùng được APP_USERS + quy tắc mặc định
    MongoClient = UpdateOne = ObjectId = None

    class PyMongoError(Exception):
        pass

    class DuplicateKeyError(PyMongoError):
        pass

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

# GoDaddy API v3 (chỉ đọc) — token đặt ở biến môi trường GODADDY_PAT (scope domains.domain:read)
GODADDY_PAT = os.environ.get("GODADDY_PAT", "").strip()
GODADDY_MIN_INTERVAL = _float_env("GODADDY_MIN_INTERVAL", 1.1)   # GoDaddy giới hạn 60 req/phút/token
GD_VAT_RATE = _float_env("GD_VAT_RATE", 0.08)              # VAT cộng sẵn vào giá (8%)
GD_USD_VND = _float_env("GD_USD_VND", 27000)               # tỷ giá quy đổi 1 USD = ? VNĐ
GD_CACHE_TTL = _int_env("GD_CACHE_TTL", 300)               # cache giá trong RAM (giây)

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
    MAX_CONTENT_LENGTH=512 * 1024,
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
    log.info("APP_USERS chưa được cấu hình → chỉ dùng tài khoản lưu trong MongoDB "
             "(nếu MongoDB lỗi, app sẽ từ chối mọi truy cập — fail-closed).")

_DUMMY_HASH = generate_password_hash("dummy-password")


# ==========================================
# MONGODB ATLAS  (users · đuôi cấm/cho phép · domain cấm)
# ==========================================
# Khuyến nghị: đặt MONGODB_URI trong Environment của Render thay vì để trong code.
MONGODB_URI = os.environ.get("MONGODB_URI") or (
    "mongodb+srv://nhattanseo3105_db_user:HeSauzpD4Vn3fbfA@cluster0.lhnikju.mongodb.net/?appName=Cluster0"
)
MONGODB_DB = os.environ.get("MONGODB_DB", "domain_checker")

ADMIN_USERNAME = "admin"                      # CHỈ tài khoản tên "admin" mới có quyền quản trị
DEFAULT_ADMIN_PASSWORD = os.environ.get("ADMIN_DEFAULT_PASSWORD") or "ares#3105"

REGISTRARS = ["Namecheap", "GoDaddy", "Dynadot", "Spaceship", "SAV"]

KW_ACTIVE, KW_DISABLED = "active", "disabled"          # trạng thái keyword cấm theo nhà cung cấp
KW_MAX_PER_PROVIDER = 5000
NOTICE_DEFAULT_TITLE = "Thông báo từ admin"
NOTICE_TITLE_MAX, NOTICE_CONTENT_MAX = 120, 5000

# Cấu hình mặc định (khớp logic cũ). Admin có thể chỉnh trong tab "Đuôi cấm / cho phép".
#   banned   : ".uk" = cả đuôi .uk và mọi .xx.uk · ".co.uk" = đúng đuôi đó · "*.uk" = mọi .xx.uk (không gồm .uk thuần)
#   allowed  : đuôi cho phép đặc biệt (thắng khi cùng mức hoặc cụ thể hơn đuôi bị cấm)
#   keywords : ".in:india" = đuôi .in mà tên domain chứa "india" thì cấm
DEFAULT_RULES = {
    "Namecheap": {
        "banned": [".ch", ".li", ".cn", ".au", ".fr", ".ca", ".eu", ".eco", ".uk"],
        "allowed": ["*.uk"],                 # chỉ cấm .uk thuần; .co.uk .org.uk ... được phép
        "keywords": [".in:india"],
    },
    "GoDaddy": {"banned": [".in", ".cz", ".eu", ".dk"], "allowed": [], "keywords": []},   # .in = tất cả .in
    "Dynadot": {"banned": [".it", ".org"], "allowed": [], "keywords": []},
    "Spaceship": {"banned": [".de"], "allowed": [".uk", ".my"], "keywords": []},
    "SAV": {"banned": [], "allowed": [], "keywords": []},
}

_db_state = {"client": None, "db": None, "fail_ts": -1e9}
_db_lock = threading.Lock()


def _now():
    return datetime.utcnow()


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(dt, datetime) else None


def _ensure_extra_schema(db):
    """Index cho 2 tính năng: từ khóa cấm theo nhà cung cấp + thông báo popup.
    Chỉ TẠO MỚI collection/index (idempotent, không đụng dữ liệu cũ). Lỗi ở đây chỉ được log,
    không được làm hỏng kết nối DB / đăng nhập của phần còn lại."""
    try:
        # 1 keyword (đã normalize) chỉ xuất hiện 1 lần trong cùng 1 nhà cung cấp
        db.provider_banned_keywords.create_index(
            [("provider", 1), ("normalized_keyword", 1)], unique=True, name="uniq_provider_keyword")
        # tối đa 1 thông báo đang bật tại một thời điểm (ép ở tầng DB, chống race giữa 2 request)
        db.admin_notifications.create_index(
            "is_active", unique=True, partialFilterExpression={"is_active": True}, name="uniq_active_notice")
    except PyMongoError as e:
        log.error("Không tạo được index cho keyword cấm / thông báo (tính năng vẫn chạy, "
                  "nhưng hãy kiểm tra quyền createIndex): %s", e)


def _ensure_schema(db):
    db.users.create_index("username_lower", unique=True)
    db.domain_blocks.create_index("domain", unique=True)
    db.tld_rules.create_index("registrar", unique=True)
    _ensure_extra_schema(db)
    now = _now()
    if db.users.find_one({"username_lower": ADMIN_USERNAME}, {"_id": 1}) is None:
        try:
            db.users.insert_one({
                "username": ADMIN_USERNAME, "username_lower": ADMIN_USERNAME,
                "password_hash": generate_password_hash(DEFAULT_ADMIN_PASSWORD),
                "pv": secrets.token_hex(4), "default_pw": True,
                "created_at": now, "updated_at": now, "created_by": "system",
            })
            log.warning("Đã tạo tài khoản admin mặc định — hãy đổi mật khẩu sau khi đăng nhập.")
        except DuplicateKeyError:
            pass
    for reg in REGISTRARS:
        if db.tld_rules.find_one({"registrar": reg}, {"_id": 1}) is None:
            try:
                db.tld_rules.insert_one({"registrar": reg, **copy.deepcopy(DEFAULT_RULES[reg]),
                                         "updated_at": now, "updated_by": "system"})
            except DuplicateKeyError:
                pass


def get_db():
    """Trả về database (hoặc None nếu chưa kết nối được; tự thử lại mỗi 20 giây)."""
    if _db_state["db"] is not None:
        return _db_state["db"]
    if MongoClient is None or not MONGODB_URI:
        return None
    with _db_lock:
        if _db_state["db"] is not None:
            return _db_state["db"]
        now = time.monotonic()
        if now - _db_state["fail_ts"] < 20:
            return None
        try:
            client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=6000, connectTimeoutMS=6000,
                                 appname="domain-checker")
            client.admin.command("ping")
            db = client[MONGODB_DB]
            _ensure_schema(db)
            _db_state.update(client=client, db=db)
            log.info("Đã kết nối MongoDB Atlas (db=%s)", MONGODB_DB)
            return db
        except Exception as e:  # noqa: BLE001
            _db_state["fail_ts"] = now
            log.error("Không kết nối được MongoDB: %s", e)
            return None


# ---------- người dùng ----------
_user_cache = {}                      # username -> (monotonic_ts, pv)
_user_cache_lock = threading.Lock()
USER_CACHE_TTL = 15


def _clear_user_cache():
    with _user_cache_lock:
        _user_cache.clear()


def auth_ready():
    return bool(USERS) or get_db() is not None


def find_user(username):
    """→ {username, secret, pv, source} | None.  MongoDB trước, rồi APP_USERS (env) làm dự phòng."""
    name = (username or "").strip()
    if not name:
        return None
    db = get_db()
    if db is not None:
        try:
            doc = db.users.find_one({"username_lower": name.lower()})
            if doc:
                return {"username": doc["username"], "secret": doc.get("password_hash", ""),
                        "pv": doc.get("pv", ""), "source": "db"}
        except PyMongoError as e:
            log.error("Lỗi đọc user từ MongoDB: %s", e)
    secret = USERS.get(name)
    if secret is not None:
        return {"username": name, "secret": secret, "pv": "env", "source": "env"}
    return None


def authenticate(username, password):
    rec = find_user(username)
    if rec is None:
        check_password_hash(_DUMMY_HASH, password)   # giữ thời gian xử lý gần như nhau
        return None
    stored = rec["secret"]
    if stored.startswith(("scrypt:", "pbkdf2:")):
        ok = check_password_hash(stored, password)
    else:
        ok = hmac.compare_digest(stored.encode("utf-8"), password.encode("utf-8"))
    return rec if ok else None


def verify_password(username, password):
    return authenticate(username, password) is not None


def _session_user_pv(user):
    """→ (found, pv); found=None nếu lỗi DB."""
    err = False
    db = get_db()
    if db is not None:
        try:
            doc = db.users.find_one({"username": user}, {"pv": 1})
            if doc:
                return True, doc.get("pv", "")
        except PyMongoError as e:
            log.error("Lỗi kiểm tra phiên: %s", e)
            err = True
    if user in USERS:
        return True, "env"
    return (None if err else False), None


def session_valid():
    """Phiên còn hiệu lực? (user vẫn tồn tại và chưa bị đổi mật khẩu / xóa bởi admin)"""
    user = session.get("user")
    if not user:
        return False
    want = session.get("pv", "env")
    now = time.monotonic()
    with _user_cache_lock:
        hit = _user_cache.get(user)
    if hit and now - hit[0] < USER_CACHE_TTL:
        return hit[1] == want
    found, pv = _session_user_pv(user)
    if found is None:                                  # lỗi DB → dùng cache cũ nếu có
        return bool(hit) and hit[1] == want
    with _user_cache_lock:
        if found:
            _user_cache[user] = (now, pv)
        else:
            _user_cache.pop(user, None)
    return bool(found) and pv == want


def is_admin():
    return session.get("user") == ADMIN_USERNAME


_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def _validate_username(name):
    if not _USERNAME_RE.match(name or ""):
        return "Tên đăng nhập 3–32 ký tự, chỉ gồm chữ, số, _ . -"
    if name.lower() == ADMIN_USERNAME:
        return 'Tên "admin" được dành riêng'
    return None


def _validate_password(pw):
    if not pw or len(pw) < 6:
        return "Mật khẩu tối thiểu 6 ký tự"
    if len(pw) > 128:
        return "Mật khẩu tối đa 128 ký tự"
    return None


# ---------- cấu hình đuôi cấm / domain cấm (cache có TTL) ----------
_SUFFIX_RE = re.compile(r"^\*?(?:\.[a-z0-9-]{1,63}){1,3}$")
_KEYWORD_RE = re.compile(r"^[a-z0-9-]{1,63}$")


def _split_tokens(items):
    if isinstance(items, str):
        items = [items]
    out = []
    for it in items or []:
        out += [t for t in re.split(r"[\s,;]+", str(it)) if t]
    return out


def normalize_suffix(tok):
    s = str(tok).strip().lower()
    wild = s.startswith("*")
    s = s.lstrip("*").strip(".")
    if not s:
        return None
    s = ("*" if wild else "") + "." + s
    return s if _SUFFIX_RE.match(s) else None


def normalize_keyword(tok):
    tld, _, kw = str(tok).strip().lower().partition(":")
    tld = normalize_suffix(tld)
    kw = kw.strip()
    if not tld or tld.startswith("*") or not _KEYWORD_RE.match(kw):
        return None
    return f"{tld}:{kw}"


def clean_banned_keyword(raw):
    """Keyword cấm theo nhà cung cấp → (keyword hiển thị, keyword normalize, lỗi).
    Trim; normalize = chữ thường nên "Bitcoin" và "bitcoin" là CÙNG một keyword.
    Keyword được so khớp với tên domain nên chỉ nhận a-z, 0-9 và dấu gạch ngang (giống từ khóa đuôi:từ khóa)."""
    if not isinstance(raw, str):
        return None, None, "Keyword không hợp lệ"
    kw = raw.strip()
    if not kw:
        return None, None, "Keyword không được để trống"
    norm = kw.lower()
    if not _KEYWORD_RE.match(norm):
        return None, None, "Keyword chỉ gồm chữ a-z, số 0-9 và dấu gạch ngang (-), tối đa 63 ký tự, không có khoảng trắng"
    return kw, norm, None


def _banned_keyword_hit(domain, full_suffix, keywords):
    """Keyword (nếu có) nằm trong phần TÊN của domain (bỏ đuôi, vd 'india-shop' của 'india-shop.in')."""
    if not keywords:
        return ""
    name = domain[:-len(full_suffix)] if full_suffix and domain.endswith(full_suffix) else domain
    for kw in keywords:
        if kw in name:
            return "Tên domain chứa từ khóa bị cấm"          # không lộ keyword cho user thường
    return ""


def _clean_list(items, fn):
    good, bad = [], []
    for tok in _split_tokens(items):
        v = fn(tok)
        if v is None:
            bad.append(tok)
        elif v not in good:
            good.append(v)
    return sorted(good), bad


def extract_domains(text):
    out, seen = [], set()
    for tok in re.split(r"[\s,;|]+", str(text or "").lower()):
        tok = re.sub(r"^[a-z]+://", "", tok).split("/")[0].split(":")[0]
        if tok.startswith("www."):
            tok = tok[4:]
        tok = tok.rstrip(".")
        if tok and tok not in seen and DOMAIN_RE.match(tok):
            seen.add(tok)
            out.append(tok)
    return out


def _compile_rule(banned, allowed, keywords):
    kws = []
    for k in keywords or []:
        tld, _, kw = str(k).partition(":")
        if tld and kw:
            kws.append((tld, kw))
    return {"banned": set(banned or []), "allowed": set(allowed or []), "keywords": kws}


def _rule_to_lists(rule):
    return {"banned": sorted(rule["banned"]), "allowed": sorted(rule["allowed"]),
            "keywords": [f"{t}:{k}" for t, k in rule["keywords"]]}


def _default_config():
    return ({r: _compile_rule(**DEFAULT_RULES[r]) for r in REGISTRARS}, {})


_cfg = {"ts": -1e9, "rules": None, "blocks": None, "kw": None}   # kw: {registrar: tuple(keyword đang bật)}
_cfg_lock = threading.Lock()
CFG_TTL = 20


def _invalidate_config():
    with _cfg_lock:
        _cfg["ts"] = -1e9


def get_config(force=False):
    """→ (rules{registrar: rule}, blocks{domain: set(registrars)}) — cache 20s, tự nạp lại khi admin sửa."""
    now = time.monotonic()
    with _cfg_lock:
        if not force and _cfg["rules"] is not None and now - _cfg["ts"] < CFG_TTL:
            return _cfg["rules"], _cfg["blocks"]
        db = get_db()
        if db is None:
            if _cfg["rules"] is None:
                _cfg["rules"], _cfg["blocks"] = _default_config()
            if _cfg["kw"] is None:
                _cfg["kw"] = {}
            _cfg["ts"] = now - CFG_TTL + 5                       # thử lại sau ~5 giây
            return _cfg["rules"], _cfg["blocks"]
        try:
            rules, _ = _default_config()
            for doc in db.tld_rules.find({}):
                reg = doc.get("registrar")
                if reg in rules:
                    rules[reg] = _compile_rule(doc.get("banned"), doc.get("allowed"), doc.get("keywords"))
            blocks = {}
            for doc in db.domain_blocks.find({}, {"domain": 1, "registrars": 1}):
                if doc.get("registrars"):
                    blocks[doc["domain"]] = set(doc["registrars"])
            kw_acc = {}
            for doc in db.provider_banned_keywords.find({"status": KW_ACTIVE}, {"provider": 1, "normalized_keyword": 1}):
                if doc.get("provider") in rules and doc.get("normalized_keyword"):
                    kw_acc.setdefault(doc["provider"], []).append(doc["normalized_keyword"])
            _cfg.update(rules=rules, blocks=blocks, kw={p: tuple(v) for p, v in kw_acc.items()}, ts=now)
        except PyMongoError as e:
            log.error("Lỗi nạp cấu hình từ MongoDB: %s", e)
            if _cfg["rules"] is None:
                _cfg["rules"], _cfg["blocks"] = _default_config()
            if _cfg["kw"] is None:
                _cfg["kw"] = {}
            _cfg["ts"] = now - CFG_TTL + 5
        return _cfg["rules"], _cfg["blocks"]


def get_provider_keywords():
    """→ {registrar: tuple(keyword đã normalize, đang bật)} — dùng chung cache với get_config()."""
    get_config()
    return _cfg["kw"] or {}


def rules_summary():
    rules, _ = get_config()
    out = []
    for reg in REGISTRARS:
        r = rules[reg]
        lines = []
        if r["banned"]:
            lines.append("Cấm: " + " ".join(sorted(r["banned"])))
        if r["allowed"]:
            lines.append("Cho phép đặc biệt: " + " ".join(sorted(r["allowed"])))
        for tld, kw in r["keywords"]:
            lines.append(f'Cấm {tld} chứa "{kw}"')
        out.append({"name": reg, "lines": lines or ["Chưa có lưu ý · luôn cho phép"]})
    return out


# ---------- cài đặt kiểm tra (admin bật/tắt cho TẤT CẢ user) ----------
CHECK_OPTIONS = [
    ("check_buy", "Khả năng mua (theo registrar)"),
    ("check_registrar", "Nhà đăng ký (Registrar)"),
    ("check_dates", "Ngày đăng ký"),
    ("check_cf", "Cloudflare Banned"),
    ("check_hold", "Trạng thái Domain (Hold / Lock)"),
]
CHECK_OPTION_KEYS = [k for k, _ in CHECK_OPTIONS]
_opt_cache = {"ts": -1e9, "val": None}
_opt_lock = threading.Lock()
OPT_TTL = 10


def _invalidate_check_options():
    with _opt_lock:
        _opt_cache["ts"] = -1e9


def get_check_options(force=False):
    """→ {check_xxx: bool}  True = admin cho phép user tick mục này. Mục nào admin không chọn → False.
    Chưa cấu hình / MongoDB lỗi → dùng giá trị cache cũ hoặc mặc định (cho phép tất cả)."""
    now = time.monotonic()
    with _opt_lock:
        if not force and _opt_cache["val"] is not None and now - _opt_cache["ts"] < OPT_TTL:
            return dict(_opt_cache["val"])
        val = {k: True for k in CHECK_OPTION_KEYS}
        db = get_db()
        if db is None:
            if _opt_cache["val"] is not None:
                val = dict(_opt_cache["val"])
            _opt_cache["ts"] = now - OPT_TTL + 3
            _opt_cache["val"] = val
            return dict(val)
        try:
            doc = db.app_settings.find_one({"_id": "check_options"}) or {}
            saved = doc.get("options") or {}
            for k in CHECK_OPTION_KEYS:
                if k in saved:
                    val[k] = bool(saved[k])
            _opt_cache.update(ts=now, val=val)
        except PyMongoError as e:
            log.error("Lỗi đọc cài đặt kiểm tra từ MongoDB: %s", e)
            if _opt_cache["val"] is not None:
                val = dict(_opt_cache["val"])
            _opt_cache["ts"] = now - OPT_TTL + 3
            _opt_cache["val"] = val
        return dict(val)


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
admin_limiter = RateLimiter()
notice_limiter = RateLimiter()


def _csrf_ok(token):
    expected = session.get("csrf")
    if not expected or not token:
        return False
    return hmac.compare_digest(str(expected).encode("utf-8"), str(token).encode("utf-8"))


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not auth_ready():
            return "Chưa kết nối được MongoDB và chưa cấu hình APP_USERS trên server.", 503
        if "user" not in session:
            return redirect(url_for("login"))
        if not session_valid():                      # user bị xóa / đổi mật khẩu → đăng nhập lại
            session.clear()
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def api_guard(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if not auth_ready() or not user:
            return jsonify(error="unauthorized", failed=True), 401
        if not session_valid():
            session.clear()
            return jsonify(error="unauthorized", failed=True), 401
        if not _csrf_ok(request.headers.get("X-CSRF-Token", "")):
            return jsonify(error="csrf", failed=True), 403
        if api_limiter.blocked(user, API_LIMIT_PER_MIN, 60):
            return jsonify(error="rate_limited", failed=True), 429
        api_limiter.hit(user, 60)
        return view(*args, **kwargs)
    return wrapper


def admin_guard(view):
    """Chỉ tài khoản tên "admin" (đã đăng nhập, CSRF hợp lệ) mới gọi được API quản trị."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if not auth_ready() or not user:
            return jsonify(error="unauthorized"), 401
        if not session_valid():
            session.clear()
            return jsonify(error="unauthorized"), 401
        if not _csrf_ok(request.headers.get("X-CSRF-Token", "")):
            return jsonify(error="Phiên không hợp lệ (CSRF) — hãy tải lại trang"), 403
        if user != ADMIN_USERNAME:
            return jsonify(error="Chỉ tài khoản admin mới có quyền thực hiện"), 403
        key = "admin:" + user
        if admin_limiter.blocked(key, 120, 60):
            return jsonify(error="Thao tác quá nhanh, thử lại sau"), 429
        admin_limiter.hit(key, 60)
        return view(*args, **kwargs)
    return wrapper


def user_read_guard(view):
    """API chỉ-đọc cho mọi người dùng ĐÃ ĐĂNG NHẬP (vd lấy thông báo popup).
    Có limiter riêng để không ăn vào hạn mức /api/check của user."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if not auth_ready() or not user:
            return jsonify(success=False, error="unauthorized"), 401
        if not session_valid():
            session.clear()
            return jsonify(success=False, error="unauthorized"), 401
        key = "notice:" + user
        if notice_limiter.blocked(key, 60, 60):
            return jsonify(success=False, error="rate_limited"), 429
        notice_limiter.hit(key, 60)
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

# Các danh sách trên là cấu hình MẶC ĐỊNH (xem DEFAULT_RULES bên dưới) — admin chỉnh trực tiếp
# trên website, dữ liệu lưu ở MongoDB.

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


def _rule_hit(domain, full_suffix, last_tld, rule):
    """Trả về lý do bị cấm (chuỗi) hoặc "" nếu được phép.
    Mức cụ thể hơn thắng: đuôi đầy đủ (.co.uk) → wildcard (*.uk) → đuôi cuối (.uk).
    Cùng một mức mà có cả cấm lẫn cho phép → cho phép thắng."""
    order = [full_suffix]
    if full_suffix != last_tld:
        order += ["*" + last_tld, last_tld]
    reason = ""
    for c in order:
        if c in rule["allowed"]:
            break
        if c in rule["banned"]:
            if c == last_tld and full_suffix != last_tld:
                reason = f"Cấm đuôi {c} ({full_suffix})"
            elif c.startswith("*"):
                reason = f"Cấm đuôi {full_suffix}"
            else:
                reason = f"Cấm đuôi {c}"
            break
    if not reason:
        for tld, kw in rule["keywords"]:
            if tld in (full_suffix, last_tld) and kw in domain:
                reason = f'Domain {tld} chứa "{kw}"'
                break
    return reason


def check_buyability(domain: str):
    """Trả về ({registrar: {"ok": bool, "reason": str}}, can_buy)
    can_buy = True nếu có ÍT NHẤT 1 registrar cho phép.
    Quy tắc lấy từ MongoDB (admin chỉnh được) + danh sách domain cấm riêng của admin."""
    domain = domain.lower().strip()
    full_suffix, last_tld = get_tld_parts(domain)
    rules, blocks = get_config()
    blocked_regs = blocks.get(domain, ())
    kw_map = get_provider_keywords()
    results = {}
    for reg in REGISTRARS:
        reason = _rule_hit(domain, full_suffix, last_tld, rules[reg])
        if not reason and reg in blocked_regs:
            reason = "Domain nằm trong danh sách cấm nội bộ"
        if not reason:
            reason = _banned_keyword_hit(domain, full_suffix, kw_map.get(reg))
        results[reg] = {"ok": not reason, "reason": reason}
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
                + "<div class='buy-reason'>Hãy thử kiểm tra lại domain này.</div>")
    if cf.get("failed"):
        return (_badge("badge-warning", "CHƯA XÁC ĐỊNH")
                + "<div class='buy-reason'>Hãy thử kiểm tra lại domain này.</div>")

    banned = [(n, i["reason"] or "TLD bị cấm") for n, i in results.items() if not i["ok"]]
    ban_tags = " ".join(
        f"<span class='ban-tag' title='{html.escape(reason, quote=True)}'>{html.escape(name)}</span>"
        for name, reason in banned
    )
    cf_blocked = bool(cf.get("blocked"))

    if tld_ok and not cf_blocked:
        out = [_badge("badge-success", "CÓ THỂ MUA")]
        if banned:
            out.append(f"<div class='buy-reason'>⛔ Cấm tại: {ban_tags}</div>")
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


# ---------- bổ sung: retry HTTP, RDAP chính thức của TLD (IANA bootstrap), DNS ----------
def _http_get(url, timeout=(4, 8), tries=2, **kw):
    """GET có retry khi timeout / 429 / 5xx. Trả về Response hoặc None nếu mọi lần đều lỗi."""
    last = None
    headers = kw.pop("headers", HTTP_HEADERS)
    for i in range(tries):
        try:
            r = requests.get(url, timeout=timeout, headers=headers, **kw)
            if r.status_code in (429, 500, 502, 503, 504) and i < tries - 1:
                time.sleep(0.8 * (i + 1))
                continue
            return r
        except requests.RequestException as e:
            last = e
            if i < tries - 1:
                time.sleep(0.5)
    if last:
        log.info("GET %s lỗi: %s", url.split("/")[2], last)
    return None


_IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_IANA_TTL = 24 * 3600
_bootstrap = {"map": None, "ts": 0.0, "fail_ts": -1e9}
_bootstrap_lock = threading.Lock()


def _rdap_base_for(domain):
    """URL RDAP chính thức của TLD (lấy từ IANA, cache 24h).
    Trả về: URL | "" nếu TLD không có RDAP | None nếu chưa tải được bootstrap."""
    now = time.monotonic()
    with _bootstrap_lock:
        stale = _bootstrap["map"] is None or now - _bootstrap["ts"] > _IANA_TTL
        if stale and now - _bootstrap["fail_ts"] > 60:
            data = _fetch_json(_IANA_BOOTSTRAP_URL, timeout=(4, 8))
            mapping = {}
            try:
                for tlds, urls in (data or {}).get("services", []):
                    https = [u for u in urls if u.startswith("https://")] or urls
                    for t in tlds:
                        mapping[t.lower()] = https[0]
            except (TypeError, ValueError, IndexError):
                mapping = {}
            if mapping:
                _bootstrap.update(map=mapping, ts=now)
            else:
                _bootstrap["fail_ts"] = now
        mapping = _bootstrap["map"]
    if mapping is None:
        return None
    return mapping.get(domain.rsplit(".", 1)[-1].lower(), "")


def _dns_ns_check(domain, timeout=4):
    """Hỏi NS qua DNS-over-HTTPS. Trả về "exists" | "nxdomain" | "nodata" | None (không hỏi được)."""
    for url in ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"):
        r = _http_get(url, timeout=(timeout, timeout), tries=1,
                      params={"name": domain, "type": "NS"},
                      headers={**HTTP_HEADERS, "Accept": "application/dns-json"})
        if r is None or r.status_code != 200:
            continue
        try:
            j = r.json()
        except ValueError:
            continue
        if j.get("Status") == 3:
            return "nxdomain"
        if j.get("Status") == 0:
            has_ns = any(a.get("type") == 2 for a in (j.get("Answer") or []))
            return "exists" if has_ns else "nodata"
    return None


def _rdap_event_date(data, actions):
    """Ngày (date) mới nhất của sự kiện RDAP có eventAction thuộc `actions`, hoặc None."""
    best = None
    for ev in (data.get("events") or []) if isinstance(data, dict) else []:
        if str(ev.get("eventAction", "")).lower() in actions:
            m = re.search(r"(\d{4})-(\d{2})-(\d{2})", str(ev.get("eventDate", "")))
            if m:
                try:
                    d = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                except ValueError:
                    continue
                best = d if best is None or d > best else best
    return best


def _unregistered_info():
    ok = _badge("badge-success", "Chưa đăng ký")
    return {"state": "unregistered", "status_html": ok, "registrar": ok, "created": None, "expires": None}


def get_domain_info(domain):
    """
    Trả về dict: state ∈ {registered, unregistered, restricted, unknown}, status_html, registrar, created, expires.

    - registered   : có registrar HOẶC ngày đăng ký (bằng chứng chắc chắn)
    - unregistered : RDAP 404 / nguồn trả rỗng VÀ whois xác nhận "no match" (hoặc RDAP 404 + DNS NXDOMAIN)
    - restricted   : RDAP 404 kèm nội dung Registry Policy
    - unknown      : mọi nguồn lỗi / không đủ bằng chứng → KHÔNG được coi là "chưa đăng ký"
    """
    deadline = time.monotonic() + LOOKUP_BUDGET_SEC
    remaining = lambda: deadline - time.monotonic()  # noqa: E731

    status, registrar, created, expires = set(), None, None, None
    restricted = rdap_404 = empty_ok = False
    last_transfer = None

    def merge(parsed):
        nonlocal status, registrar, created, expires
        st, reg, cr, exp = parsed
        status |= st
        registrar = registrar or reg
        created = created or cr
        expires = expires or exp

    # ---- 1. RDAP: server chính thức của TLD (IANA) → fallback rdap.org ----
    base = _rdap_base_for(domain)
    no_rdap_tld = base == ""
    rdap_urls = []
    if base:
        rdap_urls.append(base.rstrip("/") + "/domain/" + domain)
    if not no_rdap_tld:
        rdap_urls.append(f"https://rdap.org/domain/{domain}")
    for url in rdap_urls:
        if remaining() <= 2:
            break
        r = _http_get(url, timeout=(4, min(8, max(2, remaining()))))
        if r is None:
            continue
        if r.status_code == 200:
            try:
                rdap_json = r.json()
                merge(_parse_rdap_json(rdap_json))
                last_transfer = _rdap_event_date(rdap_json, ("transfer",)) or last_transfer
            except ValueError:
                continue
            break
        if r.status_code == 404:
            rdap_404 = True
            restricted = _looks_restricted(r)
            break
        log.info("RDAP %s %s → HTTP %s", url.split("/")[2], domain, r.status_code)

    def need_more():
        return not restricted and not (registrar or created)

    # ---- 1b. DNS (nhanh) – bằng chứng phụ ----
    dns = _dns_ns_check(domain) if need_more() and remaining() > 3 else None

    # ---- 2. who-dat / rdap.cloud (chỉ khi RDAP không cho kết quả & không phải 404) ----
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
            "status_keys": sorted(status), "transferred": last_transfer,
        }
    # Có NS đang chạy = chắc chắn đã có chủ (dù không lấy được registrar/ngày)
    if dns == "exists":
        return {
            "state": "registered",
            "status_html": format_status_display(status),
            "registrar": "Không xác định (có DNS)", "created": None, "expires": None,
            "status_keys": sorted(status), "transferred": last_transfer,
        }
    # Chưa đăng ký: cần 1 nguồn "không có" + 1 nguồn xác nhận.
    # NXDOMAIN một mình KHÔNG đủ (domain bị clientHold cũng NXDOMAIN) → chỉ dùng kèm RDAP 404 chính thức.
    if whois_no_match and (rdap_404 or empty_ok or no_rdap_tld):
        return _unregistered_info()
    if rdap_404 and dns == "nxdomain":
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
# 2b. KIỂM TRA ĐỦ ĐIỀU KIỆN TRANSFER
# ==========================================
TRANSFER_MIN_DAYS = _int_env("TRANSFER_MIN_DAYS", 60)

_TRANSFER_BLOCKERS = {
    "serverTransferProhibited": "Registry chặn Transfer (serverTransferProhibited)",
    "pendingTransfer": "Domain đang trong quá trình transfer (pendingTransfer)",
    "redemptionPeriod": "Domain đang ở Redemption Period",
    "pendingDelete": "Domain đang Pending Delete",
    "pendingRestore": "Domain đang Pending Restore",
    "serverHold": "Domain bị serverHold",
}


CLIENT_LOCK_NOTE = "clientTransferProhibited - liên hệ IT để mở khóa domain"


def _parse_short_date(s):
    """'DD/MM/YY' → date (YY ≤ năm hiện tại+1 → 20YY, ngược lại 19YY)"""
    m = re.fullmatch(r"(\d{2})/(\d{2})/(\d{2})", s or "")
    if not m:
        return None
    d, mo, yy = (int(x) for x in m.groups())
    year = 2000 + yy if yy <= (datetime.utcnow().year % 100) + 1 else 1900 + yy
    try:
        return date(year, mo, d)
    except ValueError:
        return None


def check_transfer_eligibility(domain):
    """Đủ điều kiện transfer = đã đăng ký > TRANSFER_MIN_DAYS ngày (và lần transfer gần nhất nếu có)
    + không bị chặn transfer. Dữ liệu từ WHOIS/RDAP công khai."""
    info = get_domain_info(domain)
    state = info["state"]
    out = {
        "domain": domain, "eligible": False, "failed": False, "age_days": None, "reasons": [],
        "registrar": info["registrar"], "status": info["status_html"],
        "created": info["created"], "expires": info["expires"], "result_html": "",
    }

    def done(badge_cls, text, reasons=(), ok_note=""):
        out["reasons"] = list(reasons)
        parts = [_badge(badge_cls, text)]
        parts += [f"<div class='buy-reason'>⛔ {html.escape(r)}</div>" for r in reasons]
        if ok_note:
            parts.append(f"<div class='buy-reason ok'>{html.escape(ok_note)}</div>")
        out["result_html"] = "".join(parts)
        return out

    if state == "unknown":
        out["failed"] = True
        return done("badge-warning", "CHƯA XÁC ĐỊNH", ["Không tra cứu được WHOIS/RDAP — bấm Retry lỗi"])
    if state == "unregistered":
        return done("badge-muted", "CHƯA ĐĂNG KÝ", ["Domain chưa đăng ký — không có gì để transfer"])
    if state == "restricted":
        return done("badge-danger", "KHÔNG THỂ TRANSFER", ["Domain bị Registry Policy cấm đăng ký"])

    today = datetime.utcnow().date()
    reasons = []
    created = _parse_short_date(info["created"])
    if created:
        age = (today - created).days
        out["age_days"] = age
        if age <= TRANSFER_MIN_DAYS:
            reasons.append(f"Mới đăng ký {age} ngày — cần hơn {TRANSFER_MIN_DAYS} ngày "
                           f"(còn {TRANSFER_MIN_DAYS + 1 - age} ngày nữa)")
    transferred = info.get("transferred")
    if transferred:
        since = (today - transferred).days
        if since <= TRANSFER_MIN_DAYS:
            reasons.append(f"Vừa transfer {since} ngày trước — cần hơn {TRANSFER_MIN_DAYS} ngày kể từ lần transfer gần nhất")
    keys = set(info.get("status_keys") or [])
    client_lock = "clientTransferProhibited" in keys          # khóa ở registrar → chỉ cần IT mở khóa
    for key, text in _TRANSFER_BLOCKERS.items():
        if key in keys:
            reasons.append(text)

    if reasons:
        if client_lock:
            reasons.append(CLIENT_LOCK_NOTE)
        return done("badge-danger", "CHƯA ĐỦ ĐIỀU KIỆN", reasons)
    if not created:
        notes = ["Không lấy được ngày đăng ký nên chưa kiểm tra được mốc 60 ngày "
                 + ("(không phát hiện khóa transfer)" if not client_lock else "")]
        if client_lock:
            notes.append(CLIENT_LOCK_NOTE)
        return done("badge-warning", "CHƯA XÁC ĐỊNH", notes)
    if client_lock:
        out["eligible"] = True
        out["needs_unlock"] = True
        out["reasons"] = [CLIENT_LOCK_NOTE]
        out["result_html"] = (
            _badge("badge-warning", "Có thể chuyển")
            + f"<div class='buy-reason'>⚠ {html.escape(CLIENT_LOCK_NOTE)}</div>"
            + f"<div class='buy-reason ok'>✓ Đã đăng ký {out['age_days']} ngày</div>")
        return out
    out["eligible"] = True
    return done("badge-success", "ĐỦ ĐIỀU KIỆN",
                ok_note=f"✓ Đã đăng ký {out['age_days']} ngày · không bị chặn transfer")


# ==========================================
# 2c. GIÁ DOMAIN MUA MỚI (1 NĂM) TỪ GODADDY API v3
# ==========================================
GD_CHECK_URL = "https://api.godaddy.com/v3/domains/check-availability"
_gd_lock = threading.Lock()
_gd_last_call = 0.0
_gd_block_until = 0.0            # sau khi bị 429: tạm dừng gọi đến mốc này (monotonic)
_gd_cache = {}
_gd_cache_lock = threading.Lock()


def _gd_throttle():
    """Giãn cách các lần gọi GoDaddy giữa mọi thread (giới hạn 60 req/phút/token)."""
    global _gd_last_call
    with _gd_lock:
        wait = GODADDY_MIN_INTERVAL - (time.monotonic() - _gd_last_call)
        if wait > 0:
            time.sleep(wait)
        _gd_last_call = time.monotonic()


def _gd_result(state, html_, failed=False, **extra):
    out = {"state": state, "failed": failed, "result_html": html_,
           "price_usd": "", "price_vat": "", "price_vnd": ""}
    out.update(extra)
    return out


def _fmt_usd(amount):
    return "$" + format(amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP), ",.2f")


def _fmt_vnd(amount):
    return format(int(amount.quantize(Decimal("1"), rounding=ROUND_HALF_UP)), ",").replace(",", ".") + " ₫"


def _gd_pick_one_year(prices):
    """Lấy mục giá đăng ký 1 năm (period = 1, term = YEAR) trong prices[]."""
    for p in prices or []:
        try:
            if int(p.get("period")) == 1 and str(p.get("term", "YEAR")).upper() == "YEAR":
                return p
        except (TypeError, ValueError, AttributeError):
            continue
    return None


def _gd_build_price(data):
    """JSON check-availability → kết quả hiển thị. Giá API tính theo cent."""
    domain_note = ""
    inventory = str(data.get("inventory") or "")
    if inventory and inventory.upper() != "REGISTRY":
        domain_note = "<div class='buy-reason'>Nguồn: " + html.escape(inventory) + " (có thể là domain premium)</div>"

    if not data.get("available"):
        return _gd_result("unavailable", _badge("badge-muted", "KHÔNG KHẢ DỤNG") +
                          "<div class='buy-reason'>GoDaddy báo domain không đăng ký mới được</div>")

    one = _gd_pick_one_year(data.get("prices"))
    price = (one or {}).get("price") or {}
    try:
        cents = Decimal(str(price.get("value")))
    except Exception:  # noqa: BLE001
        cents = None
    if one is None or cents is None:
        return _gd_result("noprice", _badge("badge-warning", "KHÔNG CÓ GIÁ 1 NĂM") + domain_note)

    cur = str(price.get("currencyCode") or "USD").upper()
    base = cents / Decimal(100)
    with_vat = base * (Decimal(1) + Decimal(str(GD_VAT_RATE)))
    if cur != "USD":      # chỉ quy đổi tỷ giá khi giá gốc là USD
        return _gd_result("ok", _badge("badge-success", "CÓ GIÁ") + domain_note +
                          "<div class='buy-reason'>Đơn vị " + html.escape(cur) + " — chưa quy đổi VNĐ</div>",
                          price_usd=f"{base:.2f} {cur}", price_vat=f"{with_vat:.2f} {cur}")
    vnd = with_vat * Decimal(str(GD_USD_VND))
    return _gd_result("ok", _badge("badge-success", "CÓ GIÁ") + domain_note,
                      price_usd=_fmt_usd(base), price_vat=_fmt_usd(with_vat), price_vnd=_fmt_vnd(vnd))


def check_godaddy_price(domain):
    """Giá đăng ký mới 1 năm trên GoDaddy (API v3, chỉ đọc) + VAT + quy đổi VNĐ."""
    global _gd_block_until
    if not GODADDY_PAT:
        return _gd_result("nokey", _badge("badge-muted", "Thiếu API GoDaddy"))

    now = time.monotonic()
    with _gd_cache_lock:
        hit = _gd_cache.get(domain)
        if hit and hit[0] > now:
            return dict(hit[1])
    if _gd_block_until > now:
        return _gd_result("ratelimit", _badge("badge-warning", "GoDaddy giới hạn tốc độ — thử lại sau"), failed=True)

    headers = {"Authorization": f"Bearer {GODADDY_PAT}", "Accept": "application/json",
               "User-Agent": HTTP_HEADERS["User-Agent"]}
    try:
        _gd_throttle()
        r = requests.get(GD_CHECK_URL, headers=headers, params={"domain": domain}, timeout=(5, 12))
    except requests.RequestException as e:
        log.warning("GoDaddy lỗi %s: %s", domain, type(e).__name__)
        return _gd_result("error", _badge("badge-danger", "Lỗi gọi API GoDaddy"), failed=True)

    if r.status_code == 429:
        try:
            wait = min(max(int(r.headers.get("Retry-After", "30")), 1), 120)
        except ValueError:
            wait = 30
        _gd_block_until = time.monotonic() + wait
        log.warning("GoDaddy 429 — tạm dừng %ss", wait)
        return _gd_result("ratelimit", _badge("badge-warning", "GoDaddy giới hạn tốc độ — thử lại sau"), failed=True)
    if r.status_code == 401:
        log.error("GoDaddy 401: GODADDY_PAT sai hoặc đã hết hạn / bị thu hồi")
        return _gd_result("auth", _badge("badge-danger", "Token GoDaddy không hợp lệ"), failed=True)
    if r.status_code == 403:
        log.error("GoDaddy 403: token thiếu scope domains.domain:read hoặc tài khoản chưa đủ điều kiện")
        return _gd_result("auth", _badge("badge-danger", "Token thiếu quyền / tài khoản chưa đủ điều kiện"), failed=True)
    if r.status_code == 400:
        return _gd_result("invalid", _badge("badge-muted", "GoDaddy từ chối domain này"))
    if r.status_code >= 500:
        return _gd_result("error", _badge("badge-warning", "GoDaddy quá tải — thử lại"), failed=True)
    if r.status_code != 200:
        log.warning("GoDaddy HTTP %s cho %s", r.status_code, domain)
        return _gd_result("error", _badge("badge-danger", f"Lỗi GoDaddy HTTP {r.status_code}"), failed=True)
    try:
        data = r.json()
    except ValueError:
        return _gd_result("error", _badge("badge-muted", "GoDaddy trả phản hồi không hợp lệ"), failed=True)

    out = _gd_build_price(data if isinstance(data, dict) else {})
    if not out["failed"]:
        with _gd_cache_lock:
            if len(_gd_cache) > 5000:
                _gd_cache.clear()
            _gd_cache[domain] = (time.monotonic() + GD_CACHE_TTL, dict(out))
    return out


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

        /* ===== Tabs & form (tính năng mới) ===== */
        .tabs { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 18px; border-bottom: 1px solid var(--border); }
        .tab-btn {
            background: transparent; color: var(--text-muted); border: 1px solid transparent; border-bottom: none;
            border-radius: 8px 8px 0 0; padding: 10px 16px; font-size: 13.5px; font-weight: 600;
        }
        .tab-btn:hover { color: var(--text); background: var(--bg-elevated); }
        .tab-btn.active { color: #fff; background: var(--bg-card); border-color: var(--border-light); box-shadow: inset 0 2px 0 var(--primary); }
        .tab-sep { width: 1px; background: var(--border-light); margin: 6px 6px; }
        .tab-panel { display: none; }
        .tab-panel.show { display: block; }
        .field {
            width: 100%; padding: 10px 12px; background: var(--bg); border: 1px solid var(--border);
            border-radius: var(--radius-sm); color: var(--text); font-size: 14px; font-family: inherit;
        }
        .field:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2); }
        .field-mono { font-family: 'JetBrains Mono', monospace; font-size: 13px; }
        textarea.field { height: 86px; resize: vertical; }
        .form-row { display: flex; gap: 12px; flex-wrap: wrap; align-items: flex-end; }
        .form-group { display: flex; flex-direction: column; gap: 6px; flex: 1; min-width: 200px; }
        .form-group label { font-size: 12.5px; color: var(--text-muted); font-weight: 500; }
        .inline-row { display: flex; gap: 6px; }
        .hint { font-size: 12px; color: var(--text-dim); line-height: 1.55; margin-top: 8px; }
        .section-title { font-size: 15px; font-weight: 700; margin-bottom: 6px; }
        .check-grid { display: flex; flex-wrap: wrap; gap: 10px; margin: 14px 0 4px; }
        .check-chip {
            display: inline-flex; align-items: center; gap: 8px; padding: 8px 12px; background: var(--bg);
            border: 1px solid var(--border-light); border-radius: 8px; cursor: pointer; font-size: 13.5px; user-select: none;
        }
        .check-chip input { width: 16px; height: 16px; accent-color: var(--primary); cursor: pointer; }
        .btn-danger { background: linear-gradient(135deg, #ef4444, #dc2626); color: #fff; }
        .btn-sm { padding: 6px 12px; font-size: 12.5px; }
        .rules-edit-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr)); gap: 16px; }
        .reg-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); padding: 18px; }
        .reg-card h4 { font-size: 15px; margin-bottom: 12px; }
        .reg-card .form-group { margin-bottom: 10px; }
        .msg { font-size: 13px; min-height: 18px; margin-top: 8px; }
        .msg.ok { color: #4ade80; }
        .msg.err { color: #f87171; }
        .buy-reason.ok { color: #4ade80; }
        .tbl-sm { min-width: 560px; }
        .tag-x {
            display: inline-flex; align-items: center; gap: 4px; background: rgba(239, 68, 68, 0.18); color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 6px; padding: 1px 4px 1px 8px; font-size: 11.5px;
            font-weight: 600; margin: 2px;
        }
        .tag-x button { background: none; padding: 0 5px; font-size: 14px; color: #fca5a5; line-height: 1.2; border-radius: 4px; }
        .tag-x button:hover { background: rgba(239, 68, 68, 0.3); }
        .price-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }
        .price-card h3 { font-size: 15px; margin-bottom: 8px; }
        .price-card p { font-size: 13px; color: var(--text-muted); margin-bottom: 16px; line-height: 1.55; }
        a.link-btn {
            display: inline-flex; align-items: center; gap: 6px; padding: 10px 18px; font-size: 14px; font-weight: 600;
            border-radius: var(--radius-sm); text-decoration: none; color: #fff;
            background: linear-gradient(135deg, #3b82f6, #2563eb); box-shadow: 0 2px 12px rgba(59, 130, 246, 0.35);
        }
        a.link-btn:hover { transform: translateY(-1px); }
        .user-box .badge { font-size: 10.5px; }

        /* ===== Popup thông báo (hiển thị cho mọi user khi vào / F5 trang) ===== */
        .notice-overlay {
            position: fixed; inset: 0; z-index: 2000; background: rgba(0, 0, 0, 0.65); backdrop-filter: blur(4px);
            opacity: 0; visibility: hidden; transition: opacity 0.25s ease, visibility 0s linear 0.25s;
        }
        .notice-overlay.show { opacity: 1; visibility: visible; transition: opacity 0.25s ease; }
        .notice-dialog {
            position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%) scale(0.94);
            width: min(480px, calc(100vw - 32px)); max-height: calc(100vh - 32px); max-height: calc(100dvh - 32px);
            display: flex; flex-direction: column; text-align: center; padding: 26px 24px 22px;
            background: var(--bg-card); border: 1px solid var(--border-light); border-radius: 16px;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5); transition: transform 0.25s ease;
        }
        .notice-overlay.show .notice-dialog { transform: translate(-50%, -50%) scale(1); }
        .notice-icon { font-size: 30px; line-height: 1; margin-bottom: 10px; flex-shrink: 0; }
        .notice-title { font-size: 1.15rem; font-weight: 700; margin-bottom: 12px; flex-shrink: 0; overflow-wrap: anywhere; }
        .notice-body {
            flex: 1 1 auto; min-height: 0; overflow-y: auto; overscroll-behavior: contain; white-space: pre-wrap;
            overflow-wrap: anywhere; font-size: 14px; line-height: 1.65; color: var(--text-muted);
            scrollbar-width: thin; scrollbar-color: var(--border-light) transparent;
        }
        .notice-count { margin-top: 16px; font-size: 12.5px; color: var(--text-dim); flex-shrink: 0; }
        .notice-close { margin: 12px auto 0; justify-content: center; min-width: 120px; flex-shrink: 0; }
        @media (prefers-reduced-motion: reduce) {
            .notice-overlay, .notice-overlay.show, .notice-dialog { transition: none; }
        }

{% if is_admin %}
        /* ===== Admin: toast + các tab quản trị mới ===== */
        .toast-box {
            position: fixed; right: 18px; bottom: 18px; z-index: 3000; display: flex; flex-direction: column;
            gap: 8px; max-width: calc(100vw - 36px); pointer-events: none;
        }
        .toast {
            pointer-events: auto; background: var(--bg-elevated); border: 1px solid var(--border-light);
            border-left: 3px solid var(--primary); color: var(--text); padding: 10px 14px; font-size: 13px;
            border-radius: var(--radius-sm); box-shadow: 0 8px 28px rgba(0, 0, 0, 0.45); animation: toastIn 0.2s ease;
        }
        .toast.ok { border-left-color: var(--success); }
        .toast.err { border-left-color: var(--danger); color: #fca5a5; }
        @keyframes toastIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
        .kw-provs { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
        .kw-prov {
            background: var(--bg); color: var(--text-muted); border: 1px solid var(--border-light);
            padding: 8px 14px; font-size: 13.5px;
        }
        .kw-prov:hover { color: var(--text); background: var(--bg-elevated); }
        .kw-prov.active { color: #fff; border-color: var(--primary); background: rgba(59, 130, 246, 0.15); }
        .kw-count { background: var(--bg-elevated); border-radius: 10px; padding: 0 7px; font-size: 11.5px; color: var(--text-muted); }
        select.field { cursor: pointer; }
        textarea.field-text { font-family: inherit; font-size: 14px; }
        .nt-content { white-space: normal; max-width: 360px; overflow-wrap: anywhere; color: var(--text-muted); }
        .nt-current { display: flex; gap: 12px; align-items: flex-start; flex-wrap: wrap; }
        .nt-current > div { flex: 1; min-width: 220px; }
        .row-actions { display: flex; gap: 6px; flex-wrap: wrap; }
{% endif %}
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
                {% if is_admin %}<span class="badge badge-info">ADMIN</span>{% endif %}
                <form method="post" action="/logout">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                    <button type="submit" class="btn-secondary">Đăng xuất</button>
                </form>
            </div>
        </div>

        <div class="tabs" id="tabsBar">
            <button class="tab-btn active" data-tab="buy">◈ Kiểm tra mua domain</button>
            <button class="tab-btn" data-tab="transfer">⇄ Kiểm tra Transfer</button>
            <button class="tab-btn" data-tab="price">$ Kiểm tra giá mua mới Godaddy (tham khảo)</button>
            {% if is_admin %}
            <span class="tab-sep"></span>
            <button class="tab-btn" data-tab="rules">⚙ Đuôi cấm / cho phép</button>
            <button class="tab-btn" data-tab="checkopts">☑ Cài đặt kiểm tra</button>
            <button class="tab-btn" data-tab="blocks">🚫 Domain cấm (ẩn)</button>
            <button class="tab-btn" data-tab="keywords">🔤 Cấm Keyword</button>
            <button class="tab-btn" data-tab="notices">📢 Thông báo</button>
            <button class="tab-btn" data-tab="users">👥 Tài khoản</button>
            {% endif %}
        </div>

        <div class="tab-panel show" id="tab-buy">

        <!-- Important note -->
        <div class="note-box">
            <span class="note-icon">⚠️</span>
            <div>
                <strong>Lưu ý quan trọng:</strong>
                Đây là thông tin tham khảo, có thể mua được hay không còn tùy thuộc vào thời điểm và quy định riêng của từng nhà cung cấp.
            </div>
        </div>

        <!-- Rules summary (tự cập nhật theo cấu hình admin) -->
        <div class="rules-card">
            <h3>◈ Tiêu chí cấm mua theo Registrar</h3>
            <div class="rules-grid" id="rulesGrid"></div>
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
                            <span>Chưa xác định được / lỗi Cloudflare · hãy thử kiểm tra lại domain này</span>
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
        </div><!-- /tab-buy -->

        <!-- ================= TAB: KIỂM TRA TRANSFER ================= -->
        <div class="tab-panel" id="tab-transfer">
            <div class="note-box">
                <span class="note-icon">ℹ️</span>
                <div>
                    <strong>Điều kiện đủ transfer:</strong> domain đã đăng ký <b>hơn 60 ngày</b> (và hơn 60 ngày kể từ lần transfer gần nhất nếu có)
                    và <b>không bị chặn transfer</b> (serverTransferProhibited, pendingTransfer, Redemption / Pending Delete, serverHold).
                    Riêng <b>clientTransferProhibited</b> vẫn báo vàng <b>Có thể chuyển</b> — cần liên hệ IT để mở khóa domain.
                    Dữ liệu lấy từ WHOIS/RDAP công khai nên chỉ mang tính tham khảo; một số ccTLD có quy định riêng và khi chuyển vẫn cần mã Auth/EPP từ registrar hiện tại.
                </div>
            </div>
            <div class="card">
                <textarea id="tfList" placeholder="Nhập domain cần kiểm tra transfer (mỗi dòng 1 domain)&#10;example.com&#10;example.net"></textarea>
                <div class="action-bar">
                    <button id="btnTf" class="btn-primary" onclick="startTransfer(false)">▶ Kiểm tra Transfer</button>
                    <button id="btnTfRetry" class="btn-warning" onclick="startTransfer(true)" disabled>↻ Retry lỗi</button>
                    <div class="delay-box">
                        <label for="tfDelay">Delay</label>
                        <input type="number" id="tfDelay" value="300" min="0" step="100" title="ms giữa mỗi domain">
                        <span>ms</span>
                    </div>
                </div>
                <div class="progress" id="tfProgress">Sẵn sàng kiểm tra</div>
            </div>
            <div class="table-card">
                <div class="table-wrapper">
                    <table>
                        <thead><tr><th>Domain</th><th>Kết quả</th><th>Ngày đăng ký</th><th>Tuổi domain</th><th>Nhà đăng ký</th><th>Trạng thái Domain</th></tr></thead>
                        <tbody id="tfBody"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ================= TAB: KIỂM TRA GIÁ GODADDY (API) ================= -->
        <div class="tab-panel" id="tab-price">
            <div class="note-box">
                <span class="note-icon">⚠️</span>
                <div>
                    <strong>Giá đăng ký mới 1 năm trên GoDaddy</strong>, đã cộng sẵn <b>VAT {{ gd_vat_pct }}%</b> và quy đổi theo tỷ giá <b>1 USD = {{ gd_rate }} VNĐ</b>.
                    Giá lấy từ API GoDaddy nên chỉ mang tính tham khảo (giá chính thức chốt lúc mua).
                    Nếu giá domain rẻ bất thường, vui lòng liên hệ IT mua domain để được hỗ trợ kiểm tra giá.
                </div>
            </div>
            <div class="card">
                <textarea id="gdList" placeholder="Nhập domain cần xem giá (mỗi dòng 1 domain)&#10;example.com&#10;example.net"></textarea>
                <div class="action-bar">
                    <button id="btnGd" class="btn-primary" onclick="startPrice(false)">▶ Kiểm tra giá</button>
                    <button id="btnGdRetry" class="btn-warning" onclick="startPrice(true)" disabled>↻ Retry lỗi</button>
                    <div class="delay-box">
                        <label for="gdDelay">Delay</label>
                        <input type="number" id="gdDelay" value="0" min="0" step="100" title="ms giữa mỗi domain (server đã tự giãn cách để không vượt 60 req/phút của GoDaddy)">
                        <span>ms</span>
                    </div>
                </div>
                <div class="progress" id="gdProgress">Sẵn sàng kiểm tra</div>
            </div>
            <div class="table-card">
                <div class="table-wrapper">
                    <table>
                        <thead><tr><th>Domain</th><th>Kết quả</th><th>Giá gốc 1 năm (USD)</th><th>Giá + VAT {{ gd_vat_pct }}% (USD)</th><th>Quy đổi (VNĐ)</th></tr></thead>
                        <tbody id="gdBody"></tbody>
                    </table>
                </div>
            </div>
            <div class="price-grid">
                <div class="card price-card">
                    <h3>🛒 Xem trực tiếp trên GoDaddy</h3>
                    <p>Liên kết dự phòng khi API lỗi hoặc cần đối chiếu giá: mở Bulk Domain Search của GoDaddy ở tab mới.</p>
                    <a class="link-btn" href="https://www.godaddy.com/en/domains/bulk-domain-search" target="_blank" rel="noopener noreferrer">↗ Mở GoDaddy Bulk Domain Search</a>
                </div>
                <div class="card price-card">
                    <h3>⇄ Giá transfer về GoDaddy</h3>
                    <p>Mở trang Domain Transfer của GoDaddy ở tab mới để kiểm tra giá transfer.
                       Đây chỉ là liên kết sang GoDaddy — giá transfer không kiểm tra trên website này.</p>
                    <a class="link-btn" href="https://www.godaddy.com/en/domains/domain-transfer" target="_blank" rel="noopener noreferrer">↗ Mở GoDaddy Domain Transfer</a>
                </div>
            </div>
        </div>

{% if is_admin %}
        <!-- ================= TAB (ADMIN): ĐUÔI CẤM / CHO PHÉP ================= -->
        <div class="tab-panel" id="tab-rules">
            <div class="note-box">
                <span class="note-icon">⚙</span>
                <div>
                    <strong>Chỉnh đuôi cấm / cho phép đặc biệt theo từng nhà cung cấp</strong> (mỗi dòng hoặc cách nhau bằng dấu cách/phẩy).<br>
                    <code>.uk</code> = cả đuôi .uk và mọi .xx.uk (.co.uk, .org.uk…) · <code>.co.uk</code> = chỉ đúng đuôi đó · <code>*.uk</code> = chỉ các .xx.uk (không gồm .uk thuần).<br>
                    Đuôi cụ thể hơn thắng đuôi chung; cùng mức thì "cho phép" thắng. Từ khóa theo dạng <code>.in:india</code> (đuôi .in mà tên domain chứa "india" thì cấm).
                </div>
            </div>
            <div class="rules-edit-grid" id="rulesEditor"><div class="skipped">Đang tải…</div></div>
        </div>

        <!-- ================= TAB (ADMIN): CÀI ĐẶT KIỂM TRA ================= -->
        <div class="tab-panel" id="tab-checkopts">
            <div class="note-box">
                <span class="note-icon">☑</span>
                <div>
                    <strong>Cài đặt kiểm tra áp dụng cho TẤT CẢ user.</strong>
                    Mục nào được tick sẽ hiện trong phần "Cài đặt" của tab Kiểm tra mua domain để user chọn.
                    Mục nào <b>không tick</b> thì user không thấy, không chọn được và hệ thống sẽ không chạy mục đó
                    (ví dụ bỏ tick Cloudflare Banned để ngừng gọi API Cloudflare khi đang bị rate limit).
                </div>
            </div>
            <div class="card">
                <div class="section-title">Các mục kiểm tra cho phép</div>
                <div id="aoList"><div class="skipped">Đang tải…</div></div>
                <div class="msg err" id="aoMsg"></div>
                <button class="btn-primary" id="btnAoSave" type="button" style="margin-top:14px;">Lưu cài đặt cho tất cả user</button>
            </div>
        </div>

        <!-- ================= TAB (ADMIN): DOMAIN CẤM ================= -->
        <div class="tab-panel" id="tab-blocks">
            <div class="card">
                <div class="section-title">Thêm domain vào danh sách cấm (ẩn)</div>
                <p class="hint" style="margin-top:0">Các domain này sẽ bị tính là KHÔNG MUA ĐƯỢC tại những nhà cung cấp bạn chọn. Danh sách chỉ admin xem và chỉnh sửa; người dùng khác chỉ thấy kết quả bị cấm khi kiểm tra.</p>
                <textarea id="blkInput" style="margin-top:12px" placeholder="Dán danh sách domain (mỗi dòng 1 domain, hoặc cách nhau bằng dấu cách / phẩy)&#10;example.com&#10;example.net"></textarea>
                <div class="check-grid" id="blkRegs"></div>
                <div class="action-bar">
                    <button class="btn-primary" id="btnBlkAdd">+ Thêm vào danh sách cấm</button>
                    <span class="msg" id="blkMsg"></span>
                </div>
            </div>
            <div class="card">
                <div class="form-row">
                    <div class="form-group"><label for="blkSearch">Tìm domain trong danh sách</label>
                        <input class="field field-mono" id="blkSearch" placeholder="vd: example" autocomplete="off"></div>
                    <button class="btn-secondary" id="btnBlkReload">↻ Tải lại</button>
                </div>
                <div class="hint" id="blkCount"></div>
            </div>
            <div class="table-card">
                <div class="table-wrapper">
                    <table class="tbl-sm">
                        <thead><tr><th>Domain</th><th>Bị cấm tại</th><th>Thêm bởi</th><th>Thời gian</th><th></th></tr></thead>
                        <tbody id="blkBody"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ================= TAB (ADMIN): CẤM KEYWORD THEO NHÀ CUNG CẤP ================= -->
        <div class="tab-panel" id="tab-keywords">
            <div class="note-box">
                <span class="note-icon">🔤</span>
                <div>
                    <strong>Keyword bị cấm theo từng nhà cung cấp.</strong>
                    Domain có <b>tên</b> (phần trước đuôi) chứa keyword đang bật sẽ bị tính là KHÔNG MUA ĐƯỢC tại đúng nhà cung cấp đó —
                    keyword của nhà cung cấp này không áp dụng cho nhà cung cấp khác. Không phân biệt hoa/thường (<code>Bitcoin</code> = <code>bitcoin</code>).
                    Danh sách chỉ admin xem và chỉnh sửa.
                </div>
            </div>
            <div class="card">
                <div class="section-title">Nhà cung cấp</div>
                <div class="kw-provs" id="kwProviders"></div>
            </div>
            <div class="card">
                <div class="section-title">Thêm keyword cấm</div>
                <form id="kwForm" class="form-row" style="margin-top:12px" autocomplete="off">
                    <div class="form-group" style="max-width:220px"><label for="kwProviderSel">Nhà cung cấp</label>
                        <select class="field" id="kwProviderSel"></select></div>
                    <div class="form-group"><label for="kwInput">Keyword</label>
                        <input class="field field-mono" id="kwInput" maxlength="63" autocomplete="off" placeholder="vd: bitcoin"></div>
                    <div class="form-group" style="max-width:170px;min-width:150px"><label for="kwStatusSel">Trạng thái</label>
                        <select class="field" id="kwStatusSel"><option value="active">Đang cấm</option><option value="disabled">Tạm tắt</option></select></div>
                    <button class="btn-primary" id="btnKwAdd" type="submit">+ Thêm keyword</button>
                </form>
                <div class="msg" id="kwMsg"></div>
            </div>
            <div class="card">
                <div class="form-row">
                    <div class="form-group"><label for="kwSearch">Tìm keyword của nhà cung cấp đang chọn</label>
                        <input class="field field-mono" id="kwSearch" placeholder="vd: bitcoin" autocomplete="off"></div>
                    <button class="btn-secondary" id="btnKwReload" type="button">↻ Tải lại</button>
                </div>
                <div class="hint" id="kwCount"></div>
            </div>
            <div class="table-card">
                <div class="table-wrapper">
                    <table class="tbl-sm">
                        <thead><tr><th>Keyword</th><th>Trạng thái</th><th>Thêm bởi</th><th>Cập nhật</th><th></th></tr></thead>
                        <tbody id="kwBody"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ================= TAB (ADMIN): THÔNG BÁO POPUP ================= -->
        <div class="tab-panel" id="tab-notices">
            <div class="note-box">
                <span class="note-icon">📢</span>
                <div>
                    <strong>Thông báo popup cho người dùng.</strong>
                    Thông báo đang bật sẽ hiện giữa màn hình mỗi khi người dùng vào site hoặc tải lại trang (F5), tự đóng sau 5 giây.
                    Chỉ có <b>1 thông báo</b> được bật tại một thời điểm — bật thông báo mới sẽ tự tắt thông báo đang bật trước đó.
                </div>
            </div>
            <div class="card">
                <div class="section-title">Thông báo hiện tại</div>
                <div id="ntCurrent" style="margin-top:10px"><div class="skipped">Đang tải…</div></div>
            </div>
            <div class="card">
                <div class="section-title" id="ntFormTitle">Tạo thông báo mới</div>
                <div class="form-group" style="margin-top:12px"><label for="ntTitle">Title</label>
                    <input class="field" id="ntTitle" maxlength="120" autocomplete="off" value="Thông báo từ admin"></div>
                <div class="form-group" style="margin-top:12px"><label for="ntContent">Nội dung</label>
                    <textarea class="field field-text" id="ntContent" maxlength="5000" style="height:140px" placeholder="Nhập nội dung thông báo hiển thị cho người dùng…"></textarea>
                    <div class="hint" id="ntLen" style="margin-top:0"></div></div>
                <div class="check-grid">
                    <label class="check-chip"><input type="checkbox" id="ntActive" checked> Bật thông báo (hiển thị cho người dùng)</label>
                </div>
                <div class="action-bar">
                    <button class="btn-secondary" id="btnNtPreview" type="button">👁 Preview</button>
                    <button class="btn-primary" id="btnNtSave" type="button">Lưu thông báo</button>
                    <button class="btn-secondary" id="btnNtCancel" type="button" style="display:none">Hủy chỉnh sửa</button>
                    <span class="msg" id="ntMsg"></span>
                </div>
                <p class="hint">Nội dung hiển thị dạng văn bản thuần (giữ nguyên xuống dòng), tối đa 5000 ký tự. Để trống Title sẽ dùng "Thông báo từ admin".</p>
            </div>
            <div class="table-card">
                <div class="table-wrapper">
                    <table class="tbl-sm">
                        <thead><tr><th>Title</th><th>Nội dung</th><th>Trạng thái</th><th>Cập nhật</th><th></th></tr></thead>
                        <tbody id="ntBody"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- ================= TAB (ADMIN): TÀI KHOẢN ================= -->
        <div class="tab-panel" id="tab-users">
            <div class="note-box" id="pwWarn" style="display:none">
                <span class="note-icon">⚠️</span>
                <div>Tài khoản <b>admin</b> vẫn đang dùng mật khẩu mặc định. Hãy bấm "Sửa" ở dòng admin và đổi mật khẩu ngay.</div>
            </div>
            <div class="card">
                <div class="section-title">Tạo tài khoản mới</div>
                <div class="form-row" style="margin-top:12px">
                    <div class="form-group"><label for="nuName">Tên đăng nhập</label>
                        <input class="field" id="nuName" maxlength="32" autocomplete="off" placeholder="3–32 ký tự: chữ, số, _ . -"></div>
                    <div class="form-group"><label for="nuPass">Mật khẩu</label>
                        <div class="inline-row">
                            <input class="field field-mono" id="nuPass" type="text" autocomplete="off" placeholder="Tối thiểu 6 ký tự">
                            <button type="button" class="btn-secondary" id="btnNuRand" title="Tạo mật khẩu ngẫu nhiên 8 ký tự">🎲 Ngẫu nhiên</button>
                        </div></div>
                    <button class="btn-primary" id="btnCreateUser">+ Tạo tài khoản</button>
                </div>
                <div class="msg" id="nuMsg"></div>
                <p class="hint">Mật khẩu được mã hóa khi lưu nên không xem lại được — hãy sao chép gửi cho người dùng trước khi rời trang. Quên mật khẩu thì dùng "Sửa" để đặt lại. Chỉ tài khoản tên <b>admin</b> mới có quyền quản trị.</p>
            </div>
            <div class="table-card">
                <div class="table-wrapper">
                    <table class="tbl-sm">
                        <thead><tr><th>Tên đăng nhập</th><th>Quyền</th><th>Tạo lúc</th><th>Cập nhật</th><th></th></tr></thead>
                        <tbody id="userBody"></tbody>
                    </table>
                </div>
            </div>
        </div>
{% endif %}

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


{% if is_admin %}
    <!-- Edit user Modal -->
    <div id="userModal" class="modal">
        <div class="modal-content">
            <span class="close-btn" id="userModalClose">&times;</span>
            <h3>✎ Sửa tài khoản</h3>
            <input type="hidden" id="euOld">
            <div class="form-group"><label for="euName">Tên đăng nhập</label>
                <input class="field" id="euName" maxlength="32" autocomplete="off"></div>
            <div class="form-group" style="margin-top:14px"><label for="euPass">Mật khẩu mới (để trống = giữ nguyên)</label>
                <div class="inline-row">
                    <input class="field field-mono" id="euPass" type="text" autocomplete="off">
                    <button type="button" class="btn-secondary" id="btnEuRand" title="Tạo mật khẩu ngẫu nhiên 8 ký tự">🎲</button>
                </div></div>
            <div class="msg err" id="euMsg"></div>
            <button class="btn-primary" id="btnEuSave" style="margin-top:14px; width:100%; justify-content:center;">Lưu thay đổi</button>
        </div>
    </div>

    <!-- Edit keyword Modal -->
    <div id="kwModal" class="modal">
        <div class="modal-content">
            <span class="close-btn" id="kwModalClose">&times;</span>
            <h3>✎ Sửa keyword</h3>
            <div class="hint" style="margin:-10px 0 14px">Nhà cung cấp: <b id="kwEditProv"></b></div>
            <div class="form-group"><label for="kwEditInput">Keyword</label>
                <input class="field field-mono" id="kwEditInput" maxlength="63" autocomplete="off"></div>
            <div class="form-group" style="margin-top:14px"><label for="kwEditStatus">Trạng thái</label>
                <select class="field" id="kwEditStatus"><option value="active">Đang cấm</option><option value="disabled">Tạm tắt</option></select></div>
            <div class="msg err" id="kwEditMsg"></div>
            <button class="btn-primary" id="btnKwEditSave" type="button" style="margin-top:14px; width:100%; justify-content:center;">Lưu thay đổi</button>
        </div>
    </div>
    <div class="toast-box" id="toastBox" aria-live="polite"></div>
{% endif %}

    <!-- Popup thông báo từ admin (nội dung lấy từ /api/notifications/active, không hard-code) -->
    <div id="noticeOverlay" class="notice-overlay" aria-hidden="true">
        <div class="notice-dialog" role="dialog" aria-modal="true" aria-labelledby="noticeTitle" aria-describedby="noticeBody">
            <div class="notice-icon" aria-hidden="true">📢</div>
            <h3 class="notice-title" id="noticeTitle"></h3>
            <div class="notice-body" id="noticeBody"></div>
            <div class="notice-count" id="noticeCount"></div>
            <button type="button" class="btn-primary notice-close" id="noticeClose">Đóng</button>
        </div>
    </div>
    <script>
        const CSRF_TOKEN = "{{ csrf_token }}";
        const modal = document.getElementById("settingsModal");
        const CHECK_OPT_DEFS = {{ check_option_defs|tojson }};
        let ALLOWED_OPTIONS = {{ check_options|tojson }};
        function applyAllowedOptions() {
            CHECK_OPT_DEFS.forEach(function(d) {
                const k = d[0];
                const box = document.getElementById('chk_' + k.replace('check_', ''));
                if (!box) return;
                const ok = ALLOWED_OPTIONS[k] !== false;
                const item = box.closest('.settings-item');
                if (item) item.style.display = ok ? '' : 'none';
                if (!ok) { box.checked = false; box.dataset.off = '1'; }
                else if (box.dataset.off === '1') { box.checked = true; delete box.dataset.off; }
            });
        }
        async function refreshAllowedOptions() {
            try {
                const r = await fetch('/api/check-options', { headers: { 'X-CSRF-Token': CSRF_TOKEN } });
                if (r.ok) {
                    const d = await r.json();
                    if (d && d.options) { ALLOWED_OPTIONS = d.options; applyAllowedOptions(); }
                }
            } catch (e) { /* giữ cấu hình hiện tại; server vẫn tự chặn mục không được phép */ }
        }
        function openSettings() { modal.classList.add("show"); refreshAllowedOptions(); }
        function closeSettings() { modal.classList.remove("show"); }
        window.onclick = function(e) { if (e.target === modal) closeSettings(); };

        let failedDomains = [];
        let seenLegendKeys = new Set();

        function getOptions() {
            const o = {};
            CHECK_OPT_DEFS.forEach(function(d) {
                const k = d[0];
                const box = document.getElementById('chk_' + k.replace('check_', ''));
                o[k] = ALLOWED_OPTIONS[k] !== false && !!(box && box.checked);
            });
            return o;
        }
        applyAllowedOptions();

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
            await refreshAllowedOptions();
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

        // ================= TÍNH NĂNG MỚI: TABS / TRANSFER / ADMIN =================
        const IS_ADMIN = {{ 'true' if is_admin else 'false' }};
        const REGISTRARS = {{ registrars|tojson }};
        let RULES_SUMMARY = {{ rules_summary|tojson }};
        const NL = String.fromCharCode(10);
        const el = id => document.getElementById(id);

        function esc(s) {
            return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }
        function fmtTime(iso) {
            if (!iso) return '—';
            const d = new Date(iso);
            return isNaN(d) ? '—' : d.toLocaleString('vi-VN');
        }
        function setMsg(id, text, ok) {
            const m = el(id);
            if (!m) return;
            m.textContent = text || '';
            m.className = 'msg ' + (text ? (ok ? 'ok' : 'err') : '');
        }

        // ---- tóm tắt tiêu chí cấm (động theo cấu hình admin) ----
        function renderRulesSummary() {
            el('rulesGrid').innerHTML = RULES_SUMMARY.map(r =>
                '<div class="rule-item"><strong>' + esc(r.name) + '</strong><span>' +
                r.lines.map(l => esc(l)).join('<br>') + '</span></div>').join('');
        }

        // ---- tabs ----
        const loaded = {};
        function showTab(name) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('show', p.id === 'tab-' + name));
            if (!IS_ADMIN) return;
            if (name === 'rules' && !loaded.rules) loadRules();
            if (name === 'checkopts') loadCheckOpts();
            if (name === 'blocks' && !loaded.blocks) loadBlocks();
{% if is_admin %}
            if (name === 'keywords' && !loaded.keywords) loadKeywordsTab();
            if (name === 'notices' && !loaded.notices) loadNotices();
{% endif %}
            if (name === 'users' && !loaded.users) loadUsers();
        }

        // ---- parse danh sách domain (giống logic nhập ở tab Kiểm tra mua) ----
        function parseDomains(text) {
            const re = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
            const splitter = new RegExp('[^a-z0-9.:/-]+');
            const out = [], seen = new Set();
            text.split(NL).forEach(line => {
                const tok = line.trim().toLowerCase().split(splitter)[0] || '';
                let d = tok.replace(new RegExp('^[a-z]+://'), '').split('/')[0].split(':')[0];
                if (d.indexOf('www.') === 0) d = d.slice(4);
                d = d.replace(new RegExp('[.]+$'), '');
                if (d.length > 3 && re.test(d) && !seen.has(d)) { seen.add(d); out.push(d); }
            });
            return out;
        }

        // ---- TAB KIỂM TRA TRANSFER ----
        let tfFailed = [];
        async function startTransfer(isRetry) {
            const btn = el('btnTf'), btnRetry = el('btnTfRetry'), tbody = el('tfBody');
            let domains;
            if (isRetry) {
                domains = tfFailed.slice();
                if (!domains.length) { alert('Không có domain lỗi để retry!'); return; }
            } else {
                domains = parseDomains(el('tfList').value);
                if (!domains.length) { alert('Vui lòng nhập ít nhất 1 domain hợp lệ!'); return; }
                tfFailed = [];
                tbody.innerHTML = '';
            }
            const delay = Math.max(0, parseInt(el('tfDelay').value) || 0);
            btn.disabled = true; btnRetry.disabled = true;
            let completed = 0;
            const total = domains.length;
            for (const domain of domains) {
                el('tfProgress').innerHTML = '<span class="progress-dot"></span> Đang xử lý ' + (completed + 1) + '/' + total +
                    ' — <b style="color:#93c5fd">' + esc(domain) + '</b>';
                let row = el('tf-' + domain);
                if (!row) { row = document.createElement('tr'); row.id = 'tf-' + domain; tbody.appendChild(row); }
                row.innerHTML = '<td class="domain-cell">' + esc(domain) + '</td><td colspan="5" class="skipped">Đang quét dữ liệu…</td>';
                try {
                    const r = await fetch('/api/transfer-check', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN },
                        body: JSON.stringify({ domain })
                    });
                    if (r.status === 401 || r.status === 403) { window.location.href = '/login'; return; }
                    if (r.status === 429) { await sleep(5000); throw new Error('rate limited'); }
                    if (!r.ok) throw new Error('Server error');
                    const d = await r.json();
                    const dates = d.created
                        ? '<span class="date-cell">' + esc(d.created) + '</span>' + (d.expires ? '<div class="skipped">hết hạn ' + esc(d.expires) + '</div>' : '')
                        : '—';
                    const age = d.age_days != null ? '<span class="date-cell">' + d.age_days + ' ngày</span>' : '—';
                    row.innerHTML = '<td class="domain-cell">' + esc(domain) + '</td>' +
                        '<td class="buy-cell">' + (d.result_html || '') + '</td>' +
                        '<td>' + dates + '</td><td>' + age + '</td>' +
                        '<td>' + (d.registrar || '') + '</td>' +
                        '<td class="status-cell">' + (d.status || '') + '</td>';
                    if (d.failed) { if (!tfFailed.includes(domain)) tfFailed.push(domain); }
                    else tfFailed = tfFailed.filter(x => x !== domain);
                } catch (e) {
                    row.innerHTML = '<td class="domain-cell">' + esc(domain) + '</td><td colspan="5" class="error-cell">Lỗi network / quá tải — thử lại sau</td>';
                    if (!tfFailed.includes(domain)) tfFailed.push(domain);
                }
                completed++;
                if (completed < total && delay > 0) await sleep(delay);
            }
            el('tfProgress').innerHTML = '✓ Hoàn thành ' + completed + '/' + total + ' domain' +
                (tfFailed.length ? ' · <span style="color:#f87171">' + tfFailed.length + ' lỗi</span>' : '');
            btn.disabled = false;
            btnRetry.disabled = tfFailed.length === 0;
        }

        // ---- TAB GIÁ GODADDY (API) ----
        let gdFailed = [];
        async function startPrice(isRetry) {
            const btn = el('btnGd'), btnRetry = el('btnGdRetry'), tbody = el('gdBody');
            let domains;
            if (isRetry) {
                domains = gdFailed.slice();
                if (!domains.length) { alert('Không có domain lỗi để retry!'); return; }
            } else {
                domains = parseDomains(el('gdList').value);
                if (!domains.length) { alert('Vui lòng nhập ít nhất 1 domain hợp lệ!'); return; }
                gdFailed = [];
                tbody.innerHTML = '';
            }
            const delay = Math.max(0, parseInt(el('gdDelay').value) || 0);
            btn.disabled = true; btnRetry.disabled = true;
            let completed = 0;
            const total = domains.length;
            for (const domain of domains) {
                el('gdProgress').innerHTML = '<span class="progress-dot"></span> Đang xử lý ' + (completed + 1) + '/' + total +
                    ' — <b style="color:#93c5fd">' + esc(domain) + '</b>';
                let row = el('gd-' + domain);
                if (!row) { row = document.createElement('tr'); row.id = 'gd-' + domain; tbody.appendChild(row); }
                row.innerHTML = '<td class="domain-cell">' + esc(domain) + '</td><td colspan="4" class="skipped">Đang lấy giá…</td>';
                try {
                    const r = await fetch('/api/price-check', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF_TOKEN },
                        body: JSON.stringify({ domain })
                    });
                    if (r.status === 401 || r.status === 403) { window.location.href = '/login'; return; }
                    if (r.status === 429) { await sleep(5000); throw new Error('rate limited'); }
                    if (!r.ok) throw new Error('Server error');
                    const d = await r.json();
                    row.innerHTML = '<td class="domain-cell">' + esc(domain) + '</td>' +
                        '<td class="buy-cell">' + (d.result_html || '') + '</td>' +
                        '<td>' + (d.price_usd ? esc(d.price_usd) : '—') + '</td>' +
                        '<td>' + (d.price_vat ? esc(d.price_vat) : '—') + '</td>' +
                        '<td><b>' + (d.price_vnd ? esc(d.price_vnd) : '—') + '</b></td>';
                    if (d.failed) { if (!gdFailed.includes(domain)) gdFailed.push(domain); }
                    else gdFailed = gdFailed.filter(x => x !== domain);
                } catch (e) {
                    row.innerHTML = '<td class="domain-cell">' + esc(domain) + '</td><td colspan="4" class="error-cell">Lỗi network / quá tải — thử lại sau</td>';
                    if (!gdFailed.includes(domain)) gdFailed.push(domain);
                }
                completed++;
                if (completed < total && delay > 0) await sleep(delay);
            }
            el('gdProgress').innerHTML = '✓ Hoàn thành ' + completed + '/' + total + ' domain' +
                (gdFailed.length ? ' · <span style="color:#f87171">' + gdFailed.length + ' lỗi</span>' : '');
            btn.disabled = false;
            btnRetry.disabled = gdFailed.length === 0;
        }

        // ---- ADMIN: helper gọi API ----
        async function adminApi(url, body, method) {
            const opt = { method: method || (body === undefined ? 'GET' : 'POST'), headers: { 'X-CSRF-Token': CSRF_TOKEN } };
            if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
            const r = await fetch(url, opt);
            if (r.status === 401) { window.location.href = '/login'; throw new Error('Phiên đã hết hạn'); }
            let data = {};
            try { data = await r.json(); } catch (e) { /* ignore */ }
            if (!r.ok) throw new Error(data.error || ('Lỗi ' + r.status));
            return data;
        }

        // ---- ADMIN: cài đặt kiểm tra cho tất cả user ----
        async function loadCheckOpts() {
            setMsg('aoMsg', '');
            try {
                const d = await adminApi('/api/admin/check-options');
                el('aoList').innerHTML = CHECK_OPT_DEFS.map(function(x) {
                    const id = 'ao_' + x[0];
                    return '<div class="settings-item"><input type="checkbox" id="' + id + '"' +
                        (d.options[x[0]] !== false ? ' checked' : '') + '><label for="' + id + '">' + esc(x[1]) + '</label></div>';
                }).join('');
            } catch (e) { setMsg('aoMsg', e.message, false); }
        }
        async function saveCheckOpts() {
            const body = {};
            CHECK_OPT_DEFS.forEach(function(x) { const b = el('ao_' + x[0]); body[x[0]] = !!(b && b.checked); });
            try {
                const d = await adminApi('/api/admin/check-options', { options: body });
                ALLOWED_OPTIONS = d.options;
                applyAllowedOptions();
                setMsg('aoMsg', 'Đã lưu — áp dụng cho tất cả user', true);
            } catch (e) { setMsg('aoMsg', e.message, false); }
        }

        // ---- ADMIN: mật khẩu ngẫu nhiên 8 ký tự ----
        function randInt(n) {
            const a = new Uint32Array(1);
            const lim = Math.floor(4294967296 / n) * n;
            do { crypto.getRandomValues(a); } while (a[0] >= lim);
            return a[0] % n;
        }
        function randomPassword() {
            const U = 'ABCDEFGHJKLMNPQRSTUVWXYZ', L = 'abcdefghijkmnpqrstuvwxyz', D = '23456789';
            const all = U + L + D;
            const pick = s => s[randInt(s.length)];
            const c = [pick(U), pick(L), pick(D)];
            while (c.length < 8) c.push(pick(all));
            for (let i = c.length - 1; i > 0; i--) { const j = randInt(i + 1); const t = c[i]; c[i] = c[j]; c[j] = t; }
            return c.join('');
        }

        // ---- ADMIN: đuôi cấm / cho phép ----
        let RULES_DATA = null;
        async function loadRules() {
            try {
                const data = await adminApi('/api/admin/rules');
                RULES_DATA = data.rules;
                loaded.rules = true;
                renderRulesEditor();
            } catch (e) {
                el('rulesEditor').innerHTML = '<div class="error-cell">' + esc(e.message) + '</div>';
            }
        }
        function renderRulesEditor() {
            el('rulesEditor').innerHTML = REGISTRARS.map(reg => {
                const r = RULES_DATA[reg] || { banned: [], allowed: [], keywords: [] };
                return '<div class="reg-card" data-reg="' + esc(reg) + '"><h4>' + esc(reg) + '</h4>' +
                    '<div class="form-group"><label>⛔ Đuôi bị cấm</label><textarea class="field field-mono" data-f="banned" placeholder=".ch .li .cn">' + esc(r.banned.join(NL)) + '</textarea></div>' +
                    '<div class="form-group"><label>✅ Đuôi cho phép đặc biệt</label><textarea class="field field-mono" data-f="allowed" placeholder="*.uk">' + esc(r.allowed.join(NL)) + '</textarea></div>' +
                    '<div class="form-group"><label>🔎 Cấm theo từ khóa (đuôi:từ khóa)</label><textarea class="field field-mono" data-f="keywords" placeholder=".in:india">' + esc(r.keywords.join(NL)) + '</textarea></div>' +
                    '<div class="action-bar" style="margin-top:6px">' +
                    '<button class="btn-primary btn-sm" data-act="save">Lưu</button>' +
                    '<button class="btn-secondary btn-sm" data-act="reset">Khôi phục mặc định</button></div>' +
                    '<div class="msg" data-msg></div></div>';
            }).join('');
        }
        async function ruleAction(card, act) {
            const reg = card.dataset.reg, msg = card.querySelector('[data-msg]');
            const setM = (t, ok) => { msg.textContent = t; msg.className = 'msg ' + (ok ? 'ok' : 'err'); };
            try {
                let data;
                if (act === 'reset') {
                    if (!confirm('Khôi phục quy tắc mặc định cho ' + reg + '?')) return;
                    data = await adminApi('/api/admin/rules/reset', { registrar: reg });
                } else {
                    const body = { registrar: reg };
                    card.querySelectorAll('textarea[data-f]').forEach(t => { body[t.dataset.f] = t.value; });
                    data = await adminApi('/api/admin/rules/save', body);
                }
                RULES_DATA[reg] = data.rule;
                RULES_SUMMARY = data.summary;
                renderRulesSummary();
                card.querySelectorAll('textarea[data-f]').forEach(t => { t.value = (data.rule[t.dataset.f] || []).join(NL); });
                setM(act === 'reset' ? 'Đã khôi phục mặc định' : 'Đã lưu', true);
            } catch (e) { setM(e.message, false); }
        }

        // ---- ADMIN: domain cấm ----
        function initBlockChips() {
            el('blkRegs').innerHTML = REGISTRARS.map(r =>
                '<label class="check-chip"><input type="checkbox" class="blk-reg" value="' + esc(r) + '"> ' + esc(r) + '</label>').join('') +
                '<label class="check-chip"><input type="checkbox" id="blkAll"> <b>Chọn tất cả</b></label>';
            el('blkAll').addEventListener('change', e => {
                document.querySelectorAll('.blk-reg').forEach(c => { c.checked = e.target.checked; });
            });
        }
        async function loadBlocks() {
            try {
                const q = el('blkSearch').value.trim();
                const data = await adminApi('/api/admin/blocks?q=' + encodeURIComponent(q));
                loaded.blocks = true;
                el('blkCount').textContent = data.total + ' domain trong danh sách' + (data.total > data.items.length ? ' (hiển thị ' + data.items.length + ' mới nhất — dùng ô tìm kiếm để lọc)' : '');
                el('blkBody').innerHTML = data.items.length ? data.items.map(it =>
                    '<tr><td class="domain-cell">' + esc(it.domain) + '</td><td>' +
                    it.registrars.map(r => '<span class="tag-x">' + esc(r) + '<button title="Bỏ cấm tại ' + esc(r) + '" data-d="' + esc(it.domain) + '" data-r="' + esc(r) + '">×</button></span>').join('') +
                    '</td><td>' + esc(it.added_by || '—') + '</td><td class="date-cell">' + esc(fmtTime(it.created_at)) + '</td>' +
                    '<td><button class="btn-danger btn-sm" data-d="' + esc(it.domain) + '">Xóa</button></td></tr>').join('')
                    : '<tr><td colspan="5" class="skipped">Danh sách trống</td></tr>';
            } catch (e) {
                el('blkBody').innerHTML = '<tr><td colspan="5" class="error-cell">' + esc(e.message) + '</td></tr>';
            }
        }
        async function addBlocks() {
            const regs = Array.from(document.querySelectorAll('.blk-reg')).filter(c => c.checked).map(c => c.value);
            if (!regs.length) { setMsg('blkMsg', 'Hãy chọn ít nhất 1 nhà cung cấp', false); return; }
            try {
                const data = await adminApi('/api/admin/blocks/add', { domains: el('blkInput').value, registrars: regs });
                setMsg('blkMsg', 'Đã thêm / cập nhật ' + data.count + ' domain', true);
                el('blkInput').value = '';
                loadBlocks();
            } catch (e) { setMsg('blkMsg', e.message, false); }
        }

        // ---- ADMIN: tài khoản ----
        async function loadUsers() {
            try {
                const data = await adminApi('/api/admin/users');
                loaded.users = true;
                el('pwWarn').style.display = data.users.some(u => u.username === 'admin' && u.default_pw) ? 'flex' : 'none';
                el('userBody').innerHTML = data.users.map(u => {
                    const role = u.role === 'admin' ? '<span class="badge badge-info">ADMIN</span>' : '<span class="badge badge-muted">USER</span>';
                    const actions = u.source === 'env'
                        ? '<span class="skipped">cấu hình APP_USERS (chỉ đọc)</span>'
                        : '<button class="btn-secondary btn-sm" data-edit="' + esc(u.username) + '">✎ Sửa</button> ' +
                          (u.role === 'admin' ? '' : '<button class="btn-danger btn-sm" data-del="' + esc(u.username) + '">Xóa</button>');
                    return '<tr><td class="domain-cell">' + esc(u.username) + '</td><td>' + role + '</td><td class="date-cell">' +
                        esc(fmtTime(u.created_at)) + '</td><td class="date-cell">' + esc(fmtTime(u.updated_at)) + '</td><td>' + actions + '</td></tr>';
                }).join('');
            } catch (e) {
                el('userBody').innerHTML = '<tr><td colspan="5" class="error-cell">' + esc(e.message) + '</td></tr>';
            }
        }
        async function createUser() {
            try {
                await adminApi('/api/admin/users/create', { username: el('nuName').value, password: el('nuPass').value });
                setMsg('nuMsg', 'Đã tạo tài khoản "' + el('nuName').value.trim() + '" — mật khẩu: ' + el('nuPass').value + ' (hãy sao chép ngay)', true);
                el('nuName').value = ''; el('nuPass').value = '';
                loadUsers();
            } catch (e) { setMsg('nuMsg', e.message, false); }
        }
        const userModal = IS_ADMIN ? el('userModal') : null;
        function openUserModal(name) {
            el('euOld').value = name; el('euName').value = name; el('euPass').value = ''; setMsg('euMsg', '');
            el('euName').disabled = (name === 'admin');
            userModal.classList.add('show');
        }
        function closeUserModal() { userModal.classList.remove('show'); }
        async function saveUser() {
            try {
                await adminApi('/api/admin/users/update', {
                    username: el('euOld').value, new_username: el('euName').value, password: el('euPass').value
                });
                closeUserModal();
                loadUsers();
            } catch (e) { setMsg('euMsg', e.message, false); }
        }
        async function deleteUser(name) {
            if (!confirm('Xóa tài khoản "' + name + '"? Người dùng sẽ bị đăng xuất.')) return;
            try { await adminApi('/api/admin/users/delete', { username: name }); loadUsers(); }
            catch (e) { alert(e.message); }
        }

        // ---- khởi tạo ----
        document.querySelectorAll('.tab-btn').forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));
        renderRulesSummary();
        if (IS_ADMIN) {
            initBlockChips();
            el('btnAoSave').addEventListener('click', saveCheckOpts);
            el('rulesEditor').addEventListener('click', e => {
                const b = e.target.closest('button[data-act]');
                if (b) ruleAction(b.closest('.reg-card'), b.dataset.act);
            });
            el('btnBlkAdd').addEventListener('click', addBlocks);
            el('btnBlkReload').addEventListener('click', loadBlocks);
            let blkTimer = null;
            el('blkSearch').addEventListener('input', () => { clearTimeout(blkTimer); blkTimer = setTimeout(loadBlocks, 300); });
            el('blkBody').addEventListener('click', async e => {
                const b = e.target.closest('button[data-d]');
                if (!b) return;
                const d = b.dataset.d, r = b.dataset.r;
                if (!r && !confirm('Xóa "' + d + '" khỏi danh sách cấm?')) return;
                try { await adminApi('/api/admin/blocks/remove', r ? { domain: d, registrar: r } : { domain: d }); loadBlocks(); }
                catch (err) { alert(err.message); }
            });
            el('btnNuRand').addEventListener('click', () => { el('nuPass').value = randomPassword(); });
            el('btnEuRand').addEventListener('click', () => { el('euPass').value = randomPassword(); });
            el('btnCreateUser').addEventListener('click', createUser);
            el('btnEuSave').addEventListener('click', saveUser);
            el('userModalClose').addEventListener('click', closeUserModal);
            userModal.addEventListener('click', e => { if (e.target === userModal) closeUserModal(); });
            el('userBody').addEventListener('click', e => {
                const ed = e.target.closest('button[data-edit]');
                if (ed) openUserModal(ed.dataset.edit);
                const dl = e.target.closest('button[data-del]');
                if (dl) deleteUser(dl.dataset.del);
            });
        }
    </script>

    <script>
        // ================= POPUP THÔNG BÁO TỪ ADMIN =================
        // Nội dung lấy từ /api/notifications/active (không hard-code). Mở lại = reset đếm ngược về 5s.
        (function () {
            const overlay = document.getElementById('noticeOverlay');
            if (!overlay) return;
            const titleEl = document.getElementById('noticeTitle'), bodyEl = document.getElementById('noticeBody');
            const countEl = document.getElementById('noticeCount'), closeBtn = document.getElementById('noticeClose');
            const TOTAL_MS = 5000, DEFAULT_TITLE = 'Thông báo từ admin';
            let timer = null, deadline = 0, leftMs = 0, isOpen = false, lastFocus = null;

            function stopTimer() { if (timer !== null) { clearInterval(timer); timer = null; } }
            function secondsLeft() { return Math.max(0, Math.ceil((deadline - Date.now()) / 1000)); }
            function render() { countEl.textContent = 'Tự động đóng sau ' + secondsLeft() + 's'; }
            function startTimer() {
                stopTimer();
                deadline = Date.now() + leftMs;
                render();
                timer = setInterval(function () {
                    if (Date.now() >= deadline) { closePopup(); return; }
                    render();
                }, 200);
            }
            function closePopup() {
                stopTimer();
                if (!isOpen) return;
                isOpen = false;
                overlay.classList.remove('show');
                overlay.setAttribute('aria-hidden', 'true');
                if (lastFocus && document.contains(lastFocus) && lastFocus.focus) { try { lastFocus.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }
                lastFocus = null;
            }
            function showPopup(title, content) {
                stopTimer();                                   // mở lại khi đang mở → không để timer cũ chạy chồng
                if (!isOpen) lastFocus = document.activeElement;
                titleEl.textContent = title || DEFAULT_TITLE;
                bodyEl.textContent = content || '';           // textContent: nội dung admin không bao giờ được chạy như HTML
                bodyEl.scrollTop = 0;
                isOpen = true;
                overlay.classList.add('show');
                overlay.setAttribute('aria-hidden', 'false');
                leftMs = TOTAL_MS;                             // reset đếm ngược mỗi lần mở
                if (document.hidden) { countEl.textContent = 'Tự động đóng sau ' + (TOTAL_MS / 1000) + 's'; } else { startTimer(); }
                try { closeBtn.focus({ preventScroll: true }); } catch (e) { /* ignore */ }
            }

            closeBtn.addEventListener('click', closePopup);
            overlay.addEventListener('click', function (e) { if (e.target === overlay) closePopup(); });
            document.addEventListener('keydown', function (e) {
                if (!isOpen) return;
                if (e.key === 'Escape') { closePopup(); }
                else if (e.key === 'Tab') { e.preventDefault(); closeBtn.focus(); }   // giữ focus trong popup
            });
            // Tab bị ẩn → tạm dừng đếm ngược để user kịp đọc khi quay lại
            document.addEventListener('visibilitychange', function () {
                if (!isOpen) return;
                if (document.hidden) { leftMs = Math.max(0, deadline - Date.now()); stopTimer(); } else { startTimer(); }
            });
            window.addEventListener('pagehide', stopTimer);
            window.showNoticePopup = showPopup;                // dùng lại cho nút Preview của admin

            fetch('/api/notifications/active', { credentials: 'same-origin', cache: 'no-store', headers: { 'Accept': 'application/json' } })
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (j) { if (j && j.success && j.data && j.data.content) showPopup(j.data.title, j.data.content); })
                .catch(function () { /* lỗi mạng/API: không hiện popup, không ảnh hưởng trang */ });
        })();
    </script>
{% if is_admin %}
    <script>
        // ================= ADMIN: CẤM KEYWORD THEO NHÀ CUNG CẤP + QUẢN LÝ THÔNG BÁO =================
        function toast(text, ok) {
            const box = el('toastBox');
            if (!box) return;
            const t = document.createElement('div');
            t.className = 'toast ' + (ok ? 'ok' : 'err');
            t.textContent = text;
            box.appendChild(t);
            setTimeout(function () { t.remove(); }, ok ? 3000 : 5000);
        }

        // ---- Cấm keyword ----
        let kwProvider = REGISTRARS[0], kwProvList = [], kwItems = [], kwReq = 0, kwEditId = null, kwAdding = false;
        const kwModal = el('kwModal');
        const kwUrl = p => '/api/admin/providers/' + encodeURIComponent(p) + '/banned-keywords';

        function renderKwProviders() {
            const byName = {};
            kwProvList.forEach(p => { byName[p.name] = p; });
            el('kwProviders').innerHTML = REGISTRARS.map(name => {
                const p = byName[name] || { total: 0, active: 0 };
                return '<button type="button" class="kw-prov' + (name === kwProvider ? ' active' : '') + '" data-p="' + esc(name) + '">' +
                    esc(name) + ' <span class="kw-count" title="đang cấm / tổng số keyword">' + p.active + '/' + p.total + '</span></button>';
            }).join('');
        }
        async function loadKwProviders() {
            try { kwProvList = (await adminApi('/api/admin/providers')).data || []; }
            catch (e) { toast(e.message, false); }
            renderKwProviders();
        }
        async function loadKeywords() {
            const req = ++kwReq, body = el('kwBody');
            try {
                const q = el('kwSearch').value.trim();
                const d = (await adminApi(kwUrl(kwProvider) + (q ? '?q=' + encodeURIComponent(q) : ''))).data;
                if (req !== kwReq) return;                      // đã đổi nhà cung cấp / từ khóa tìm → bỏ kết quả cũ
                kwItems = d.items;
                el('kwCount').textContent = d.total + ' keyword tại ' + kwProvider +
                    (d.total > d.items.length ? ' (hiển thị ' + d.items.length + ' mới nhất — dùng ô tìm kiếm để lọc)' : '');
                body.innerHTML = d.items.length ? d.items.map(it => {
                    const on = it.status === 'active';
                    return '<tr><td class="domain-cell">' + esc(it.keyword) + '</td><td>' +
                        (on ? '<span class="badge badge-danger">ĐANG CẤM</span>' : '<span class="badge badge-muted">TẠM TẮT</span>') +
                        '</td><td>' + esc(it.created_by || '—') + '</td><td class="date-cell">' + esc(fmtTime(it.updated_at)) +
                        '</td><td><div class="row-actions">' +
                        '<button class="btn-secondary btn-sm" data-kact="toggle" data-id="' + esc(it.id) + '">' + (on ? 'Tạm tắt' : 'Bật lại') + '</button>' +
                        '<button class="btn-secondary btn-sm" data-kact="edit" data-id="' + esc(it.id) + '">✎ Sửa</button>' +
                        '<button class="btn-danger btn-sm" data-kact="del" data-id="' + esc(it.id) + '">Xóa</button></div></td></tr>';
                }).join('') : '<tr><td colspan="5" class="skipped">' +
                    (q ? 'Không có keyword nào khớp' : 'Chưa có keyword cấm nào cho ' + esc(kwProvider)) + '</td></tr>';
            } catch (e) {
                if (req !== kwReq) return;
                kwItems = [];
                el('kwCount').textContent = '';
                body.innerHTML = '<tr><td colspan="5" class="error-cell">' + esc(e.message) + '</td></tr>';
            }
        }
        function reloadKeywords() { return Promise.all([loadKwProviders(), loadKeywords()]); }
        async function loadKeywordsTab() {
            loaded.keywords = true;
            await reloadKeywords();
        }
        function selectKwProvider(name) {
            if (!REGISTRARS.includes(name) || name === kwProvider) return;
            kwProvider = name;
            el('kwProviderSel').value = name;
            el('kwSearch').value = '';
            setMsg('kwMsg', '');
            renderKwProviders();
            loadKeywords();
        }
        async function addKeyword(ev) {
            ev.preventDefault();
            if (kwAdding) return;
            const kw = el('kwInput').value.trim();
            if (!kw) { setMsg('kwMsg', 'Keyword không được để trống', false); el('kwInput').focus(); return; }
            kwAdding = true; el('btnKwAdd').disabled = true;
            try {
                const prov = kwProvider;
                await adminApi(kwUrl(prov), { keyword: kw, status: el('kwStatusSel').value });
                setMsg('kwMsg', 'Đã thêm keyword "' + kw + '" cho ' + prov, true);
                toast('Đã thêm keyword cho ' + prov, true);
                el('kwInput').value = '';
                await reloadKeywords();
            } catch (e) {
                setMsg('kwMsg', e.message, false);
                toast(e.message, false);
            } finally {
                kwAdding = false; el('btnKwAdd').disabled = false; el('kwInput').focus();
            }
        }
        function openKwModal(id) {
            const it = kwItems.find(x => x.id === id);
            if (!it) return;
            kwEditId = id;
            el('kwEditProv').textContent = kwProvider;
            el('kwEditInput').value = it.keyword;
            el('kwEditStatus').value = it.status;
            setMsg('kwEditMsg', '');
            kwModal.classList.add('show');
            el('kwEditInput').focus();
        }
        function closeKwModal() { kwModal.classList.remove('show'); kwEditId = null; }
        async function saveKwEdit() {
            if (!kwEditId) return;
            const kw = el('kwEditInput').value.trim();
            if (!kw) { setMsg('kwEditMsg', 'Keyword không được để trống', false); return; }
            const btn = el('btnKwEditSave');
            btn.disabled = true;
            try {
                await adminApi(kwUrl(kwProvider) + '/' + encodeURIComponent(kwEditId), { keyword: kw, status: el('kwEditStatus').value }, 'PUT');
                closeKwModal();
                toast('Đã cập nhật keyword', true);
                await reloadKeywords();
            } catch (e) {
                setMsg('kwEditMsg', e.message, false);
            } finally { btn.disabled = false; }
        }
        async function toggleKeyword(id) {
            const it = kwItems.find(x => x.id === id);
            if (!it) return;
            const next = it.status === 'active' ? 'disabled' : 'active';
            try {
                await adminApi(kwUrl(kwProvider) + '/' + encodeURIComponent(id), { status: next }, 'PUT');
                toast(next === 'active' ? 'Đã bật lại keyword' : 'Đã tạm tắt keyword', true);
                await reloadKeywords();
            } catch (e) { toast(e.message, false); }
        }
        async function deleteKeyword(id) {
            const it = kwItems.find(x => x.id === id);
            if (!it || !confirm('Xóa keyword "' + it.keyword + '" khỏi ' + kwProvider + '?')) return;
            try {
                await adminApi(kwUrl(kwProvider) + '/' + encodeURIComponent(id), undefined, 'DELETE');
                toast('Đã xóa keyword', true);
                await reloadKeywords();
            } catch (e) { toast(e.message, false); }
        }

        // ---- Thông báo popup ----
        const NT_DEFAULT_TITLE = 'Thông báo từ admin';
        let ntItems = [], ntEditId = null, ntBusy = false;

        function updateNtLen() { el('ntLen').textContent = el('ntContent').value.length + ' / 5000 ký tự'; }
        function ntResetForm() {
            ntEditId = null;
            el('ntTitle').value = NT_DEFAULT_TITLE;
            el('ntContent').value = '';
            el('ntActive').checked = true;
            el('ntFormTitle').textContent = 'Tạo thông báo mới';
            el('btnNtSave').textContent = 'Lưu thông báo';
            el('btnNtCancel').style.display = 'none';
            updateNtLen();
        }
        function ntShort(s, n) {
            s = String(s || '').split(NL).join(' ');
            return s.length > n ? s.slice(0, n) + '…' : s;
        }
        function renderNotices() {
            const active = ntItems.find(x => x.is_active);
            el('ntCurrent').innerHTML = active
                ? '<div class="nt-current"><div><b>' + esc(active.title) + '</b> <span class="badge badge-success">ĐANG BẬT</span>' +
                  '<div class="nt-content" style="margin-top:6px;max-width:none;white-space:pre-wrap">' + esc(active.content) + '</div></div></div>'
                : '<div class="skipped">Hiện chưa có thông báo nào đang bật — người dùng sẽ không thấy popup.</div>';
            el('ntBody').innerHTML = ntItems.length ? ntItems.map(it =>
                '<tr><td><b>' + esc(it.title) + '</b></td><td class="nt-content">' + esc(ntShort(it.content, 140)) + '</td><td>' +
                (it.is_active ? '<span class="badge badge-success">ĐANG BẬT</span>' : '<span class="badge badge-muted">TẮT</span>') +
                '</td><td class="date-cell">' + esc(fmtTime(it.updated_at)) + '</td><td><div class="row-actions">' +
                '<button class="btn-secondary btn-sm" data-nact="toggle" data-id="' + esc(it.id) + '">' + (it.is_active ? 'Tắt' : 'Bật') + '</button>' +
                '<button class="btn-secondary btn-sm" data-nact="edit" data-id="' + esc(it.id) + '">✎ Sửa</button>' +
                '<button class="btn-danger btn-sm" data-nact="del" data-id="' + esc(it.id) + '">Xóa</button></div></td></tr>').join('')
                : '<tr><td colspan="5" class="skipped">Chưa có thông báo nào</td></tr>';
        }
        async function loadNotices() {
            try {
                ntItems = (await adminApi('/api/admin/notifications')).data || [];
                loaded.notices = true;
                renderNotices();
            } catch (e) {
                toast(e.message, false);
                el('ntCurrent').innerHTML = '<div class="error-cell">' + esc(e.message) + '</div>';
                el('ntBody').innerHTML = '<tr><td colspan="5" class="error-cell">' + esc(e.message) + '</td></tr>';
            }
        }
        async function saveNotice() {
            if (ntBusy) return;
            const content = el('ntContent').value.trim();
            if (!content) { setMsg('ntMsg', 'Nội dung thông báo không được để trống', false); el('ntContent').focus(); return; }
            const body = { title: el('ntTitle').value.trim() || NT_DEFAULT_TITLE, content: content, is_active: el('ntActive').checked };
            const editing = ntEditId;
            ntBusy = true; el('btnNtSave').disabled = true;
            try {
                if (editing) await adminApi('/api/admin/notifications/' + encodeURIComponent(editing), body, 'PUT');
                else await adminApi('/api/admin/notifications', body);
                toast(editing ? 'Đã cập nhật thông báo' : 'Đã lưu thông báo', true);
                setMsg('ntMsg', '');
                ntResetForm();
                await loadNotices();
            } catch (e) {
                setMsg('ntMsg', e.message, false);
                toast(e.message, false);
            } finally { ntBusy = false; el('btnNtSave').disabled = false; }
        }
        function editNotice(id) {
            const it = ntItems.find(x => x.id === id);
            if (!it) return;
            ntEditId = id;
            el('ntTitle').value = it.title;
            el('ntContent').value = it.content;
            el('ntActive').checked = it.is_active;
            el('ntFormTitle').textContent = 'Chỉnh sửa thông báo';
            el('btnNtSave').textContent = 'Lưu thay đổi';
            el('btnNtCancel').style.display = '';
            setMsg('ntMsg', '');
            updateNtLen();
            el('ntFormTitle').scrollIntoView({ behavior: 'smooth', block: 'center' });
            el('ntContent').focus();
        }
        async function toggleNotice(id) {
            const it = ntItems.find(x => x.id === id);
            if (!it) return;
            try {
                await adminApi('/api/admin/notifications/' + encodeURIComponent(id) + '/status', { is_active: !it.is_active }, 'PATCH');
                toast(it.is_active ? 'Đã tắt thông báo' : 'Đã bật thông báo (các thông báo khác được tắt)', true);
                await loadNotices();
            } catch (e) { toast(e.message, false); }
        }
        async function deleteNotice(id) {
            const it = ntItems.find(x => x.id === id);
            if (!it || !confirm('Xóa thông báo "' + it.title + '"? Người dùng sẽ không còn nhận thông báo này.')) return;
            try {
                await adminApi('/api/admin/notifications/' + encodeURIComponent(id), undefined, 'DELETE');
                if (ntEditId === id) ntResetForm();
                toast('Đã xóa thông báo', true);
                await loadNotices();
            } catch (e) { toast(e.message, false); }
        }
        function previewNotice() {
            const content = el('ntContent').value.trim();
            if (!content) { toast('Hãy nhập nội dung để xem trước', false); return; }
            if (typeof window.showNoticePopup !== 'function') { toast('Không mở được popup xem trước', false); return; }
            window.showNoticePopup(el('ntTitle').value.trim() || NT_DEFAULT_TITLE, content);
        }

        // ---- khởi tạo ----
        (function () {
            el('kwProviderSel').innerHTML = REGISTRARS.map(r => '<option value="' + esc(r) + '">' + esc(r) + '</option>').join('');
            el('kwProviderSel').value = kwProvider;
            renderKwProviders();
            el('kwProviders').addEventListener('click', e => {
                const b = e.target.closest('button[data-p]');
                if (b) selectKwProvider(b.dataset.p);
            });
            el('kwProviderSel').addEventListener('change', e => selectKwProvider(e.target.value));
            el('kwForm').addEventListener('submit', addKeyword);
            el('btnKwReload').addEventListener('click', reloadKeywords);
            let kwTimer = null;
            el('kwSearch').addEventListener('input', () => { clearTimeout(kwTimer); kwTimer = setTimeout(loadKeywords, 300); });
            el('kwBody').addEventListener('click', e => {
                const b = e.target.closest('button[data-kact]');
                if (!b) return;
                if (b.dataset.kact === 'toggle') toggleKeyword(b.dataset.id);
                else if (b.dataset.kact === 'edit') openKwModal(b.dataset.id);
                else if (b.dataset.kact === 'del') deleteKeyword(b.dataset.id);
            });
            el('kwModalClose').addEventListener('click', closeKwModal);
            kwModal.addEventListener('click', e => { if (e.target === kwModal) closeKwModal(); });
            el('btnKwEditSave').addEventListener('click', saveKwEdit);
            el('kwEditInput').addEventListener('keydown', e => { if (e.key === 'Enter') saveKwEdit(); });
            document.addEventListener('keydown', e => { if (e.key === 'Escape' && kwModal.classList.contains('show')) closeKwModal(); });

            el('ntContent').addEventListener('input', updateNtLen);
            el('btnNtSave').addEventListener('click', saveNotice);
            el('btnNtPreview').addEventListener('click', previewNotice);
            el('btnNtCancel').addEventListener('click', () => { ntResetForm(); setMsg('ntMsg', ''); });
            el('ntBody').addEventListener('click', e => {
                const b = e.target.closest('button[data-nact]');
                if (!b) return;
                if (b.dataset.nact === 'toggle') toggleNotice(b.dataset.id);
                else if (b.dataset.nact === 'edit') editNotice(b.dataset.id);
                else if (b.dataset.nact === 'del') deleteNotice(b.dataset.id);
            });
            updateNtLen();
        })();
    </script>
{% endif %}
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
    if not auth_ready():
        return "Chưa kết nối được MongoDB và chưa cấu hình APP_USERS trên server.", 503
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
            rec = authenticate(username, password)
            if rec:
                login_limiter.clear(ip)
                session.clear()                                   # chống session fixation
                session["user"] = rec["username"]
                session["pv"] = rec["pv"]
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
    return render_template_string(
        HTML_TEMPLATE, username=session["user"], csrf_token=session["csrf"],
        is_admin=is_admin(), registrars=REGISTRARS, rules_summary=rules_summary(),
        check_options=get_check_options(), check_option_defs=CHECK_OPTIONS,
        gd_vat_pct=("%g" % (GD_VAT_RATE * 100)),
        gd_rate=format(int(round(GD_USD_VND)), ",").replace(",", "."),
    )


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
        allowed = get_check_options()          # admin không cho phép mục nào → mục đó KHÔNG BAO GIỜ chạy
        opt = lambda k: bool(allowed.get(k, True)) and bool(options.get(k, True))  # noqa: E731
        check_buy, check_reg = opt("check_buy"), opt("check_registrar")
        check_hold, check_dates, check_cf = opt("check_hold"), opt("check_dates"), opt("check_cf")

        # ---- WHOIS / RDAP trước: cần biết đã ĐK hay chưa ----
        info = None
        if check_buy or check_reg or check_hold or check_dates:
            info = get_domain_info(domain)

        # ---- Cloudflare: CHỈ gọi khi mục "Cloudflare Banned" được chọn (và admin cho phép) ----
        cf = None
        if check_cf:
            try:
                cf = check_cf_eligibility(domain)
            except Exception:  # noqa: BLE001  (lỗi CF không được làm hỏng các cột khác)
                log.exception("Lỗi kiểm tra Cloudflare %r", domain)
                cf = _cf_result(_badge("badge-danger", "Lỗi Call API CF"), failed=True)
            # WHOIS không chắc chắn nhưng CF báo "chưa ĐK" (1049) → dùng làm bằng chứng bổ sung
            if info and info["state"] == "unknown" and cf["unregistered"]:
                info = _unregistered_info()

        # ---- Verdict mua ----
        can_buy, buy_html = False, "Bỏ qua"
        if check_buy:
            results, tld_ok = check_buyability(domain)
            state = info["state"] if info else "unknown"
            cf_bad = bool(cf) and (cf["failed"] or cf["blocked"])      # không chọn CF → bỏ qua hoàn toàn
            can_buy = state == "unregistered" and tld_ok and not cf_bad
            buy_html = format_buyability_html(results, tld_ok, state, cf)

        # ---- Cờ lỗi để frontend đưa vào danh sách Retry ----
        failed = False
        if info and info["state"] == "unknown":
            failed = True
        if cf and cf["failed"]:
            failed = True

        return jsonify({
            "domain": domain,
            "buy_html": buy_html,
            "can_buy": can_buy,
            "cf_add_status": (cf["html"] if cf else "") if check_cf else "Bỏ qua",
            "options": {k: opt(k) for k in CHECK_OPTION_KEYS},
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


@app.route("/api/check-options", methods=["GET"])
@user_read_guard
def api_check_options():
    """Các mục kiểm tra mà admin cho phép (user nào cũng đọc được)."""
    return jsonify(options=get_check_options())


@app.route("/api/transfer-check", methods=["POST"])
@api_guard
def api_transfer_check():
    domain = ""
    try:
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        if not DOMAIN_RE.match(domain):
            return jsonify(error="Domain không hợp lệ", failed=True), 400
        return jsonify(check_transfer_eligibility(domain))
    except Exception:  # noqa: BLE001
        log.exception("Lỗi kiểm tra transfer %r", domain)
        return jsonify({
            "domain": domain or "Unknown", "eligible": False, "failed": True, "age_days": None,
            "reasons": [], "registrar": "Lỗi", "status": "Lỗi", "created": None, "expires": None,
            "result_html": _badge("badge-danger", "Lỗi"),
        }), 500


@app.route("/api/price-check", methods=["POST"])
@api_guard
def api_price_check():
    domain = ""
    try:
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        if not DOMAIN_RE.match(domain):
            return jsonify(error="Domain không hợp lệ", failed=True), 400
        res = check_godaddy_price(domain)
        res["domain"] = domain
        return jsonify(res)
    except Exception:  # noqa: BLE001
        log.exception("Lỗi kiểm tra giá %r", domain)
        return jsonify({
            "domain": domain or "Unknown", "state": "error", "failed": True,
            "result_html": _badge("badge-danger", "Lỗi"), "price_usd": "", "price_vat": "", "price_vnd": "",
        }), 500


# ---------------- ADMIN: tài khoản ----------------
def _no_db():
    return jsonify(error="Chưa kết nối được MongoDB — kiểm tra MONGODB_URI / Network Access trên Atlas"), 503


@app.route("/api/admin/users", methods=["GET"])
@admin_guard
def api_admin_users():
    db = get_db()
    if db is None:
        return _no_db()
    items, names = [], set()
    for doc in db.users.find({}).sort("created_at", 1):
        names.add(doc["username"].lower())
        items.append({
            "username": doc["username"],
            "role": "admin" if doc["username"] == ADMIN_USERNAME else "user",
            "created_at": _iso(doc.get("created_at")), "updated_at": _iso(doc.get("updated_at")),
            "default_pw": bool(doc.get("default_pw")), "source": "db",
        })
    for name in USERS:                      # tài khoản cũ từ APP_USERS (chỉ đọc)
        if name.lower() not in names:
            items.append({"username": name, "role": "admin" if name == ADMIN_USERNAME else "user",
                          "created_at": None, "updated_at": None, "default_pw": False, "source": "env"})
    return jsonify(users=items)


@app.route("/api/admin/users/create", methods=["POST"])
@admin_guard
def api_admin_user_create():
    db = get_db()
    if db is None:
        return _no_db()
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    err = _validate_username(username) or _validate_password(password)
    if err:
        return jsonify(error=err), 400
    now = _now()
    try:
        db.users.insert_one({
            "username": username, "username_lower": username.lower(),
            "password_hash": generate_password_hash(password), "pv": secrets.token_hex(4),
            "default_pw": False, "created_at": now, "updated_at": now, "created_by": session["user"],
        })
    except DuplicateKeyError:
        return jsonify(error="Tên đăng nhập đã tồn tại"), 409
    log.info("Admin %s tạo tài khoản %s", session["user"], username)
    return jsonify(ok=True)


@app.route("/api/admin/users/update", methods=["POST"])
@admin_guard
def api_admin_user_update():
    db = get_db()
    if db is None:
        return _no_db()
    data = request.get_json(silent=True) or {}
    target = str(data.get("username", "")).strip()
    new_name = str(data.get("new_username", "")).strip()
    password = str(data.get("password", ""))
    doc = db.users.find_one({"username": target})
    if not doc:
        return jsonify(error="Không tìm thấy tài khoản"), 404
    upd = {}
    if new_name and new_name != doc["username"]:
        if doc["username"] == ADMIN_USERNAME:
            return jsonify(error='Không thể đổi tên tài khoản "admin"'), 400
        err = _validate_username(new_name)
        if err:
            return jsonify(error=err), 400
        upd.update(username=new_name, username_lower=new_name.lower())
    new_pv = None
    if password:
        err = _validate_password(password)
        if err:
            return jsonify(error=err), 400
        new_pv = secrets.token_hex(4)
        upd.update(password_hash=generate_password_hash(password), pv=new_pv, default_pw=False)
    if not upd:
        return jsonify(error="Không có thay đổi nào"), 400
    upd["updated_at"] = _now()
    try:
        db.users.update_one({"_id": doc["_id"]}, {"$set": upd})
    except DuplicateKeyError:
        return jsonify(error="Tên đăng nhập đã tồn tại"), 409
    _clear_user_cache()
    if new_pv and doc["username"] == session.get("user"):
        session["pv"] = new_pv                       # admin tự đổi pass → giữ phiên của chính mình
    log.info("Admin %s sửa tài khoản %s", session["user"], target)
    return jsonify(ok=True)


@app.route("/api/admin/users/delete", methods=["POST"])
@admin_guard
def api_admin_user_delete():
    db = get_db()
    if db is None:
        return _no_db()
    target = str((request.get_json(silent=True) or {}).get("username", "")).strip()
    if target.lower() == ADMIN_USERNAME:
        return jsonify(error='Không thể xóa tài khoản "admin"'), 400
    res = db.users.delete_one({"username": target})
    if not res.deleted_count:
        return jsonify(error="Không tìm thấy tài khoản"), 404
    _clear_user_cache()
    log.info("Admin %s xóa tài khoản %s", session["user"], target)
    return jsonify(ok=True)


# ---------------- ADMIN: đuôi cấm / cho phép ----------------
@app.route("/api/admin/check-options", methods=["GET"])
@admin_guard
def api_admin_check_options():
    return jsonify(options=get_check_options(force=True))


@app.route("/api/admin/check-options", methods=["POST"])
@admin_guard
def api_admin_check_options_save():
    db = get_db()
    if db is None:
        return _no_db()
    data = request.get_json(silent=True) or {}
    raw = data.get("options")
    if not isinstance(raw, dict):
        return jsonify(error="Dữ liệu không hợp lệ"), 400
    opts = {k: bool(raw.get(k, False)) for k in CHECK_OPTION_KEYS}
    if not any(opts.values()):
        return jsonify(error="Phải bật ít nhất 1 mục kiểm tra"), 400
    try:
        db.app_settings.update_one(
            {"_id": "check_options"},
            {"$set": {"options": opts, "updated_at": _now(), "updated_by": session["user"]}},
            upsert=True)
    except PyMongoError:
        log.exception("Lỗi lưu cài đặt kiểm tra")
        return jsonify(error="Lỗi cơ sở dữ liệu — chưa lưu được"), 503
    _invalidate_check_options()
    log.info("Admin %s cập nhật cài đặt kiểm tra: %s", session["user"], opts)
    return jsonify(ok=True, options=get_check_options(force=True))


@app.route("/api/admin/rules", methods=["GET"])
@admin_guard
def api_admin_rules():
    rules, _ = get_config(force=True)
    return jsonify(rules={r: _rule_to_lists(rules[r]) for r in REGISTRARS})


@app.route("/api/admin/rules/save", methods=["POST"])
@admin_guard
def api_admin_rules_save():
    db = get_db()
    if db is None:
        return _no_db()
    data = request.get_json(silent=True) or {}
    reg = data.get("registrar")
    if reg not in REGISTRARS:
        return jsonify(error="Nhà cung cấp không hợp lệ"), 400
    banned, b1 = _clean_list(data.get("banned"), normalize_suffix)
    allowed, b2 = _clean_list(data.get("allowed"), normalize_suffix)
    keywords, b3 = _clean_list(data.get("keywords"), normalize_keyword)
    bad = b1 + b2 + b3
    if bad:
        return jsonify(error="Giá trị không hợp lệ: " + ", ".join(bad[:10])), 400
    db.tld_rules.update_one(
        {"registrar": reg},
        {"$set": {"banned": banned, "allowed": allowed, "keywords": keywords,
                  "updated_at": _now(), "updated_by": session["user"]}},
        upsert=True,
    )
    _invalidate_config()
    rules, _ = get_config(force=True)
    log.info("Admin %s cập nhật quy tắc đuôi của %s", session["user"], reg)
    return jsonify(ok=True, rule=_rule_to_lists(rules[reg]), summary=rules_summary())


@app.route("/api/admin/rules/reset", methods=["POST"])
@admin_guard
def api_admin_rules_reset():
    db = get_db()
    if db is None:
        return _no_db()
    reg = (request.get_json(silent=True) or {}).get("registrar")
    if reg not in REGISTRARS:
        return jsonify(error="Nhà cung cấp không hợp lệ"), 400
    db.tld_rules.update_one(
        {"registrar": reg},
        {"$set": {**copy.deepcopy(DEFAULT_RULES[reg]), "updated_at": _now(), "updated_by": session["user"]}},
        upsert=True,
    )
    _invalidate_config()
    rules, _ = get_config(force=True)
    log.info("Admin %s khôi phục mặc định quy tắc đuôi của %s", session["user"], reg)
    return jsonify(ok=True, rule=_rule_to_lists(rules[reg]), summary=rules_summary())


# ---------------- ADMIN: domain cấm (danh sách ẩn) ----------------
@app.route("/api/admin/blocks", methods=["GET"])
@admin_guard
def api_admin_blocks():
    db = get_db()
    if db is None:
        return _no_db()
    q = request.args.get("q", "").strip().lower()[:100]
    flt = {"domain": {"$regex": re.escape(q)}} if q else {}
    total = db.domain_blocks.count_documents(flt)
    items = [{
        "domain": d["domain"], "registrars": sorted(d.get("registrars") or []),
        "added_by": d.get("added_by"), "created_at": _iso(d.get("created_at")),
    } for d in db.domain_blocks.find(flt).sort("created_at", -1).limit(500)]
    return jsonify(total=total, items=items)


@app.route("/api/admin/blocks/add", methods=["POST"])
@admin_guard
def api_admin_blocks_add():
    db = get_db()
    if db is None:
        return _no_db()
    data = request.get_json(silent=True) or {}
    regs = [r for r in REGISTRARS if r in (data.get("registrars") or [])]
    if not regs:
        return jsonify(error="Hãy chọn ít nhất 1 nhà cung cấp"), 400
    domains = extract_domains(data.get("domains", ""))
    if not domains:
        return jsonify(error="Không có domain hợp lệ trong danh sách"), 400
    if len(domains) > 2000:
        return jsonify(error="Tối đa 2000 domain mỗi lần thêm"), 400
    now = _now()
    db.domain_blocks.bulk_write([
        UpdateOne({"domain": d},
                  {"$addToSet": {"registrars": {"$each": regs}},
                   "$set": {"updated_at": now},
                   "$setOnInsert": {"created_at": now, "added_by": session["user"]}},
                  upsert=True)
        for d in domains
    ], ordered=False)
    _invalidate_config()
    log.info("Admin %s thêm %d domain vào danh sách cấm (%s)", session["user"], len(domains), ",".join(regs))
    return jsonify(ok=True, count=len(domains))


@app.route("/api/admin/blocks/remove", methods=["POST"])
@admin_guard
def api_admin_blocks_remove():
    db = get_db()
    if db is None:
        return _no_db()
    data = request.get_json(silent=True) or {}
    domain = str(data.get("domain", "")).strip().lower()
    reg = data.get("registrar")
    if not domain:
        return jsonify(error="Thiếu domain"), 400
    if reg:
        if reg not in REGISTRARS:
            return jsonify(error="Nhà cung cấp không hợp lệ"), 400
        db.domain_blocks.update_one({"domain": domain}, {"$pull": {"registrars": reg}})
        db.domain_blocks.delete_one({"domain": domain, "registrars": {"$size": 0}})
    else:
        db.domain_blocks.delete_one({"domain": domain})
    _invalidate_config()
    return jsonify(ok=True)


# ---------------- helper chung cho 2 tính năng admin mới ----------------
_PROVIDER_BY_LOWER = {r.lower(): r for r in REGISTRARS}
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _fail(msg, status):
    return jsonify(success=False, error=msg), status


def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def _oid(value):
    """Chuỗi 24 ký tự hex → ObjectId, ngược lại None (ID không hợp lệ)."""
    if ObjectId is None or not isinstance(value, str) or len(value) != 24 or not ObjectId.is_valid(value):
        return None
    return ObjectId(value)


def _resolve_provider(name):
    return _PROVIDER_BY_LOWER.get(str(name or "").strip().lower())


def db_errors(view):
    """Lỗi MongoDB trong 1 request → JSON 500 thân thiện thay vì làm sập trang."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        try:
            return view(*args, **kwargs)
        except PyMongoError:
            log.exception("Lỗi MongoDB ở %s", request.path)
            return _fail("Lỗi cơ sở dữ liệu, vui lòng thử lại", 500)
    return wrapper


# ---------------- ADMIN: keyword cấm theo nhà cung cấp ----------------
def _kw_item(doc):
    return {
        "id": str(doc["_id"]), "provider": doc.get("provider"), "keyword": doc.get("keyword", ""),
        "status": doc.get("status", KW_ACTIVE), "created_by": doc.get("created_by"),
        "created_at": _iso(doc.get("created_at")), "updated_at": _iso(doc.get("updated_at")),
    }


def _kw_status(value, default=KW_ACTIVE):
    if value is None:
        return default
    return value if value in (KW_ACTIVE, KW_DISABLED) else None


@app.route("/api/admin/providers", methods=["GET"])
@admin_guard
@db_errors
def api_admin_providers():
    db = get_db()
    if db is None:
        return _no_db()
    counts = {}
    for row in db.provider_banned_keywords.aggregate(
            [{"$group": {"_id": {"p": "$provider", "s": "$status"}, "n": {"$sum": 1}}}]):
        c = counts.setdefault(row["_id"].get("p"), {"total": 0, "active": 0})
        c["total"] += row["n"]
        if row["_id"].get("s") == KW_ACTIVE:
            c["active"] += row["n"]
    return jsonify(success=True, data=[
        {"id": r, "name": r, "total": counts.get(r, {}).get("total", 0), "active": counts.get(r, {}).get("active", 0)}
        for r in REGISTRARS])


@app.route("/api/admin/providers/<provider>/banned-keywords", methods=["GET"])
@admin_guard
@db_errors
def api_admin_kw_list(provider):
    prov = _resolve_provider(provider)
    if not prov:
        return _fail("Nhà cung cấp không tồn tại", 404)
    db = get_db()
    if db is None:
        return _no_db()
    flt = {"provider": prov}
    q = request.args.get("q", "").strip().lower()[:100]
    if q:
        flt["normalized_keyword"] = {"$regex": re.escape(q)}
    status = request.args.get("status", "").strip()
    if status:
        if status not in (KW_ACTIVE, KW_DISABLED):
            return _fail("Trạng thái không hợp lệ", 400)
        flt["status"] = status
    total = db.provider_banned_keywords.count_documents(flt)
    items = [_kw_item(d) for d in db.provider_banned_keywords.find(flt).sort("created_at", -1).limit(1000)]
    return jsonify(success=True, data={"provider": prov, "total": total, "items": items})


@app.route("/api/admin/providers/<provider>/banned-keywords", methods=["POST"])
@admin_guard
@db_errors
def api_admin_kw_create(provider):
    prov = _resolve_provider(provider)
    if not prov:
        return _fail("Nhà cung cấp không tồn tại", 404)
    data = _json_body()
    if data is None:
        return _fail("Dữ liệu gửi lên không hợp lệ", 400)
    kw, norm, err = clean_banned_keyword(data.get("keyword"))
    if err:
        return _fail(err, 400)
    status = _kw_status(data.get("status"))
    if status is None:
        return _fail("Trạng thái không hợp lệ", 400)
    db = get_db()
    if db is None:
        return _no_db()
    col = db.provider_banned_keywords
    if col.find_one({"provider": prov, "normalized_keyword": norm}, {"_id": 1}):
        return _fail(f'Keyword "{kw}" đã tồn tại ở {prov}', 409)
    if col.count_documents({"provider": prov}) >= KW_MAX_PER_PROVIDER:
        return _fail(f"Mỗi nhà cung cấp tối đa {KW_MAX_PER_PROVIDER} keyword", 400)
    now = _now()
    doc = {"provider": prov, "keyword": kw, "normalized_keyword": norm, "status": status,
           "created_at": now, "updated_at": now, "created_by": session["user"]}
    try:
        doc["_id"] = col.insert_one(doc).inserted_id
    except DuplicateKeyError:
        return _fail(f'Keyword "{kw}" đã tồn tại ở {prov}', 409)
    _invalidate_config()
    log.info("Admin %s thêm keyword cấm %r cho %s", session["user"], norm, prov)
    return jsonify(success=True, data=_kw_item(doc)), 201


@app.route("/api/admin/providers/<provider>/banned-keywords/<kid>", methods=["PUT"])
@admin_guard
@db_errors
def api_admin_kw_update(provider, kid):
    prov = _resolve_provider(provider)
    if not prov:
        return _fail("Nhà cung cấp không tồn tại", 404)
    oid = _oid(kid)
    if oid is None:
        return _fail("ID không hợp lệ", 400)
    data = _json_body()
    if data is None:
        return _fail("Dữ liệu gửi lên không hợp lệ", 400)
    upd = {}
    if "keyword" in data:
        kw, norm, err = clean_banned_keyword(data.get("keyword"))
        if err:
            return _fail(err, 400)
        upd.update(keyword=kw, normalized_keyword=norm)
    if "status" in data:
        status = _kw_status(data.get("status"), default=None)
        if status is None:
            return _fail("Trạng thái không hợp lệ", 400)
        upd["status"] = status
    if not upd:
        return _fail("Không có thay đổi nào", 400)
    db = get_db()
    if db is None:
        return _no_db()
    col = db.provider_banned_keywords
    cur = col.find_one({"_id": oid, "provider": prov})
    if not cur:
        return _fail("Không tìm thấy keyword", 404)
    if "normalized_keyword" in upd and col.find_one(
            {"provider": prov, "normalized_keyword": upd["normalized_keyword"], "_id": {"$ne": oid}}, {"_id": 1}):
        return _fail(f'Keyword "{upd["keyword"]}" đã tồn tại ở {prov}', 409)
    upd.update(updated_at=_now(), updated_by=session["user"])
    try:
        col.update_one({"_id": oid, "provider": prov}, {"$set": upd})
    except DuplicateKeyError:
        return _fail("Keyword đã tồn tại ở nhà cung cấp này", 409)
    _invalidate_config()
    log.info("Admin %s sửa keyword cấm %s của %s", session["user"], kid, prov)
    return jsonify(success=True, data=_kw_item({**cur, **upd}))


@app.route("/api/admin/providers/<provider>/banned-keywords/<kid>", methods=["DELETE"])
@admin_guard
@db_errors
def api_admin_kw_delete(provider, kid):
    prov = _resolve_provider(provider)
    if not prov:
        return _fail("Nhà cung cấp không tồn tại", 404)
    oid = _oid(kid)
    if oid is None:
        return _fail("ID không hợp lệ", 400)
    db = get_db()
    if db is None:
        return _no_db()
    if not db.provider_banned_keywords.delete_one({"_id": oid, "provider": prov}).deleted_count:
        return _fail("Không tìm thấy keyword", 404)
    _invalidate_config()
    log.info("Admin %s xóa keyword cấm %s của %s", session["user"], kid, prov)
    return jsonify(success=True, data=None)


# ---------------- ADMIN: thông báo popup ----------------
def _notice_item(doc):
    return {
        "id": str(doc["_id"]), "title": doc.get("title") or NOTICE_DEFAULT_TITLE, "content": doc.get("content", ""),
        "is_active": bool(doc.get("is_active")), "created_by": doc.get("created_by"),
        "created_at": _iso(doc.get("created_at")), "updated_at": _iso(doc.get("updated_at")),
    }


def _clean_notice_text(value, limit):
    value = _CTRL_RE.sub("", value.replace("\r\n", "\n").replace("\r", "\n"))
    return value.strip() if len(value.strip()) <= limit else None


def _clean_notice_fields(data, need_content=True):
    """→ ({title?, content?}, lỗi). Title để trống = tiêu đề mặc định; content bắt buộc khi tạo."""
    out = {}
    if "title" in data or need_content:
        raw = data.get("title")
        if raw is not None and not isinstance(raw, str):
            return None, "Tiêu đề không hợp lệ"
        title = _clean_notice_text(raw or "", NOTICE_TITLE_MAX)
        if title is None:
            return None, f"Tiêu đề tối đa {NOTICE_TITLE_MAX} ký tự"
        out["title"] = title.replace("\n", " ") or NOTICE_DEFAULT_TITLE
    if "content" in data or need_content:
        raw = data.get("content")
        if not isinstance(raw, str):
            return None, "Nội dung không hợp lệ"
        content = _clean_notice_text(raw, NOTICE_CONTENT_MAX)
        if content is None:
            return None, f"Nội dung tối đa {NOTICE_CONTENT_MAX} ký tự"
        if not content:
            return None, "Nội dung thông báo không được để trống"
        out["content"] = content
    return out, None


def _set_notice_active(db, oid, active, user):
    """Bật/tắt 1 thông báo. Khi bật: tắt mọi thông báo khác (chỉ 1 thông báo active; index unique
    từng phần chặn race giữa 2 request đồng thời → thử lại vài lần)."""
    col = db.admin_notifications
    now = _now()
    if not active:
        col.update_one({"_id": oid}, {"$set": {"is_active": False, "updated_at": now, "updated_by": user}})
        return True
    for _ in range(3):
        col.update_many({"_id": {"$ne": oid}, "is_active": True}, {"$set": {"is_active": False, "updated_at": now}})
        try:
            col.update_one({"_id": oid}, {"$set": {"is_active": True, "updated_at": now, "updated_by": user}})
            return True
        except DuplicateKeyError:
            continue
    return False


@app.route("/api/admin/notifications", methods=["GET"])
@admin_guard
@db_errors
def api_admin_notices():
    db = get_db()
    if db is None:
        return _no_db()
    items = [_notice_item(d) for d in db.admin_notifications.find({}).sort("created_at", -1).limit(200)]
    return jsonify(success=True, data=items)


@app.route("/api/admin/notifications", methods=["POST"])
@admin_guard
@db_errors
def api_admin_notice_create():
    data = _json_body()
    if data is None:
        return _fail("Dữ liệu gửi lên không hợp lệ", 400)
    fields, err = _clean_notice_fields(data)
    if err:
        return _fail(err, 400)
    active = data.get("is_active", False)
    if not isinstance(active, bool):
        return _fail("Trạng thái không hợp lệ", 400)
    db = get_db()
    if db is None:
        return _no_db()
    now = _now()
    doc = {**fields, "is_active": False, "created_by": session["user"], "created_at": now, "updated_at": now}
    doc["_id"] = db.admin_notifications.insert_one(doc).inserted_id
    if active:
        if not _set_notice_active(db, doc["_id"], True, session["user"]):
            return _fail("Không bật được thông báo (đang có thao tác khác) — hãy thử lại", 409)
        doc["is_active"] = True
    log.info("Admin %s tạo thông báo %s (active=%s)", session["user"], doc["_id"], active)
    return jsonify(success=True, data=_notice_item(doc)), 201


@app.route("/api/admin/notifications/<nid>", methods=["PUT"])
@admin_guard
@db_errors
def api_admin_notice_update(nid):
    oid = _oid(nid)
    if oid is None:
        return _fail("ID không hợp lệ", 400)
    data = _json_body()
    if data is None:
        return _fail("Dữ liệu gửi lên không hợp lệ", 400)
    fields, err = _clean_notice_fields(data, need_content=False)
    if err:
        return _fail(err, 400)
    active = data.get("is_active")
    if active is not None and not isinstance(active, bool):
        return _fail("Trạng thái không hợp lệ", 400)
    if not fields and active is None:
        return _fail("Không có thay đổi nào", 400)
    db = get_db()
    if db is None:
        return _no_db()
    col = db.admin_notifications
    if not col.find_one({"_id": oid}, {"_id": 1}):
        return _fail("Không tìm thấy thông báo", 404)
    if fields:
        col.update_one({"_id": oid}, {"$set": {**fields, "updated_at": _now(), "updated_by": session["user"]}})
    if active is not None and not _set_notice_active(db, oid, active, session["user"]):
        return _fail("Không bật được thông báo (đang có thao tác khác) — hãy thử lại", 409)
    doc = col.find_one({"_id": oid})
    if not doc:
        return _fail("Không tìm thấy thông báo", 404)
    log.info("Admin %s sửa thông báo %s", session["user"], nid)
    return jsonify(success=True, data=_notice_item(doc))


@app.route("/api/admin/notifications/<nid>/status", methods=["PATCH"])
@admin_guard
@db_errors
def api_admin_notice_status(nid):
    oid = _oid(nid)
    if oid is None:
        return _fail("ID không hợp lệ", 400)
    data = _json_body()
    if data is None or not isinstance(data.get("is_active"), bool):
        return _fail("Thiếu hoặc sai giá trị is_active (true/false)", 400)
    db = get_db()
    if db is None:
        return _no_db()
    if not db.admin_notifications.find_one({"_id": oid}, {"_id": 1}):
        return _fail("Không tìm thấy thông báo", 404)
    if not _set_notice_active(db, oid, data["is_active"], session["user"]):
        return _fail("Không bật được thông báo (đang có thao tác khác) — hãy thử lại", 409)
    doc = db.admin_notifications.find_one({"_id": oid})
    if not doc:
        return _fail("Không tìm thấy thông báo", 404)
    log.info("Admin %s %s thông báo %s", session["user"], "bật" if data["is_active"] else "tắt", nid)
    return jsonify(success=True, data=_notice_item(doc))


@app.route("/api/admin/notifications/<nid>", methods=["DELETE"])
@admin_guard
@db_errors
def api_admin_notice_delete(nid):
    oid = _oid(nid)
    if oid is None:
        return _fail("ID không hợp lệ", 400)
    db = get_db()
    if db is None:
        return _no_db()
    if not db.admin_notifications.delete_one({"_id": oid}).deleted_count:
        return _fail("Không tìm thấy thông báo", 404)
    log.info("Admin %s xóa thông báo %s", session["user"], nid)
    return jsonify(success=True, data=None)


# ---------------- USER: thông báo đang bật (popup) ----------------
@app.route("/api/notifications/active", methods=["GET"])
@user_read_guard
def api_notice_active():
    """Chỉ trả title + content của thông báo đang bật (hoặc data=null). Không lộ trường quản trị."""
    db = get_db()
    if db is None:
        return jsonify(success=False, data=None, error="Chưa kết nối được cơ sở dữ liệu"), 503
    try:
        doc = db.admin_notifications.find_one({"is_active": True}, sort=[("updated_at", -1)])
    except PyMongoError:
        log.exception("Lỗi đọc thông báo active")
        return jsonify(success=False, data=None, error="Lỗi cơ sở dữ liệu"), 503
    if not doc or not str(doc.get("content", "")).strip():
        return jsonify(success=True, data=None)
    return jsonify(success=True, data={"title": doc.get("title") or NOTICE_DEFAULT_TITLE, "content": doc["content"]})


try:                       # kết nối MongoDB sớm (lỗi thì tự thử lại ở request sau)
    get_db()
except Exception:  # noqa: BLE001
    log.exception("Khởi tạo MongoDB lỗi")


if __name__ == "__main__":
    # Tạo hash mật khẩu cho APP_USERS:  python app.py hash   (hoặc: python app.py hash "mat-khau")
    if len(sys.argv) >= 2 and sys.argv[1] == "hash":
        pw = sys.argv[2] if len(sys.argv) >= 3 else getpass.getpass("Mật khẩu: ")
        print(generate_password_hash(pw))
        sys.exit(0)
    port = _int_env("PORT", 5000)
    app.run(host="0.0.0.0", port=port)
