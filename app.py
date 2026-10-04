import os
import re
import time
import hmac
import html
import secrets
import logging
import threading
from datetime import datetime, timedelta
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

import requests
import whois
from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for, flash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from pymongo import MongoClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger("domain-checker")

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ==========================================
# CẤU HÌNH CƠ BẢN & MONGODB
# ==========================================
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)

MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://nhattanseo3105_db_user:HeSauzpD4Vn3fbfA@cluster0.lhnikju.mongodb.net/?appName=Cluster0")
db_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db = db_client["domain_checker_db"]
users_col = db["users"]
rules_col = db["registrar_rules"]
banned_col = db["banned_domains"]

# Khởi tạo dữ liệu mặc định nếu Database trống
def init_db():
    if users_col.count_documents({}) == 0:
        users_col.insert_one({"username": "admin", "password_hash": generate_password_hash("admin")})
        log.info("Đã tạo tài khoản mặc định: admin / admin")
    
    if rules_col.count_documents({}) == 0:
        default_rules = [
            {"registrar": "Namecheap", "banned_tlds": ".ch, .li, .cn, .au, .fr, .ca, .eu, .eco, .uk", "allowed_tlds": "", "note": "Cấm .in chứa 'india', .uk thuần"},
            {"registrar": "GoDaddy", "banned_tlds": ".cz, .eu, .dk, .in", "allowed_tlds": "", "note": "Cấm mọi đuôi .in"},
            {"registrar": "Dynadot", "banned_tlds": ".it, .org", "allowed_tlds": "", "note": ""},
            {"registrar": "Spaceship", "banned_tlds": ".de", "allowed_tlds": ".uk, .my", "note": ""},
            {"registrar": "SAV", "banned_tlds": "", "allowed_tlds": "", "note": "Luôn cho phép"}
        ]
        rules_col.insert_many(default_rules)
init_db()

# ==========================================
# BẢO MẬT & MIDDLEWARE
# ==========================================
def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper

def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if session.get("user") != "admin":
            return "Bạn không có quyền truy cập trang này!", 403
        return view(*args, **kwargs)
    return wrapper

# ==========================================
# LOGIC WHOIS & RDAP (Lấy ngày giờ chuẩn)
# ==========================================
HTTP_HEADERS = {"User-Agent": "DomainBuyChecker/3.0", "Accept": "application/json"}
_whois_pool = ThreadPoolExecutor(max_workers=4)

def _parse_date_to_dt(dt_val):
    if not dt_val: return None
    if isinstance(dt_val, list): dt_val = dt_val[0]
    if isinstance(dt_val, datetime): return dt_val
    if isinstance(dt_val, str):
        try:
            return datetime.fromisoformat(dt_val.replace("Z", "+00:00").split("T")[0])
        except:
            m = re.search(r"(\d{4})-(\d{2})-(\d{2})", dt_val)
            if m: return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None

def get_domain_info(domain):
    """Lấy thông tin status, registrar, và đặc biệt là Ngày tạo (datetime) để tính điều kiện Transfer."""
    try:
        fut = _whois_pool.submit(whois.whois, domain)
        w = fut.result(timeout=5)
    except:
        return None

    status = set()
    raw_status = getattr(w, "status", [])
    if isinstance(raw_status, str): raw_status = [raw_status]
    for s in raw_status:
        if s: status.add(s.lower())
        
    created_dt = _parse_date_to_dt(getattr(w, "creation_date", None))
    registrar = getattr(w, "registrar", None)
    
    # Tính điều kiện transfer
    is_60_days = False
    if created_dt:
        days_old = (datetime.now() - created_dt).days
        is_60_days = days_old > 60

    # Kiểm tra khóa transfer
    transfer_locked = any("transferprohibited" in st for st in status)
    
    return {
        "status": status,
        "registrar": registrar,
        "created_dt": created_dt,
        "created_str": created_dt.strftime("%d/%m/%Y") if created_dt else "Không rõ",
        "is_60_days": is_60_days,
        "transfer_locked": transfer_locked
    }

# ==========================================
# LOGIC KIỂM TRA MUA (Áp dụng MongoDB Rules)
# ==========================================
def parse_tlds(tld_string):
    return [t.strip().lower() for t in tld_string.replace(".", " .").split(",") if t.strip()]

def check_buyability(domain):
    domain = domain.lower().strip()
    parts = domain.split(".")
    last_tld = "." + parts[-1]
    full_suffix = "." + parts[-2] + "." + parts[-1] if len(parts) >= 3 else last_tld

    # 1. Lấy luật từ MongoDB
    rules = list(rules_col.find({}))
    banned_db = list(banned_col.find({"domain": domain}))
    blocked_registrars_by_domain = banned_db[0]["registrars"] if banned_db else []

    results = {}
    can_buy_any = False

    for r in rules:
        reg_name = r["registrar"]
        banned = parse_tlds(r.get("banned_tlds", ""))
        allowed = parse_tlds(r.get("allowed_tlds", ""))
        
        reason = ""
        # 2. Check danh sách domain cấm ẩn của Admin
        if reg_name in blocked_registrars_by_domain:
            reason = "Bị khóa bởi Admin (Domain cấm)"
        
        # 3. Check đuôi TLD
        elif not reason:
            if full_suffix in banned or last_tld in banned:
                if full_suffix not in allowed and last_tld not in allowed:
                    reason = f"Đuôi cấm ({last_tld})"
            
            # Giữ lại luật ngoại lệ đặc thù cho Namecheap/Godaddy nếu người dùng không ghi đè
            if reg_name == "Namecheap" and last_tld == ".uk" and full_suffix == ".uk":
                reason = "Cấm .uk thuần"
            if reg_name == "Namecheap" and last_tld == ".in" and "india" in domain:
                reason = "Domain .in chứa 'india'"

        is_ok = not bool(reason)
        if is_ok: can_buy_any = True
        results[reg_name] = {"ok": is_ok, "reason": reason}

    return results, can_buy_any

# ==========================================
# ROUTING CƠ BẢN
# ==========================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session: return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = users_col.find_one({"username": username})
        
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user"] = username
            session.permanent = True
            return redirect(url_for("index"))
        error = "Sai tên đăng nhập hoặc mật khẩu!"
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    users = list(users_col.find({}))
    rules = list(rules_col.find({}))
    banned = list(banned_col.find({}))
    return render_template_string(MAIN_TEMPLATE, username=session["user"], users=users, rules=rules, banned=banned)

@app.route("/api/check", methods=["POST"])
@login_required
def api_check():
    domain = request.json.get("domain", "").lower().strip()
    mode = request.json.get("mode", "buy") # 'buy' hoặc 'transfer'
    
    info = get_domain_info(domain)
    if not info:
        return jsonify({"domain": domain, "error": True, "msg": "Không tra cứu được Whois"})

    if mode == "transfer":
        return jsonify({
            "domain": domain,
            "created_str": info["created_str"],
            "is_60_days": info["is_60_days"],
            "transfer_locked": info["transfer_locked"],
            "can_transfer": info["is_60_days"] and not info["transfer_locked"]
        })
    else:
        # Chế độ Mua mới
        results, can_buy = check_buyability(domain)
        html_badges = []
        if not info["created_dt"]:
            html_badges.append("<span class='badge badge-success'>CÓ THỂ MUA (Chưa ĐK)</span>")
            for reg, res in results.items():
                if not res["ok"]:
                    html_badges.append(f"<div class='buy-reason'>⛔ {reg}: {res['reason']}</div>")
        else:
            html_badges.append("<span class='badge badge-muted'>ĐÃ ĐĂNG KÝ (Không thể mua)</span>")

        return jsonify({
            "domain": domain,
            "buy_html": "".join(html_badges),
            "registrar": info["registrar"] or "Không rõ",
            "created_str": info["created_str"]
        })

# ==========================================
# ADMIN ROUTING (CẬP NHẬT DB)
# ==========================================
@app.route("/admin/action", methods=["POST"])
@admin_required
def admin_action():
    action = request.form.get("action")
    
    if action == "add_user" or action == "edit_user":
        username = request.form.get("username").strip()
        password = request.form.get("password")
        if action == "add_user" and users_col.find_one({"username": username}):
            flash("User đã tồn tại!")
        else:
            update_data = {}
            if password: update_data["password_hash"] = generate_password_hash(password)
            users_col.update_one({"username": username}, {"$set": update_data}, upsert=True)
            
    elif action == "delete_user":
        username = request.form.get("username")
        if username != "admin": users_col.delete_one({"username": username})
        
    elif action == "update_rule":
        reg = request.form.get("registrar")
        banned = request.form.get("banned_tlds", "")
        allowed = request.form.get("allowed_tlds", "")
        rules_col.update_one({"registrar": reg}, {"$set": {"banned_tlds": banned, "allowed_tlds": allowed}})
        
    elif action == "add_banned":
        domain = request.form.get("domain").strip().lower()
        regs = request.form.getlist("registrars")
        banned_col.update_one({"domain": domain}, {"$set": {"registrars": regs}}, upsert=True)
        
    elif action == "delete_banned":
        domain = request.form.get("domain")
        banned_col.delete_one({"domain": domain})

    return redirect(url_for("index"))

# ==========================================
# TEMPLATES GIAO DIỆN
# ==========================================
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Đăng nhập — Domain Checker</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #0b0f19; color: #e2e8f0; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .box { background: #111827; padding: 30px; border-radius: 12px; width: 320px; text-align: center; border: 1px solid #1e293b; }
        input { width: 90%; padding: 10px; margin: 10px 0; border-radius: 6px; border: 1px solid #334155; background: #0b0f19; color: white; }
        button { width: 98%; padding: 10px; background: #3b82f6; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }
        .err { color: #f87171; margin-top: 10px; font-size: 14px; }
    </style>
</head>
<body>
    <form class="box" method="post">
        <h2>Domain Checker</h2>
        <input name="username" placeholder="Tài khoản" required autofocus>
        <input name="password" type="password" placeholder="Mật khẩu" required>
        <button type="submit">Đăng nhập</button>
        {% if error %}<div class="err">{{ error }}</div>{% endif %}
    </form>
</body>
</html>
"""

MAIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Buy & Transfer Checker</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root { --bg: #0b0f19; --card: #111827; --border: #1e293b; --primary: #3b82f6; --text: #e2e8f0; }
        body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 15px;}
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab-btn { background: var(--card); color: var(--text); border: 1px solid var(--border); padding: 10px 20px; cursor: pointer; border-radius: 6px; font-weight: 600; }
        .tab-btn.active { background: var(--primary); border-color: var(--primary); }
        .tab-content { display: none; background: var(--card); border: 1px solid var(--border); padding: 20px; border-radius: 8px; }
        .tab-content.active { display: block; }
        
        .godaddy-box { background: rgba(245, 158, 11, 0.1); border: 1px solid #f59e0b; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .godaddy-box a { display: inline-block; background: #f59e0b; color: #000; text-decoration: none; padding: 8px 15px; border-radius: 5px; font-weight: bold; margin-right: 10px; }
        .godaddy-warn { color: #f87171; font-weight: bold; margin-top: 10px; font-size: 14px; }
        
        textarea { width: 100%; height: 100px; background: var(--bg); color: white; border: 1px solid var(--border); padding: 10px; border-radius: 6px; box-sizing: border-box;}
        button.action-btn { background: var(--primary); color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; margin-top: 10px;}
        
        table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border); }
        th { background: #1a2234; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge-success { background: rgba(34,197,94,0.2); color: #4ade80; }
        .badge-danger { background: rgba(239,68,68,0.2); color: #f87171; }
        .badge-muted { background: rgba(148,163,184,0.2); color: #94a3b8; }
        
        /* Admin forms */
        .admin-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .admin-card { background: var(--bg); border: 1px solid var(--border); padding: 15px; border-radius: 8px; }
        .admin-card input[type="text"], .admin-card input[type="password"] { width: 100%; padding: 8px; margin: 5px 0 15px; background: var(--card); border: 1px solid var(--border); color: white; box-sizing: border-box;}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>◈ Domain System - Xin chào, {{ username }}</h2>
            <a href="/logout" style="color: #f87171; text-decoration: none; font-weight: bold;">Đăng xuất</a>
        </div>

        <div class="godaddy-box">
            <h4>🔗 Liên kết Check Giá Nhanh (GoDaddy)</h4>
            <a href="https://www.godaddy.com/en/domains/bulk-domain-search" target="_blank">🔍 Check Giá Mua Mới</a>
            <a href="https://www.godaddy.com/en/domains/domain-transfer" target="_blank">🔄 Check Giá Transfer</a>
            <div class="godaddy-warn">
                (Nếu giá domain rẻ bất thường, vui lòng liên hệ IT mua domain để được hỗ trợ kiểm tra giá)<br>
                LƯU Ý: CHỨC NĂNG NÀY CHỈ LÀ DẪN LINK MỞ GODADDY, KHÔNG PHẢI THỰC HIỆN TRÊN WEBSITE NÀY.
            </div>
        </div>

        <div class="tabs">
            <button class="tab-btn active" onclick="openTab('buy')">Kiểm tra Mua Mới</button>
            <button class="tab-btn" onclick="openTab('transfer')">Điều kiện Transfer</button>
            {% if username == 'admin' %}
            <button class="tab-btn" onclick="openTab('admin')">Quản trị Hệ thống</button>
            {% endif %}
        </div>

        <!-- TAB 1: MUA MỚI -->
        <div id="buy" class="tab-content active">
            <h3>Tra cứu khả năng mua mới theo luật</h3>
            <textarea id="buyList" placeholder="Nhập domain (mỗi dòng 1 domain)"></textarea>
            <button class="action-btn" onclick="startCheck('buy')">▶ Bắt đầu kiểm tra</button>
            <table>
                <thead><tr><th>Domain</th><th>Khả năng mua</th><th>Nhà đăng ký hiện tại</th></tr></thead>
                <tbody id="buyResult"></tbody>
            </table>
        </div>

        <!-- TAB 2: TRANSFER -->
        <div id="transfer" class="tab-content">
            <h3>Tra cứu điều kiện Transfer (>60 ngày & Không khóa)</h3>
            <textarea id="transList" placeholder="Nhập domain (mỗi dòng 1 domain)"></textarea>
            <button class="action-btn" onclick="startCheck('transfer')">▶ Bắt đầu kiểm tra</button>
            <table>
                <thead><tr><th>Domain</th><th>Ngày tạo</th><th>> 60 Ngày?</th><th>Khóa Transfer?</th><th>Kết luận Transfer</th></tr></thead>
                <tbody id="transResult"></tbody>
            </table>
        </div>

        <!-- TAB 3: ADMIN -->
        {% if username == 'admin' %}
        <div id="admin" class="tab-content">
            <div class="admin-grid">
                <!-- Quản lý User -->
                <div class="admin-card">
                    <h3>👥 Quản lý User</h3>
                    <table>
                        <tr><th>Tài khoản</th><th>Hành động</th></tr>
                        {% for u in users %}
                        <tr>
                            <td>{{ u.username }}</td>
                            <td>
                                {% if u.username != 'admin' %}
                                <form method="post" action="/admin/action" style="display:inline;">
                                    <input type="hidden" name="action" value="delete_user">
                                    <input type="hidden" name="username" value="{{ u.username }}">
                                    <button type="submit" style="background:#f87171; color:white; border:none; border-radius:4px; cursor:pointer;">Xóa</button>
                                </form>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </table>
                    <hr style="border-color: var(--border); margin:15px 0;">
                    <form method="post" action="/admin/action">
                        <input type="hidden" name="action" value="add_user">
                        <label>Tên tài khoản (để tạo mới hoặc đổi pass user cũ):</label>
                        <input type="text" name="username" required>
                        <label>Mật khẩu:</label>
                        <input type="password" name="password" required>
                        <button type="submit" class="action-btn" style="width:100%;">Lưu / Đổi Pass</button>
                    </form>
                </div>

                <!-- Domain Ẩn -->
                <div class="admin-card">
                    <h3>⛔ Banned Domain (Ẩn)</h3>
                    <table>
                        <tr><th>Domain</th><th>Chặn tại</th><th>Xóa</th></tr>
                        {% for b in banned %}
                        <tr>
                            <td>{{ b.domain }}</td><td>{{ b.registrars | join(', ') }}</td>
                            <td>
                                <form method="post" action="/admin/action" style="display:inline;">
                                    <input type="hidden" name="action" value="delete_banned">
                                    <input type="hidden" name="domain" value="{{ b.domain }}">
                                    <button type="submit" style="background:#f87171; color:white; border:none; border-radius:4px; cursor:pointer;">X</button>
                                </form>
                            </td>
                        </tr>
                        {% endfor %}
                    </table>
                    <hr style="border-color: var(--border); margin:15px 0;">
                    <form method="post" action="/admin/action">
                        <input type="hidden" name="action" value="add_banned">
                        <label>Domain cần cấm:</label>
                        <input type="text" name="domain" placeholder="VD: thegioididong.com" required>
                        <label>Cấm trên nhà cung cấp (Chọn nhiều):</label><br>
                        <input type="checkbox" name="registrars" value="Namecheap"> Namecheap
                        <input type="checkbox" name="registrars" value="GoDaddy"> GoDaddy
                        <input type="checkbox" name="registrars" value="Dynadot"> Dynadot
                        <input type="checkbox" name="registrars" value="Spaceship"> Spaceship
                        <input type="checkbox" name="registrars" value="SAV"> SAV
                        <button type="submit" class="action-btn" style="width:100%; margin-top:10px;">Thêm Domain Cấm</button>
                    </form>
                </div>
            </div>

            <!-- Cấu hình Đuôi Domain -->
            <div class="admin-card" style="margin-top:20px;">
                <h3>⚙️ Cấu hình luật Đuôi (TLD) theo Registrar</h3>
                <table>
                    <tr><th>Nhà cung cấp</th><th>Các đuôi cấm (Cách nhau bằng dấu phẩy)</th><th>Đuôi ngoại lệ cho phép</th><th>Lưu</th></tr>
                    {% for r in rules %}
                    <tr>
                        <form method="post" action="/admin/action">
                            <input type="hidden" name="action" value="update_rule">
                            <input type="hidden" name="registrar" value="{{ r.registrar }}">
                            <td><b>{{ r.registrar }}</b><br><small style="color:var(--primary);">{{ r.note }}</small></td>
                            <td><input type="text" name="banned_tlds" value="{{ r.banned_tlds }}"></td>
                            <td><input type="text" name="allowed_tlds" value="{{ r.allowed_tlds }}"></td>
                            <td><button type="submit" style="background:var(--primary); color:white; border:none; padding:5px 10px; border-radius:4px; cursor:pointer;">Cập nhật</button></td>
                        </form>
                    </tr>
                    {% endfor %}
                </table>
            </div>
        </div>
        {% endif %}
    </div>

    <script>
        function openTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            event.currentTarget.classList.add('active');
        }

        async function startCheck(mode) {
            const listId = mode === 'buy' ? 'buyList' : 'transList';
            const tbodyId = mode === 'buy' ? 'buyResult' : 'transResult';
            
            let domains = document.getElementById(listId).value.split('\\n').map(d => d.trim()).filter(d => d);
            const tbody = document.getElementById(tbodyId);
            tbody.innerHTML = '';

            for (let domain of domains) {
                let row = document.createElement('tr');
                row.innerHTML = `<td>${domain}</td><td colspan="4">Đang kiểm tra...</td>`;
                tbody.appendChild(row);

                try {
                    let res = await fetch('/api/check', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({domain, mode})
                    });
                    let data = await res.json();
                    
                    if(data.error) {
                        row.innerHTML = `<td>${domain}</td><td colspan="4" style="color:#f87171;">Lỗi WHOIS / Không lấy được thông tin</td>`;
                        continue;
                    }

                    if (mode === 'buy') {
                        row.innerHTML = `<td>${domain}</td><td>${data.buy_html}</td><td>${data.registrar}</td>`;
                    } else {
                        let is60 = data.is_60_days ? '<span class="badge badge-success">Đạt (>60 ngày)</span>' : '<span class="badge badge-danger">Chưa đủ ngày</span>';
                        let isLock = data.transfer_locked ? '<span class="badge badge-danger">Đang bị khóa</span>' : '<span class="badge badge-success">Không khóa</span>';
                        let canTrans = data.can_transfer ? '<span class="badge badge-success">✔️ ĐỦ ĐIỀU KIỆN TRANSFER</span>' : '<span class="badge badge-danger">❌ KHÔNG ĐỦ ĐIỀU KIỆN</span>';
                        row.innerHTML = `<td>${domain}</td><td>${data.created_str}</td><td>${is60}</td><td>${isLock}</td><td>${canTrans}</td>`;
                    }
                } catch(e) {
                    row.innerHTML = `<td>${domain}</td><td colspan="4" style="color:#f87171;">Lỗi kết nối server</td>`;
                }
            }
        }
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
