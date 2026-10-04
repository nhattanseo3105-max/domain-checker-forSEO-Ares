import os
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
import requests
import whois

app = Flask(__name__)

# ==========================================
# CẤU HÌNH CLOUDFLARE API
# ==========================================
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "")

# ==========================================
# TIÊU CHÍ CẤM THEO REGISTRAR
# ==========================================
# Namecheap: .ch .li .cn .au .fr .ca .eu .eco .uk (chỉ .uk thuần)
#            + .in có chứa "india"
# GoDaddy:   TẤT CẢ .in (kể cả .co.in .net.in ...), .cz .eu .dk
# Dynadot:   .it .org
# Spaceship: .de (cho phép .uk .my)

NAMECHEAP_BANNED_TLDS = {".ch", ".li", ".cn", ".au", ".fr", ".ca", ".eu", ".eco", ".uk"}
GODADDY_BANNED_TLDS = {".cz", ".eu", ".dk"}  # + tất cả đuôi kết thúc bằng .in
DYNADOT_BANNED_TLDS = {".it", ".org"}
SPACESHIP_BANNED_TLDS = {".de"}


def get_tld_parts(domain: str):
    """Trả về (full_suffix, last_tld)  ví dụ: ('co.uk', 'uk') hoặc ('in', 'in')"""
    domain = domain.lower().strip().rstrip(".")
    parts = domain.split(".")
    if len(parts) < 2:
        return "", ""
    last = "." + parts[-1]
    # 2-level TLD phổ biến
    if len(parts) >= 3:
        two = "." + parts[-2] + "." + parts[-1]
        return two, last
    return last, last


def check_buyability(domain: str):
    """
    Kiểm tra domain có bị cấm mua ở các registrar hay không.
    Trả về dict: {registrar: {"ok": bool, "reason": str}}
    và overall "can_buy" (True nếu ít nhất 1 registrar cho phép).
    """
    domain = domain.lower().strip()
    full_suffix, last_tld = get_tld_parts(domain)
    results = {}

    # ---------- Namecheap ----------
    # Cấm: .ch .li .cn .au .fr .ca .eu .eco
    # .uk: CHỈ cấm .uk thuần (example.uk). Mọi dạng *.xx.uk (.co.uk, .org.uk, .me.uk...) ĐƯỢC PHÉP
    # .in: cấm nếu domain chứa "india"
    nc_ok = True
    nc_reason = ""

    if last_tld == ".uk":
        # Chỉ cấm khi đúng là domain.uk (không có cấp 2)
        if full_suffix == ".uk":
            nc_ok = False
            nc_reason = "Cấm đuôi .uk thuần"
        # else: .co.uk / .org.uk / .me.uk / ... → được phép, bỏ qua
    elif full_suffix in NAMECHEAP_BANNED_TLDS or last_tld in NAMECHEAP_BANNED_TLDS:
        banned = full_suffix if full_suffix in NAMECHEAP_BANNED_TLDS else last_tld
        nc_ok = False
        nc_reason = f"Cấm đuôi {banned}"

    if nc_ok and (last_tld == ".in" or full_suffix.endswith(".in")):
        if "india" in domain:
            nc_ok = False
            nc_reason = 'Domain .in chứa "india"'

    results["Namecheap"] = {"ok": nc_ok, "reason": nc_reason}

    # ---------- GoDaddy ----------
    gd_ok = True
    gd_reason = ""
    if last_tld == ".in" or full_suffix.endswith(".in"):
        gd_ok = False
        gd_reason = f"Cấm mọi đuôi .in ({full_suffix})"
    elif full_suffix in GODADDY_BANNED_TLDS or last_tld in GODADDY_BANNED_TLDS:
        gd_ok = False
        gd_reason = f"Cấm đuôi {full_suffix if full_suffix in GODADDY_BANNED_TLDS else last_tld}"
    results["GoDaddy"] = {"ok": gd_ok, "reason": gd_reason}

    # ---------- Dynadot ----------
    dn_ok = True
    dn_reason = ""
    if full_suffix in DYNADOT_BANNED_TLDS or last_tld in DYNADOT_BANNED_TLDS:
        dn_ok = False
        dn_reason = f"Cấm đuôi {full_suffix if full_suffix in DYNADOT_BANNED_TLDS else last_tld}"
    results["Dynadot"] = {"ok": dn_ok, "reason": dn_reason}

    # ---------- Spaceship ----------
    ss_ok = True
    ss_reason = ""
    if full_suffix in SPACESHIP_BANNED_TLDS or last_tld in SPACESHIP_BANNED_TLDS:
        ss_ok = False
        ss_reason = f"Cấm đuôi {full_suffix if full_suffix in SPACESHIP_BANNED_TLDS else last_tld}"
    # .uk và .my được phép (không cần xử lý thêm)
    results["Spaceship"] = {"ok": ss_ok, "reason": ss_reason}

    can_buy = any(r["ok"] for r in results.values())
    return results, can_buy


def format_buyability_html(results, can_buy):
    """Tạo HTML badge tổng + chi tiết từng registrar"""
    if can_buy:
        overall = "<span class='badge badge-success'>CÓ THỂ MUA</span>"
    else:
        overall = "<span class='badge badge-danger'>KHÔNG MUA ĐƯỢC</span>"

    details = []
    for name, info in results.items():
        if info["ok"]:
            details.append(f"<span class='badge badge-success' title='Được phép'>{name} ✓</span>")
        else:
            details.append(
                f"<span class='badge badge-danger' title='{info['reason']}'>{name} ✗</span>"
            )
    detail_html = " ".join(details)
    return overall + "<br><div class='buy-detail'>" + detail_html + "</div>"


# ==========================================
# 1. CÁC HÀM KIỂM TRA & XỬ LÝ DỮ LIỆU
# ==========================================
def format_date_short(dt):
    """Chuyển datetime / ISO string → DD/MM/YY"""
    if not dt:
        return None
    try:
        if isinstance(dt, list):
            dt = dt[0]
        if isinstance(dt, str):
            dt = dt.replace("Z", "+00:00").split("+")[0].split(".")[0]
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    dt = datetime.strptime(dt[:19] if "T" in dt else dt[:10], fmt)
                    break
                except ValueError:
                    continue
            else:
                return None
        if isinstance(dt, datetime):
            return dt.strftime("%d/%m/%y")
    except Exception:
        pass
    return None


def check_cf_eligibility(domain):
    """Giả lập add domain vào CF để check xem có bị Banned không"""
    if not CF_API_TOKEN or not CF_ACCOUNT_ID:
        return "<span class='badge badge-muted'>Thiếu API CF</span>"
    url = "https://api.cloudflare.com/client/v4/zones"
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    data = {
        "name": domain,
        "account": {"id": CF_ACCOUNT_ID},
        "jump_start": False
    }
    try:
        r = requests.post(url, headers=headers, json=data, timeout=10)
        resp = r.json()
        if r.status_code == 200 and resp.get("success"):
            zone_id = resp["result"]["id"]
            requests.delete(f"{url}/{zone_id}", headers=headers, timeout=5)
            return "<span class='badge badge-success'>Sạch</span>"
        errors = resp.get("errors", [])
        if errors:
            err_code = errors[0].get("code")
            if err_code == 1049:
                return "<span class='badge badge-info'>Sạch (Chưa ĐK)</span>"
            elif err_code == 1097:
                return "<span class='badge badge-danger'>BANNED</span>"
            elif err_code == 1095:
                return "<span class='badge badge-danger'>Bị CF Chặn Add</span>"
            elif err_code == 1116:
                return "<span class='badge badge-warning'>Đuôi TLD bị CF cấm</span>"
            elif err_code == 1061:
                return "<span class='badge badge-success'>Sạch (Đã nằm trong CF khác)</span>"
            else:
                return f"<span class='badge badge-muted'>Lỗi CF: {err_code}</span>"
        return "<span class='badge badge-muted'>Không rõ trạng thái</span>"
    except Exception:
        return "<span class='badge badge-danger'>Lỗi Call API CF</span>"


def _normalize_status(s):
    """Chuẩn hóa 1 status string → key chuẩn"""
    s = str(s).lower().replace(" ", "").replace("_", "").replace("-", "")
    mapping = {
        "serverhold": "serverHold",
        "clienthold": "clientHold",
        "clienttransferprohibited": "clientTransferProhibited",
        "servertransferprohibited": "serverTransferProhibited",
        "pendingtransfer": "pendingTransfer",
        "clientupdateprohibited": "clientUpdateProhibited",
        "serverupdateprohibited": "serverUpdateProhibited",
        "clientdeleteprohibited": "clientDeleteProhibited",
        "serverdeleteprohibited": "serverDeleteProhibited",
        "redemptionperiod": "redemptionPeriod",
        "pendingdelete": "pendingDelete",
        "ok": "ok",
        "active": "ok",
    }
    for k, v in mapping.items():
        if k in s:
            return v
    return None


def _parse_rdap_json(data):
    """Parse RDAP JSON → status set + registrar + dates"""
    status_found = set()
    registrar = None
    created = None
    expires = None
    statuses = data.get("status", [])
    for s in statuses:
        key = _normalize_status(s)
        if key:
            status_found.add(key)
    entities = data.get("entities", [])
    for ent in entities:
        roles = ent.get("roles", [])
        if "registrar" in roles:
            vcard = ent.get("vcardArray", [])
            if len(vcard) > 1:
                for prop in vcard[1]:
                    if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
                        registrar = prop[3]
                        break
            if not registrar:
                registrar = ent.get("handle") or ent.get("name")
    events = data.get("events", [])
    for ev in events:
        action = str(ev.get("eventAction", "")).lower()
        date_str = ev.get("eventDate")
        if not date_str:
            continue
        if action in ("registration", "registered"):
            created = format_date_short(date_str)
        elif action in ("expiration", "expiry", "expired", "registrar expiration"):
            expires = format_date_short(date_str)
    return status_found, registrar, created, expires


def format_status_display(status_set):
    """Chuyển set status → HTML badge đẹp, mỗi trạng thái 1 dòng"""
    if not status_set:
        return "<span class='badge badge-success'>Active / Không bị lock</span>"
    labels = {
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
        "ok": ("Active", "badge-success"),
    }
    priority = [
        "serverHold", "clientHold", "pendingTransfer",
        "redemptionPeriod", "pendingDelete",
        "clientTransferProhibited", "serverTransferProhibited",
        "clientUpdateProhibited", "serverUpdateProhibited",
        "clientDeleteProhibited", "serverDeleteProhibited", "ok"
    ]
    badges = []
    for key in priority:
        if key in status_set:
            text, cls = labels.get(key, (key, "badge-muted"))
            badges.append(f"<span class='badge {cls}'>{text}</span>")
    for key in status_set:
        if key not in priority:
            badges.append(f"<span class='badge badge-muted'>{key}</span>")
    return "<br>".join(badges) if badges else "<span class='badge badge-success'>Active / Không bị lock</span>"


def get_domain_info(domain):
    """
    Lấy status (Hold + Transfer + Lock) + Registrar + ngày ĐK.
    Phát hiện domain bị Registry Policy cấm đăng ký.
    """
    status_found = set()
    registrar = None
    created = None
    expires = None
    is_registered = False
    is_restricted = False

    # ---------- 1. rdap.org ----------
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
        if r.status_code == 200:
            is_registered = True
            data = r.json()
            st, reg, cr, exp = _parse_rdap_json(data)
            status_found.update(st)
            if reg:
                registrar = reg
            if cr:
                created = cr
            if exp:
                expires = exp
        elif r.status_code == 404:
            try:
                data = r.json()
                desc = data.get("description") or []
                if isinstance(desc, list):
                    desc_text = " ".join(str(d) for d in desc).lower()
                else:
                    desc_text = str(desc).lower()
                title = str(data.get("title", "")).lower()
                full_text = desc_text + " " + title
                if (
                    "not available for registration" in full_text
                    or "restricted by registry policy" in full_text
                    or "registry policy" in full_text
                    or "prohibited" in full_text
                ):
                    is_restricted = True
            except Exception:
                pass
    except Exception:
        pass

    # ---------- 2. who-dat.as93.net ----------
    if not is_restricted and (not registrar or not status_found or not created or not expires):
        try:
            r = requests.get(f"https://who-dat.as93.net/{domain}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get("isRegistered") is True or data.get("id") or (data.get("registrar") and data.get("registrar") not in (None, {})):
                    is_registered = True
                if "registrar" in data and data["registrar"]:
                    reg_val = data["registrar"]
                    if isinstance(reg_val, str):
                        registrar = registrar or reg_val
                    elif isinstance(reg_val, dict):
                        registrar = registrar or reg_val.get("name") or reg_val.get("organization")
                statuses = data.get("status") or data.get("statuses") or []
                if isinstance(statuses, str):
                    statuses = [statuses]
                for s in statuses:
                    key = _normalize_status(s)
                    if key:
                        status_found.add(key)
                for key_map in [
                    ("created", "creationDate", "creation_date", "registered"),
                    ("expires", "expirationDate", "expiration_date", "expiry"),
                ]:
                    for k in key_map:
                        if k in data and data[k]:
                            formatted = format_date_short(data[k])
                            if formatted:
                                if "creat" in k or "regist" in k:
                                    created = created or formatted
                                else:
                                    expires = expires or formatted
                            break
                if "rdap" in data and isinstance(data["rdap"], dict):
                    st, reg, cr, exp = _parse_rdap_json(data["rdap"])
                    status_found.update(st)
                    if reg and not registrar:
                        registrar = reg
                    if cr and not created:
                        created = cr
                    if exp and not expires:
                        expires = exp
        except Exception:
            pass

    # ---------- 3. rdap.cloud ----------
    if not is_restricted and (not registrar or not status_found or not created or not expires):
        try:
            r = requests.get(f"https://rdap.cloud/api/v1/{domain}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                is_registered = True
                if "registrar" in data:
                    reg_val = data["registrar"]
                    if isinstance(reg_val, str):
                        registrar = registrar or reg_val
                    elif isinstance(reg_val, dict):
                        registrar = registrar or reg_val.get("name") or reg_val.get("organization")
                statuses = data.get("status") or data.get("statuses") or []
                if isinstance(statuses, str):
                    statuses = [statuses]
                for s in statuses:
                    key = _normalize_status(s)
                    if key:
                        status_found.add(key)
                for key_map in [
                    ("created", "creationDate", "creation_date", "registered"),
                    ("expires", "expirationDate", "expiration_date", "expiry"),
                ]:
                    for k in key_map:
                        if k in data and data[k]:
                            formatted = format_date_short(data[k])
                            if formatted:
                                if "creat" in k or "regist" in k:
                                    created = created or formatted
                                else:
                                    expires = expires or formatted
                            break
                st, reg, cr, exp = _parse_rdap_json(data)
                status_found.update(st)
                if reg and not registrar:
                    registrar = reg
                if cr and not created:
                    created = cr
                if exp and not expires:
                    expires = exp
        except Exception:
            pass

    # ---------- 4. python-whois (fallback) ----------
    if not is_restricted and (not is_registered or not registrar or not status_found or not created or not expires):
        try:
            w = whois.whois(domain)
            if w.domain_name:
                is_registered = True
                raw_status = w.status
                if isinstance(raw_status, str):
                    raw_status = [raw_status]
                if raw_status:
                    for s in raw_status:
                        key = _normalize_status(s)
                        if key:
                            status_found.add(key)
                if w.registrar and not registrar:
                    registrar = w.registrar
                if not created and getattr(w, "creation_date", None):
                    created = format_date_short(w.creation_date)
                if not expires and getattr(w, "expiration_date", None):
                    expires = format_date_short(w.expiration_date)
        except Exception:
            pass

    if is_restricted:
        return (
            "<span class='badge badge-danger'>Không thể đăng ký</span><br>"
            "<span class='badge badge-warning'>Restricted by Registry Policy</span>",
            "Registry Policy",
            None,
        )

    if not is_registered:
        return "Chưa đăng ký / Ẩn thông tin", "Không có dữ liệu", None

    final_status = format_status_display(status_found)
    final_registrar = registrar if registrar else "Không xác định"
    return final_status, final_registrar, created


# ==========================================
# 2. GIAO DIỆN WEB
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
                            <span>Ít nhất 1 registrar cho phép</span>
                        </div>
                        <div class="legend-row" data-key="cannotBuy">
                            <span class="badge badge-danger">KHÔNG MUA ĐƯỢC</span>
                            <span>Tất cả registrar đều cấm</span>
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
                        <div class="legend-row" data-key="chuaDK">
                            <span class="badge badge-muted">Chưa đăng ký / Ẩn thông tin</span>
                            <span>Domain chưa đăng ký hoặc WHOIS bị ẩn</span>
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
            if (!data) return true;
            if (options.check_registrar) {
                const reg = (data.registrar || "").toString().toLowerCase();
                if (reg.includes("không có dữ liệu") || reg.includes("không xác định") || reg.includes("lỗi") || reg === "") return true;
            }
            if (options.check_hold) {
                const st = (data.status || "").toString().toLowerCase();
                if (st.includes("lỗi") || st.includes("chưa đăng ký")) return true;
            }
            if (data.cf_add_status && data.cf_add_status.toString().toLowerCase().includes("lỗi")) return true;
            return false;
        }

        function collectLegendKeysFromResult(data, options) {
            if (options.check_buy && data.buy_html) {
                if (data.can_buy) seenLegendKeys.add("canBuy");
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
                    if (["canBuy","cannotBuy"].includes(key)) hasBuy = true;
                    else if (["active","serverHold","clientHold","transferLock","pendingTransfer","updateLock","redemption","chuaDK","restricted"].includes(key)) hasDomain = true;
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
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain, options })
                    });
                    if (!response.ok) throw new Error("Server error");
                    const data = await response.json();

                    collectLegendKeysFromResult(data, options);

                    let registrarText = data.registrar || "";
                    if (["Không có dữ liệu", "Không xác định", "Bỏ qua"].includes(registrarText)) {
                        registrarText = `<span class="error-cell">${registrarText}</span>`;
                    }

                    let datesText = "—";
                    if (data.created) {
                        datesText = `<span class="date-cell">${data.created}</span>`;
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


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/check', methods=['POST'])
def api_check():
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        options = data.get('options', {})
        if not domain:
            return jsonify({"status": "Lỗi", "registrar": "", "created": None}), 400

        status = "Bỏ qua"
        registrar = "Bỏ qua"
        created = None
        cf_add_status = "Bỏ qua"
        buy_html = "Bỏ qua"
        can_buy = True

        # Luôn check buyability (nhanh, local)
        if options.get('check_buy', True):
            results, can_buy = check_buyability(domain)
            buy_html = format_buyability_html(results, can_buy)

        need_whois = (
            options.get('check_registrar', True)
            or options.get('check_hold', True)
            or options.get('check_dates', True)
        )

        if need_whois:
            status, registrar, created = get_domain_info(domain)
            if not options.get('check_registrar', True):
                registrar = "Bỏ qua"
            if not options.get('check_hold', True):
                status = "Bỏ qua"
            if not options.get('check_dates', True):
                created = None

        if options.get('check_cf', True):
            cf_add_status = check_cf_eligibility(domain)

        return jsonify({
            "domain": domain,
            "buy_html": buy_html,
            "can_buy": can_buy,
            "cf_add_status": cf_add_status,
            "registrar": registrar,
            "status": status,
            "created": created
        })
    except Exception:
        return jsonify({
            "domain": domain if 'domain' in locals() else "Unknown",
            "buy_html": "<span class='badge badge-danger'>Lỗi</span>",
            "can_buy": False,
            "cf_add_status": "Lỗi Backend",
            "registrar": "Lỗi",
            "status": "Lỗi",
            "created": None
        })


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
