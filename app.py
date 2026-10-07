"""Captive portal thử nghiệm: UniFi External Portal + whitelist số điện thoại (không OTP).

Luồng: UniFi redirect khách -> /guest/s/<site>/?id=<MAC>&ap=..&ssid=..&url=..
       khách nhập SĐT -> tra bảng customers -> có và active thì gọi API UniFi authorize MAC.
"""
import html
import logging
import os
import re
import time
from collections import defaultdict, deque
from urllib.parse import urlencode, urlparse
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, text

load_dotenv()
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("portal")

# ---------- Cấu hình (đặt trong .env) ----------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///portal.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

UNIFI_BASE = os.getenv("UNIFI_BASE", "").rstrip("/")  # vd https://try.unifi.unihosted.com:8443
UNIFI_USER = os.getenv("UNIFI_USER", "")
UNIFI_PASS = os.getenv("UNIFI_PASS", "")
UNIFI_OS = os.getenv("UNIFI_OS", "0") == "1"  # 1 nếu là UniFi OS (UDM, Cloud Key Gen2...)
UNIFI_VERIFY_TLS = os.getenv("UNIFI_VERIFY_TLS", "1") == "1"
UNIFI_MOCK = os.getenv("UNIFI_MOCK", "1") == "1"  # 1 = không gọi controller thật
DEFAULT_SITE = os.getenv("UNIFI_SITE", "default")  # dùng khi UniFi không gửi kèm tên site
BRAND_TITLE = os.getenv("BRAND_TITLE", "Xin chào")
BRAND_SUBTITLE = os.getenv("BRAND_SUBTITLE", "Chào mừng bạn đến với WiFi miễn phí")
FOOTER_TEXT = os.getenv("FOOTER_TEXT", "Free WiFi")
BRAND_COLOR = os.getenv("BRAND_COLOR", "#e02020")
# --- Grandstream (GWN): portal chuyển khách về AP kèm username/password để AP hỏi RADIUS ---
GWN_SHARED_PASSWORD = os.getenv("GWN_SHARED_PASSWORD", "")  # phải trùng mật khẩu RADIUS chấp nhận
GWN_USER_SUFFIX = os.getenv("GWN_USER_SUFFIX", "")  # vd "@gwn" nếu RADIUS yêu cầu
GWN_LOGIN_HOSTS = [h.strip().lower() for h in os.getenv("GWN_LOGIN_HOSTS", "cwp.gwnportal.cloud").split(",") if h.strip()]
if not re.fullmatch(r"#[0-9a-fA-F]{3,8}", BRAND_COLOR):
    BRAND_COLOR = "#e02020"
SESSION_MINUTES = int(os.getenv("SESSION_MINUTES", "480"))
MAX_FAILS = int(os.getenv("MAX_FAILS", "5"))
WINDOW_SEC = 600

engine = create_engine(DATABASE_URL, pool_pre_ping=True)


def init_db():
    with engine.begin() as c:
        c.execute(text(
            "CREATE TABLE IF NOT EXISTS customers ("
            "phone VARCHAR(20) PRIMARY KEY, name VARCHAR(200), active INTEGER DEFAULT 1)"))
        c.execute(text(
            "CREATE TABLE IF NOT EXISTS login_log ("
            "ts VARCHAR(40), phone VARCHAR(20), mac VARCHAR(20), "
            "ap VARCHAR(20), ssid VARCHAR(100), result VARCHAR(40))"))


init_db()
app = FastAPI()
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")
fails = defaultdict(deque)

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
SITE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


# ---------- Tiện ích ----------
def normalize_phone(raw):
    """0912..., +84912..., 84912..., 912... -> 0912xxxxxx (10 số). Sai định dạng trả None."""
    d = re.sub(r"\D", "", raw or "")
    if d.startswith("00"):
        d = d[2:]
    if d.startswith("84") and len(d) == 11:
        d = "0" + d[2:]
    elif len(d) == 9:
        d = "0" + d
    return d if re.fullmatch(r"0\d{9}", d) else None


def too_many(key):
    now = time.time()
    q = fails[key]
    while q and now - q[0] > WINDOW_SEC:
        q.popleft()
    return len(q) >= MAX_FAILS


def add_fail(key):
    fails[key].append(time.time())


def write_log(phone, mac, ap, ssid, result):
    with engine.begin() as c:
        c.execute(
            text("INSERT INTO login_log VALUES (:ts,:p,:m,:a,:s,:r)"),
            {"ts": datetime.now(timezone.utc).isoformat(), "p": phone or "",
             "m": mac, "a": ap, "s": ssid, "r": result})


def unifi_authorize(site, mac, minutes):
    if UNIFI_MOCK:
        log.info("MOCK authorize mac=%s site=%s minutes=%s", mac, site, minutes)
        return
    s = requests.Session()
    s.verify = UNIFI_VERIFY_TLS
    creds = {"username": UNIFI_USER, "password": UNIFI_PASS}
    headers, prefix = {}, ""
    if UNIFI_OS:
        r = s.post(f"{UNIFI_BASE}/api/auth/login", json=creds, timeout=10)
        r.raise_for_status()
        token = r.headers.get("X-CSRF-Token") or r.headers.get("x-csrf-token")
        if token:
            headers["X-CSRF-Token"] = token
        prefix = "/proxy/network"
    else:
        r = s.post(f"{UNIFI_BASE}/api/login", json=creds, timeout=10)
        r.raise_for_status()
    r = s.post(
        f"{UNIFI_BASE}{prefix}/api/s/{site}/cmd/stamgr",
        json={"cmd": "authorize-guest", "mac": mac, "minutes": minutes},
        headers=headers, timeout=10)
    r.raise_for_status()
    log.info("UniFi trả về: %s", r.text[:200])


# ---------- Giao diện (không dùng CDN/font ngoài) ----------
PAGE_TMPL = """<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>WiFi</title>
<style>
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{font-family:Helvetica,Arial,sans-serif;color:#111;display:flex;align-items:center;
 justify-content:center;padding:16px;
 background:url(/static/bg.jpg) center/cover no-repeat fixed,linear-gradient(135deg,#2b0a0a,#b3261e)}
.card{width:100%;max-width:460px;padding:36px 28px 28px;text-align:center;border-radius:28px;
 background:rgba(255,255,255,.55);-webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px);
 box-shadow:0 8px 32px rgba(0,0,0,.25)}
.logo{width:76px;height:76px;border-radius:50%;background:#fff;object-fit:contain;
 margin:0 auto 26px;display:block}
h1{font-size:26px;margin:0 0 6px;font-weight:700}
.sub{font-size:14px;margin:0 0 22px;color:#222}
input[type=tel]{width:100%;padding:14px;font-size:18px;text-align:center;
 border:1px solid rgba(0,0,0,.2);border-radius:12px;background:rgba(255,255,255,.85)}
button{width:100%;margin-top:12px;padding:14px;font-size:16px;font-weight:600;border:0;
 border-radius:12px;background:__COLOR__;color:#fff}
.e{color:#b00020;background:rgba(255,255,255,.8);border-radius:8px;padding:8px;
 margin:0 0 12px;font-size:14px}
.foot{position:fixed;bottom:14px;left:50%;transform:translateX(-50%);padding:10px 26px;
 border-radius:999px;background:rgba(0,0,0,.6);color:#fff;font-size:14px;white-space:nowrap}
</style></head><body>
<div class="card"><img class="logo" src="/static/logo.png" alt="" onerror="this.style.display='none'">
<h1>__TITLE__</h1><p class="sub">__SUB__</p>__BODY__</div>
<div class="foot">__FOOT__</div></body></html>"""


def page(body):
    out = (PAGE_TMPL.replace("__COLOR__", BRAND_COLOR)
           .replace("__TITLE__", html.escape(BRAND_TITLE))
           .replace("__SUB__", html.escape(BRAND_SUBTITLE))
           .replace("__FOOT__", html.escape(FOOTER_TEXT))
           .replace("__BODY__", body))  # BODY thay cuối để nội dung không bị xử lý lại
    return HTMLResponse(out)


def form_page(site, mac, ap, ssid, url, error="", login_url=""):
    h = lambda v: html.escape(v or "", quote=True)
    err = f'<div class="e">{h(error)}</div>' if error else ""
    return page(f"""{err}
<form method="post" action="/login">
<input type="hidden" name="site" value="{h(site)}"><input type="hidden" name="id" value="{h(mac)}">
<input type="hidden" name="ap" value="{h(ap)}"><input type="hidden" name="ssid" value="{h(ssid)}">
<input type="hidden" name="url" value="{h(url)}"><input type="hidden" name="login_url" value="{h(login_url)}">
<input type="tel" name="phone" placeholder="Nhập số điện thoại (09xx xxx xxx)" autocomplete="tel" required>
<button type="submit">Kết nối</button></form>""")


# ---------- Route ----------
MAC_KEYS = ("id", "mac", "clientMac", "client_mac", "usermac", "sta_mac", "clientmac")
URL_KEYS = ("url", "orig_url")
AP_KEYS = ("ap", "apmac", "ap_mac", "gw_id")


def pick(q, keys):
    for k in keys:
        if q.get(k):
            return q.get(k)
    return ""


def gwn_login_ok(u):
    """Chỉ chấp nhận login_url trỏ về máy chủ Grandstream đã khai báo (tránh open redirect)."""
    try:
        x = urlparse(u)
    except ValueError:
        return False
    host = (x.hostname or "").lower()
    return x.scheme in ("http", "https") and bool(host) and (
        host in GWN_LOGIN_HOSTS or host.endswith(".gwnportal.cloud"))


@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)


@app.get("/health")
def health():
    return {"ok": True, "mock": UNIFI_MOCK}


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    # Luôn hiện trang portal; nhận nhiều tên tham số MAC khác nhau (UniFi, Grandstream...)
    q = request.query_params
    log.info("root query: %s", dict(q))
    return form_page(q.get("site") or DEFAULT_SITE, pick(q, MAC_KEYS), pick(q, AP_KEYS),
                     q.get("ssid", ""), pick(q, URL_KEYS), login_url=q.get("login_url", ""))


@app.get("/guest/s/{site}/", response_class=HTMLResponse)
@app.get("/guest/s/{site}", response_class=HTMLResponse)
def guest(site: str, request: Request):
    q = request.query_params
    return form_page(site, pick(q, MAC_KEYS), pick(q, AP_KEYS), q.get("ssid", ""),
                     pick(q, URL_KEYS), login_url=q.get("login_url", ""))


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, phone: str = Form(""), site: str = Form("default"),
          mac: str = Form("", alias="id"), ap: str = Form(""),
          ssid: str = Form(""), url: str = Form(""), login_url: str = Form("")):
    mac = mac.lower().strip().replace("-", ":")
    if not SITE_RE.match(site) or not MAC_RE.match(mac):
        return form_page(site, mac, ap, ssid, url, login_url=login_url, error="Thiếu thông tin thiết bị, hãy kết nối lại WiFi.")

    key = f"{request.client.host}|{mac}"
    if too_many(key):
        write_log(phone, mac, ap, ssid, "rate_limited")
        return form_page(site, mac, ap, ssid, url, login_url=login_url, error="Thử quá nhiều lần, vui lòng đợi ít phút.")

    p = normalize_phone(phone)
    if not p:
        add_fail(key)
        write_log(phone, mac, ap, ssid, "bad_format")
        return form_page(site, mac, ap, ssid, url, login_url=login_url, error="Số điện thoại không hợp lệ.")

    with engine.connect() as c:
        row = c.execute(text("SELECT active FROM customers WHERE phone=:p"), {"p": p}).fetchone()
    if not row or not row[0]:
        add_fail(key)
        write_log(p, mac, ap, ssid, "denied")
        return form_page(site, mac, ap, ssid, url, login_url=login_url, error="Số điện thoại chưa được đăng ký.")

    if login_url and gwn_login_ok(login_url):  # luồng Grandstream: chuyển về AP để AP hỏi RADIUS
        if not GWN_SHARED_PASSWORD:
            log.error("Thiếu GWN_SHARED_PASSWORD")
            write_log(p, mac, ap, ssid, "gwn_not_configured")
            return form_page(site, mac, ap, ssid, url, login_url=login_url,
                             error="Hệ thống chưa cấu hình xong.")
        back = url if url.startswith(("http://", "https://")) else "http://connectivitycheck.gstatic.com/generate_204"
        qs = urlencode({"username": p + GWN_USER_SUFFIX, "password": GWN_SHARED_PASSWORD, "redirect": back})
        target = login_url + ("&" if "?" in login_url else "?") + qs
        write_log(p, mac, ap, ssid, "ok_gwn_handoff")
        return RedirectResponse(target, status_code=303)

    try:
        unifi_authorize(site, mac, SESSION_MINUTES)
    except Exception:
        log.exception("authorize lỗi")
        write_log(p, mac, ap, ssid, "controller_error")
        return form_page(site, mac, ap, ssid, url, login_url=login_url, error="Hệ thống đang bận, vui lòng thử lại.")

    write_log(p, mac, ap, ssid, "ok")
    safe = url if url.startswith(("http://", "https://")) else ""
    refresh = f'<meta http-equiv="refresh" content="2;url={html.escape(safe, quote=True)}">' if safe else ""
    return page(f"{refresh}<p class='sub'><b>Đã kết nối.</b> Chúc bạn lướt web vui vẻ.</p>")
