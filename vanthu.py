#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VĂN THƯ – quản lý văn bản đến/đi, hồ sơ, nhiệm vụ & nhắc hạn.
Chỉ dùng thư viện chuẩn Python >= 3.9 (SQLite FTS5). Không gọi ra Internet, chạy được trong mạng LAN cô lập.
  python3 vanthu.py --host 0.0.0.0 --port 8080   chạy máy chủ (dữ liệu ở ./data)
  python3 vanthu.py --verify                      kiểm tra hash tệp + chuỗi nhật ký
  python3 vanthu.py --backup THƯ_MỤC              sao lưu CSDL + tệp
  python3 vanthu.py --reset TÊN_ĐĂNG_NHẬP         đặt lại mật khẩu (in ra màn hình)"""
import os, re, sys, json, html, time, shutil, hashlib, hmac, secrets, sqlite3, argparse, tempfile, subprocess, unicodedata, zipfile
from datetime import datetime, timedelta, timezone, date
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote, quote

BASE = os.path.dirname(os.path.abspath(__file__)); DATA = os.path.join(BASE, "data"); FILES = os.path.join(DATA, "files")
DB = os.path.join(DATA, "vanthu.db"); TZ = timezone(timedelta(hours=7)); MAX_UPLOAD = 100 * 1024 * 1024
LEVELS = ["Thường", "Mật", "Tối mật", "Tuyệt mật"]            # chỉnh theo quy định đơn vị
URG = ["Thường", "Khẩn", "Thượng khẩn", "Hỏa tốc"]
ST = {"den": ["Mới", "Đang xử lý", "Chờ phối hợp", "Đã xử lý", "Lưu trữ"],
      "di": ["Dự thảo", "Chờ duyệt", "Đã ký", "Đã phát hành", "Lưu trữ"]}
ROLES = {"admin": {"users"},                                   # quản trị hệ thống: không mặc nhiên đọc tài liệu mật
         "vanthu": {"write", "assign"}, "lanhdao": {"write", "assign"}, "xuly": set(), "kiemtoan": {"audit"}}
EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".png", ".jpg", ".jpeg", ".tif", ".tiff"}  # chặn macro/exe
SEC = [("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
       ("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")]

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, name TEXT, role TEXT, level INT DEFAULT 0, salt TEXT, pw TEXT, active INT DEFAULT 1, fails INT DEFAULT 0, locked_until REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, uid INT, exp REAL);
CREATE TABLE IF NOT EXISTS dossiers(id INTEGER PRIMARY KEY, code TEXT UNIQUE, title TEXT);
CREATE TABLE IF NOT EXISTS docs(id INTEGER PRIMARY KEY, dossier_id INT, kind TEXT, reg_year INT, reg_no INT, so_kh TEXT, ngay_vb TEXT, ngay_den TEXT,
  coquan TEXT, nguoiky TEXT, trichyeu TEXT, level INT DEFAULT 0, urgency TEXT, status TEXT, creator INT, at TEXT, deleted INT DEFAULT 0, UNIQUE(kind, reg_year, reg_no));
CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY, doc_id INT, name TEXT, sha TEXT, size INT, ver INT, uploader INT, at TEXT);
CREATE TABLE IF NOT EXISTS texts(file_id INTEGER PRIMARY KEY, doc_id INT, txt TEXT);
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY, doc_id INT, title TEXT, assignee INT, due TEXT, done INT DEFAULT 0, done_at TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, uid INT, who TEXT, act TEXT, target TEXT, info TEXT, prev TEXT, h TEXT);
CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(body);
"""

class Err(Exception):
    def __init__(s, code, msg): s.code, s.msg = code, msg
def need(cond, code, msg):
    if not cond: raise Err(code, msg)

now = lambda: datetime.now(TZ)
today = lambda: now().date()
S = lambda d, k: str(d.get(k) or "").strip()[:500]
blob = lambda sha: os.path.join(FILES, sha[:2], sha)

def fold(s):  # bỏ dấu tiếng Việt để tìm không cần gõ dấu
    s = unicodedata.normalize("NFD", (s or "").lower().replace("đ", "d"))
    return "".join(c for c in s if unicodedata.category(c) != "Mn")

def hpw(p, salt): return hashlib.pbkdf2_hmac("sha256", p.encode(), bytes.fromhex(salt), 200_000).hex()

def vdate(s, req=False):
    s = str(s or "").strip()
    if not s: need(not req, 400, "Thiếu ngày"); return ""
    try: date.fromisoformat(s)
    except ValueError: raise Err(400, "Ngày không hợp lệ")
    return s

def db():
    c = sqlite3.connect(DB, timeout=15, isolation_level=None); c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL"); return c

# ---- nhật ký có chuỗi băm: sửa/xóa một dòng sẽ làm hỏng các dòng sau ----
def ah(*a): return hashlib.sha256("|".join(map(str, a)).encode()).hexdigest()
def audit(c, u, act, target="", info=""):
    prev = (c.execute("SELECT h FROM audit ORDER BY id DESC LIMIT 1").fetchone() or ["0" * 64])[0]
    ts = now().isoformat(timespec="seconds"); who = u["username"] if u else "-"
    c.execute("INSERT INTO audit(ts,uid,who,act,target,info,prev,h) VALUES(?,?,?,?,?,?,?,?)",
              (ts, u["id"] if u else None, who, act, target, info, prev, ah(prev, ts, who, act, target, info)))
def chain_bad(c):
    prev = "0" * 64
    for r in c.execute("SELECT * FROM audit ORDER BY id"):
        if r["prev"] != prev or r["h"] != ah(prev, r["ts"], r["who"], r["act"], r["target"], r["info"]): return r["id"]
        prev = r["h"]
    return 0

# ---- trích xuất văn bản: docx/xlsx/txt gốc; PDF cần pdftotext; quét ảnh cần tesseract (+ pdftoppm) nếu máy có ----
def extract(path, name):
    ext = os.path.splitext(name)[1].lower(); t = ""
    try:
        if ext == ".txt": t = open(path, encoding="utf-8", errors="ignore").read()
        elif ext in (".docx", ".xlsx"):
            with zipfile.ZipFile(path) as z:
                parts = ["word/document.xml"] if ext == ".docx" else [n for n in z.namelist() if n.endswith("sharedStrings.xml")]
                t = " ".join(html.unescape(re.sub(r"<[^>]+>", " ", z.read(n).decode("utf8", "ignore"))) for n in parts)
        elif ext == ".pdf" and shutil.which("pdftotext"):
            t = subprocess.run(["pdftotext", "-q", path, "-"], capture_output=True, timeout=120).stdout.decode("utf8", "ignore")
        if len(t.strip()) < 20 and shutil.which("tesseract") and ext in (".pdf", ".png", ".jpg", ".jpeg", ".tif", ".tiff"):
            with tempfile.TemporaryDirectory() as td:
                imgs = [path]
                if ext == ".pdf":
                    if not shutil.which("pdftoppm"): return t
                    subprocess.run(["pdftoppm", "-r", "200", "-l", "30", "-png", path, td + "/p"], timeout=300)
                    imgs = sorted(os.path.join(td, f) for f in os.listdir(td))
                t = " ".join(subprocess.run(["tesseract", i, "-", "-l", "vie+eng"], capture_output=True, timeout=300).stdout.decode("utf8", "ignore") for i in imgs)
    except Exception as e: sys.stderr.write("extract: %r\n" % e)
    return t[:1_000_000]

def reindex(c, id):
    d = c.execute("SELECT * FROM docs WHERE id=?", (id,)).fetchone()
    txt = " ".join(r[0] for r in c.execute("SELECT txt FROM texts WHERE doc_id=?", (id,)))
    c.execute("DELETE FROM fts WHERE rowid=?", (id,))
    if not d["deleted"]:
        c.execute("INSERT INTO fts(rowid,body) VALUES(?,?)", (id, fold(" ".join(str(d[k] or "") for k in ("so_kh", "coquan", "nguoiky", "trichyeu")) + " " + txt)))

def need_doc(h, id):  # tài liệu vượt quyền trả 404, không lộ sự tồn tại
    d = h.c.execute("SELECT * FROM docs WHERE id=? AND deleted=0", (id,)).fetchone()
    need(d and d["level"] <= h.user["level"], 404, "Không tìm thấy văn bản")
    return d

ROUTES = []
def route(m, rx, perm="auth"):
    def d(f): ROUTES.append((m, re.compile(rx), f, perm)); return f
    return d

# ================= API =================
@route("POST", r"/api/login", None)
def login(h):
    d, c = h.body(), h.c
    c.execute("DELETE FROM sessions WHERE exp<?", (time.time(),))
    u = c.execute("SELECT * FROM users WHERE username=?", (S(d, "u").lower(),)).fetchone()
    if u and u["locked_until"] > time.time(): raise Err(429, "Tài khoản tạm khóa, thử lại sau ít phút")
    if not u or not u["active"] or not hmac.compare_digest(hpw(str(d.get("p", "")), u["salt"]), u["pw"]):
        if u:
            f = u["fails"] + 1
            c.execute("UPDATE users SET fails=?, locked_until=? WHERE id=?", (f % 5, time.time() + 300 if f >= 5 else 0, u["id"]))
        audit(c, u, "login_fail", info=S(d, "u")[:40]); c.execute("COMMIT")
        raise Err(401, "Sai tên đăng nhập hoặc mật khẩu")
    tok = secrets.token_hex(32)
    c.execute("INSERT INTO sessions VALUES(?,?,?)", (tok, u["id"], time.time() + 8 * 3600))
    c.execute("UPDATE users SET fails=0, locked_until=0 WHERE id=?", (u["id"],)); audit(c, u, "login")
    h.out.append(("Set-Cookie", "sid=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800%s" % (tok, "; Secure" if h.headers.get("X-Forwarded-Proto") == "https" else "")))
    return {"ok": 1}

@route("POST", r"/api/logout")
def logout(h):
    h.c.execute("DELETE FROM sessions WHERE uid=?", (h.user["id"],)); audit(h.c, h.user, "logout")
    h.out.append(("Set-Cookie", "sid=; Path=/; Max-Age=0")); return {"ok": 1}

@route("GET", r"/api/me")
def me(h):
    u = h.user
    return {"id": u["id"], "name": u["name"], "username": u["username"], "role": u["role"], "level": u["level"],
            "perms": sorted(ROLES[u["role"]]), "levels": LEVELS, "roles": list(ROLES)}

@route("GET", r"/api/docs")
def docs_list(h):
    q, w, a = h.q, ["d.deleted=0", "d.level<=?"], [h.user["level"]]   # lọc theo quyền ngay tại truy vấn (security trimming)
    for k, col in (("kind", "d.kind"), ("status", "d.status"), ("dossier", "d.dossier_id")):
        if q.get(k): w.append(col + "=?"); a.append(q[k])
    if q.get("from"): w.append("d.ngay_vb>=?"); a.append(q["from"])
    if q.get("to"): w.append("d.ngay_vb<=?"); a.append(q["to"])
    terms = re.findall(r"\w+", fold(q.get("q", "")))
    if terms: w.append("d.id IN (SELECT rowid FROM fts WHERE fts MATCH ?)"); a.append(" ".join(t + "*" for t in terms))
    sql = ("SELECT d.id,d.kind,d.reg_no,d.reg_year,d.so_kh,d.ngay_vb,d.coquan,d.trichyeu,d.level,d.urgency,d.status,"
           "(SELECT MIN(due) FROM tasks WHERE doc_id=d.id AND done=0) due FROM docs d WHERE " + " AND ".join(w) + " ORDER BY d.id DESC LIMIT 300")
    if terms: audit(h.c, h.user, "search", info=" ".join(terms)[:80])
    return [dict(r) for r in h.c.execute(sql, a)]

@route("POST", r"/api/docs", "write")
def doc_new(h):
    d, u, c = h.body(), h.user, h.c
    kind = d.get("kind"); need(kind in ST, 400, "Loại văn bản không hợp lệ")
    lv = int(d.get("level") or 0); need(0 <= lv <= u["level"], 403, "Không đủ quyền với mức độ mật này")
    ty = S(d, "trichyeu"); need(ty, 400, "Thiếu trích yếu")
    yr = now().year   # số đến/đi cấp trong giao dịch BEGIN IMMEDIATE nên không trùng khi nhiều người đăng ký cùng lúc
    no = (c.execute("SELECT MAX(reg_no) FROM docs WHERE kind=? AND reg_year=?", (kind, yr)).fetchone()[0] or 0) + 1
    urg = d.get("urgency") if d.get("urgency") in URG else URG[0]
    cur = c.execute("INSERT INTO docs(dossier_id,kind,reg_year,reg_no,so_kh,ngay_vb,ngay_den,coquan,nguoiky,trichyeu,level,urgency,status,creator,at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (int(d["dossier_id"]) if d.get("dossier_id") else None, kind, yr, no, S(d, "so_kh"), vdate(d.get("ngay_vb")),
                     vdate(d.get("ngay_den")) or (today().isoformat() if kind == "den" else ""), S(d, "coquan"), S(d, "nguoiky"), ty, lv, urg,
                     ST[kind][0], u["id"], now().isoformat(timespec="seconds")))
    reindex(c, cur.lastrowid); audit(c, u, "doc_new", "doc:%d" % cur.lastrowid, "%s %d/%d level=%d" % (kind, no, yr, lv))
    return {"id": cur.lastrowid, "reg_no": no}

@route("GET", r"/api/docs/(\d+)")
def doc_get(h, id):
    d = need_doc(h, id); c = h.c; audit(c, h.user, "view", "doc:%d" % id)
    r = dict(d)
    r["dossier"] = " ".join((c.execute("SELECT code,title FROM dossiers WHERE id=?", (d["dossier_id"],)).fetchone() or [""])[:2]) if d["dossier_id"] else ""
    r["files"] = [dict(x) for x in c.execute("SELECT id,name,sha,size,ver,at FROM files WHERE doc_id=? ORDER BY ver DESC", (id,))]
    r["tasks"] = [dict(x) for x in c.execute("SELECT t.*,u.name an FROM tasks t LEFT JOIN users u ON u.id=t.assignee WHERE t.doc_id=? ORDER BY t.done,t.due", (id,))]
    return r

@route("POST", r"/api/docs/(\d+)", "write")
def doc_upd(h, id):
    d, c, u = h.body(), h.c, h.user; o = need_doc(h, id); ch = {}
    need(o["status"] != "Lưu trữ" or not (set(d) - {"status"}), 409, "Hồ sơ đã lưu trữ (chỉ đọc). Hãy đổi trạng thái trước khi sửa")
    if "status" in d: need(d["status"] in ST[o["kind"]], 400, "Trạng thái không hợp lệ"); ch["status"] = d["status"]
    for k in ("so_kh", "coquan", "nguoiky", "trichyeu"):
        if k in d: ch[k] = S(d, k)
    for k in ("ngay_vb", "ngay_den"):
        if k in d: ch[k] = vdate(d[k])
    if "urgency" in d: need(d["urgency"] in URG, 400, "Độ khẩn không hợp lệ"); ch["urgency"] = d["urgency"]
    if "level" in d: need(0 <= int(d["level"]) <= u["level"], 403, "Không đủ quyền với mức độ mật này"); ch["level"] = int(d["level"])
    if "dossier_id" in d: ch["dossier_id"] = int(d["dossier_id"]) if d["dossier_id"] else None
    need(ch, 400, "Không có thay đổi")
    c.execute("UPDATE docs SET " + ",".join(k + "=?" for k in ch) + " WHERE id=?", (*ch.values(), id)); reindex(c, id)
    audit(c, u, "doc_upd", "doc:%d" % id, ",".join(k if k not in ("status", "level") else "%s=%s" % (k, v) for k, v in ch.items()))
    return {"ok": 1}

@route("POST", r"/api/docs/(\d+)/delete", "write")
def doc_del(h, id):  # xóa mềm
    need_doc(h, id); h.c.execute("UPDATE docs SET deleted=1 WHERE id=?", (id,)); reindex(h.c, id); audit(h.c, h.user, "doc_delete", "doc:%d" % id)
    return {"ok": 1}

@route("POST", r"/api/docs/(\d+)/file", "write")
def upload(h, id):
    d, c, u = need_doc(h, id), h.c, h.user
    need(d["status"] != "Lưu trữ", 409, "Hồ sơ đã lưu trữ (chỉ đọc)")
    name = os.path.basename(unquote(h.headers.get("X-Filename", "tep")))[:200] or "tep"
    need(os.path.splitext(name)[1].lower() in EXTS, 400, "Định dạng tệp không được phép")
    data = h.body(raw=True); need(data, 400, "Tệp rỗng")
    sha = hashlib.sha256(data).hexdigest(); p = blob(sha)
    if not os.path.exists(p):
        os.makedirs(os.path.dirname(p), exist_ok=True); tmp = p + ".tmp"
        with open(tmp, "wb") as f: f.write(data)
        os.replace(tmp, p)
    dup = [r[0] for r in c.execute("SELECT DISTINCT f.doc_id FROM files f JOIN docs d ON d.id=f.doc_id WHERE f.sha=? AND f.doc_id!=? AND d.deleted=0 AND d.level<=?", (sha, id, u["level"]))]
    ver = (c.execute("SELECT MAX(ver) FROM files WHERE doc_id=?", (id,)).fetchone()[0] or 0) + 1   # không ghi đè: mỗi lần tải lên là một phiên bản
    fid = c.execute("INSERT INTO files(doc_id,name,sha,size,ver,uploader,at) VALUES(?,?,?,?,?,?,?)", (id, name, sha, len(data), ver, u["id"], now().isoformat(timespec="seconds"))).lastrowid
    c.execute("INSERT INTO texts VALUES(?,?,?)", (fid, id, extract(p, name))); reindex(c, id)
    audit(c, u, "upload", "doc:%d" % id, "file:%d v%d" % (fid, ver))
    return {"ok": 1, "dup": dup}

@route("GET", r"/api/files/(\d+)")
def download(h, id):
    f = h.c.execute("SELECT * FROM files WHERE id=?", (id,)).fetchone(); need(f, 404, "Không tìm thấy tệp")
    need_doc(h, f["doc_id"]); need(os.path.exists(blob(f["sha"])), 500, "Mất tệp trên đĩa")
    data = open(blob(f["sha"]), "rb").read()
    need(hashlib.sha256(data).hexdigest() == f["sha"], 500, "Tệp đã bị thay đổi ngoài hệ thống")
    audit(h.c, h.user, "download", "doc:%d" % f["doc_id"], "file:%d" % id)
    h.raw(200, data, "application/octet-stream", [("Content-Disposition", "attachment; filename*=UTF-8''" + quote(f["name"]))])

@route("POST", r"/api/docs/(\d+)/tasks", "assign")
def task_new(h, id):
    need_doc(h, id); d = h.body(); t = S(d, "title"); need(t, 400, "Thiếu nội dung công việc")
    due = vdate(d.get("due"), True); a = int(d.get("assignee") or 0)
    need(h.c.execute("SELECT 1 FROM users WHERE id=? AND active=1", (a,)).fetchone(), 400, "Người phụ trách không hợp lệ")
    tid = h.c.execute("INSERT INTO tasks(doc_id,title,assignee,due) VALUES(?,?,?,?)", (id, t, a, due)).lastrowid
    audit(h.c, h.user, "task_new", "doc:%d" % id, "task:%d to=%d due=%s" % (tid, a, due)); return {"id": tid}

@route("POST", r"/api/tasks/(\d+)/done")
def task_done(h, id):
    t = h.c.execute("SELECT * FROM tasks WHERE id=?", (id,)).fetchone(); need(t, 404, "Không tìm thấy việc")
    need_doc(h, t["doc_id"]); need(t["assignee"] == h.user["id"] or "assign" in ROLES[h.user["role"]], 403, "Chỉ người phụ trách hoặc người giao việc được xác nhận")
    h.c.execute("UPDATE tasks SET done=1, done_at=? WHERE id=?", (now().isoformat(timespec="seconds"), id)); audit(h.c, h.user, "task_done", "doc:%d" % t["doc_id"], "task:%d" % id)
    return {"ok": 1}

@route("GET", r"/api/dash")
def dash(h):
    u, c = h.user, h.c; asg = int("assign" in ROLES[u["role"]])
    rows = c.execute("SELECT t.id,t.title,t.due,t.doc_id,t.assignee,d.so_kh,d.trichyeu,a.name an FROM tasks t JOIN docs d ON d.id=t.doc_id AND d.deleted=0 "
                     "LEFT JOIN users a ON a.id=t.assignee WHERE t.done=0 AND d.level<=? AND (t.assignee=? OR ?) ORDER BY t.due", (u["level"], u["id"], asg))
    tasks = [{**dict(r), "days": (date.fromisoformat(r["due"]) - today()).days} for r in rows]
    stats = [dict(r) for r in c.execute("SELECT kind,status,COUNT(*) n FROM docs WHERE deleted=0 AND level<=? GROUP BY kind,status", (u["level"],))]
    return {"tasks": tasks, "stats": stats}

@route("GET", r"/api/dossiers")
def dos_list(h):
    return [dict(r) for r in h.c.execute("SELECT s.id,s.code,s.title,(SELECT COUNT(*) FROM docs d WHERE d.dossier_id=s.id AND d.deleted=0 AND d.level<=?) n FROM dossiers s ORDER BY s.id DESC", (h.user["level"],))]

@route("POST", r"/api/dossiers", "write")
def dos_new(h):
    d = h.body(); code, title = S(d, "code"), S(d, "title"); need(code and title, 400, "Thiếu mã hoặc tên hồ sơ")
    need(not h.c.execute("SELECT 1 FROM dossiers WHERE code=?", (code,)).fetchone(), 409, "Mã hồ sơ đã tồn tại")
    i = h.c.execute("INSERT INTO dossiers(code,title) VALUES(?,?)", (code, title)).lastrowid; audit(h.c, h.user, "dossier_new", "dossier:%d" % i); return {"id": i}

@route("GET", r"/api/people")
def people(h): return [{"id": r["id"], "name": r["name"]} for r in h.c.execute("SELECT id,name FROM users WHERE active=1 ORDER BY name")]

def mkuser(c, username, name, role, level, pw):
    need(re.fullmatch(r"[a-z0-9._-]{3,32}", username), 400, "Tên đăng nhập 3–32 ký tự a-z, 0-9, . _ -")
    need(role in ROLES and 0 <= level < len(LEVELS), 400, "Vai trò hoặc mức mật không hợp lệ"); need(len(pw) >= 10, 400, "Mật khẩu tối thiểu 10 ký tự")
    need(not c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone(), 409, "Tên đăng nhập đã tồn tại")
    salt = secrets.token_hex(16)
    return c.execute("INSERT INTO users(username,name,role,level,salt,pw) VALUES(?,?,?,?,?,?)", (username, name or username, role, level, salt, hpw(pw, salt))).lastrowid

@route("GET", r"/api/users", "users")
def users_list(h): return [dict(r) for r in h.c.execute("SELECT id,username,name,role,level,active FROM users ORDER BY id")]

@route("POST", r"/api/users", "users")
def users_new(h):
    d = h.body(); i = mkuser(h.c, S(d, "username").lower(), S(d, "name"), S(d, "role"), int(d.get("level") or 0), str(d.get("pw") or ""))
    audit(h.c, h.user, "user_new", "user:%d" % i, "role=%s level=%s" % (d.get("role"), d.get("level"))); return {"id": i}

@route("POST", r"/api/users/(\d+)", "users")
def users_set(h, id):
    d, c = h.body(), h.c
    need(id != h.user["id"] or not ({"role", "level", "active"} & set(d)), 403, "Không tự đổi quyền của chính mình")
    need(c.execute("SELECT 1 FROM users WHERE id=?", (id,)).fetchone(), 404, "Không tìm thấy người dùng"); ch = {}
    if "role" in d: need(d["role"] in ROLES, 400, "Vai trò không hợp lệ"); ch["role"] = d["role"]
    if "level" in d: need(0 <= int(d["level"]) < len(LEVELS), 400, "Mức mật không hợp lệ"); ch["level"] = int(d["level"])
    if "active" in d: ch["active"] = int(bool(d["active"]))
    if d.get("pw"):
        need(len(d["pw"]) >= 10, 400, "Mật khẩu tối thiểu 10 ký tự"); salt = secrets.token_hex(16); ch["salt"], ch["pw"] = salt, hpw(d["pw"], salt)
    need(ch, 400, "Không có thay đổi")
    c.execute("UPDATE users SET " + ",".join(k + "=?" for k in ch) + " WHERE id=?", (*ch.values(), id))
    if ch.get("active") == 0 or "pw" in ch: c.execute("DELETE FROM sessions WHERE uid=?", (id,))
    audit(c, h.user, "user_set", "user:%d" % id, ",".join(k if k in ("pw", "salt") is False else k for k in ch if k != "salt").replace("pw", "pw(changed)") if False else ",".join(k for k in ch if k not in ("salt", "pw")) + (" pw" if "pw" in ch else ""))
    return {"ok": 1}

@route("GET", r"/api/audit", "audit")
def audit_list(h): return [dict(r) for r in h.c.execute("SELECT ts,who,act,target,info FROM audit ORDER BY id DESC LIMIT 300")]

@route("GET", r"/api/audit/verify", "audit")
def audit_verify(h): b = chain_bad(h.c); return {"ok": b == 0, "bad": b}

# ================= HTTP =================
class H(BaseHTTPRequestHandler):
    server_version = "VanThu"
    def log_message(self, *a): pass
    def raw(self, code, body, ctype, extra=()):
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
        for k, v in (*SEC, *self.out, *extra): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)
    def js(self, code, obj): self.raw(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")
    def body(self, raw=False):
        n = int(self.headers.get("Content-Length") or 0); need(n <= MAX_UPLOAD, 413, "Tệp quá lớn")
        b = self.rfile.read(n)
        if raw: return b
        try: d = json.loads(b or b"{}")
        except ValueError: raise Err(400, "Dữ liệu không hợp lệ")
        need(isinstance(d, dict), 400, "Dữ liệu không hợp lệ"); return d
    def auth(self, c):
        m = re.search(r"sid=([0-9a-f]{64})", self.headers.get("Cookie", ""))
        return c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.uid WHERE s.token=? AND s.exp>? AND u.active=1", (m[1], time.time())).fetchone() if m else None
    def do_GET(self): self.go("GET")
    def do_POST(self): self.go("POST")
    def go(self, m):
        p = urlparse(self.path); self.q = {k: v[0] for k, v in parse_qs(p.query).items()}; self.out = []
        if m == "GET" and p.path == "/": return self.raw(200, PAGE.encode(), "text/html; charset=utf-8")
        c = self.c = db()
        try:
            need(m == "GET" or self.headers.get("X-Req") == "1", 403, "Yêu cầu không hợp lệ")   # chống CSRF
            self.user = self.auth(c)
            for rm, rx, fn, perm in ROUTES:
                mt = rx.fullmatch(p.path)
                if rm == m and mt: break
            else: raise Err(404, "Không tìm thấy")
            need(perm is None or self.user, 401, "Cần đăng nhập")
            if perm not in (None, "auth") and perm not in ROLES[self.user["role"]]:
                c.execute("BEGIN IMMEDIATE"); audit(c, self.user, "denied", p.path[:80]); c.execute("COMMIT"); raise Err(403, "Không đủ quyền")
            c.execute("BEGIN IMMEDIATE")   # tuần tự hóa ghi: số đến/đi và chuỗi nhật ký không bị trùng/đứt
            r = fn(self, *[int(x) if x.isdigit() else x for x in mt.groups()])
            if c.in_transaction: c.execute("COMMIT")
            if r is not None: self.js(200, r)
        except Err as e: self.js(e.code, {"error": e.msg})
        except Exception as e: sys.stderr.write(repr(e) + "\n"); self.js(500, {"error": "Lỗi hệ thống"})
        finally:
            if c.in_transaction: c.execute("ROLLBACK")
            c.close()

# ================= Giao diện (một trang) =================
PAGE = r"""<!doctype html><html lang="vi"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Văn thư</title>
<style>
:root{--bg:#eef1f5;--fg:#18212f;--mut:#667085;--card:#fff;--bd:#d9dee7;--ac:#17407a;--red:#c0271c;--amb:#b54708;--yel:#9a6700;--hd:#142a4a}
@media(prefers-color-scheme:dark){:root{--bg:#0e1319;--fg:#e4e8ef;--mut:#93a0b4;--card:#161d27;--bd:#283243;--ac:#7fa8f0;--red:#f97066;--amb:#fdb022;--yel:#fde272;--hd:#0a0f15}}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 "Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--fg)}
header{display:flex;gap:14px;align-items:center;padding:10px 18px;background:var(--hd);color:#fff;flex-wrap:wrap}header b{font-size:16px}header .mut{color:#b8c3d6}
header input{flex:1;min-width:200px;max-width:520px}nav{display:flex;gap:2px;padding:0 14px;background:var(--card);border-bottom:1px solid var(--bd);overflow-x:auto}
nav a{padding:10px 14px;cursor:pointer;border-bottom:3px solid transparent;white-space:nowrap}nav a.on{border-color:var(--ac);color:var(--ac);font-weight:600}
main{padding:16px 18px;max-width:1200px;margin:auto}h2{margin:0 12px 0 0;font-size:18px}h3,h4{margin:14px 0 6px}.mut{color:var(--mut)}.bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:0 0 12px}
input,select,textarea,button{font:inherit;color:inherit;background:var(--card);border:1px solid var(--bd);border-radius:5px;padding:6px 9px}button{cursor:pointer}button.pri{background:var(--ac);color:#fff;border-color:var(--ac)}
@media(prefers-color-scheme:dark){button.pri{color:#0a0f15}}textarea{width:100%}label{display:block;margin:6px 0;color:var(--mut)}label input,label select{display:block;width:100%;color:var(--fg)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--bd)}th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--bd);vertical-align:top}th{color:var(--mut);font-weight:600}tr[onclick]{cursor:pointer}tr[onclick]:hover{background:var(--bg)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-bottom:6px}.card{background:var(--card);border:1px solid var(--bd);border-radius:6px;padding:10px 14px}.card b{display:block;font-size:26px}.card.od b{color:var(--red)}
.row{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:9px 12px;margin:0 0 5px;background:var(--card);border:1px solid var(--bd);border-left:5px solid var(--bd);border-radius:4px;cursor:pointer}
.row.od{border-left-color:var(--red)}.row.d1{border-left-color:var(--amb)}.row.d3{border-left-color:var(--yel)}.row.d7{border-left-color:var(--ac)}.row.od b,.od{color:var(--red)}.row.d1 b{color:var(--amb)}
.lv{padding:1px 7px;border-radius:9px;font-size:12px;color:#fff;background:#b54708}.lv.l2{background:#b42318}.lv.l3{background:#7a0c12}
dialog{width:min(720px,94vw);max-height:90vh;overflow:auto;background:var(--card);color:var(--fg);border:1px solid var(--bd);border-radius:8px}dialog::backdrop{background:#0008}
dl{display:grid;grid-template-columns:130px 1fr;gap:3px 12px;margin:0}dt{color:var(--mut)}dd{margin:0}.grid{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}
.login{max-width:320px;margin:14vh auto;display:flex;flex-direction:column;gap:10px}
</style><div id=app></div>
<script>
const E=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const $=s=>document.querySelector(s),vd=s=>s?s.split('-').reverse().join('/'):'';
const ST={den:['Mới','Đang xử lý','Chờ phối hợp','Đã xử lý','Lưu trữ'],di:['Dự thảo','Chờ duyệt','Đã ký','Đã phát hành','Lưu trữ']},URG=['Thường','Khẩn','Thượng khẩn','Hỏa tốc'];
const NAV=[['dash','Tổng quan'],['den','Văn bản đến'],['di','Văn bản đi'],['dos','Hồ sơ'],['audit','Nhật ký','audit'],['users','Người dùng','users']];
let me,people=[],dos=[],cur,cx;
async function api(p,m='GET',b){
 const f=b instanceof Blob,r=await fetch('/api/'+p,{method:m,headers:{'X-Req':'1',...(b&&!f?{'Content-Type':'application/json'}:{}),...(f?{'X-Filename':encodeURIComponent(b.name)}:{})},body:b?(f?b:JSON.stringify(b)):undefined});
 const j=await r.json().catch(()=>({}));if(r.status==401&&p!='login'){me=null;loginView();throw Error('Hết phiên đăng nhập')}
 if(!r.ok)throw Error(j.error||r.status);return j}
const T=f=>async(...a)=>{try{await f(...a)}catch(e){alert(e.message)}};
const R=()=>go(cur,cx);
function loginView(){$('#app').innerHTML=`<form class=login onsubmit="return false"><h2>Văn thư</h2><input id=u placeholder="Tên đăng nhập" autocomplete=username><input id=p type=password placeholder="Mật khẩu" autocomplete=current-password><button class=pri id=lb>Đăng nhập</button><p id=le class=od></p></form>`;
 const f=async()=>{try{await api('login','POST',{u:$('#u').value,p:$('#p').value});boot()}catch(e){$('#le').textContent=e.message}};$('#lb').onclick=f;$('#p').onkeydown=e=>e.key=='Enter'&&f()}
async function boot(){try{me=await api('me')}catch{return loginView()}
 [people,dos]=await Promise.all([api('people'),api('dossiers')]);
 $('#app').innerHTML=`<header><b>Văn thư</b><input id=q placeholder="Tìm số, trích yếu, nội dung… (không cần gõ dấu)"><span class=mut>${E(me.name)} · ${E(me.levels[me.level])}</span><button onclick="out()">Thoát</button></header><nav>${NAV.filter(n=>!n[2]||me.perms.includes(n[2])).map(n=>`<a id=n_${n[0]} onclick="go('${n[0]}')">${n[1]}</a>`).join('')}</nav><main id=m></main><dialog id=dg></dialog>`;
 $('#q').onkeydown=e=>e.key=='Enter'&&$('#q').value.trim()&&go('s',$('#q').value);go('dash');setInterval(()=>cur=='dash'&&!$('#dg').open&&go('dash'),60000)}
const out=T(async()=>{await api('logout','POST',{});loginView()});
const go=T(async(t,x)=>{cur=t;cx=x;document.querySelectorAll('nav a').forEach(a=>a.classList.toggle('on',a.id=='n_'+(t=='s'?'':t)));
 await({dash,den:()=>lst('den'),di:()=>lst('di'),s:()=>lst('',x),dos:dview,audit:aview,users:uview}[t])()});
const cls=x=>x<0?'od':x<=1?'d1':x<=3?'d3':x<=7?'d7':'';
async function dash(){const d=await api('dash'),n=(k,s)=>d.stats.filter(r=>r.kind==k&&r.status==s).reduce((a,r)=>a+r.n,0);
 $('#m').innerHTML=`<div class=cards><div class=card><b>${n('den','Mới')}</b>Văn bản đến mới</div><div class=card><b>${n('den','Đang xử lý')}</b>Đến đang xử lý</div><div class=card><b>${n('di','Chờ duyệt')}</b>Đi chờ duyệt</div><div class="card od"><b>${d.tasks.filter(t=>t.days<0).length}</b>Việc quá hạn</div></div>
 <h3>Việc cần làm</h3>${d.tasks.map(t=>`<div class="row ${cls(t.days)}" onclick="view(${t.doc_id})"><span>${E(t.title)}<small class=mut> — ${E(t.so_kh||t.trichyeu)} · ${E(t.an||'')}</small></span><b>${t.days<0?'Quá hạn '+(-t.days)+' ngày':t.days==0?'Hôm nay':'Còn '+t.days+' ngày'} · ${vd(t.due)}</b></div>`).join('')||'<p class=mut>Không có việc đang chờ.</p>'}`}
const rows=r=>r.length?`<table><tr><th>Số<th>Số/ký hiệu<th>Ngày VB<th>Trích yếu<th>Cơ quan<th>Hạn<th>Trạng thái</tr>${r.map(d=>`<tr onclick="view(${d.id})"><td>${d.kind=='den'?'Đến':'Đi'} ${d.reg_no}/${d.reg_year}<td>${E(d.so_kh)}<td>${vd(d.ngay_vb)}<td>${d.level?`<span class="lv l${d.level}">${E(me.levels[d.level])}</span> `:''}${d.urgency!='Thường'?`<b class=od>${E(d.urgency)}</b> `:''}${E(d.trichyeu)}<td>${E(d.coquan)}<td>${vd(d.due)}<td>${E(d.status)}</tr>`).join('')}</table>`:'<p class=mut>Không có văn bản.</p>';
function lst(kind,q=''){const w=me.perms.includes('write')&&kind;
 $('#m').innerHTML=`<div class=bar><h2>${kind=='den'?'Văn bản đến':kind=='di'?'Văn bản đi':'Kết quả tìm kiếm'}</h2><select id=fs onchange=ld()><option value=''>Mọi trạng thái${[...new Set([...ST.den,...ST.di])].map(s=>`<option>${s}`).join('')}</select> Từ <input type=date id=ff onchange=ld()> đến <input type=date id=ft onchange=ld()>${w?`<button class=pri onclick="form('${kind}')">+ Đăng ký mới</button>`:''}</div><div id=res></div>`;
 window.ld=T(async()=>{$('#res').innerHTML=rows(await api('docs?'+new URLSearchParams({kind,q,status:$('#fs').value,from:$('#ff').value,to:$('#ft').value})))});ld()}
const view=T(async id=>{const d=await api('docs/'+id),w=me.perms.includes('write'),asg=me.perms.includes('assign'),ro=d.status=='Lưu trữ',f=(l,v)=>`<dt>${l}<dd>${E(v)||'—'}`;
 $('#dg').innerHTML=`<h3>${d.kind=='den'?'Văn bản đến':'Văn bản đi'} số ${d.reg_no}/${d.reg_year}</h3><p><b>${E(d.trichyeu)}</b></p><dl>${f('Số/ký hiệu',d.so_kh)}${f('Ngày văn bản',vd(d.ngay_vb))}${f('Ngày đến',vd(d.ngay_den))}${f(d.kind=='den'?'Cơ quan gửi':'Nơi nhận',d.coquan)}${f('Người ký',d.nguoiky)}${f('Mức độ mật',me.levels[d.level])}${f('Độ khẩn',d.urgency)}${f('Hồ sơ',d.dossier)}</dl>
 <p>Trạng thái: ${w?`<select onchange="setSt(${id},this.value)">${ST[d.kind].map(s=>`<option${s==d.status?' selected':''}>${s}`).join('')}</select> <button onclick="delDoc(${id})">Xóa</button>`:E(d.status)}</p>
 <h4>Tệp đính kèm</h4>${d.files.map(x=>`<div class=row style="cursor:default"><a href="/api/files/${x.id}">${E(x.name)}</a><small class=mut>v${x.ver} · ${(x.size/1024).toFixed(0)} KB · ${x.at.slice(0,10)}</small></div>`).join('')||'<p class=mut>Chưa có tệp.</p>'}
 ${w&&!ro?`<div class=bar><input type=file id=uf><button onclick="up(${id})">Tải lên</button></div>`:''}
 <h4>Nhiệm vụ</h4>${d.tasks.map(t=>`<div class="row ${t.done?'':cls((new Date(t.due)-new Date(new Date().toDateString()))/864e5)}" style="cursor:default"><span>${t.done?'✓ ':''}${E(t.title)}<small class=mut> — ${E(t.an||'')} · hạn ${vd(t.due)}</small></span>${!t.done&&(t.assignee==me.id||asg)?`<button onclick="done(${t.id},${id})">Hoàn thành</button>`:''}</div>`).join('')||'<p class=mut>Chưa có nhiệm vụ.</p>'}
 ${asg&&!ro?`<div class=bar><input id=tt placeholder="Nội dung việc"><select id=ta>${people.map(p=>`<option value=${p.id}>${E(p.name)}`).join('')}</select><input type=date id=td><button onclick="addT(${id})">Giao việc</button></div>`:''}
 <div class=bar><button onclick="$('#dg').close()">Đóng</button></div>`;if(!$('#dg').open)$('#dg').showModal()});
const setSt=T(async(id,s)=>{await api('docs/'+id,'POST',{status:s});view(id);R()});
const delDoc=T(async id=>{if(confirm('Xóa văn bản này? (xóa mềm, có ghi nhật ký)')){await api(`docs/${id}/delete`,'POST',{});$('#dg').close();R()}});
const up=T(async id=>{const f=$('#uf').files[0];if(!f)return;const r=await api(`docs/${id}/file`,'POST',f);if(r.dup.length)alert('Cảnh báo: tệp trùng với văn bản có mã nội bộ '+r.dup.join(', '));view(id);R()});
const addT=T(async id=>{await api(`docs/${id}/tasks`,'POST',{title:$('#tt').value,assignee:+$('#ta').value,due:$('#td').value});view(id);R()});
const done=T(async(t,id)=>{await api(`tasks/${t}/done`,'POST',{});view(id);R()});
const form=kind=>{const L=(l,i,t='text')=>`<label>${l}<input id=${i} type=${t}></label>`;
 $('#dg').innerHTML=`<h3>${kind=='den'?'Đăng ký văn bản đến':'Đăng ký văn bản đi'}</h3><div class=grid>${L('Số/ký hiệu','f_so')}${L('Ngày văn bản','f_nv','date')}${kind=='den'?L('Ngày đến','f_nd','date'):''}${L(kind=='den'?'Cơ quan gửi':'Nơi nhận','f_cq')}${L('Người ký','f_nk')}<label>Mức độ mật<select id=f_lv>${me.levels.slice(0,me.level+1).map((l,i)=>`<option value=${i}>${E(l)}`).join('')}</select></label><label>Độ khẩn<select id=f_ur>${URG.map(u=>`<option>${u}`).join('')}</select></label><label>Hồ sơ<select id=f_ds><option value=''>—${dos.map(s=>`<option value=${s.id}>${E(s.code)} ${E(s.title)}`).join('')}</select></label></div><label>Trích yếu<textarea id=f_ty rows=3></textarea></label><label>Tệp đính kèm<input type=file id=f_f></label><div class=bar><button class=pri onclick="save('${kind}')">Lưu</button><button onclick="$('#dg').close()">Hủy</button></div>`;$('#dg').showModal()};
const save=T(async kind=>{const g=i=>$('#'+i)?.value||'';
 const r=await api('docs','POST',{kind,so_kh:g('f_so'),ngay_vb:g('f_nv'),ngay_den:g('f_nd'),coquan:g('f_cq'),nguoiky:g('f_nk'),level:+g('f_lv'),urgency:g('f_ur'),dossier_id:g('f_ds'),trichyeu:g('f_ty')});
 const f=$('#f_f').files[0];let m='';if(f){const u=await api(`docs/${r.id}/file`,'POST',f);if(u.dup.length)m='\nCảnh báo: tệp trùng với văn bản mã nội bộ '+u.dup.join(', ')}
 $('#dg').close();R();if(m)alert('Đã lưu số '+r.reg_no+m)});
async function dview(){dos=await api('dossiers');$('#m').innerHTML=`<div class=bar><h2>Hồ sơ</h2>${me.perms.includes('write')?`<input id=dc placeholder="Mã hồ sơ"><input id=dt placeholder="Tên hồ sơ" size=36><button class=pri onclick="addD()">+ Tạo hồ sơ</button>`:''}</div>${dos.map(s=>`<div class=row onclick="dl(${s.id})"><span><b>${E(s.code)}</b> ${E(s.title)}</span><span class=mut>${s.n} văn bản</span></div>`).join('')||'<p class=mut>Chưa có hồ sơ.</p>'}<div id=res></div>`}
const addD=T(async()=>{await api('dossiers','POST',{code:$('#dc').value,title:$('#dt').value});dview()});
const dl=T(async id=>{$('#res').innerHTML='<h3>Văn bản trong hồ sơ</h3>'+rows(await api('docs?dossier='+id))});
async function aview(){const r=await api('audit');$('#m').innerHTML=`<div class=bar><h2>Nhật ký</h2><button onclick="vfy()">Kiểm tra toàn vẹn chuỗi nhật ký</button><b id=vr></b></div><table><tr><th>Thời gian<th>Người dùng<th>Hành động<th>Đối tượng<th>Chi tiết</tr>${r.map(a=>`<tr><td>${E(a.ts.replace('T',' '))}<td>${E(a.who)}<td>${E(a.act)}<td>${E(a.target)}<td>${E(a.info)}</tr>`).join('')}</table>`}
const vfy=T(async()=>{const r=await api('audit/verify');$('#vr').textContent=r.ok?'✓ Chuỗi nhật ký nguyên vẹn':'✗ Phát hiện sửa đổi tại bản ghi #'+r.bad;$('#vr').className=r.ok?'':'od'});
async function uview(){const u=await api('users');$('#m').innerHTML=`<div class=bar><h2>Người dùng</h2></div><div class=bar><input id=nu placeholder="Tên đăng nhập"><input id=nn placeholder="Họ tên"><select id=nr>${me.roles.map(r=>`<option>${r}`).join('')}</select><select id=nl>${me.levels.map((l,i)=>`<option value=${i}>${E(l)}`).join('')}</select><input id=np type=password placeholder="Mật khẩu (≥10 ký tự)"><button class=pri onclick="addU()">+ Thêm</button></div><table><tr><th>Đăng nhập<th>Họ tên<th>Vai trò<th>Được xem đến mức<th>Trạng thái<th></tr>${u.map(x=>`<tr><td>${E(x.username)}<td>${E(x.name)}<td>${E(x.role)}<td>${E(me.levels[x.level])}<td>${x.active?'Hoạt động':'Đã khóa'}<td>${x.id==me.id?'':`<button onclick="tog(${x.id},${x.active?0:1})">${x.active?'Khóa':'Mở khóa'}</button>`}</tr>`).join('')}</table>`}
const addU=T(async()=>{await api('users','POST',{username:$('#nu').value,name:$('#nn').value,role:$('#nr').value,level:+$('#nl').value,pw:$('#np').value});people=await api('people');uview()});
const tog=T(async(id,a)=>{await api('users/'+id,'POST',{active:a});people=await api('people');uview()});
boot();
</script></html>"""

# ================= CLI =================
def init():
    os.makedirs(FILES, exist_ok=True); c = db(); c.executescript(SCHEMA)
    if not c.execute("SELECT 1 FROM users").fetchone():
        pw = secrets.token_urlsafe(10); c.execute("BEGIN IMMEDIATE"); mkuser(c, "admin", "Quản trị hệ thống", "admin", 0, pw); c.execute("COMMIT")
        print("\n>>> Đã tạo tài khoản admin. Mật khẩu (chỉ hiện một lần): %s\n" % pw)
    return c

def cmd_verify(c):
    bad = 0
    for r in c.execute("SELECT DISTINCT sha FROM files"):
        p = blob(r["sha"])
        if not os.path.exists(p) or hashlib.sha256(open(p, "rb").read()).hexdigest() != r["sha"]: print("HỎNG/MẤT tệp:", r["sha"]); bad += 1
    b = chain_bad(c)
    if b: print("Chuỗi nhật ký bị sửa tại bản ghi #%d" % b)
    print("Tệp lỗi: %d | Nhật ký: %s" % (bad, "nguyên vẹn" if not b else "BỊ SỬA")); return bad or b

def cmd_backup(c, dst):
    os.makedirs(dst, exist_ok=True); d = sqlite3.connect(os.path.join(dst, "vanthu-%s.db" % now().strftime("%Y%m%d-%H%M")))
    c.backup(d); d.close(); shutil.copytree(FILES, os.path.join(dst, "files"), dirs_exist_ok=True)
    print("Đã sao lưu vào", dst, "– hãy đặt thư mục này trên ổ đĩa đã mã hóa và thử khôi phục định kỳ.")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--verify", action="store_true"); ap.add_argument("--backup"); ap.add_argument("--reset")
    a = ap.parse_args(); c = init()
    if a.verify: sys.exit(1 if cmd_verify(c) else 0)
    if a.backup: sys.exit(cmd_backup(c, a.backup))
    if a.reset:
        pw, salt = secrets.token_urlsafe(10), secrets.token_hex(16); c.execute("BEGIN IMMEDIATE")
        n = c.execute("UPDATE users SET salt=?,pw=?,fails=0,locked_until=0 WHERE username=?", (salt, hpw(pw, salt), a.reset.lower())).rowcount
        if n: audit(c, None, "pw_reset_cli", "user:" + a.reset)
        c.execute("COMMIT"); sys.exit("Mật khẩu mới: %s" % pw if n else "Không có người dùng này"); 
    c.close(); print("Văn thư chạy tại http://%s:%d  (Ctrl+C để dừng)" % (a.host, a.port))
    ThreadingHTTPServer((a.host, a.port), H).serve_forever()
