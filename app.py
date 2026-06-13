import os, sqlite3, subprocess, base64, hashlib
from flask import Flask, request, render_template, redirect, session, jsonify, send_from_directory, Response

app = Flask(__name__)
app.secret_key = "s3cr3t_k3y_do_not_share"
DB = "/tmp/vulnlab.db"

# ── database bootstrap ────────────────────────────────────────────────────────

def init_db():
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, notes TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY, title TEXT, body TEXT, author TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY, value TEXT
    )""")
    # seed users
    c.executemany("INSERT OR IGNORE INTO users VALUES (?,?,?,?,?)", [
        (1, "admin",   "5f4dcc3b5aa765d61d8327deb882cf99", "admin",  "Main admin account"),
        (2, "jdoe",    "482c811da5d5b4bc6d497ffa98491e38", "user",   "Developer account"),
        (3, "msmith",  "b14a7b8059d9c055954c92674ce60032", "user",   "QA engineer"),
        (4, "deploy",  "d8578edf8458ce06fbc5bb76a58c5ca4", "deploy", "CI/CD service account"),
    ])
    # seed posts
    c.executemany("INSERT OR IGNORE INTO posts VALUES (?,?,?,?)", [
        (1, "Welcome", "Welcome to VulnLab v1.0. This is a demo application.", "admin"),
        (2, "Maintenance", "Scheduled backup running every night at 03:00 UTC. Archives stored in /backup/archives/", "admin"),
        (3, "New feature", "Search is now live. Try it out!", "jdoe"),
    ])
    # seed config
    c.executemany("INSERT OR IGNORE INTO config VALUES (?,?)", [
        ("version",    "1.0.4"),
        ("debug",      "true"),
        ("backup_key", "BackupKey@2024!"),
        ("db_host",    "postgres.internal:5432"),
        ("db_pass",    "Pr0d_DB_P@ssword99"),
    ])
    con.commit(); con.close()

init_db()

# ── helpers ───────────────────────────────────────────────────────────────────

def get_db():
    return sqlite3.connect(DB)

def logged_in():
    return session.get("user")

def is_admin():
    return session.get("role") == "admin"

# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    con = get_db(); posts = con.execute("SELECT * FROM posts ORDER BY id DESC").fetchall(); con.close()
    return render_template("index.html", posts=posts, user=logged_in())

@app.route("/robots.txt")
def robots():
    return Response(
        "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /api/internal\nDisallow: /debug\n",
        mimetype="text/plain"
    )

# intentionally verbose 404
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html",
        code=404, msg=str(e),
        server="Werkzeug/3.0 Python/3.11",
        path=request.path), 404

# ── auth ──────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username","")
        p = request.form.get("password","")
        ph = hashlib.md5(p.encode()).hexdigest()
        # VULN: raw string interpolation → SQLi
        query = f"SELECT * FROM users WHERE username='{u}' AND password='{ph}'"
        try:
            con = get_db()
            row = con.execute(query).fetchone()
            con.close()
            if row:
                session["user"] = row[1]
                session["role"] = row[3]
                session["uid"]  = row[0]
                return redirect("/dashboard")
            error = "Invalid credentials."
        except Exception as ex:
            # VULN: leaks query errors including SQL syntax
            error = f"DB error: {ex} | Query: {query}"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ── dashboard ─────────────────────────────────────────────────────────────────

@app.route("/dashboard")
def dashboard():
    if not logged_in(): return redirect("/login")
    con = get_db()
    users = con.execute("SELECT id,username,role FROM users").fetchall()
    con.close()
    hint = "Nightly backup archive: sys_" + "20240315" + ".bak — ask sysadmin for location."
    return render_template("dashboard.html", user=logged_in(), role=session.get("role"), users=users, hint=hint)

# ── search ────────────────────────────────────────────────────────────────────

@app.route("/search")
def search():
    q = request.args.get("q","")
    results = []
    xss_note = ""
    if q:
        # VULN: SQLi in search
        con = get_db()
        try:
            rows = con.execute(f"SELECT title,body,author FROM posts WHERE title LIKE '%{q}%' OR body LIKE '%{q}%'").fetchall()
            results = rows
        except Exception as ex:
            xss_note = f"Query error: {ex}"
        con.close()
    # VULN: reflected XSS — q rendered unescaped via Markup trick in template
    return render_template("search.html", q=q, results=results, note=xss_note, user=logged_in())

# ── admin ─────────────────────────────────────────────────────────────────────

@app.route("/admin")
def admin_panel():
    # VULN: only checks cookie, no server-side role validation on some sub-paths
    if not logged_in(): return redirect("/login")
    con = get_db()
    cfg = con.execute("SELECT key,value FROM config").fetchall()
    users = con.execute("SELECT * FROM users").fetchall()
    con.close()
    return render_template("admin.html", cfg=cfg, users=users, user=logged_in(), is_admin=is_admin())

# ── file upload ───────────────────────────────────────────────────────────────

UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route("/upload", methods=["GET","POST"])
def upload():
    if not logged_in(): return redirect("/login")
    msg = None
    if request.method == "POST":
        f = request.files.get("file")
        if f:
            # VULN: no extension or content-type validation
            path = os.path.join(UPLOAD_DIR, f.filename)
            f.save(path)
            msg = f"Saved to {path}"
    return render_template("upload.html", msg=msg, user=logged_in())

# ── ping / command injection ──────────────────────────────────────────────────

@app.route("/ping", methods=["GET","POST"])
def ping():
    if not logged_in(): return redirect("/login")
    output = None
    if request.method == "POST":
        host = request.form.get("host","localhost")
        # VULN: unsanitised shell=True
        try:
            output = subprocess.check_output(f"ping -c 2 {host}", shell=True,
                stderr=subprocess.STDOUT, timeout=5).decode()
        except Exception as ex:
            output = str(ex)
    return render_template("ping.html", output=output, user=logged_in())

# ── IDOR ──────────────────────────────────────────────────────────────────────

@app.route("/api/users")
def api_users():
    uid = request.args.get("id","1")
    # VULN: no auth check, direct object reference
    con = get_db()
    row = con.execute(f"SELECT id,username,role,notes FROM users WHERE id={uid}").fetchone()
    con.close()
    if row:
        return jsonify({"id":row[0],"username":row[1],"role":row[2],"notes":row[3]})
    return jsonify({"error":"not found"}), 404

# ── internal API — exposed ────────────────────────────────────────────────────

@app.route("/api/internal/config")
def internal_config():
    # VULN: no auth, exposes prod credentials
    con = get_db()
    cfg = dict(con.execute("SELECT key,value FROM config").fetchall())
    con.close()
    return jsonify(cfg)

# ── debug endpoint ────────────────────────────────────────────────────────────

@app.route("/debug")
def debug():
    # VULN: environment dump, no auth
    env = {k: v for k, v in os.environ.items()}
    return jsonify({"env": env, "cwd": os.getcwd(), "pid": os.getpid()})

# ── backup — the main challenge ───────────────────────────────────────────────

@app.route("/backup/")
@app.route("/backup")
def backup_index():
    # VULN: 403 but leaks server header
    return Response("Access denied.", status=403,
        headers={"Server":"Apache/2.4.54 (Debian)", "X-Powered-By":"PHP/8.1.12"})

@app.route("/backup/.listing")
def backup_listing():
    # VULN: hidden .listing file reveals archive names
    listing = """# Backup Archive Index
# Updated: 2024-03-15 03:42 UTC
# DO NOT EXPOSE PUBLICLY

archives/sys_20231201.bak   [EXPIRED]
archives/sys_20240101.bak   [EXPIRED]
archives/sys_20240215.bak   [EXPIRED]
archives/sys_20240315.bak   [CURRENT]
archives/db_dump_prod.sql.gz [ENCRYPTED]
"""
    return Response(listing, mimetype="text/plain",
        headers={"Content-Disposition":"inline"})

@app.route("/backup/archives/<filename>")
def backup_file(filename):
    # VULN: path traversal possible, and the .bak file is world-readable
    safe_dir = os.path.join(os.path.dirname(__file__), "backup", "archives")
    try:
        return send_from_directory(safe_dir, filename, mimetype="text/plain")
    except Exception:
        return Response("Not found.", status=404)

# ── serve static ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
