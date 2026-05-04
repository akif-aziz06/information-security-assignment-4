"""
Intentionally Vulnerable Web Application (DVWA-Lite)
WARNING: Contains deliberate security flaws for educational purposes only.
DO NOT deploy in production.
"""

import os
import sqlite3
from flask import Flask, request, render_template_string, make_response, session

app = Flask(__name__)
app.secret_key = 'super_secret_key_123'  # VULN: Hardcoded weak secret key
app.config['DEBUG'] = True  # VULN: Debug mode enabled

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vulnerable.db')

# ─── CSS & Layout ───────────────────────────────────────────────────────────
STYLE = """<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#1a1a2e;color:#e0e0e0;min-height:100vh}
.nav{background:#16213e;padding:15px 30px;display:flex;gap:20px;border-bottom:2px solid #0f3460}
.nav a{color:#e94560;text-decoration:none;font-weight:bold}
.nav a:hover{color:#ff6b6b}
.wrap{max-width:800px;margin:40px auto;padding:20px}
.card{background:#16213e;border-radius:10px;padding:25px;margin:20px 0;border:1px solid #0f3460}
h1,h2{color:#e94560;margin-bottom:15px}
input,textarea{width:100%;padding:10px;margin:8px 0;background:#0f3460;border:1px solid #533483;color:#e0e0e0;border-radius:5px}
input[type=submit],button{background:#e94560;color:#fff;border:none;padding:10px 25px;cursor:pointer;border-radius:5px;font-size:16px;width:auto}
input[type=submit]:hover,button:hover{background:#ff6b6b}
.err{color:#ff4444;background:#2d1f1f;padding:10px;border-radius:5px;margin:10px 0}
.ok{color:#44ff44;background:#1f2d1f;padding:10px;border-radius:5px;margin:10px 0}
table{width:100%;border-collapse:collapse;margin:15px 0}
th,td{padding:10px;text-align:left;border-bottom:1px solid #0f3460}
th{background:#0f3460;color:#e94560}
.badge{background:#e94560;color:#fff;padding:3px 8px;border-radius:3px;font-size:12px}
</style>"""

NAV = """<div class="nav">
<a href="/">&#127968; Home</a>
<a href="/login">&#128273; Login</a>
<a href="/search">&#128269; Search</a>
<a href="/comment">&#128172; Comments</a>
<a href="/greet">&#128075; Greet</a>
<a href="/profile">&#128100; Profile</a>
<a href="/file">&#128193; Files</a>
<a href="/admin">&#9881; Admin</a>
</div>"""


def page(title, body):
    """Wrap body content in the base layout. No security headers added (intentional)."""
    html = f"<!DOCTYPE html><html><head><title>{title} - VulnApp</title>{STYLE}</head><body>{NAV}<div class='wrap'>{body}</div></body></html>"
    resp = make_response(html)
    # VULN: No security headers set (X-Frame-Options, CSP, etc.)
    resp.headers['Server'] = 'Flask/2.0.1 Python/3.11'  # VULN: Info disclosure
    resp.headers['X-Powered-By'] = 'Flask'  # VULN: Info disclosure
    return resp


# ─── Database ────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('DROP TABLE IF EXISTS comments')
    c.execute('''CREATE TABLE users
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
         username TEXT UNIQUE, password TEXT, email TEXT, role TEXT DEFAULT 'user')''')
    c.execute('''CREATE TABLE comments
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
         username TEXT, comment TEXT)''')
    c.execute("INSERT INTO users (username,password,email,role) VALUES ('admin','admin123','admin@vuln.com','admin')")
    c.execute("INSERT INTO users (username,password,email,role) VALUES ('user1','password','user1@vuln.com','user')")
    c.execute("INSERT INTO users (username,password,email,role) VALUES ('john','123456','john@vuln.com','user')")
    c.execute("INSERT INTO comments (username,comment) VALUES ('admin','Welcome to VulnApp!')")
    c.execute("INSERT INTO comments (username,comment) VALUES ('user1','This is a test comment.')")
    conn.commit()
    conn.close()


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return page("Home", """
    <h1>&#128274; Vulnerable Web Application</h1>
    <div class="card">
        <h2>About</h2>
        <p>This is an intentionally vulnerable web application for security testing and education.</p>
        <p style="margin-top:10px">Each page demonstrates a different vulnerability:</p>
        <table>
            <tr><th>Page</th><th>Vulnerability</th></tr>
            <tr><td>Login</td><td><span class="badge">SQL Injection</span></td></tr>
            <tr><td>Search</td><td><span class="badge">SQL Injection</span></td></tr>
            <tr><td>Comments</td><td><span class="badge">Stored XSS</span></td></tr>
            <tr><td>Greet</td><td><span class="badge">Reflected XSS</span></td></tr>
            <tr><td>Profile</td><td><span class="badge">CSRF</span></td></tr>
            <tr><td>Files</td><td><span class="badge">Path Traversal</span></td></tr>
            <tr><td>Admin</td><td><span class="badge">Broken Access Control</span></td></tr>
            <tr><td>All Pages</td><td><span class="badge">Missing Security Headers</span></td></tr>
        </table>
    </div>""")


# ── SQL Injection: Login ─────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        conn = get_db()
        # VULN: SQL Injection — string concatenation in query
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            user = conn.execute(query).fetchone()
            if user:
                session['user'] = user['username']
                session['role'] = user['role']
                # VULN: Insecure cookie — no HttpOnly, Secure, SameSite flags
                resp = page("Login", f"<h1>Welcome back, {user['username']}!</h1><div class='ok'>Login successful.</div><p>Role: {user['role']}</p>")
                resp.set_cookie('session_user', user['username'])  # VULN: Insecure cookie
                return resp
            else:
                msg = '<div class="err">Invalid credentials.</div>'
        except Exception as e:
            # VULN: Detailed error message exposed to user
            msg = f'<div class="err">Database error: {e}</div>'
        conn.close()

    return page("Login", f"""
    <h1>&#128273; Login</h1>
    <div class="card">
        <form method="POST">
            <label>Username</label><input type="text" name="username" id="username">
            <label>Password</label><input type="password" name="password" id="password">
            <br><input type="submit" value="Login" id="login-btn">
        </form>
        {msg}
        <p class="badge" style="margin-top:15px">Hint: Try ' OR '1'='1' -- in username</p>
    </div>""")


# ── SQL Injection: Search ────────────────────────────────────────────────────
@app.route('/search', methods=['GET', 'POST'])
def search():
    results = ''
    query_text = ''
    if request.method == 'POST' or request.args.get('q'):
        query_text = request.form.get('q', '') or request.args.get('q', '')
        conn = get_db()
        # VULN: SQL Injection
        sql = f"SELECT username, email, role FROM users WHERE username LIKE '%{query_text}%' OR email LIKE '%{query_text}%'"
        try:
            rows = conn.execute(sql).fetchall()
            if rows:
                results = '<table><tr><th>Username</th><th>Email</th><th>Role</th></tr>'
                for r in rows:
                    results += f"<tr><td>{r['username']}</td><td>{r['email']}</td><td>{r['role']}</td></tr>"
                results += '</table>'
            else:
                results = '<p>No results found.</p>'
        except Exception as e:
            results = f'<div class="err">SQL Error: {e}</div>'
        conn.close()

    return page("Search", f"""
    <h1>&#128269; Search Users</h1>
    <div class="card">
        <form method="POST">
            <label>Search query</label><input type="text" name="q" id="search-q" value="{query_text}">
            <input type="submit" value="Search" id="search-btn">
        </form>
        {results}
        <p class="badge" style="margin-top:15px">Hint: Try ' UNION SELECT username,password,role FROM users --</p>
    </div>""")


# ── Stored XSS: Comments ────────────────────────────────────────────────────
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'POST':
        name = request.form.get('name', 'Anonymous')
        text = request.form.get('comment', '')
        conn = get_db()
        # VULN: Stores raw user input — no sanitization
        conn.execute("INSERT INTO comments (username, comment) VALUES (?, ?)", (name, text))
        conn.commit()
        conn.close()

    conn = get_db()
    comments = conn.execute("SELECT * FROM comments ORDER BY id DESC").fetchall()
    conn.close()
    rows = ''
    for c in comments:
        # VULN: Renders stored comment without escaping — stored XSS
        rows += f"<tr><td><b>{c['username']}</b></td><td>{c['comment']}</td></tr>"

    return page("Comments", f"""
    <h1>&#128172; Comments</h1>
    <div class="card">
        <form method="POST">
            <label>Name</label><input type="text" name="name" id="comment-name">
            <label>Comment</label><textarea name="comment" id="comment-text" rows="3"></textarea>
            <input type="submit" value="Post Comment" id="comment-btn">
        </form>
        <p class="badge" style="margin-top:10px">Hint: Try &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
    </div>
    <div class="card">
        <h2>All Comments</h2>
        <table><tr><th>User</th><th>Comment</th></tr>{rows}</table>
    </div>""")


# ── Reflected XSS: Greet ────────────────────────────────────────────────────
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    greeting = ''
    if name:
        # VULN: Reflects user input without escaping — reflected XSS
        greeting = f'<div class="card"><h2>Hello, {name}!</h2><p>Welcome to VulnApp.</p></div>'

    return page("Greet", f"""
    <h1>&#128075; Greeting Page</h1>
    <div class="card">
        <form method="GET">
            <label>Enter your name</label><input type="text" name="name" id="greet-name" value="">
            <input type="submit" value="Greet Me" id="greet-btn">
        </form>
        <p class="badge" style="margin-top:10px">Hint: Try ?name=&lt;script&gt;alert('XSS')&lt;/script&gt;</p>
    </div>
    {greeting}""")


# ── CSRF: Profile ───────────────────────────────────────────────────────────
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    msg = ''
    if request.method == 'POST':
        # VULN: No CSRF token — form can be submitted from any origin
        email = request.form.get('email', '')
        msg = f'<div class="ok">Profile updated! Email changed to: {email}</div>'

    return page("Profile", f"""
    <h1>&#128100; Update Profile</h1>
    <div class="card">
        <form method="POST" id="profile-form">
            <label>New Email</label><input type="email" name="email" id="profile-email" placeholder="new@example.com">
            <input type="submit" value="Update Profile" id="profile-btn">
        </form>
        {msg}
        <p class="badge" style="margin-top:10px">Note: No CSRF token in this form</p>
    </div>""")


# ── Path Traversal: File Viewer ──────────────────────────────────────────────
@app.route('/file')
def file_view():
    filename = request.args.get('name', '')
    content = ''
    if filename:
        # VULN: No path sanitization — allows directory traversal
        try:
            filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files', filename)
            with open(filepath, 'r') as f:
                content = f'<div class="card"><h2>File: {filename}</h2><pre>{f.read()}</pre></div>'
        except Exception as e:
            # VULN: Detailed error message
            content = f'<div class="err">Error reading file: {e}</div>'

    return page("File Viewer", f"""
    <h1>&#128193; File Viewer</h1>
    <div class="card">
        <form method="GET">
            <label>Filename</label><input type="text" name="name" id="file-name" placeholder="readme.txt">
            <input type="submit" value="View File" id="file-btn">
        </form>
        <p class="badge" style="margin-top:10px">Hint: Try ../vulnerable_app.py</p>
    </div>
    {content}""")


# ── Broken Access Control: Admin ─────────────────────────────────────────────
@app.route('/admin')
def admin():
    # VULN: No authentication check — anyone can access admin panel
    conn = get_db()
    users = conn.execute("SELECT id, username, email, role FROM users").fetchall()
    conn.close()
    rows = ''
    for u in users:
        rows += f"<tr><td>{u['id']}</td><td>{u['username']}</td><td>{u['email']}</td><td>{u['role']}</td></tr>"

    return page("Admin Panel", f"""
    <h1>&#9881; Admin Panel</h1>
    <div class="card">
        <h2>All Users</h2>
        <table><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>{rows}</table>
        <p class="badge" style="margin-top:10px">Note: No authentication required to access this page</p>
    </div>""")


# ── API: User info (info disclosure) ────────────────────────────────────────
@app.route('/api/users')
def api_users():
    conn = get_db()
    # VULN: Exposes all user data including passwords via API
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    data = [dict(u) for u in users]
    from flask import jsonify
    return jsonify(data)


# ─── Main ────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    # Create sample files directory
    files_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files')
    os.makedirs(files_dir, exist_ok=True)
    with open(os.path.join(files_dir, 'readme.txt'), 'w') as f:
        f.write("This is a sample file for the file viewer.\nNothing sensitive here... or is there?")
    with open(os.path.join(files_dir, 'secret.txt'), 'w') as f:
        f.write("DB_PASSWORD=supersecret123\nAPI_KEY=sk-1234567890abcdef\nADMIN_TOKEN=admin-token-xyz")

    init_db()
    print("[*] Vulnerable Web App starting on http://127.0.0.1:5000")
    print("[!] WARNING: This app is intentionally vulnerable. Do NOT expose to the internet.")
    app.run(host='127.0.0.1', port=5000, debug=True)
