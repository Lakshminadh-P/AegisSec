"""
⚠️  INTENTIONALLY VULNERABLE APPLICATION ⚠️

This application is designed for LOCAL EDUCATIONAL SECURITY TESTING ONLY.
Do NOT deploy this to any public server.
Do NOT use this to attack real systems.

Purpose: Demonstrate OWASP Top 10 vulnerabilities for DAST testing with OWASP ZAP.

Vulnerabilities included:
1. SQL Injection (A03:2021)
2. Cross-Site Scripting / XSS (A03:2021)
3. Missing Security Headers (A05:2021)
4. Weak Authentication (A07:2021)
5. Insecure Direct Object Reference / IDOR (A01:2021)

All vulnerabilities are clearly labeled and documented.
"""
import sqlite3
import os
from flask import Flask, request, render_template_string, redirect, session

app = Flask(__name__)
app.secret_key = 'intentionally-weak-secret-for-demo-only'

# Initialize demo database
def init_db():
    conn = sqlite3.connect('vuln_lab.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            title TEXT,
            content TEXT
        )
    ''')
    # Insert demo data
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users VALUES (1, 'admin', 'password123', 'admin@example.com', 'admin')")
        cursor.execute("INSERT INTO users VALUES (2, 'user1', 'pass123', 'user1@example.com', 'user')")
        cursor.execute("INSERT INTO notes VALUES (1, 1, 'Admin Secret', 'This is confidential admin data')")
        cursor.execute("INSERT INTO notes VALUES (2, 2, 'User Note', 'Regular user note')")
    conn.commit()
    conn.close()


HOME_HTML = '''
<!DOCTYPE html>
<html>
<head><title>⚠️ Vulnerable Lab</title>
<style>
    body { font-family: sans-serif; max-width: 800px; margin: 50px auto; background: #1a1a2e; color: #eee; }
    .warning { background: #ff4757; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
    a { color: #00d4ff; }
    .vuln-list { list-style: none; padding: 0; }
    .vuln-list li { background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #ff4757; }
    input, button { padding: 10px; margin: 5px; border-radius: 4px; border: 1px solid #333; background: #16213e; color: #eee; }
    button { background: #00d4ff; color: #000; cursor: pointer; border: none; font-weight: bold; }
</style>
</head>
<body>
<div class="warning">
    <h2>⚠️ INTENTIONALLY VULNERABLE APPLICATION</h2>
    <p>This application is for LOCAL SECURITY TESTING ONLY. Do NOT deploy publicly.</p>
</div>
<h1>🔓 Vulnerable Lab — OWASP Top 10 Demo</h1>
<ul class="vuln-list">
    <li><strong>1. SQL Injection</strong> — <a href="/search">User Search</a></li>
    <li><strong>2. XSS (Cross-Site Scripting)</strong> — <a href="/greet">Greeting Page</a></li>
    <li><strong>3. Missing Security Headers</strong> — Check response headers</li>
    <li><strong>4. Weak Authentication</strong> — <a href="/login">Login</a></li>
    <li><strong>5. IDOR</strong> — <a href="/note/1">Access Notes by ID</a></li>
</ul>
</body>
</html>
'''


@app.route('/')
def home():
    # VULNERABILITY: Missing security headers (A05:2021)
    # Missing: X-Content-Type-Options, X-Frame-Options, CSP, etc.
    return HOME_HTML


@app.route('/search')
def search():
    """VULNERABILITY: SQL Injection (A03:2021)
    
    The query parameter is directly interpolated into SQL.
    An attacker can inject SQL: ?q=' OR '1'='1
    """
    query = request.args.get('q', '')
    results = []
    if query:
        conn = sqlite3.connect('vuln_lab.db')
        cursor = conn.cursor()
        # VULNERABLE: Direct string interpolation in SQL
        sql = f"SELECT username, email FROM users WHERE username LIKE '%{query}%'"
        try:
            cursor.execute(sql)
            results = cursor.fetchall()
        except:
            results = [('Error', 'Invalid query')]
        conn.close()
    
    results_html = ''.join(f'<tr><td>{r[0]}</td><td>{r[1]}</td></tr>' for r in results)
    return f'''
    <html><head><title>Search</title>
    <style>body {{ font-family: sans-serif; max-width: 600px; margin: 50px auto; background: #1a1a2e; color: #eee; }}
    input, button {{ padding: 10px; margin: 5px; border-radius: 4px; border: 1px solid #333; background: #16213e; color: #eee; }}
    button {{ background: #00d4ff; color: #000; cursor: pointer; border: none; }}
    table {{ width: 100%; border-collapse: collapse; }} th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #333; }}
    .vuln {{ color: #ff4757; font-size: 12px; }}</style></head>
    <body>
    <h2>🔍 User Search</h2>
    <p class="vuln">⚠️ VULNERABLE TO SQL INJECTION — Try: \' OR \'1\'=\'1</p>
    <form><input name="q" value="{query}" placeholder="Search users..."><button>Search</button></form>
    <table><tr><th>Username</th><th>Email</th></tr>{results_html}</table>
    <a href="/" style="color: #00d4ff;">← Home</a>
    </body></html>
    '''


@app.route('/greet')
def greet():
    """VULNERABILITY: Cross-Site Scripting / XSS (A03:2021)
    
    The name parameter is reflected without sanitization.
    An attacker can inject: ?name=<script>alert('XSS')</script>
    """
    name = request.args.get('name', 'Guest')
    # VULNERABLE: User input reflected without escaping
    return f'''
    <html><head><title>Greeting</title>
    <style>body {{ font-family: sans-serif; max-width: 600px; margin: 50px auto; background: #1a1a2e; color: #eee; }}
    input, button {{ padding: 10px; margin: 5px; border-radius: 4px; border: 1px solid #333; background: #16213e; color: #eee; }}
    button {{ background: #00d4ff; color: #000; cursor: pointer; border: none; }}
    .vuln {{ color: #ff4757; font-size: 12px; }}</style></head>
    <body>
    <h2>👋 Greeting Page</h2>
    <p class="vuln">⚠️ VULNERABLE TO XSS — Try: ?name=&lt;script&gt;alert(\'XSS\')&lt;/script&gt;</p>
    <form><input name="name" value="" placeholder="Your name..."><button>Greet</button></form>
    <h3>Hello, {name}!</h3>
    <a href="/" style="color: #00d4ff;">← Home</a>
    </body></html>
    '''


@app.route('/login', methods=['GET', 'POST'])
def vuln_login():
    """VULNERABILITY: Weak Authentication (A07:2021)
    
    - Passwords stored in plaintext
    - No rate limiting
    - No account lockout
    - Weak session management
    """
    error = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        conn = sqlite3.connect('vuln_lab.db')
        cursor = conn.cursor()
        # VULNERABLE: Plaintext password comparison
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = cursor.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect('/note/1')
        error = 'Invalid credentials'
    
    return f'''
    <html><head><title>Login</title>
    <style>body {{ font-family: sans-serif; max-width: 400px; margin: 50px auto; background: #1a1a2e; color: #eee; }}
    input, button {{ padding: 10px; margin: 5px; display: block; width: 100%; border-radius: 4px; border: 1px solid #333; background: #16213e; color: #eee; box-sizing: border-box; }}
    button {{ background: #00d4ff; color: #000; cursor: pointer; border: none; }}
    .error {{ color: #ff4757; }}
    .vuln {{ color: #ff4757; font-size: 12px; }}</style></head>
    <body>
    <h2>🔐 Login</h2>
    <p class="vuln">⚠️ WEAK AUTH — Plaintext passwords, no rate limiting</p>
    <p class="error">{error}</p>
    <form method="POST">
        <input name="username" placeholder="Username">
        <input name="password" type="password" placeholder="Password">
        <button>Login</button>
    </form>
    <p>Demo: admin / password123</p>
    <a href="/" style="color: #00d4ff;">← Home</a>
    </body></html>
    '''


@app.route('/note/<int:note_id>')
def view_note(note_id):
    """VULNERABILITY: Insecure Direct Object Reference / IDOR (A01:2021)
    
    Any user can access any note by changing the ID in the URL.
    No authorization check is performed.
    """
    conn = sqlite3.connect('vuln_lab.db')
    cursor = conn.cursor()
    # VULNERABLE: No authorization check — any user can view any note
    cursor.execute("SELECT * FROM notes WHERE id=?", (note_id,))
    note = cursor.fetchone()
    conn.close()
    
    if note:
        return f'''
        <html><head><title>Note</title>
        <style>body {{ font-family: sans-serif; max-width: 600px; margin: 50px auto; background: #1a1a2e; color: #eee; }}
        .note {{ background: #16213e; padding: 20px; border-radius: 8px; }}
        .vuln {{ color: #ff4757; font-size: 12px; }}</style></head>
        <body>
        <h2>📝 Note #{note[0]}</h2>
        <p class="vuln">⚠️ IDOR VULNERABILITY — Try changing the ID in the URL</p>
        <div class="note">
            <h3>{note[2]}</h3>
            <p>{note[3]}</p>
            <p><small>Owner: User #{note[1]}</small></p>
        </div>
        <p>Try: <a href="/note/1" style="color:#00d4ff">/note/1</a> | <a href="/note/2" style="color:#00d4ff">/note/2</a></p>
        <a href="/" style="color: #00d4ff;">← Home</a>
        </body></html>
        '''
    return 'Note not found', 404


if __name__ == '__main__':
    init_db()
    print("⚠️  VULNERABLE LAB — FOR LOCAL EDUCATIONAL USE ONLY")
    app.run(host='0.0.0.0', port=8080, debug=True)
