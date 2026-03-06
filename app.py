"""
ZeroShell - Pasteview Clone
Flask + SQLite
"""
import os, hashlib, secrets
from datetime import datetime, timedelta
from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

import sqlite3

DB = "zeroshell.db"

def get_db():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            bio TEXT DEFAULT '',
            telegram TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_views INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS pastes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            syntax TEXT DEFAULT 'text',
            visibility TEXT DEFAULT 'public',
            views INTEGER DEFAULT 0,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)
    db.commit()
    db.close()

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def random_slug(n=8):
    return secrets.token_urlsafe(n)[:n]

def get_badge(views, pastes_30d):
    if views >= 10000: return ('Legendary', '👑', '#ffd700')
    if views >= 5000:  return ('Famous',    '⚡', '#ff6b00')
    if views >= 1000:  return ('Popular',   '🔥', '#ff2d55')
    if pastes_30d >= 5: return ('Active',   '🏃', '#00f5ff')
    return ('Newcomer', '⭐', '#8899aa')

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STYLE = """
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#04080f;--card:#0b1623;--border:#0f2a40;--cyan:#00f5ff;--green:#00ff88;
--red:#ff2d55;--yellow:#ffd60a;--orange:#ff6b00;--blue:#2979ff;--purple:#bf5af2;
--text:#c8e0f0;--dim:#4a6a80;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;min-height:100vh;}
body::before{content:'';position:fixed;inset:0;
background-image:linear-gradient(rgba(0,245,255,.025) 1px,transparent 1px),
linear-gradient(90deg,rgba(0,245,255,.025) 1px,transparent 1px);
background-size:40px 40px;pointer-events:none;z-index:0;}
.wrap{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:20px;}
/* NAV */
nav{display:flex;align-items:center;justify-content:space-between;
padding:14px 24px;background:rgba(11,22,35,.9);
border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;
backdrop-filter:blur(10px);}
.nav-logo{font-family:'Share Tech Mono',monospace;font-size:22px;color:var(--cyan);
text-decoration:none;text-shadow:0 0 15px rgba(0,245,255,.5);letter-spacing:2px;}
.nav-links{display:flex;gap:16px;align-items:center;}
.nav-links a{color:var(--text);text-decoration:none;font-size:15px;font-weight:600;
padding:6px 14px;border-radius:6px;transition:all .2s;letter-spacing:1px;}
.nav-links a:hover{color:var(--cyan);background:rgba(0,245,255,.08);}
.btn{padding:8px 18px;border-radius:6px;border:none;cursor:pointer;
font-family:'Rajdhani',sans-serif;font-size:15px;font-weight:700;
letter-spacing:1px;text-decoration:none;display:inline-block;transition:all .2s;}
.btn-cyan{background:linear-gradient(135deg,#00b8cc,#00f5ff);color:#000;}
.btn-cyan:hover{box-shadow:0 0 20px rgba(0,245,255,.4);transform:translateY(-1px);}
.btn-outline{background:transparent;border:1px solid var(--border);color:var(--text);}
.btn-outline:hover{border-color:var(--cyan);color:var(--cyan);}
.btn-red{background:rgba(255,45,85,.15);border:1px solid rgba(255,45,85,.3);color:var(--red);}
/* CARD */
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;
padding:24px;margin-bottom:20px;position:relative;overflow:hidden;}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;
background:linear-gradient(90deg,transparent,var(--cyan),transparent);opacity:.4;}
/* FORM */
input,textarea,select{width:100%;padding:10px 14px;background:rgba(0,0,0,.3);
border:1px solid var(--border);border-radius:8px;color:var(--text);
font-family:'Rajdhani',sans-serif;font-size:15px;transition:all .2s;outline:none;}
input:focus,textarea:focus,select:focus{border-color:var(--cyan);box-shadow:0 0 10px rgba(0,245,255,.15);}
label{display:block;font-size:13px;color:var(--dim);margin-bottom:6px;
text-transform:uppercase;letter-spacing:1px;}
.form-group{margin-bottom:18px;}
/* PASTE CARD */
.paste-item{display:flex;justify-content:space-between;align-items:center;
padding:14px 20px;background:var(--card);border:1px solid var(--border);
border-radius:10px;margin-bottom:10px;transition:all .2s;text-decoration:none;color:var(--text);}
.paste-item:hover{border-color:var(--cyan);background:rgba(0,245,255,.04);transform:translateX(3px);}
.paste-title{font-size:16px;font-weight:700;color:var(--cyan);margin-bottom:3px;}
.paste-meta{font-size:12px;color:var(--dim);font-family:'Share Tech Mono',monospace;}
.paste-views{font-family:'Share Tech Mono',monospace;color:var(--green);font-size:13px;}
/* BADGE */
.badge{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;
border-radius:99px;font-size:12px;font-weight:700;letter-spacing:1px;}
/* SYNTAX */
.code-block{background:#020810;border:1px solid var(--border);border-radius:8px;
padding:20px;overflow-x:auto;font-family:'Share Tech Mono',monospace;
font-size:14px;line-height:1.7;white-space:pre-wrap;word-break:break-all;
color:#a8d0e0;max-height:600px;overflow-y:auto;}
/* PROFILE */
.profile-header{display:flex;align-items:center;gap:24px;margin-bottom:30px;}
.avatar{width:80px;height:80px;border-radius:50%;background:linear-gradient(135deg,var(--cyan),var(--blue));
display:flex;align-items:center;justify-content:center;font-size:32px;
font-weight:700;color:#000;border:3px solid var(--cyan);
box-shadow:0 0 20px rgba(0,245,255,.3);}
.stats-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:24px;}
.stat-box{background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:8px;
padding:14px;text-align:center;}
.stat-num{font-family:'Share Tech Mono',monospace;font-size:26px;font-weight:700;display:block;}
.stat-lbl{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;}
/* GRID */
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:20px;}
@media(max-width:600px){.grid-2{grid-template-columns:1fr;}.profile-header{flex-direction:column;}}
/* ALERT */
.alert{padding:12px 18px;border-radius:8px;margin-bottom:18px;font-size:14px;}
.alert-red{background:rgba(255,45,85,.1);border:1px solid rgba(255,45,85,.3);color:var(--red);}
.alert-green{background:rgba(0,255,136,.1);border:1px solid rgba(0,255,136,.3);color:var(--green);}
/* TAG */
.tag{display:inline-block;padding:2px 10px;border-radius:99px;font-size:11px;
font-weight:700;letter-spacing:1px;margin:2px;}
.scanlines{position:fixed;inset:0;pointer-events:none;z-index:999;
background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.06) 2px,rgba(0,0,0,.06) 4px);}
footer{text-align:center;padding:30px;color:var(--dim);font-family:'Share Tech Mono',monospace;
font-size:12px;letter-spacing:2px;border-top:1px solid var(--border);margin-top:40px;}
</style>"""

NAV = """
<nav>
  <a class="nav-logo" href="/">⚡ ZeroShell</a>
  <div class="nav-links">
    <a href="/">Home</a>
    <a href="/new">+ New Paste</a>
    {% if session.user %}
      <a href="/profile/{{ session.user }}">👤 {{ session.user }}</a>
      <a href="/logout">Logout</a>
    {% else %}
      <a href="/login">Login</a>
      <a href="/register" class="btn btn-cyan">Register</a>
    {% endif %}
  </div>
</nav>"""

BASE = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}ZeroShell{% endblock %}</title>""" + STYLE + """
</head>
<body>
<div class="scanlines"></div>""" + NAV + """
<div class="wrap">
{% with msgs = get_flashed_messages(with_categories=true) %}
  {% for cat, msg in msgs %}
    <div class="alert alert-{{ cat }}">{{ msg }}</div>
  {% endfor %}
{% endwith %}
{% block content %}{% endblock %}
</div>
<footer>⚡ ZEROSHELL · PASTE & SHARE · t.me/ZeroShell_Store</footer>
</body></html>"""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HOMEPAGE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HOME_TPL = BASE.replace("{% block title %}ZeroShell{% endblock %}", "ZeroShell - Home").replace(
"{% block content %}{% endblock %}", """
<!-- HERO -->
<div style="text-align:center;padding:50px 20px 30px;">
  <div style="font-family:'Share Tech Mono',monospace;font-size:clamp(28px,6vw,52px);
              color:var(--cyan);text-shadow:0 0 30px rgba(0,245,255,.5);
              letter-spacing:4px;margin-bottom:12px;">⚡ ZEROSHELL</div>
  <div style="color:var(--dim);font-size:15px;letter-spacing:3px;margin-bottom:30px;">
    PASTE · SHARE · TRACK
  </div>
  <a href="/new" class="btn btn-cyan" style="font-size:17px;padding:12px 36px;letter-spacing:2px;">
    + Create New Paste
  </a>
</div>

<!-- STATS BAR -->
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:30px;">
  <div class="stat-box"><span class="stat-num" style="color:var(--cyan);">{{ total_pastes }}</span><span class="stat-lbl">Total Pastes</span></div>
  <div class="stat-box"><span class="stat-num" style="color:var(--green);">{{ total_views }}</span><span class="stat-lbl">Total Views</span></div>
  <div class="stat-box"><span class="stat-num" style="color:var(--yellow);">{{ total_users }}</span><span class="stat-lbl">Users</span></div>
</div>

<!-- RECENT PASTES -->
<div class="card">
  <div style="font-size:17px;font-weight:700;color:var(--cyan);letter-spacing:2px;margin-bottom:18px;">
    🕐 RECENT PASTES
  </div>
  {% for p in pastes %}
  <a href="/paste/{{ p.slug }}" class="paste-item">
    <div>
      <div class="paste-title">{{ p.title }}</div>
      <div class="paste-meta">
        by {{ p.username or 'Anonymous' }} · {{ p.created_at[:10] }} · {{ p.syntax }}
      </div>
    </div>
    <div class="paste-views">👁 {{ p.views }}</div>
  </a>
  {% else %}
  <div style="text-align:center;color:var(--dim);padding:30px;">No pastes yet. Be the first!</div>
  {% endfor %}
</div>
""")

@app.route('/')
def home():
    from flask import get_flashed_messages, render_template_string
    db = get_db()
    pastes = db.execute("""
        SELECT p.*, u.username FROM pastes p
        LEFT JOIN users u ON p.user_id = u.id
        WHERE p.visibility = 'public'
        ORDER BY p.created_at DESC LIMIT 20
    """).fetchall()
    total_pastes = db.execute("SELECT COUNT(*) FROM pastes").fetchone()[0]
    total_views  = db.execute("SELECT SUM(views) FROM pastes").fetchone()[0] or 0
    total_users  = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    db.close()
    return render_template_string(HOME_TPL, pastes=pastes,
        total_pastes=total_pastes, total_views=total_views, total_users=total_users)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NEW PASTE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NEW_TPL = BASE.replace("{% block title %}ZeroShell{% endblock %}", "New Paste - ZeroShell").replace(
"{% block content %}{% endblock %}", """
<div style="max-width:800px;margin:0 auto;">
<div class="card">
  <div style="font-size:18px;font-weight:700;color:var(--cyan);letter-spacing:2px;margin-bottom:24px;">
    📝 CREATE NEW PASTE
  </div>
  <form method="POST">
    <div class="form-group">
      <label>Title</label>
      <input name="title" placeholder="Enter paste title..." required>
    </div>
    <div class="form-group">
      <label>Content</label>
      <textarea name="content" rows="14" placeholder="Paste your content here..." required
        style="font-family:'Share Tech Mono',monospace;font-size:13px;resize:vertical;"></textarea>
    </div>
    <div class="grid-2">
      <div class="form-group">
        <label>Syntax</label>
        <select name="syntax">
          <option value="text">Plain Text</option>
          <option value="python">Python</option>
          <option value="javascript">JavaScript</option>
          <option value="html">HTML</option>
          <option value="css">CSS</option>
          <option value="sql">SQL</option>
          <option value="bash">Bash</option>
          <option value="json">JSON</option>
        </select>
      </div>
      <div class="form-group">
        <label>Visibility</label>
        <select name="visibility">
          <option value="public">🌐 Public</option>
          <option value="private">🔒 Private</option>
        </select>
      </div>
    </div>
    <button type="submit" class="btn btn-cyan" style="width:100%;font-size:16px;padding:14px;">
      🚀 Create Paste
    </button>
  </form>
</div>
</div>
""")

@app.route('/new', methods=['GET','POST'])
def new_paste():
    from flask import render_template_string, flash
    if request.method == 'POST':
        title   = request.form.get('title','').strip()
        content = request.form.get('content','').strip()
        syntax  = request.form.get('syntax','text')
        vis     = request.form.get('visibility','public')
        if not title or not content:
            flash('Title and content required!', 'red')
            return render_template_string(NEW_TPL)
        slug = random_slug()
        db = get_db()
        uid = None
        if session.get('user_id'):
            uid = session['user_id']
        db.execute("INSERT INTO pastes (slug,title,content,syntax,visibility,user_id) VALUES (?,?,?,?,?,?)",
                   (slug, title, content, syntax, vis, uid))
        db.commit()
        db.close()
        return redirect(f'/paste/{slug}')
    return render_template_string(NEW_TPL)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# VIEW PASTE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VIEW_TPL = BASE.replace("{% block title %}ZeroShell{% endblock %}", "{{ paste.title }} - ZeroShell").replace(
"{% block content %}{% endblock %}", """
<div style="max-width:900px;margin:0 auto;">
  <!-- HEADER -->
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:14px;">
      <div>
        <div style="font-size:22px;font-weight:700;color:var(--cyan);margin-bottom:8px;">
          {{ paste.title }}
        </div>
        <div style="font-size:13px;color:var(--dim);font-family:'Share Tech Mono',monospace;">
          by <a href="/profile/{{ author }}" style="color:var(--cyan);text-decoration:none;">
            {{ author or 'Anonymous' }}</a> ·
          {{ paste.created_at[:16] }} ·
          <span style="color:var(--green);">{{ paste.syntax }}</span>
        </div>
      </div>
      <div style="display:flex;gap:10px;align-items:center;">
        <span style="font-family:'Share Tech Mono',monospace;color:var(--green);">
          👁 {{ paste.views }} views
        </span>
        <button onclick="copyPaste()" class="btn btn-outline" style="font-size:13px;padding:6px 14px;">
          📋 Copy
        </button>
        {% if session.user_id == paste.user_id %}
        <a href="/delete/{{ paste.slug }}" class="btn btn-red" style="font-size:13px;padding:6px 14px;"
           onclick="return confirm('Delete this paste?')">🗑 Delete</a>
        {% endif %}
      </div>
    </div>
  </div>

  <!-- CONTENT -->
  <div class="card" style="padding:0;">
    <div style="padding:14px 20px;border-bottom:1px solid var(--border);
                display:flex;justify-content:space-between;align-items:center;">
      <span style="font-family:'Share Tech Mono',monospace;font-size:13px;color:var(--dim);">
        {{ paste.syntax.upper() }}
      </span>
      <span style="font-size:12px;color:var(--dim);">
        {{ paste.content|length }} chars
      </span>
    </div>
    <div class="code-block" id="pasteContent">{{ paste.content }}</div>
  </div>
</div>

<script>
function copyPaste(){
  navigator.clipboard.writeText(document.getElementById('pasteContent').innerText);
  alert('✅ Copied!');
}
</script>
""")

@app.route('/paste/<slug>')
def view_paste(slug):
    from flask import render_template_string, abort
    db = get_db()
    paste = db.execute("SELECT * FROM pastes WHERE slug=?", (slug,)).fetchone()
    if not paste:
        abort(404)
    db.execute("UPDATE pastes SET views=views+1 WHERE slug=?", (slug,))
    if paste['user_id']:
        db.execute("UPDATE users SET total_views=total_views+1 WHERE id=?", (paste['user_id'],))
    db.commit()
    author = None
    if paste['user_id']:
        u = db.execute("SELECT username FROM users WHERE id=?", (paste['user_id'],)).fetchone()
        if u: author = u['username']
    db.close()
    return render_template_string(VIEW_TPL, paste=paste, author=author)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROFILE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PROFILE_TPL = BASE.replace("{% block title %}ZeroShell{% endblock %}", "{{ user.username }} - ZeroShell").replace(
"{% block content %}{% endblock %}", """
<div style="max-width:900px;margin:0 auto;">
  <div class="card">
    <div class="profile-header">
      <div class="avatar">{{ user.username[0].upper() }}</div>
      <div>
        <div style="font-size:26px;font-weight:700;color:var(--cyan);margin-bottom:6px;">
          {{ user.username }}
        </div>
        <div style="margin-bottom:8px;">
          <span class="badge" style="background:{{ badge[2] }}22;color:{{ badge[2] }};border:1px solid {{ badge[2] }}44;">
            {{ badge[0] }} {{ badge[1] }}
          </span>
        </div>
        {% if user.bio %}
        <div style="color:var(--dim);font-size:14px;">{{ user.bio }}</div>
        {% endif %}
        {% if user.telegram %}
        <a href="https://t.me/{{ user.telegram }}" target="_blank"
           style="color:#00aaff;font-size:13px;text-decoration:none;">✈️ @{{ user.telegram }}</a>
        {% endif %}
      </div>
    </div>

    <!-- STATS -->
    <div class="stats-row">
      <div class="stat-box">
        <span class="stat-num" style="color:var(--cyan);">{{ paste_count }}</span>
        <span class="stat-lbl">Total Pastes</span>
      </div>
      <div class="stat-box">
        <span class="stat-num" style="color:var(--green);">{{ user.total_views }}</span>
        <span class="stat-lbl">Total Views</span>
      </div>
      <div class="stat-box">
        <span class="stat-num" style="color:var(--yellow);">{{ pastes_30d }}</span>
        <span class="stat-lbl">Pastes (30d)</span>
      </div>
      <div class="stat-box">
        <span class="stat-num" style="color:var(--orange);">{{ user.created_at[:10] }}</span>
        <span class="stat-lbl">Joined</span>
      </div>
    </div>

    <!-- BADGES PROGRESS -->
    <div style="margin-bottom:20px;">
      <div style="font-size:14px;color:var(--dim);letter-spacing:2px;margin-bottom:12px;">BADGES</div>
      <div style="display:flex;flex-wrap:wrap;gap:8px;">
        {% for b in all_badges %}
        <span class="badge" style="background:{{ b[2] }}{{ '22' if b[3] else '08' }};
              color:{{ b[2] if b[3] else '#4a6a80' }};
              border:1px solid {{ b[2] }}{{ '44' if b[3] else '18' }};">
          {{ b[1] }} {{ b[0] }}
        </span>
        {% endfor %}
      </div>
    </div>
  </div>

  <!-- PASTES -->
  <div class="card">
    <div style="font-size:16px;font-weight:700;color:var(--cyan);letter-spacing:2px;margin-bottom:16px;">
      📝 PASTES
    </div>
    {% for p in pastes %}
    <a href="/paste/{{ p.slug }}" class="paste-item">
      <div>
        <div class="paste-title">{{ p.title }}</div>
        <div class="paste-meta">{{ p.created_at[:10] }} · {{ p.syntax }}</div>
      </div>
      <div class="paste-views">👁 {{ p.views }}</div>
    </a>
    {% else %}
    <div style="text-align:center;color:var(--dim);padding:20px;">No pastes yet.</div>
    {% endfor %}
  </div>
</div>
""")

@app.route('/profile/<username>')
def profile(username):
    from flask import render_template_string, abort
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user: abort(404)
    pastes = db.execute("""SELECT * FROM pastes WHERE user_id=? AND visibility='public'
                           ORDER BY created_at DESC""", (user['id'],)).fetchall()
    paste_count = len(pastes)
    cutoff = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    pastes_30d = db.execute(
        "SELECT COUNT(*) FROM pastes WHERE user_id=? AND created_at>=?",
        (user['id'], cutoff)).fetchone()[0]
    db.close()
    badge = get_badge(user['total_views'], pastes_30d)
    all_badges = [
        ('Active',    '🏃', '#00f5ff', pastes_30d >= 5),
        ('Popular',   '🔥', '#ff2d55', user['total_views'] >= 1000),
        ('Famous',    '⚡', '#ff6b00', user['total_views'] >= 5000),
        ('Legendary', '👑', '#ffd700', user['total_views'] >= 10000),
    ]
    return render_template_string(PROFILE_TPL, user=user, pastes=pastes,
        paste_count=paste_count, pastes_30d=pastes_30d,
        badge=badge, all_badges=all_badges)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AUTH
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AUTH_TPL = BASE.replace("{% block title %}ZeroShell{% endblock %}", "{{ page_title }} - ZeroShell").replace(
"{% block content %}{% endblock %}", """
<div style="max-width:420px;margin:40px auto;">
<div class="card">
  <div style="text-align:center;margin-bottom:24px;">
    <div style="font-size:20px;font-weight:700;color:var(--cyan);letter-spacing:2px;">
      {{ page_title.upper() }}
    </div>
  </div>
  <form method="POST">
    <div class="form-group">
      <label>Username</label>
      <input name="username" placeholder="Enter username..." required autocomplete="off">
    </div>
    <div class="form-group">
      <label>Password</label>
      <input name="password" type="password" placeholder="Enter password..." required>
    </div>
    {% if page_title == 'Register' %}
    <div class="form-group">
      <label>Telegram (optional)</label>
      <input name="telegram" placeholder="@username (without @)">
    </div>
    {% endif %}
    <button type="submit" class="btn btn-cyan" style="width:100%;padding:13px;font-size:16px;">
      {{ page_title }}
    </button>
  </form>
  <div style="text-align:center;margin-top:16px;font-size:14px;color:var(--dim);">
    {% if page_title == 'Login' %}
      No account? <a href="/register" style="color:var(--cyan);">Register</a>
    {% else %}
      Have account? <a href="/login" style="color:var(--cyan);">Login</a>
    {% endif %}
  </div>
</div>
</div>
""")

@app.route('/register', methods=['GET','POST'])
def register():
    from flask import render_template_string, flash
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        telegram = request.form.get('telegram','').strip().lstrip('@')
        if not username or not password:
            flash('Fill all fields!', 'red')
            return render_template_string(AUTH_TPL, page_title='Register')
        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            flash('Username already taken!', 'red')
            db.close()
            return render_template_string(AUTH_TPL, page_title='Register')
        db.execute("INSERT INTO users (username, password, telegram) VALUES (?,?,?)",
                   (username, hash_password(password), telegram))
        db.commit()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        db.close()
        session['user'] = username
        session['user_id'] = user['id']
        return redirect(f'/profile/{username}')
    return render_template_string(AUTH_TPL, page_title='Register')

@app.route('/login', methods=['GET','POST'])
def login():
    from flask import render_template_string, flash
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=? AND password=?",
                          (username, hash_password(password))).fetchone()
        db.close()
        if user:
            session['user'] = username
            session['user_id'] = user['id']
            return redirect(f'/profile/{username}')
        flash('Wrong username or password!', 'red')
    return render_template_string(AUTH_TPL, page_title='Login')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/delete/<slug>')
def delete_paste(slug):
    from flask import flash
    if not session.get('user_id'):
        return redirect('/login')
    db = get_db()
    paste = db.execute("SELECT * FROM pastes WHERE slug=?", (slug,)).fetchone()
    if paste and paste['user_id'] == session['user_id']:
        db.execute("DELETE FROM pastes WHERE slug=?", (slug,))
        db.commit()
    db.close()
    return redirect('/')

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    print(f"\n{'='*50}")
    print(f"  ⚡  ZEROSHELL STARTING...")
    print(f"  🌐  http://localhost:{port}")
    print(f"  ✈️   t.me/ZeroShell_Store")
    print(f"{'='*50}\n")
    app.run(host='0.0.0.0', port=port, debug=False)
