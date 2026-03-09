"""ZeroShell v11.4"""
import os,hashlib,secrets,json,re,hmac,struct,time,base64,urllib.request,urllib.parse,smtplib,threading,shutil
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime,timedelta
from flask import Flask,request,redirect,session,flash,get_flashed_messages,Response,jsonify

app=Flask(__name__)
app.secret_key=os.environ.get('SECRET_KEY') or secrets.token_hex(32)
if not os.environ.get('SECRET_KEY'):
  print("[WARN] SECRET_KEY not set! Sessions will reset on restart. Set SECRET_KEY env var in production.")
import sqlite3
DB="zeroshell.db"

# ━━━ DB ━━━
def get_db():
  db=sqlite3.connect(DB,timeout=30,check_same_thread=False)
  db.row_factory=sqlite3.Row
  db.execute("PRAGMA journal_mode=WAL")   # allows concurrent reads + writes
  db.execute("PRAGMA synchronous=NORMAL") # faster writes, still safe
  db.execute("PRAGMA busy_timeout=10000") # wait 10s if locked
  return db

def init_db():
  db=get_db()
  db.executescript("""
  CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,email TEXT DEFAULT '',password TEXT NOT NULL,bio TEXT DEFAULT '',telegram TEXT DEFAULT '',avatar TEXT DEFAULT '👤',theme TEXT DEFAULT 'cyan',is_admin INTEGER DEFAULT 0,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,total_views INTEGER DEFAULT 0,totp_secret TEXT DEFAULT '',totp_enabled INTEGER DEFAULT 0,api_key TEXT DEFAULT '',google_id TEXT DEFAULT '',is_premium INTEGER DEFAULT 0,premium_note TEXT DEFAULT '',is_banned INTEGER DEFAULT 0,email_verified INTEGER DEFAULT 0);
  CREATE TABLE IF NOT EXISTS pastes(id INTEGER PRIMARY KEY AUTOINCREMENT,slug TEXT UNIQUE NOT NULL,title TEXT NOT NULL,content TEXT NOT NULL,syntax TEXT DEFAULT 'text',tags TEXT DEFAULT '',visibility TEXT DEFAULT 'public',password TEXT DEFAULT '',views INTEGER DEFAULT 0,likes INTEGER DEFAULT 0,dislikes INTEGER DEFAULT 0,pinned INTEGER DEFAULT 0,user_id INTEGER,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,expires_at TIMESTAMP DEFAULT NULL,ai_summary TEXT DEFAULT '');
  CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY AUTOINCREMENT,paste_id INTEGER,user_id INTEGER,content TEXT NOT NULL,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,message TEXT NOT NULL,link TEXT DEFAULT '',read INTEGER DEFAULT 0,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS follows(id INTEGER PRIMARY KEY AUTOINCREMENT,follower_id INTEGER,following_id INTEGER,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,UNIQUE(follower_id,following_id));
  CREATE TABLE IF NOT EXISTS paste_likes(id INTEGER PRIMARY KEY AUTOINCREMENT,paste_id INTEGER,user_id INTEGER,vote INTEGER,UNIQUE(paste_id,user_id));
  CREATE TABLE IF NOT EXISTS paste_views(id INTEGER PRIMARY KEY AUTOINCREMENT,paste_id INTEGER,viewer_key TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,UNIQUE(paste_id,viewer_key));
  CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,action TEXT,target_id INTEGER,target_type TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS ads(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,content TEXT NOT NULL,url TEXT DEFAULT '',active INTEGER DEFAULT 1,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS bookmarks(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,paste_id INTEGER,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,UNIQUE(user_id,paste_id));
  CREATE TABLE IF NOT EXISTS revisions(id INTEGER PRIMARY KEY AUTOINCREMENT,paste_id INTEGER,content TEXT,title TEXT,syntax TEXT,editor_id INTEGER,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS email_verifications(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,token TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS rate_limits(id INTEGER PRIMARY KEY AUTOINCREMENT,ip TEXT,action TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS payment_requests(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,plan TEXT,coin TEXT,tx_hash TEXT,amount TEXT,status TEXT DEFAULT 'pending',created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS email_otps(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT NOT NULL,otp TEXT NOT NULL,purpose TEXT DEFAULT 'register',created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS pending_users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL,email TEXT NOT NULL,password TEXT NOT NULL,telegram TEXT DEFAULT '',created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS admin_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,admin_id INTEGER,admin_username TEXT,action TEXT NOT NULL,target TEXT DEFAULT '',ip TEXT DEFAULT '',created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS backups(id INTEGER PRIMARY KEY AUTOINCREMENT,filename TEXT NOT NULL,size INTEGER DEFAULT 0,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT,paste_id INTEGER,reporter_id INTEGER,reason TEXT NOT NULL,status TEXT DEFAULT 'pending',created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS login_attempts(id INTEGER PRIMARY KEY AUTOINCREMENT,ip TEXT NOT NULL,username TEXT DEFAULT '',success INTEGER DEFAULT 0,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS banned_ips(id INTEGER PRIMARY KEY AUTOINCREMENT,ip TEXT UNIQUE NOT NULL,reason TEXT DEFAULT '',banned_by TEXT DEFAULT '',created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  """)
  safe=[("users","avatar","TEXT DEFAULT '👤'"),("users","theme","TEXT DEFAULT 'cyan'"),("users","is_admin","INTEGER DEFAULT 0"),("users","email","TEXT DEFAULT ''"),("users","totp_secret","TEXT DEFAULT ''"),("users","totp_enabled","INTEGER DEFAULT 0"),("users","api_key","TEXT DEFAULT ''"),("pastes","password","TEXT DEFAULT ''"),("pastes","pinned","INTEGER DEFAULT 0"),("pastes","expires_at","TIMESTAMP DEFAULT NULL"),("pastes","tags","TEXT DEFAULT ''"),("pastes","likes","INTEGER DEFAULT 0"),("pastes","dislikes","INTEGER DEFAULT 0"),("pastes","ai_summary","TEXT DEFAULT ''"),("users","is_premium","INTEGER DEFAULT 0"),("users","premium_note","TEXT DEFAULT ''"),("users","email_verified","INTEGER DEFAULT 0"),("users","link1","TEXT DEFAULT ''"),("users","link2","TEXT DEFAULT ''"),("users","link3","TEXT DEFAULT ''"),("users","link4","TEXT DEFAULT ''"),("users","link5","TEXT DEFAULT ''"),("users","avatar_url","TEXT DEFAULT ''"),("users","is_banned","INTEGER DEFAULT 0"),("pastes","file_type","TEXT DEFAULT ''")]
  for t,c,d in safe:
    try: db.execute(f"ALTER TABLE {t} ADD COLUMN {c} {d}")
    except: pass
  db.commit(); db.close()

def cleanup_expired():
  try:
    db=get_db()
    now=datetime.now().isoformat()
    deleted=db.execute("DELETE FROM pastes WHERE expires_at IS NOT NULL AND expires_at < ?",(now,))
    db.commit(); db.close()
    return deleted.rowcount
  except Exception as e:
    print(f'[CLEANUP ERROR] {e}'); return 0

# ━━━ HELPERS ━━━
def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()
def rand_slug(n=8): return secrets.token_urlsafe(n)[:n]
def is_expired(p):
  if not p['expires_at']: return False
  try: return datetime.now()>datetime.fromisoformat(str(p['expires_at']))
  except: return False

def viewer_key(paste_id):
  uid=session.get('user_id')
  if uid:
    raw=f"u:{uid}:p:{paste_id}"
  else:
    ip=get_real_ip()
    ua=request.headers.get('User-Agent','')[:40]
    raw=f"g:{ip}:{ua}:p:{paste_id}"
  return hash_pw(raw)[:24]

def count_unique_view(paste_id,slug=None):
  key=viewer_key(paste_id)
  try:
    db=get_db()
    db.execute("INSERT OR IGNORE INTO paste_views(paste_id,viewer_key) VALUES(?,?)",(paste_id,key))
    changed=db.execute("SELECT changes()").fetchone()[0]
    if changed:
      real=db.execute("SELECT COUNT(*) FROM paste_views WHERE paste_id=?",(paste_id,)).fetchone()[0]
      db.execute("UPDATE pastes SET views=? WHERE id=?",(real,paste_id))
    db.commit(); db.close(); return changed==1
  except: return False

def send_notif(uid,msg,link=''):
  try:
    db=get_db(); db.execute("INSERT INTO notifications(user_id,message,link) VALUES(?,?,?)",(uid,msg,link)); db.commit(); db.close()
  except: pass

def log_activity(uid,action,target_id=0,target_type=''):
  try:
    db=get_db(); db.execute("INSERT INTO activity(user_id,action,target_id,target_type) VALUES(?,?,?,?)",(uid,action,target_id,target_type)); db.commit(); db.close()
  except: pass

def unread_count(uid):
  if not uid: return 0
  try:
    db=get_db(); c=db.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND read=0",(uid,)).fetchone()[0]; db.close(); return c
  except: return 0

# ━━━ CLOUDFLARE: Real IP ━━━
def get_real_ip():
  """Get real visitor IP — works behind Cloudflare proxy."""
  cf_ip=request.headers.get('CF-Connecting-IP','')
  if cf_ip: return cf_ip
  xff=request.headers.get('X-Forwarded-For','')
  if xff: return xff.split(',')[0].strip()
  return request.remote_addr or '0.0.0.0'

# ━━━ PAGINATION HELPER ━━━
def paginate(total, page, per=20):
  """Returns (pages, prev_url_params, next_url_params) helper dict."""
  pages=max(1,(total+per-1)//per)
  page=max(1,min(page,pages))
  return {'pages':pages,'page':page,'per':per,'offset':(page-1)*per,
          'has_prev':page>1,'has_next':page<pages}

def pg_nav(page, pages, base_url):
  """Render pagination bar HTML."""
  if pages<=1: return ''
  btns=[]
  btns.append(f'<a href="{base_url}&page={page-1}" class="btn btn-o" style="padding:5px 12px;font-size:12px;">← Prev</a>' if page>1 else '<span class="btn btn-o" style="padding:5px 12px;font-size:12px;opacity:.3;cursor:default;">← Prev</span>')
  # page numbers — show at most 5
  start=max(1,page-2); end=min(pages,page+2)
  if start>1: btns.append(f'<a href="{base_url}&page=1" class="btn btn-o" style="padding:5px 10px;font-size:12px;">1</a>')
  if start>2: btns.append('<span style="color:var(--dim);padding:0 4px;">…</span>')
  for p in range(start,end+1):
    active='background:var(--p);color:#000;border-color:var(--p);' if p==page else ''
    btns.append(f'<a href="{base_url}&page={p}" class="btn btn-o" style="padding:5px 10px;font-size:12px;{active}">{p}</a>')
  if end<pages-1: btns.append('<span style="color:var(--dim);padding:0 4px;">…</span>')
  if end<pages: btns.append(f'<a href="{base_url}&page={pages}" class="btn btn-o" style="padding:5px 10px;font-size:12px;">{pages}</a>')
  btns.append(f'<a href="{base_url}&page={page+1}" class="btn btn-o" style="padding:5px 12px;font-size:12px;">Next →</a>' if page<pages else '<span class="btn btn-o" style="padding:5px 12px;font-size:12px;opacity:.3;cursor:default;">Next →</span>')
  return f'<div style="display:flex;align-items:center;gap:4px;flex-wrap:wrap;justify-content:center;margin-top:14px;">{"".join(btns)}</div>'

# ━━━ IP BAN + LOGIN SECURITY ━━━
def is_ip_banned(ip):
  try:
    db=get_db(); r=db.execute("SELECT id FROM banned_ips WHERE ip=?",(ip,)).fetchone(); db.close(); return bool(r)
  except: return False

def log_login_attempt(ip, username, success):
  try:
    db=get_db()
    db.execute("INSERT INTO login_attempts(ip,username,success) VALUES(?,?,?)",(ip,username,int(success)))
    db.commit(); db.close()
  except: pass

def is_login_locked(ip):
  """5 failed attempts in 10 min → locked for 15 min."""
  try:
    db=get_db()
    window=datetime.now()-timedelta(minutes=10)
    fails=db.execute("SELECT COUNT(*) FROM login_attempts WHERE ip=? AND success=0 AND created_at>?",(ip,window.isoformat())).fetchone()[0]
    db.close(); return fails>=5
  except: return False

def login_fail_count(ip):
  try:
    db=get_db(); window=datetime.now()-timedelta(minutes=10)
    c=db.execute("SELECT COUNT(*) FROM login_attempts WHERE ip=? AND success=0 AND created_at>?",(ip,window.isoformat())).fetchone()[0]; db.close(); return c
  except: return 0

# ━━━ RATE LIMITER ━━━
PASTE_LIMIT=5        # max pastes per window
PASTE_WINDOW=60      # seconds
REGISTER_LIMIT=3     # max register attempts per window
REGISTER_WINDOW=300  # 5 minutes
COMMENT_LIMIT=10     # max comments per window
COMMENT_WINDOW=60    # seconds

def check_rate_limit(action,limit,window,key=None):
  """Returns (allowed:bool, remaining:int, reset_in:int)"""
  ip=key or get_real_ip()
  try:
    db=get_db()
    cutoff=(datetime.now()-timedelta(seconds=window)).isoformat()
    db.execute("DELETE FROM rate_limits WHERE created_at < ?",(cutoff,))
    count=db.execute("SELECT COUNT(*) FROM rate_limits WHERE ip=? AND action=?",(ip,action)).fetchone()[0]
    if count>=limit:
      oldest=db.execute("SELECT created_at FROM rate_limits WHERE ip=? AND action=? ORDER BY created_at ASC LIMIT 1",(ip,action)).fetchone()
      reset_in=window
      if oldest:
        elapsed=(datetime.now()-datetime.fromisoformat(oldest['created_at'])).total_seconds()
        reset_in=max(0,int(window-elapsed))
      db.commit(); db.close()
      return False,0,reset_in
    db.execute("INSERT INTO rate_limits(ip,action) VALUES(?,?)",(ip,action))
    db.commit(); db.close()
    return True,limit-count-1,0
  except: return True,limit,0

def rate_limit_response(action,reset_in):
  msg=f'Too many requests! Please wait {reset_in}s before trying again.'
  if request.is_json or request.headers.get('X-API-Key') or request.args.get('api_key'):
    return jsonify({'error':msg,'retry_after':reset_in}),429
  flash(msg,'red')
  return None  # caller redirects

# ━━━ CSRF PROTECTION ━━━
def gen_csrf():
  if '_csrf' not in session: session['_csrf']=secrets.token_hex(24)
  return session['_csrf']

def csrf_ok():
  """Verify CSRF token on POST. Skip for API routes."""
  if request.headers.get('X-API-Key') or request.args.get('api_key'): return True
  if request.headers.get('X-Requested-With')=='XMLHttpRequest': return True
  tok=request.form.get('_csrf') or request.headers.get('X-CSRF-Token','')
  return tok and tok==session.get('_csrf')

def csrf_field():
  return f'<input type="hidden" name="_csrf" value="{gen_csrf()}">'

@app.before_request
def csrf_check():
  safe_routes=['/api/','/login','/register','/forgot-password','/sw.js','/manifest.json']
  if request.method!='POST': return
  if any(request.path.startswith(r) for r in safe_routes): return
  if not session.get('user_id'): return
  if not csrf_ok():
    flash('Session expired. Please try again.','error')
    return redirect(request.referrer or '/')

# ━━━ PASSWORD STRENGTH ━━━
PW_STRENGTH_JS='''<script>
function pwStrength(pw){
  let s=0,tips=[];
  if(pw.length>=8)s++;else tips.push('8+ chars');
  if(pw.length>=12)s++;
  if(/[A-Z]/.test(pw))s++;else tips.push('uppercase');
  if(/[0-9]/.test(pw))s++;else tips.push('number');
  if(/[^A-Za-z0-9]/.test(pw))s++;else tips.push('symbol');
  return{score:s,tips};
}
function updatePwStrength(input){
  const bar=document.getElementById('pw-strength-bar');
  const txt=document.getElementById('pw-strength-txt');
  if(!bar||!txt)return;
  const r=pwStrength(input.value);
  const labels=['','Weak','Fair','Good','Strong','Very Strong'];
  const colors=['','#ff453a','#ff9f0a','#ffd60a','#30d158','#00f5ff'];
  bar.style.width=(r.score/5*100)+'%';
  bar.style.background=colors[r.score]||'#ff453a';
  txt.textContent=r.score>0?(labels[r.score]+(r.tips.length?' — needs: '+r.tips.join(', '):'')):'';
  txt.style.color=colors[r.score]||'#ff453a';
}
</script>'''

# ━━━ PASTE SIZE LIMIT ━━━
MAX_PASTE_BYTES = 1 * 1024 * 1024  # 1 MB
MAX_TITLE_CHARS = 200

def check_paste_size(content, title=''):
  size=len(content.encode('utf-8'))
  if size>MAX_PASTE_BYTES:
    mb=size/1024/1024
    return False,f'Paste too large! {mb:.2f} MB — max is 1 MB.'
  if len(title)>MAX_TITLE_CHARS:
    return False,f'Title too long! Max {MAX_TITLE_CHARS} characters.'
  return True,''

# ━━━ ADMIN LOGGER ━━━
def admin_log(action, target=''):
  """Log admin actions to admin_logs table."""
  try:
    admin_id=session.get('user_id',0)
    admin_username=session.get('user','?')
    ip=get_real_ip()
    db=get_db()
    db.execute("INSERT INTO admin_logs(admin_id,admin_username,action,target,ip) VALUES(?,?,?,?,?)",
               (admin_id,admin_username,action,str(target),ip))
    db.commit(); db.close()
  except Exception as e:
    print(f'[ADMIN LOG ERROR] {e}')

# ━━━ BACKUP SYSTEM ━━━
BACKUP_DIR=os.environ.get('BACKUP_DIR','backups')
BACKUP_KEEP_DAYS=30

def do_backup():
  """Create a timestamped DB backup."""
  try:
    os.makedirs(BACKUP_DIR,exist_ok=True)
    ts=datetime.now().strftime('%Y%m%d_%H%M%S')
    fname=f'zeroshell_{ts}.db'
    fpath=os.path.join(BACKUP_DIR,fname)
    shutil.copy2(DB,fpath)
    size=os.path.getsize(fpath)
    # Record in DB
    db=get_db()
    db.execute("INSERT INTO backups(filename,size) VALUES(?,?)",(fname,size))
    # Cleanup old backups > BACKUP_KEEP_DAYS
    cutoff=(datetime.now()-timedelta(days=BACKUP_KEEP_DAYS)).isoformat()
    old=db.execute("SELECT filename FROM backups WHERE created_at < ?",(cutoff,)).fetchall()
    for o in old:
      try: os.remove(os.path.join(BACKUP_DIR,o['filename']))
      except: pass
    db.execute("DELETE FROM backups WHERE created_at < ?",(cutoff,))
    db.commit(); db.close()
    print(f'[BACKUP] ✅ {fname} ({size//1024} KB)')
    return fname,size
  except Exception as e:
    print(f'[BACKUP ERROR] {e}')
    return None,0

def backup_scheduler():
  """Run daily backup every 24 hours in background thread."""
  while True:
    time.sleep(86400)  # 24 hours
    do_backup()


GMAIL_USER=os.environ.get('GMAIL_USER','')
GMAIL_PASS=os.environ.get('GMAIL_APP_PASSWORD','')

# ── Google OAuth ──
GOOGLE_CLIENT_ID=os.environ.get('GOOGLE_CLIENT_ID','')
GOOGLE_CLIENT_SECRET=os.environ.get('GOOGLE_CLIENT_SECRET','')
GOOGLE_REDIRECT_URI=os.environ.get('GOOGLE_REDIRECT_URI','http://localhost:5000/auth/google/callback')

def google_auth_url():
  params=urllib.parse.urlencode({
    'client_id':GOOGLE_CLIENT_ID,'redirect_uri':GOOGLE_REDIRECT_URI,
    'response_type':'code','scope':'openid email profile',
    'access_type':'offline','prompt':'select_account',
  })
  return f'https://accounts.google.com/o/oauth2/v2/auth?{params}'

def google_exchange_code(code):
  try:
    data=urllib.parse.urlencode({
      'code':code,'client_id':GOOGLE_CLIENT_ID,'client_secret':GOOGLE_CLIENT_SECRET,
      'redirect_uri':GOOGLE_REDIRECT_URI,'grant_type':'authorization_code',
    }).encode()
    req=urllib.request.Request('https://oauth2.googleapis.com/token',data=data,
      headers={'Content-Type':'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req,timeout=10) as r:
      tokens=json.loads(r.read())
    payload=tokens['id_token'].split('.')[1]
    payload+='=='*(-len(payload)%4)
    info=json.loads(base64.b64decode(payload))
    return {'email':info.get('email',''),'name':info.get('name',''),'google_id':info.get('sub','')}
  except Exception as e:
    print(f'[GOOGLE OAUTH ERROR] {e}'); return None

def send_email(to,subject,html_body):
  if not GMAIL_USER or not GMAIL_PASS: return False
  try:
    msg=MIMEMultipart('alternative')
    msg['Subject']=subject; msg['From']=f'ZeroShell <{GMAIL_USER}>'; msg['To']=to
    msg.attach(MIMEText(html_body,'html'))
    with smtplib.SMTP_SSL('smtp.gmail.com',465,timeout=10) as s:
      s.login(GMAIL_USER,GMAIL_PASS); s.sendmail(GMAIL_USER,to,msg.as_string())
    return True
  except Exception as e:
    print(f'[EMAIL ERROR] {e}'); return False

def gen_otp(): return str(secrets.randbelow(900000)+100000)

def save_otp(email,otp,purpose='register'):
  db=get_db()
  db.execute("DELETE FROM email_otps WHERE email=? AND purpose=?",(email,purpose))
  db.execute("INSERT INTO email_otps(email,otp,purpose) VALUES(?,?,?)",(email,otp,purpose))
  db.commit(); db.close()

def verify_otp(email,otp,purpose='register'):
  db=get_db()
  row=db.execute("SELECT * FROM email_otps WHERE email=? AND otp=? AND purpose=? AND created_at > datetime('now','-15 minutes')",(email,otp,purpose)).fetchone()
  if row: db.execute("DELETE FROM email_otps WHERE email=? AND purpose=?",(email,purpose)); db.commit()
  db.close(); return bool(row)

def otp_email_html(otp,purpose='register'):
  action='Email Verification' if purpose=='register' else 'Password Reset'
  return f'''<!DOCTYPE html><html><body style="background:#04080f;font-family:Arial,sans-serif;margin:0;padding:20px;">
<div style="max-width:480px;margin:0 auto;background:#0b1623;border:1px solid #0f2a40;border-radius:14px;padding:30px;">
<div style="text-align:center;margin-bottom:20px;"><span style="font-size:32px;">⚡</span><div style="font-size:22px;font-weight:800;color:#00f5ff;letter-spacing:3px;margin-top:6px;">ZEROSHELL</div></div>
<div style="font-size:16px;font-weight:700;color:#c8e0f0;margin-bottom:8px;">{action}</div>
<div style="font-size:13px;color:#4a6a80;margin-bottom:22px;">Your one-time code (valid for 15 minutes):</div>
<div style="text-align:center;background:#020810;border:1px solid #00f5ff33;border-radius:10px;padding:20px;margin-bottom:22px;">
<div style="font-size:40px;font-weight:900;color:#00f5ff;letter-spacing:12px;font-family:monospace;">{otp}</div></div>
<div style="font-size:12px;color:#4a6a80;text-align:center;">If you did not request this, please ignore this email.</div>
</div></body></html>'''

# ━━━ TOTP (no external lib) ━━━
def totp_gen_secret(): return base64.b32encode(secrets.token_bytes(20)).decode()

def totp_hotp(secret,counter):
  key=base64.b32decode(secret.upper()+'='*8,casefold=True)
  msg=struct.pack('>Q',counter)
  h=hmac.new(key,msg,'sha1').digest()
  offset=h[-1]&0xf
  code=struct.unpack('>I',h[offset:offset+4])[0]&0x7fffffff
  return str(code%1000000).zfill(6)

def totp_now(secret):
  return totp_hotp(secret,int(time.time())//30)

def totp_verify(secret,code):
  t=int(time.time())//30
  for i in [-1,0,1]:
    if totp_hotp(secret,t+i)==str(code): return True
  return False

def totp_uri(secret,username):
  return f"otpauth://totp/ZeroShell:{username}?secret={secret}&issuer=ZeroShell"

def get_badge(views,p30):
  if views>=10000: return('Legendary','👑','#ffd700')
  if views>=5000: return('Famous','⚡','#ff6b00')
  if views>=1000: return('Popular','','#ff2d55')
  if p30>=5: return('Active','🏃','#00f5ff')
  return('Newcomer','⭐','#8899aa')

THEMES={'cyan':'#00f5ff','red':'#ff2d55','green':'#00ff88','gold':'#ffd60a','purple':'#bf5af2','blue':'#2979ff'}

# Bat icon SVG (inline, reusable)
BAT_SVG='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><path d="M32 28c-4-8-12-14-20-14 2 4 3 8 2 12-3-2-6-2-8 0 2 1 4 3 4 6-4 0-7 2-8 5 3 0 6 1 8 3-1 3 0 6 2 8 2-2 5-3 8-2-1 3 0 6 2 8 2-3 6-5 10-5s8 2 10 5c2-2 3-5 2-8 3-1 6 0 8 2 2-2 3-5 2-8 2-2 5-3 8-3-1-3-4-5-8-5 0-3 2-5 4-6-2-2-5-2-8 0-1-4 0-8 2-12-8 0-16 6-20 14z" fill="#0a0a0a" stroke="#00c8ff" stroke-width="2"/><ellipse cx="22" cy="34" rx="2.5" ry="3" fill="#00c8ff"/><ellipse cx="42" cy="34" rx="2.5" ry="3" fill="#00c8ff"/></svg>'
BAT_SVG_URL='data:image/svg+xml;charset=utf-8,'+__import__('urllib.parse',fromlist=['quote']).quote('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><path d="M32 28c-4-8-12-14-20-14 2 4 3 8 2 12-3-2-6-2-8 0 2 1 4 3 4 6-4 0-7 2-8 5 3 0 6 1 8 3-1 3 0 6 2 8 2-2 5-3 8-2-1 3 0 6 2 8 2-3 6-5 10-5s8 2 10 5c2-2 3-5 2-8 3-1 6 0 8 2 2-2 3-5 2-8 2-2 5-3 8-3-1-3-4-5-8-5 0-3 2-5 4-6-2-2-5-2-8 0-1-4 0-8 2-12-8 0-16 6-20 14z" fill="%230a0a0a" stroke="%2300c8ff" stroke-width="2"/><ellipse cx="22" cy="34" rx="2.5" ry="3" fill="%2300c8ff"/><ellipse cx="42" cy="34" rx="2.5" ry="3" fill="%2300c8ff"/></svg>',safe='')
AVATARS=['👤','⚡','','💀','🤖','👾','🦊','🐉','🎭','🔮','🦅','🐺']
EXPIRE_OPTS=[('','Never'),('1h','1 Hour'),('1d','1 Day'),('1w','1 Week'),('1m','1 Month')]
ALL_TAGS=['python','javascript','html','css','bash','json','config','snippet','tutorial','other']

# ━━━ SYNTAX HIGHLIGHT ━━━
def highlight(code,lang):
  import html as h; code=h.escape(code)
  if lang=='python':
    code=re.sub(r'(#[^\n]*)','<span style="color:#6272a4">\\1</span>',code)
    code=re.sub(r'("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"[^"]*"|\'[^\']*\')','<span style="color:#f1fa8c">\\1</span>',code)
    code=re.sub(r'\b(def|class|import|from|return|if|elif|else|for|while|in|not|and|or|try|except|finally|with|as|pass|break|continue|lambda|yield|True|False|None)\b','<span style="color:#ff79c6">\\1</span>',code)
    code=re.sub(r'\b(\d+\.?\d*)\b','<span style="color:#bd93f9">\\1</span>',code)
    code=re.sub(r'\b(print|len|range|int|str|float|list|dict|set|type|open|input)\b','<span style="color:#8be9fd">\\1</span>',code)
  elif lang=='javascript':
    code=re.sub(r'(//[^\n]*)','<span style="color:#6272a4">\\1</span>',code)
    code=re.sub(r'(`[^`]*`|"[^"]*"|\'[^\']*\')','<span style="color:#f1fa8c">\\1</span>',code)
    code=re.sub(r'\b(const|let|var|function|return|if|else|for|while|class|import|export|from|new|this|async|await|try|catch|true|false|null|undefined)\b','<span style="color:#ff79c6">\\1</span>',code)
    code=re.sub(r'\b(\d+\.?\d*)\b','<span style="color:#bd93f9">\\1</span>',code)
  elif lang=='html':
    code=re.sub(r'(&lt;/?)([\w-]+)','\\1<span style="color:#ff79c6">\\2</span>',code)
    code=re.sub(r'("([^"]*)")','<span style="color:#f1fa8c">\\1</span>',code)
  elif lang=='json':
    code=re.sub(r'"([^"]+)"(\s*:)','<span style="color:#8be9fd">"\\1"</span>\\2',code)
    code=re.sub(r'(:\s*)"([^"]*)"','\\1<span style="color:#f1fa8c">"\\2"</span>',code)
    code=re.sub(r'\b(true|false|null)\b','<span style="color:#ff79c6">\\1</span>',code)
  elif lang=='bash':
    code=re.sub(r'(#[^\n]*)','<span style="color:#6272a4">\\1</span>',code)
    code=re.sub(r'("[^"]*"|\'[^\']*\')','<span style="color:#f1fa8c">\\1</span>',code)
    code=re.sub(r'\b(if|then|else|fi|for|while|do|done|echo|export|cd|ls|mkdir|rm|git|pip|python|sudo)\b','<span style="color:#ff79c6">\\1</span>',code)
    code=re.sub(r'(\$[\w{}\(\)]+)','<span style="color:#50fa7b">\\1</span>',code)
  elif lang=='sql':
    code=re.sub(r'\b(SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|CREATE|DROP|TABLE|JOIN|LEFT|RIGHT|ON|AS|ORDER|BY|GROUP|HAVING|LIMIT|AND|OR|NOT|IN|NULL)\b','<span style="color:#ff79c6">\\1</span>',code,flags=re.I)
    code=re.sub(r'("[^"]*"|\'[^\']*\')','<span style="color:#f1fa8c">\\1</span>',code)
  return code

# ━━━ STYLE ━━━
def style(theme='cyan',light=False):
  p=THEMES.get(theme,'#00f5ff')
  bg,card,border,text,dim=('#04080f','#0b1623','#0f2a40','#ffffff','#8899aa')
  nav_bg='rgba(11,22,35,.97)'
  code_bg='#020810'
  code_col='#e0f0ff'
  return f"""<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{{--bg:{bg};--card:{card};--border:{border};--bd:{border};--p:{p};--green:#00cc66;--red:#ff2d55;--yellow:#e6b800;--text:{text};--t:{text};--dim:{dim};--s:{dim};}}
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;min-height:100vh;}}
body::before{{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(128,128,128,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(128,128,128,.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0;}}
.wrap{{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:20px;}}
nav{{background:{nav_bg};border-bottom:1px solid var(--border);position:sticky;top:0;z-index:200;backdrop-filter:blur(20px);}}
.logo{{font-family:'Share Tech Mono',monospace;font-size:20px;color:var(--p);text-decoration:none;letter-spacing:3px;text-shadow:0 0 18px {p}66;font-weight:700;flex-shrink:0;}}
.nav-links{{display:flex;gap:4px;align-items:center;flex:1;flex-wrap:nowrap;overflow:hidden;margin-left:8px;}}
.nav-links a{{color:var(--text);text-decoration:none;font-size:14px;font-weight:600;padding:6px 12px;border-radius:8px;transition:all .15s;white-space:nowrap;}}
.nav-links a:hover{{background:rgba(128,128,128,.12);color:var(--p);}}
.hamburger{{display:none;flex-direction:column;gap:5px;cursor:pointer;padding:7px;border-radius:7px;border:1px solid var(--border);background:transparent;}}
.hamburger span{{display:block;width:20px;height:2px;background:var(--text);border-radius:2px;}}
.mob-menu{{display:none;flex-direction:column;gap:3px;padding:10px 14px 16px;background:{nav_bg};border-bottom:1px solid var(--border);}}
.mob-menu a{{color:var(--text);text-decoration:none;font-size:15px;font-weight:600;padding:10px 14px;border-radius:8px;}}
.mob-menu a:hover{{background:rgba(128,128,128,.08);}}
@media(max-width:800px){{
  .nav-links{{display:none;}}
  .hamburger{{display:flex;}}
  .mob-menu.open{{display:flex;}}
}}
@media(max-width:700px){{
  body{{padding:0 4px;}}
  .card{{padding:14px 12px;}}
  .wrap{{padding:12px 8px!important;}}
  div[style*="max-width:1100px"]{{grid-template-columns:1fr!important;}}
  div[style*="max-width:1100px"]>div:first-child{{position:static!important;}}
  div[style*="230px 1fr"]{{grid-template-columns:1fr!important;}}
  div[style*="1fr 360px"]{{grid-template-columns:1fr!important;}}
  div[style*="1fr 220px"]{{grid-template-columns:1fr!important;}}
  div[style*="1fr 1fr;gap"]{{grid-template-columns:1fr!important;}}
  div[style*="1fr 1fr 1fr"]{{grid-template-columns:1fr 1fr!important;}}
}}
@media(max-width:600px){{
  .g2,.g3,.g4{{grid-template-columns:1fr 1fr;}}
  div[style*="grid-template-columns:2fr 1fr 1fr 1fr"]{{grid-template-columns:1fr 1fr!important;}}
  div[style*="repeat(3,1fr)"]{{grid-template-columns:1fr 1fr!important;}}
  footer .grid-cols{{grid-template-columns:1fr!important;}}
  nav .logo{{font-size:16px!important;}}
  #ai-panel{{width:calc(100vw - 24px)!important;right:-50px!important;}}
  .pi{{flex-direction:column;align-items:flex-start;gap:4px;}}
}}
@media(max-width:480px){{
  .g2,.g3,.g4{{grid-template-columns:1fr!important;}}
  div[style*="grid-template-columns:repeat(3,1fr)"]{{grid-template-columns:1fr 1fr!important;}}
  div[style*="grid-template-columns:2fr 1fr 1fr 1fr"]{{grid-template-columns:1fr 1fr!important;}}
  footer div[style*="2fr 1fr 1fr 1fr"]{{grid-template-columns:1fr 1fr!important;}}
  table{{font-size:11px;}}
  .btn{{font-size:11px;padding:4px 8px;}}
}}
#toast{{position:fixed;bottom:22px;right:18px;z-index:9999;padding:10px 18px;border-radius:9px;font-family:'Rajdhani',sans-serif;font-size:13px;font-weight:700;background:var(--card);border:1px solid var(--p);color:var(--p);box-shadow:0 4px 20px {p}33;transform:translateY(60px);opacity:0;transition:all .3s cubic-bezier(.4,0,.2,1);pointer-events:none;}}
#toast.show{{transform:translateY(0);opacity:1;}}
.btn{{padding:5px 12px;border-radius:6px;border:none;cursor:pointer;font-family:'Rajdhani',sans-serif;font-size:12px;font-weight:700;letter-spacing:1px;text-decoration:none;display:inline-block;transition:all .2s;}}
.btn-p{{background:var(--p);color:#000;}}.btn-p:hover{{box-shadow:0 0 14px {p}55;transform:translateY(-1px);}}
.btn-o{{background:transparent;border:1px solid var(--border);color:var(--text);}}.btn-o:hover{{border-color:var(--p);color:var(--p);}}
.btn-r{{background:rgba(255,45,85,.1);border:1px solid rgba(255,45,85,.3);color:var(--red);}}
.btn-g{{background:rgba(0,204,102,.1);border:1px solid rgba(0,204,102,.3);color:var(--green);}}
.btn-y{{background:rgba(230,184,0,.1);border:1px solid rgba(230,184,0,.3);color:var(--yellow);}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:14px;position:relative;overflow:hidden;}}
.card::before{{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--p),transparent);opacity:.4;}}
input,textarea,select{{width:100%;padding:8px 11px;background:rgba(0,0,0,.4);border:1px solid var(--border);border-radius:7px;color:var(--text);font-family:'Rajdhani',sans-serif;font-size:13px;outline:none;transition:border .2s;}}
input:focus,textarea:focus,select:focus{{border-color:var(--p);}}
label{{display:block;font-size:10px;color:var(--dim);margin-bottom:4px;text-transform:uppercase;letter-spacing:1px;}}
.fg{{margin-bottom:12px;}}
.pi{{display:flex;justify-content:space-between;align-items:center;padding:9px 13px;background:rgba(0,0,0,.2);border:1px solid var(--border);border-radius:8px;margin-bottom:5px;transition:all .2s;text-decoration:none;color:var(--text);}}
.pi:hover{{border-color:var(--p);transform:translateX(3px);}}.pi.pinned{{border-color:{p}55;}}
.pt{{font-size:13px;font-weight:700;color:var(--p);margin-bottom:1px;}}.pm{{font-size:9px;color:var(--dim);font-family:'Share Tech Mono',monospace;}}.pv{{font-family:'Share Tech Mono',monospace;color:var(--green);font-size:10px;white-space:nowrap;}}
.badge{{display:inline-flex;align-items:center;gap:3px;padding:2px 7px;border-radius:99px;font-size:9px;font-weight:700;letter-spacing:1px;}}
.tag{{display:inline-block;padding:2px 7px;border-radius:99px;font-size:9px;font-weight:700;background:rgba(128,128,128,.1);border:1px solid var(--border);color:var(--dim);margin:2px;cursor:pointer;transition:all .2s;text-decoration:none;}}
.tag:hover,.tag.active{{border-color:var(--p);color:var(--p);background:{p}11;}}
.code{{background:{code_bg};border:1px solid var(--border);border-radius:8px;padding:14px;overflow-x:auto;font-family:'Share Tech Mono',monospace;font-size:12px;line-height:1.8;white-space:pre-wrap;word-break:break-all;color:{code_col};max-height:560px;overflow-y:auto;}}
.sg{{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:7px;margin-bottom:14px;}}
.sb{{background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:8px;padding:9px;text-align:center;transition:transform .2s;}}.sb:hover{{transform:translateY(-2px);}}
.sn{{font-family:'Share Tech Mono',monospace;font-size:18px;font-weight:700;display:block;}}.sl{{font-size:9px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;}}
.g2{{display:grid;grid-template-columns:1fr 1fr;gap:11px;}}.g3{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;}}.g4{{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;}}
.alert{{padding:8px 12px;border-radius:7px;margin-bottom:10px;font-size:12px;}}
.ar{{background:rgba(255,45,85,.1);border:1px solid rgba(255,45,85,.3);color:var(--red);}}.ag{{background:rgba(0,204,102,.1);border:1px solid rgba(0,204,102,.3);color:var(--green);}}
.av{{width:52px;height:52px;border-radius:50%;background:rgba(128,128,128,.1);display:flex;align-items:center;justify-content:center;font-size:24px;border:2px solid var(--p);box-shadow:0 0 10px {p}33;}}
.lc-bar{{display:flex;justify-content:space-between;flex-wrap:wrap;gap:5px;padding:5px 9px;background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:6px;margin-top:4px;font-family:'Share Tech Mono',monospace;font-size:10px;}}
.lc-num{{color:var(--p);font-weight:700;}}
.ad-bar{{background:rgba(230,184,0,.05);border:1px solid rgba(230,184,0,.2);border-radius:7px;padding:7px 12px;margin-bottom:10px;}}
.sb-wrap{{display:flex;gap:7px;margin-bottom:12px;}}.sb-wrap input{{flex:1;}}
.ao{{font-size:22px;cursor:pointer;padding:4px;border-radius:6px;border:2px solid transparent;transition:all .2s;display:inline-block;}}.ao:hover,.ao.sel{{border-color:var(--p);}}
.th-btn{{width:26px;height:26px;border-radius:50%;border:3px solid transparent;cursor:pointer;transition:all .2s;display:inline-block;}}.th-btn:hover,.th-btn.act{{border-color:#fff;transform:scale(1.2);}}
.at{{width:100%;border-collapse:collapse;font-size:11px;}}.at th{{padding:6px;text-align:left;color:var(--dim);border-bottom:1px solid var(--border);font-size:9px;letter-spacing:1px;text-transform:uppercase;}}.at td{{padding:6px;border-bottom:1px solid var(--border);}}
.comment{{padding:9px 12px;background:rgba(0,0,0,.2);border:1px solid var(--border);border-radius:8px;margin-bottom:6px;}}
.notif{{padding:8px 12px;border-radius:7px;margin-bottom:4px;background:rgba(0,0,0,.2);border:1px solid var(--border);font-size:11px;display:flex;justify-content:space-between;align-items:center;gap:7px;}}
.notif.unread{{border-color:{p}55;background:{p}08;}}
.notif-dot{{width:6px;height:6px;border-radius:50%;background:var(--p);flex-shrink:0;}}
.notif-badge{{background:var(--red);color:#fff;border-radius:99px;font-size:9px;font-weight:700;padding:1px 5px;margin-left:2px;}}
.like-btn{{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:99px;border:1px solid var(--border);background:transparent;color:var(--text);cursor:pointer;font-size:11px;font-weight:700;font-family:'Rajdhani',sans-serif;transition:all .2s;}}
.like-btn:hover,.like-btn.active{{border-color:var(--p);color:var(--p);background:{p}11;}}
.like-btn.dislike:hover,.like-btn.dislike.active{{border-color:var(--red);color:var(--red);background:rgba(255,45,85,.1);}}
.follow-btn{{padding:5px 13px;border-radius:99px;border:1px solid var(--p);background:transparent;color:var(--p);cursor:pointer;font-size:11px;font-weight:700;font-family:'Rajdhani',sans-serif;transition:all .2s;}}
.follow-btn:hover,.follow-btn.following{{background:var(--p);color:#000;}}
/* ── Premium Badge ── */
.prem-badge{{display:inline-flex;align-items:center;gap:3px;padding:2px 8px 2px 5px;border-radius:99px;font-size:11px;font-weight:800;letter-spacing:.3px;background:linear-gradient(135deg,#7b2ff7,#f107a3,#ffd700);color:#fff;vertical-align:middle;position:relative;overflow:hidden;cursor:default;flex-shrink:0;}}
.prem-badge::after{{content:'';position:absolute;top:0;left:-100%;width:60%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.35),transparent);animation:pbShimmer 2.4s infinite;}}
@keyframes pbShimmer{{0%{{left:-100%}}60%,100%{{left:160%}}}}
@keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:0}}}}
.prem-badge-lg{{font-size:13px;padding:3px 12px 3px 8px;gap:5px;}}
.prem-avatar-ring{{border:3px solid transparent!important;background-clip:padding-box;box-shadow:0 0 0 3px #ffd700,0 0 16px #ffd70055!important;}}
.prem-name{{background:linear-gradient(90deg,#ffd700,#f107a3,#7b2ff7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}}
.diff-add{{background:rgba(0,204,102,.15);border-left:3px solid var(--green);display:block;}}
.diff-del{{background:rgba(255,45,85,.15);border-left:3px solid var(--red);display:block;}}
.diff-eq{{display:block;color:var(--dim);}}
.scan{{position:fixed;inset:0;pointer-events:none;z-index:999;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.025) 2px,rgba(0,0,0,.025) 4px);}}
footer{{color:var(--s);}}
.install-btn{{background:linear-gradient(135deg,{p},{p}aa);color:#000;border:none;padding:6px 14px;border-radius:99px;font-size:11px;font-weight:700;cursor:pointer;font-family:'Rajdhani',sans-serif;display:none;}}
@media(max-width:600px){{.g2,.g3,.g4{{grid-template-columns:1fr 1fr;}}}}
</style>"""

TOAST_JS='<div id="toast"></div><script>function toast(m,c){const t=document.getElementById("toast");t.textContent=m;t.style.borderColor=c||"var(--p)";t.style.color=c||"var(--p)";t.classList.add("show");setTimeout(()=>t.classList.remove("show"),2500);}</script>'
MOB_JS='<script>function toggleMenu(){document.getElementById("mm").classList.toggle("open");}</script>'
AI_JS='''<script>
(function(){
  let busy=false, history=[], open=false;

  /* ── markdown renderer ── */
  function md(t){
    return t
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/```([\s\S]*?)```/g,'<pre style="background:rgba(0,0,0,.4);border:1px solid rgba(0,245,255,.15);border-radius:8px;padding:10px 12px;margin:6px 0;overflow-x:auto;font-family:monospace;font-size:11px;color:#00f5ff;white-space:pre-wrap;">$1</pre>')
      .replace(/`([^`]+)`/g,'<code style="background:rgba(0,245,255,.12);padding:2px 6px;border-radius:4px;font-family:monospace;font-size:11px;color:#00f5ff;">$1</code>')
      .replace(/[*][*](.+?)[*][*]/g,'<b style="color:#e0f8ff;">$1</b>')
      .replace(/[*](.+?)[*]/g,'<i>$1</i>')
      .replace(/^#{1,3}\s+(.+)$/gm,'<div style="font-weight:800;color:#00c8ff;font-size:12px;margin:4px 0;">$1</div>')
      .replace(/^[-•]\s+(.+)$/gm,'<div style="padding-left:12px;margin:2px 0;">· $1</div>')
      .replace(/\n/g,'<br>');
  }

  function msgs(){return document.getElementById('ai-msgs');}
  function inp(){return document.getElementById('ai-inp');}

  function scrollBottom(){const m=msgs();if(m)m.scrollTop=m.scrollHeight;}

  function addMsg(role,html,isHtml){
    const m=msgs(); if(!m)return null;
    const row=document.createElement('div');
    row.style.cssText='display:flex;align-items:flex-end;gap:8px;animation:fadeUp .2s ease;' + (role==='user'?'flex-direction:row-reverse;':'')+'margin-bottom:2px;';
    const av=document.createElement('div');
    av.style.cssText='width:26px;height:26px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:14px;' + (role==='user'?'background:rgba(0,245,255,.15);border:1px solid rgba(0,245,255,.3);':'background:linear-gradient(135deg,rgba(123,47,247,.3),rgba(0,200,255,.2));border:1px solid rgba(0,200,255,.3);');
    av.textContent=role==='user'?'👤':'🤖';
    const bub=document.createElement('div');
    bub.style.cssText='max-width:80%;padding:9px 12px;font-size:12.5px;line-height:1.6;word-break:break-word;' + (role==='user'?'border-radius:14px 14px 4px 14px;background:linear-gradient(135deg,rgba(0,200,255,.18),rgba(0,200,255,.1));border:1px solid rgba(0,200,255,.3);color:#e0f8ff;':'border-radius:14px 14px 14px 4px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.09);color:#ddeeff;');
    if(isHtml)bub.innerHTML=html; else bub.textContent=html;
    row.appendChild(av); row.appendChild(bub);
    m.appendChild(row); scrollBottom();
    return bub;
  }

  function addTyping(){
    const m=msgs(); if(!m)return null;
    const row=document.createElement('div');
    row.id='ai-typing';
    row.style.cssText='display:flex;align-items:flex-end;gap:8px;margin-bottom:2px;';
    const av=document.createElement('div');
    av.style.cssText='width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,rgba(123,47,247,.3),rgba(0,200,255,.2));border:1px solid rgba(0,200,255,.3);display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0;';
    av.textContent='🤖';
    const dots=document.createElement('div');
    dots.style.cssText='padding:10px 14px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.09);border-radius:14px 14px 14px 4px;display:flex;gap:5px;align-items:center;';
    dots.innerHTML='<span style="width:7px;height:7px;border-radius:50%;background:#00c8ff;animation:aiDot .9s ease-in-out infinite;"></span><span style="width:7px;height:7px;border-radius:50%;background:#00c8ff;animation:aiDot .9s ease-in-out .18s infinite;"></span><span style="width:7px;height:7px;border-radius:50%;background:#00c8ff;animation:aiDot .9s ease-in-out .36s infinite;"></span>';
    row.appendChild(av); row.appendChild(dots);
    m.appendChild(row); scrollBottom();
    return row;
  }

  /* inject CSS once */
  if(!document.getElementById('ai-style')){
    const s=document.createElement('style');
    s.id='ai-style';
    s.textContent='@keyframes aiDot{0%,80%,100%{transform:scale(.55);opacity:.35}40%{transform:scale(1);opacity:1}}@keyframes fadeUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}@keyframes slideIn{from{opacity:0;transform:translateY(-8px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}#ai-msgs::-webkit-scrollbar{width:3px}#ai-msgs::-webkit-scrollbar-track{background:transparent}#ai-msgs::-webkit-scrollbar-thumb{background:rgba(0,200,255,.2);border-radius:99px}';
    document.head.appendChild(s);
  }

  window.sendAi=async function(){
    const i=inp(); const btn=document.getElementById('ai-send-btn');
    if(!i||busy)return;
    const q=i.value.trim(); if(!q)return;
    busy=true; i.value=''; i.disabled=true;
    if(btn){btn.disabled=true;btn.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/></svg>';btn.style.opacity='.5';}
    addMsg('user',q,false);
    history.push({role:'user',content:q});
    const typing=addTyping();
    try{
      const r=await fetch('/api/ai-chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({q,history:history.slice(-14)})});
      const d=await r.json();
      if(typing)typing.remove();
      const reply=d.reply||'Sorry, no response available.';
      addMsg('ai',md(reply),true);
      history.push({role:'assistant',content:reply});
    }catch(e){
      if(typing)typing.remove();
      addMsg('ai','🔴 Connection error. Try again.',false);
    }
    busy=false; i.disabled=false; i.focus();
    if(btn){btn.disabled=false;btn.innerHTML='<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><path d="M2 21l21-9L2 3v7l15 2-15 2v7z"/></svg>';btn.style.opacity='1';}
  };

  window.clearAiChat=function(){
    history=[];
    const m=msgs(); if(!m)return;
    m.innerHTML=_aiWelcome();
  };

  function _aiWelcome(){
    return '<div style="text-align:center;padding:24px 12px;"><div style="font-size:36px;margin-bottom:10px;">🤖</div><div style="font-size:13px;font-weight:800;color:#00c8ff;margin-bottom:5px;">ZeroShell AI</div><div style="font-size:11px;color:#4a7a8a;line-height:1.6;">Ask me anything about pastes,<br>features, API, or your account.</div></div>';
  }

  window.toggleAiPanel=function(){
    const p=document.getElementById('ai-panel');
    if(!p)return;
    open=p.style.display==='none'||p.style.display==='';
    p.style.display=open?'flex':'none';
    if(open){p.style.animation='slideIn .2s ease';setTimeout(()=>{const i=inp();if(i)i.focus();},80);}
  };

  window.openHelpWith=function(msg){
    const p=document.getElementById('ai-panel');
    if(p&&(p.style.display==='none'||p.style.display==='')){p.style.display='flex';open=true;}
    const i=inp(); if(i)i.value=msg;
    setTimeout(()=>window.sendAi(),80);
  };

  document.addEventListener('click',function(e){
    const p=document.getElementById('ai-panel');
    if(!p||!open)return;
    const wrap=p.closest('.ai-wrap')||p.parentElement;
    if(wrap&&!wrap.contains(e.target)){p.style.display='none';open=false;}
  });
})();
</script>'''

PWA_JS="""
<script>
// PWA Install
let deferredPrompt;
window.addEventListener('beforeinstallprompt',(e)=>{
 e.preventDefault(); deferredPrompt=e;
 const btn=document.getElementById('installBtn');
 if(btn){btn.style.display='inline-block';}
});
function installPWA(){
 if(deferredPrompt){deferredPrompt.prompt();deferredPrompt.userChoice.then(()=>{deferredPrompt=null;});}
}
// Service Worker
if('serviceWorker' in navigator){
 navigator.serviceWorker.register('/sw.js').catch(()=>{});
}
</script>
"""


def base(content,title="ZeroShell",theme='cyan',auth_page=False):
  s=style(theme,False)
  msgs=get_flashed_messages(with_categories=True)
  alerts=''.join(f'<div class="alert {"ag" if c in ("green","success") else "ar"}">{m}</div>' for c,m in msgs)
  try:
    db=get_db(); ad=db.execute("SELECT * FROM ads WHERE active=1 ORDER BY RANDOM() LIMIT 1").fetchone(); db.close()
  except: ad=None
  ad_html=f'<div class="ad-bar"><span style="color:var(--yellow);font-size:9px;font-weight:700;">📢</span><a href="{ad["url"] or "#"}" target="_blank" style="color:var(--yellow);text-decoration:none;font-size:11px;margin-left:7px;">{ad["title"]} — {ad["content"]}</a></div>' if ad else ''
  u=session.get('user',''); uid=session.get('user_id')
  uc=unread_count(uid)
  # ── icon button helper ──
  def _nb(href,icon,tip,badge='',extra_style=''):
    b=f'<span style="position:absolute;top:-3px;right:-3px;min-width:16px;height:16px;border-radius:99px;background:#ff3b30;color:#fff;font-size:9px;font-weight:800;display:flex;align-items:center;justify-content:center;padding:0 3px;pointer-events:none;">{badge}</span>' if badge else ''
    return (f'<a href="{href}" title="{tip}" style="position:relative;display:flex;align-items:center;justify-content:center;'
      f'width:36px;height:36px;border-radius:9px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);'
      f'color:var(--t);text-decoration:none;font-size:17px;transition:all .2s;flex-shrink:0;{extra_style}"'
      f' onmouseover="this.style.background=\'rgba(255,255,255,.11)\';this.style.borderColor=\'rgba(255,255,255,.18)\'"'
      f' onmouseout="this.style.background=\'rgba(255,255,255,.05)\';this.style.borderColor=\'rgba(255,255,255,.08)\'">'f'{icon}{b}</a>')
  if u:
    prem_badge=('<span style="font-size:9px;font-weight:800;padding:1px 5px;border-radius:99px;'
      'background:linear-gradient(135deg,#7b2ff7,#ffd700);color:#fff;margin-left:3px;vertical-align:middle;">PRO</span>'
      if session.get('is_premium') else '')
    notif_n=str(uc) if uc>0 else ''
    # user avatar pill - clean professional design
    av=session.get('avatar','👤')
    _prem_txt='&#9733; Premium' if session.get('is_premium') else 'Free account'
    _admin_item=''
    if session.get('is_admin'):
      _admin_item='<a href="/admin" style="display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:8px;color:#ffd700;text-decoration:none;font-size:13px;" onmouseover="this.style.background=\'rgba(255,215,0,.08)\'" onmouseout="this.style.background=\'none\'"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>Admin Panel</a>'
    user_pill=(
      '<div style="position:relative;display:inline-block;">'
      f'<button onclick="var d=this.nextElementSibling;d.style.display=d.style.display===\'block\'?\'none\':\'block\'"'
      ' style="display:flex;align-items:center;gap:8px;padding:5px 10px 5px 6px;border-radius:10px;'
      'background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);cursor:pointer;'
      'color:var(--t);font-size:13px;font-weight:600;transition:all .2s;"'
      ' onmouseover="this.style.background=\'rgba(255,255,255,.1)\'"'
      ' onmouseout="this.style.background=\'rgba(255,255,255,.05)\'">'
      f'<span style="width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,rgba(0,200,255,.18),rgba(123,47,247,.14));border:1.5px solid rgba(0,200,255,.35);display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0;">{av}</span>'
      f'<span style="max-width:90px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{u}</span>'
      f'{prem_badge}'
      '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="opacity:.35;flex-shrink:0;"><path d="m6 9 6 6 6-6"/></svg>'
      '</button>'
      '<div style="display:none;position:absolute;top:calc(100% + 8px);right:0;min-width:200px;'
      'background:#07111f;border:1px solid rgba(255,255,255,.1);border-radius:14px;'
      'box-shadow:0 16px 48px rgba(0,0,0,.8);z-index:9999;padding:6px;overflow:hidden;"'
      ' onmouseleave="this.style.display=\'none\'">'
      f'<div style="padding:10px 12px 11px;border-bottom:1px solid rgba(255,255,255,.07);margin-bottom:5px;">'
      f'<div style="font-size:13px;font-weight:700;color:#fff;margin-bottom:2px;">{u}</div>'
      f'<div style="font-size:11px;color:var(--dim);">{_prem_txt}</div>'
      '</div>'
      f'<a href="/profile/{u}" style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:9px;color:var(--t);text-decoration:none;font-size:13px;" onmouseover="this.style.background=\'rgba(255,255,255,.06)\'" onmouseout="this.style.background=\'none\'"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>Profile</a>'
      f'<a href="/dashboard" style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:9px;color:var(--t);text-decoration:none;font-size:13px;" onmouseover="this.style.background=\'rgba(255,255,255,.06)\'" onmouseout="this.style.background=\'none\'"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>Dashboard</a>'
      f'<a href="/settings" style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:9px;color:var(--t);text-decoration:none;font-size:13px;" onmouseover="this.style.background=\'rgba(255,255,255,.06)\'" onmouseout="this.style.background=\'none\'"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>Settings</a>'
      f'{_admin_item}'
      '<div style="border-top:1px solid rgba(255,255,255,.07);margin:5px 0 0;padding-top:5px;">'
      '<a href="/logout" style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:9px;color:#ff453a;text-decoration:none;font-size:13px;" onmouseover="this.style.background=\'rgba(255,69,58,.08)\'" onmouseout="this.style.background=\'none\'"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>Log out</a>'
      '</div></div></div>'
    )
    # Icon-only nav buttons
    def _icon_btn(href, svg, tooltip, badge=0):
      b=(f'<span style="position:absolute;top:-3px;right:-3px;min-width:16px;height:16px;border-radius:99px;'
        f'background:#ff453a;color:#fff;font-size:9px;font-weight:800;display:flex;align-items:center;'
        f'justify-content:center;padding:0 3px;line-height:1;border:1.5px solid #030d1a;">{badge}</span>'
        if badge and int(badge)>0 else '')
      return (f'<a href="{href}" title="{tooltip}" style="position:relative;width:36px;height:36px;display:flex;'
        f'align-items:center;justify-content:center;border-radius:9px;color:rgba(255,255,255,.6);'
        f'text-decoration:none;transition:all .2s;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);"'
        f' onmouseover="this.style.background=\'rgba(255,255,255,.09)\';this.style.color=\'#fff\'"'
        f' onmouseout="this.style.background=\'rgba(255,255,255,.03)\';this.style.color=\'rgba(255,255,255,.6)\'">'  
        f'{svg}{b}</a>')
    nav_r=(
      _icon_btn('/notifications','<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>','Notifications',notif_n)
      +user_pill)
    mob_r=f'<a href="/profile/{u}">{av} {u}</a><a href="/dashboard">Dashboard</a><a href="/bookmarks">Saved</a><a href="/notifications">Notifications{(" ("+str(uc)+")" if uc>0 else "")}</a><a href="/settings">Settings</a>{"<a href=/admin style=color:#ffd700>★ Admin</a>" if session.get("is_admin") else ""}<a href="/logout" style="color:#ff453a;">Log out</a>'
  else:
    nav_r=('<a href="/login" style="font-weight:600;font-size:13px;color:rgba(255,255,255,.65);text-decoration:none;padding:7px 16px;border-radius:9px;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.03);transition:all .2s;" onmouseover="this.style.background=\'rgba(255,255,255,.09)\';this.style.color=\'#fff\'" onmouseout="this.style.background=\'rgba(255,255,255,.03)\';this.style.color=\'rgba(255,255,255,.65)\'">Log in</a>'
      '<a href="/register" style="font-weight:700;font-size:13px;color:#000;text-decoration:none;padding:7px 18px;border-radius:9px;background:linear-gradient(135deg,#00c8ff,#0094cc);box-shadow:0 2px 14px rgba(0,200,255,.35);transition:all .2s;" onmouseover="this.style.boxShadow=\'0 4px 22px rgba(0,200,255,.55)\';this.style.transform=\'translateY(-1px)\'" onmouseout="this.style.boxShadow=\'0 2px 14px rgba(0,200,255,.35)\';this.style.transform=\'none\'">Sign up</a>')
    mob_r='<a href="/login">Login</a><a href="/register">Register</a>'
  p_color=THEMES.get(theme,'#00f5ff')
  return f'''<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="{p_color}">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="ZeroShell">
<link rel="manifest" href="/manifest.json">
<title>{title} - ZeroShell</title><link rel="icon" type="image/svg+xml" href="{BAT_SVG_URL}">{s}</head><body>
{TOAST_JS}{MOB_JS}{PWA_JS}{AI_JS}
<nav>
<div style="max-width:1280px;margin:0 auto;padding:0 24px;height:62px;display:flex;align-items:center;gap:8px;">
 <a class="logo" href="/" style="text-decoration:none;display:inline-flex;align-items:center;gap:8px;position:relative;"><div style="width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#04080f,#0b1623);border:2px solid #00c8ff;box-shadow:0 0 10px rgba(0,200,255,0.4);display:flex;align-items:center;justify-content:center;flex-shrink:0;"><svg width="20" height="20" viewBox="0 0 64 64" fill="#111"><path d="M32 28c-4-8-12-14-20-14 2 4 3 8 2 12-3-2-6-2-8 0 2 1 4 3 4 6-4 0-7 2-8 5 3 0 6 1 8 3-1 3 0 6 2 8 2-2 5-3 8-2-1 3 0 6 2 8 2-3 6-5 10-5s8 2 10 5c2-2 3-5 2-8 3-1 6 0 8 2 2-2 3-5 2-8 2-2 5-3 8-3-1-3-4-5-8-5 0-3 2-5 4-6-2-2-5-2-8 0-1-4 0-8 2-12-8 0-16 6-20 14z" fill="#0a0a0a" stroke="#00c8ff" stroke-width="2"/><ellipse cx="22" cy="34" rx="2.5" ry="3" fill="#00c8ff"/><ellipse cx="42" cy="34" rx="2.5" ry="3" fill="#00c8ff"/></svg></div><span style="font-size:20px;font-weight:900;font-style:italic;color:#ffffff;filter:drop-shadow(0 0 8px rgba(255,255,255,0.5));letter-spacing:1px;">𝐙𝐞𝐫𝐨</span><span style="font-size:20px;font-weight:900;font-style:italic;color:#00c8ff;filter:drop-shadow(0 0 8px rgba(0,200,255,0.6));letter-spacing:1px;">𝐒𝐡𝐞𝐥𝐥</span></a>
 <div class="nav-links">
  {'' if auth_page else '<a href="/">Home</a><a href="/trending">🔥 Trending</a><a href="/leaderboard">Board</a><a href="/api/v1/docs">API</a><a href="/premium" style="background:linear-gradient(135deg,#ffd700,#ff8c00);color:#000;font-weight:800;border-radius:8px;padding:6px 14px;font-size:13px;">Premium</a>'}
  <div style="position:relative;display:inline-block;" class="ai-wrap">
    <button onclick="toggleAiPanel()" style="background:linear-gradient(135deg,rgba(0,200,255,.15),rgba(123,47,247,.1));border:1px solid rgba(0,200,255,.35);color:#00c8ff;font-weight:700;border-radius:9px;padding:7px 16px;font-size:13px;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:7px;letter-spacing:.2px;" onmouseover="this.style.background='linear-gradient(135deg,rgba(0,200,255,.25),rgba(123,47,247,.18))'" onmouseout="this.style.background='linear-gradient(135deg,rgba(0,200,255,.15),rgba(123,47,247,.1))'">
      <span style="width:7px;height:7px;border-radius:50%;background:#00ff88;box-shadow:0 0 8px #00ff88;animation:pulse 2s infinite;flex-shrink:0;"></span>
      AI Help
    </button>
    <div id="ai-panel" style="display:none;position:absolute;top:calc(100% + 10px);right:0;width:370px;background:#07111f;border:1px solid rgba(0,200,255,.2);border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.8),0 0 0 1px rgba(0,200,255,.05),inset 0 1px 0 rgba(255,255,255,.04);z-index:9999;flex-direction:column;">
      <!-- Header -->
      <div style="display:flex;align-items:center;justify-content:space-between;padding:13px 14px;background:linear-gradient(135deg,rgba(0,200,255,.07),rgba(123,47,247,.05));border-bottom:1px solid rgba(255,255,255,.06);border-radius:16px 16px 0 0;">
        <div style="display:flex;align-items:center;gap:9px;">
          <div style="width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#00c8ff33,#7b2ff722);border:1px solid rgba(0,200,255,.35);display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0;">🤖</div>
          <div>
            <div style="font-size:13px;font-weight:800;color:#00c8ff;letter-spacing:.3px;">ZeroShell AI</div>
            <div style="font-size:10px;color:#2a6a7a;margin-top:1px;display:flex;align-items:center;gap:5px;"><span style="width:5px;height:5px;border-radius:50%;background:#00ff88;display:inline-block;"></span>Online · Powered by Claude</div>
          </div>
        </div>
        <div style="display:flex;gap:5px;">
          <button onclick="clearAiChat()" title="New chat" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);color:#3a6a80;cursor:pointer;padding:5px 8px;border-radius:7px;font-size:12px;transition:all .15s;" onmouseover="this.style.background='rgba(255,255,255,.1)'" onmouseout="this.style.background='rgba(255,255,255,.04)'">🗑 New</button>
          <button onclick="toggleAiPanel()" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);color:#3a6a80;cursor:pointer;padding:5px 9px;border-radius:7px;font-size:15px;line-height:1;transition:all .15s;" onmouseover="this.style.background='rgba(255,255,255,.1)'" onmouseout="this.style.background='rgba(255,255,255,.04)'">✕</button>
        </div>
      </div>
      <!-- Messages -->
      <div id="ai-msgs" style="height:300px;overflow-y:auto;padding:14px 12px;display:flex;flex-direction:column;gap:10px;scroll-behavior:smooth;scrollbar-width:thin;">
        <div style="text-align:center;padding:20px 12px;">
          <div style="font-size:38px;margin-bottom:10px;">🤖</div>
          <div style="font-size:14px;font-weight:800;color:#00c8ff;margin-bottom:5px;">ZeroShell AI</div>
          <div style="font-size:11px;color:#2a5a6a;line-height:1.7;">Ask me anything about pastes,<br>features, API, or your account.</div>
        </div>
      </div>
      <!-- Quick chips -->
      <div style="padding:8px 12px 6px;border-top:1px solid rgba(255,255,255,.05);display:flex;gap:5px;flex-wrap:wrap;">
        <button onclick="openHelpWith('How do I create a paste?')" style="background:rgba(0,200,255,.07);border:1px solid rgba(0,200,255,.18);border-radius:99px;padding:4px 11px;color:#00c8ff;font-size:10px;cursor:pointer;transition:all .15s;" onmouseover="this.style.background='rgba(0,200,255,.18)'" onmouseout="this.style.background='rgba(0,200,255,.07)'">📝 Create paste</button>
        <button onclick="openHelpWith('What are the benefits of Premium?')" style="background:rgba(255,215,0,.07);border:1px solid rgba(255,215,0,.18);border-radius:99px;padding:4px 11px;color:#ffd700;font-size:10px;cursor:pointer;transition:all .15s;" onmouseover="this.style.background='rgba(255,215,0,.18)'" onmouseout="this.style.background='rgba(255,215,0,.07)'">⭐ Premium</button>
        <button onclick="openHelpWith('How do I use the API?')" style="background:rgba(0,255,136,.07);border:1px solid rgba(0,255,136,.18);border-radius:99px;padding:4px 11px;color:#00ff88;font-size:10px;cursor:pointer;transition:all .15s;" onmouseover="this.style.background='rgba(0,255,136,.18)'" onmouseout="this.style.background='rgba(0,255,136,.07)'">🔌 API docs</button>
        <button onclick="openHelpWith('I have a problem with my account.')" style="background:rgba(255,100,50,.07);border:1px solid rgba(255,100,50,.18);border-radius:99px;padding:4px 11px;color:#ff7744;font-size:10px;cursor:pointer;transition:all .15s;" onmouseover="this.style.background='rgba(255,100,50,.18)'" onmouseout="this.style.background='rgba(255,100,50,.07)'">🆘 Account</button>
      </div>
      <!-- Input -->
      <div style="padding:10px 12px 12px;display:flex;gap:8px;align-items:center;">
        <input id="ai-inp" type="text" placeholder="Ask anything..." maxlength="500"
          style="flex:1;padding:10px 14px;background:rgba(255,255,255,.05);border:1.5px solid rgba(255,255,255,.1);border-radius:10px;color:#fff;font-size:13px;outline:none;transition:border .2s;"
          onfocus="this.style.borderColor='rgba(0,200,255,.5)'" onblur="this.style.borderColor='rgba(255,255,255,.1)'"
          onkeydown="if(event.key==='Enter'&&!event.shiftKey){{event.preventDefault();sendAi();}}">
        <button onclick="sendAi()" id="ai-send-btn"
          style="width:38px;height:38px;padding:0;background:linear-gradient(135deg,#00c8ff,#007aaa);color:#fff;border:none;border-radius:10px;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;flex-shrink:0;box-shadow:0 2px 12px rgba(0,200,255,.3);"
          onmouseover="this.style.boxShadow='0 4px 20px rgba(0,200,255,.55)';this.style.transform='scale(1.05)'" onmouseout="this.style.boxShadow='0 2px 12px rgba(0,200,255,.3)';this.style.transform='scale(1)'">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><path d="M2 21l21-9L2 3v7l15 2-15 2v7z"/></svg>
        </button>
      </div>
    </div>
  </div>
 </div>
 <div style="display:flex;gap:6px;align-items:center;margin-left:auto;flex-shrink:0;">
  {('<a href="/login" style="font-weight:600;font-size:13px;color:rgba(255,255,255,.65);text-decoration:none;padding:7px 16px;border-radius:9px;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.03);transition:all .2s;" onmouseover="this.style.background=\'rgba(255,255,255,.09)\';this.style.color=\'#fff\'" onmouseout="this.style.background=\'rgba(255,255,255,.03)\';this.style.color=\'rgba(255,255,255,.65)\'">Log in</a><a href="/register" style="font-weight:700;font-size:13px;color:#000;text-decoration:none;padding:7px 18px;border-radius:9px;background:linear-gradient(135deg,#00c8ff,#0094cc);box-shadow:0 2px 14px rgba(0,200,255,.35);transition:all .2s;" onmouseover="this.style.boxShadow=\'0 4px 22px rgba(0,200,255,.55)\';this.style.transform=\'translateY(-1px)\'" onmouseout="this.style.boxShadow=\'0 2px 14px rgba(0,200,255,.35)\';this.style.transform=\'none\'">Sign up</a>' if not session.get('user_id') else '') if auth_page else nav_r}
 </div>
 {'<div class="hamburger" onclick="toggleMenu()"><span></span><span></span><span></span></div>' if not auth_page else ''}
</div>
</nav>
<div class="mob-menu" id="mm">
 {'<a href="/">Home</a><a href="/leaderboard">Leaderboard</a><a href="/api/v1/docs">API</a><a href="/premium" style="color:#ffd700;font-weight:700;">Premium</a>' if not auth_page else ''}
 {mob_r}
</div>
<div class="wrap">{alerts}{ad_html}{content}</div>
<footer style="background:var(--bg);border-top:1px solid var(--bd);margin-top:40px;padding:48px 0 0;">
<div style="max-width:1280px;margin:0 auto;padding:0 24px;">
  <div style="display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:40px;padding-bottom:40px;">

    <!-- About -->
    <div>
      <div style="font-size:20px;font-weight:900;color:var(--t);margin-bottom:16px;">
        <div style="display:inline-flex;align-items:center;gap:10px;"><div style="width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,#04080f,#0b1623);border:2px solid #00c8ff;box-shadow:0 0 12px rgba(0,200,255,0.35);display:flex;align-items:center;justify-content:center;flex-shrink:0;"><svg width="24" height="24" viewBox="0 0 64 64"><path d="M32 28c-4-8-12-14-20-14 2 4 3 8 2 12-3-2-6-2-8 0 2 1 4 3 4 6-4 0-7 2-8 5 3 0 6 1 8 3-1 3 0 6 2 8 2-2 5-3 8-2-1 3 0 6 2 8 2-3 6-5 10-5s8 2 10 5c2-2 3-5 2-8 3-1 6 0 8 2 2-2 3-5 2-8 2-2 5-3 8-3-1-3-4-5-8-5 0-3 2-5 4-6-2-2-5-2-8 0-1-4 0-8 2-12-8 0-16 6-20 14z" fill="#0a0a0a" stroke="#00c8ff" stroke-width="2"/><ellipse cx="22" cy="34" rx="2.5" ry="3" fill="#00c8ff"/><ellipse cx="42" cy="34" rx="2.5" ry="3" fill="#00c8ff"/></svg></div><span style="font-size:26px;font-weight:900;font-style:italic;color:#ffffff;filter:drop-shadow(0 0 10px rgba(255,255,255,0.5));letter-spacing:1px;">𝐙𝐞𝐫𝐨</span><span style="font-size:26px;font-weight:900;font-style:italic;color:#00c8ff;filter:drop-shadow(0 0 10px rgba(0,200,255,0.6));letter-spacing:1px;">𝐒𝐡𝐞𝐥𝐥</span></div>
      </div>
      <p style="font-size:13px;color:var(--s);line-height:1.8;margin-bottom:16px;max-width:300px;">
        ZeroShell is a fast and modern paste sharing platform for code, text, and configs. Share anything instantly with your team or the world.
      </p>
      <div style="font-size:12px;color:var(--s);margin-bottom:14px;">#1 Paste Site · Pastebin Alternative</div>
      <div id="footer-ai" style="max-width:280px;margin-bottom:16px;">
        <div id="footer-ai-box" style="display:none;background:#0b1623;border:1px solid var(--p);border-radius:10px;margin-bottom:8px;overflow:hidden;">
          <div style="padding:8px 12px;border-bottom:1px solid rgba(0,245,255,.15);display:flex;justify-content:space-between;align-items:center;">
            <span style="font-size:11px;font-weight:700;color:var(--p);">&#129302; ZeroShell AI</span>
            <span onclick="document.getElementById('footer-ai-box').style.display='none'" style="cursor:pointer;color:var(--s);font-size:14px;line-height:1;">&#215;</span>
          </div>
          <div id="footer-ai-msgs" style="height:160px;overflow-y:auto;padding:10px;display:flex;flex-direction:column;gap:7px;font-size:12px;"></div>
          <div style="padding:8px;border-top:1px solid rgba(0,245,255,.1);display:flex;gap:6px;">
            <input id="footer-ai-inp" placeholder="Ask anything..." style="flex:1;padding:6px 9px;font-size:12px;background:rgba(0,0,0,.4);border:1px solid rgba(0,245,255,.2);border-radius:6px;color:#c8e0f0;outline:none;" onkeydown="if(event.key==='Enter')zsAiSend()">
            <button onclick="zsAiSend()" style="background:var(--p);color:#000;border:none;border-radius:6px;padding:6px 11px;font-size:13px;font-weight:700;cursor:pointer;">&#8594;</button>
          </div>
        </div>
        <button onclick="var b=document.getElementById('footer-ai-box');b.style.display=(b.style.display==='none'||b.style.display==='')?'block':'none'" style="background:rgba(0,245,255,.08);border:1px solid rgba(0,245,255,.3);border-radius:8px;padding:7px 13px;color:var(--p);font-size:12px;font-weight:700;cursor:pointer;display:inline-flex;align-items:center;gap:6px;font-family:'Rajdhani',sans-serif;">&#129302; Ask AI Assistant</button>
      </div>
      <script>
      var zsAiHistory=[];
      function zsAiSend(){{
        var inp=document.getElementById('footer-ai-inp');
        var msgs=document.getElementById('footer-ai-msgs');
        var txt=inp.value.trim();
        if(!txt)return;
        inp.value='';
        var ub=document.createElement('div');
        ub.style.textAlign='right';
        ub.innerHTML='<span style="background:rgba(0,245,255,.12);border:1px solid rgba(0,245,255,.25);border-radius:7px 7px 2px 7px;padding:5px 9px;display:inline-block;max-width:90%;word-break:break-word;">'+txt+'</span>';
        msgs.appendChild(ub);
        zsAiHistory.push({{role:'user',content:txt}});
        var lb=document.createElement('div');
        lb.style.textAlign='left';
        lb.innerHTML='<span style="background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:7px 7px 7px 2px;padding:5px 9px;display:inline-block;color:#8899aa;">&#9203; Thinking...</span>';
        msgs.appendChild(lb);
        msgs.scrollTop=msgs.scrollHeight;
        fetch('/ai-chat',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{messages:zsAiHistory}})}})
          .then(function(r){{return r.json();}})
          .then(function(d){{
            var reply=d.reply||d.error||'Error';
            zsAiHistory.push({{role:'assistant',content:reply}});
            lb.innerHTML='<span style="background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:7px 7px 7px 2px;padding:5px 9px;display:inline-block;max-width:90%;word-break:break-word;line-height:1.5;">'+reply+'</span>';
            msgs.scrollTop=msgs.scrollHeight;
          }})
          .catch(function(){{lb.innerHTML='<span style="color:#ff2d55;">Error: Could not connect</span>';}});
      }}
      </script>
      <!-- Social icons -->
      <div style="display:flex;gap:10px;margin-top:4px;">
        <a href="https://t.me/ZeroShell" target="_blank" title="Telegram" style="width:42px;height:42px;background:#229ed918;border:1px solid #229ed944;border-radius:50%;display:flex;align-items:center;justify-content:center;text-decoration:none;transition:all .2s;" onmouseover="this.style.background='#229ed930';this.style.borderColor='#229ed9'" onmouseout="this.style.background='#229ed918';this.style.borderColor='#229ed944'">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="#229ed9"><path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.894 8.221l-1.97 9.28c-.145.658-.537.818-1.084.508l-3-2.21-1.447 1.394c-.16.16-.295.295-.605.295l.213-3.053 5.56-5.023c.242-.213-.054-.333-.373-.12l-6.871 4.326-2.962-.924c-.643-.204-.657-.643.136-.953l11.57-4.461c.537-.194 1.006.131.833.94z"/></svg>
        </a>
        <a href="https://discord.gg/9QMQWcCM" target="_blank" title="Discord" style="width:42px;height:42px;background:#5865f218;border:1px solid #5865f244;border-radius:50%;display:flex;align-items:center;justify-content:center;text-decoration:none;transition:all .2s;" onmouseover="this.style.background='#5865f230';this.style.borderColor='#5865f2'" onmouseout="this.style.background='#5865f218';this.style.borderColor='#5865f244'">
          <svg width="19" height="19" viewBox="0 0 24 24" fill="#5865f2"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057c.002.022.015.043.033.055a19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03z"/></svg>
        </a>

      </div>
    </div>

    <!-- Hub -->
    <div>
      <div style="font-size:13px;font-weight:800;color:var(--t);letter-spacing:.5px;margin-bottom:18px;text-transform:uppercase;">Hub</div>
      <div style="display:flex;flex-direction:column;gap:12px;">
        <a href="/" style="font-size:14px;color:var(--s);text-decoration:none;transition:color .15s;" onmouseover="this.style.color='var(--p)'" onmouseout="this.style.color='var(--s)'">ZeroShell</a>
        <a href="/pastes" style="font-size:14px;color:var(--s);text-decoration:none;transition:color .15s;" onmouseover="this.style.color='var(--p)'" onmouseout="this.style.color='var(--s)'">Paste Archive</a>
        <a href="/leaderboard" style="font-size:14px;color:var(--s);text-decoration:none;transition:color .15s;" onmouseover="this.style.color='var(--p)'" onmouseout="this.style.color='var(--s)'">Leaderboard</a>
        <a href="/premium" style="font-size:14px;color:#ffd700;text-decoration:none;font-weight:600;">Premium</a>
      </div>
    </div>

    <!-- Legal -->
    <div>
      <div style="font-size:13px;font-weight:800;color:var(--t);letter-spacing:.5px;margin-bottom:18px;text-transform:uppercase;">Community</div>
      <div style="display:flex;flex-direction:column;gap:12px;">
        <a href="https://t.me/ZeroShell" target="_blank" style="font-size:14px;color:var(--s);text-decoration:none;transition:color .15s;" onmouseover="this.style.color='#229ed9'" onmouseout="this.style.color='var(--s)'">Telegram</a>
        <a href="https://discord.gg/9QMQWcCM" target="_blank" style="font-size:14px;color:var(--s);text-decoration:none;transition:color .15s;" onmouseover="this.style.color='#5865f2'" onmouseout="this.style.color='var(--s)'">Discord</a>
      </div>
    </div>

    <!-- Useful Links -->
    <div>
      <div style="font-size:13px;font-weight:800;color:var(--t);letter-spacing:.5px;margin-bottom:18px;text-transform:uppercase;">Useful Links</div>
      <div style="display:flex;flex-direction:column;gap:12px;">
        <a href="/new" style="font-size:14px;color:var(--s);text-decoration:none;transition:color .15s;" onmouseover="this.style.color='var(--p)'" onmouseout="this.style.color='var(--s)'">New Paste</a>
        <a href="/pastes" style="font-size:14px;color:var(--s);text-decoration:none;transition:color .15s;" onmouseover="this.style.color='var(--p)'" onmouseout="this.style.color='var(--s)'">Paste Archive</a>
        <a href="/api/v1/docs" style="font-size:14px;color:var(--s);text-decoration:none;transition:color .15s;" onmouseover="this.style.color='var(--p)'" onmouseout="this.style.color='var(--s)'">API Documentation</a>
        <a href="/contact" style="font-size:14px;color:var(--s);text-decoration:none;transition:color .15s;" onmouseover="this.style.color='#ea4335'" onmouseout="this.style.color='var(--s)'">&#9993; Contact Us</a>
        <div style="display:flex;align-items:center;gap:7px;margin-top:4px;">
          <div style="width:8px;height:8px;background:#3fb950;border-radius:50%;box-shadow:0 0 6px #3fb95066;"></div>
          <span style="font-size:13px;color:var(--s);">All services are online</span>
        </div>
      </div>
    </div>

  </div>

  <!-- Bottom bar -->
  <div style="border-top:1px solid var(--bd);padding:20px 0;text-align:center;">
    <div style="display:flex;align-items:center;justify-content:center;gap:16px;flex-wrap:wrap;margin-bottom:10px;">
      <a href="https://t.me/ZeroShell" target="_blank" style="display:inline-flex;align-items:center;gap:6px;color:#229ed9;text-decoration:none;font-size:13px;font-weight:600;transition:opacity .2s;" onmouseover="this.style.opacity='.7'" onmouseout="this.style.opacity='1'">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="#229ed9"><path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.894 8.221l-1.97 9.28c-.145.658-.537.818-1.084.508l-3-2.21-1.447 1.394c-.16.16-.295.295-.605.295l.213-3.053 5.56-5.023c.242-.213-.054-.333-.373-.12l-6.871 4.326-2.962-.924c-.643-.204-.657-.643.136-.953l11.57-4.461c.537-.194 1.006.131.833.94z"/></svg>
        Telegram
      </a>
      <span style="color:var(--bd);">|</span>
      <a href="https://discord.gg/9QMQWcCM" target="_blank" style="display:inline-flex;align-items:center;gap:6px;color:#5865f2;text-decoration:none;font-size:13px;font-weight:600;transition:opacity .2s;" onmouseover="this.style.opacity='.7'" onmouseout="this.style.opacity='1'">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="#5865f2"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03z"/></svg>
        Discord
      </a>
      <span style="color:var(--bd);">|</span>
      <a href="mailto:zeroshellx@gmail.com" style="display:inline-flex;align-items:center;gap:6px;color:var(--s);text-decoration:none;font-size:13px;font-weight:600;transition:opacity .2s;" onmouseover="this.style.opacity='.7'" onmouseout="this.style.opacity='1'">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m2 7 10 7 10-7"/></svg>
        zeroshellx@gmail.com
      </a>
    </div>
    <span style="font-size:12px;color:var(--dim);">© 2026 ZeroShell. All Rights Reserved.</span>
  </div>
</div>
</footer>
</body></html>'''


@app.route('/contact')
def contact():
  c='''<div style="max-width:560px;margin:0 auto;">
<div style="background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:32px;text-align:center;">
  <div style="font-size:48px;margin-bottom:12px;">&#9993;</div>
  <div style="font-size:22px;font-weight:800;color:var(--t);margin-bottom:6px;">Contact Us</div>
  <div style="font-size:14px;color:var(--s);margin-bottom:24px;">Have questions or issues? Get in touch with us</div>
  <div style="display:flex;flex-direction:column;gap:12px;">
    <a href="mailto:zeroshellx@gmail.com" style="display:flex;align-items:center;gap:14px;padding:16px 20px;background:var(--bg);border:1px solid var(--bd);border-radius:12px;text-decoration:none;transition:border-color .15s;" onmouseover="this.style.borderColor='#ea4335'" onmouseout="this.style.borderColor='var(--bd)'">
      <div style="width:44px;height:44px;background:#ea433518;border:1px solid #ea433544;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none"><rect x="2" y="4" width="20" height="16" rx="2" fill="#ea433515" stroke="#ea4335" stroke-width="1.5"/><path d="M2 7l10 7 10-7" stroke="#ea4335" stroke-width="1.5"/></svg>
      </div>
      <div style="text-align:left;"><div style="font-size:14px;font-weight:700;color:var(--t);">Gmail</div><div style="font-size:12px;color:#ea4335;">zeroshellx@gmail.com</div></div>
    </a>
    <a href="mailto:zeroshellx@gmail.com" style="display:flex;align-items:center;gap:14px;padding:16px 20px;background:var(--bg);border:1px solid var(--bd);border-radius:12px;text-decoration:none;transition:border-color .15s;" onmouseover="this.style.borderColor='var(--p)'" onmouseout="this.style.borderColor='var(--bd)'">
      <div style="width:44px;height:44px;background:#ea433518;border:1px solid #ea433544;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ea4335" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m2 7 10 7 10-7"/></svg>
      <div style="text-align:left;"><div style="font-size:14px;font-weight:700;color:var(--t);">Email Support</div><div style="font-size:12px;color:#ea4335;">zeroshellx@gmail.com</div>
    </a>
    <a href="https://t.me/ZeroShell" target="_blank" style="display:flex;align-items:center;gap:14px;padding:16px 20px;background:var(--bg);border:1px solid var(--bd);border-radius:12px;text-decoration:none;transition:border-color .15s;" onmouseover="this.style.borderColor='#229ed9'" onmouseout="this.style.borderColor='var(--bd)'">
      <div style="width:48px;height:48px;border-radius:12px;background:#229ed918;border:1px solid #229ed944;display:flex;align-items:center;justify-content:center;flex-shrink:0;"><svg width="22" height="22" viewBox="0 0 24 24" fill="#229ed9"><path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.894 8.221l-1.97 9.28c-.145.658-.537.818-1.084.508l-3-2.21-1.447 1.394c-.16.16-.295.295-.605.295l.213-3.053 5.56-5.023c.242-.213-.054-.333-.373-.12l-6.871 4.326-2.962-.924c-.643-.204-.657-.643.136-.953l11.57-4.461c.537-.194 1.006.131.833.94z"/></svg></div>
      <div style="text-align:left;"><div style="font-size:14px;font-weight:700;color:var(--t);">Telegram</div><div style="font-size:12px;color:#229ed9;">t.me/ZeroShell</div></div>
    </a>
        <a href="https://discord.gg/9QMQWcCM" target="_blank" style="display:flex;align-items:center;gap:14px;padding:16px 20px;background:var(--bg);border:1px solid var(--bd);border-radius:12px;text-decoration:none;transition:border-color .15s;" onmouseover="this.style.borderColor='#5865f2'" onmouseout="this.style.borderColor='var(--bd)'">
      <div style="width:44px;height:44px;background:#5865f218;border:1px solid #5865f244;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="#5865f2"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057c.002.022.015.043.033.055a19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03z"/></svg>
      </div>
      <div style="text-align:left;"><div style="font-size:14px;font-weight:700;color:var(--t);">Discord</div><div style="font-size:12px;color:#5865f2;">discord.gg/9QMQWcCM</div></div>
    </a>
  </div>
  <div style="margin-top:20px;font-size:12px;color:var(--s);">We usually reply within 24 hours</div>
</div>
</div>'''
  return base(c,"Contact",session.get('theme','cyan'))

# ━━━ PWA Manifest & SW ━━━
@app.route('/robots.txt')
def robots():
  return Response(
    'User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /settings\nDisallow: /dashboard\nDisallow: /api/\nSitemap: https://zeroshell-paste.up.railway.app/sitemap.xml\n',
    mimetype='text/plain')

@app.route('/sitemap.xml')
def sitemap():
  base_url='https://zeroshell-paste.up.railway.app'
  db=get_db()
  pastes=db.execute("SELECT slug,created_at FROM pastes WHERE visibility='public' ORDER BY created_at DESC LIMIT 1000").fetchall()
  users=db.execute("SELECT username FROM users ORDER BY created_at DESC LIMIT 500").fetchall()
  db.close()
  static_urls=[('/',1.0,'daily'),('/trending',0.9,'hourly'),('/leaderboard',0.8,'daily'),('/pastes',0.8,'hourly'),('/premium',0.7,'weekly'),('/search',0.6,'weekly')]
  xml=['<?xml version="1.0" encoding="UTF-8"?>','<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
  for loc,pri,chg in static_urls:
    xml.append(f'<url><loc>{base_url}{loc}</loc><priority>{pri}</priority><changefreq>{chg}</changefreq></url>')
  for p in pastes:
    xml.append(f'<url><loc>{base_url}/paste/{p["slug"]}</loc><lastmod>{p["created_at"][:10]}</lastmod><priority>0.6</priority><changefreq>monthly</changefreq></url>')
  for u in users:
    xml.append(f'<url><loc>{base_url}/profile/{u["username"]}</loc><priority>0.5</priority><changefreq>weekly</changefreq></url>')
  xml.append('</urlset>')
  return Response('\n'.join(xml),mimetype='application/xml')

@app.route('/manifest.json')
def manifest():
  m={"name":"ZeroShell","short_name":"ZeroShell","description":"Paste sharing platform","start_url":"/","display":"standalone","background_color":"#04080f","theme_color":"#00f5ff","icons":[{"src":BAT_SVG_URL,"sizes":"any","type":"image/svg+xml"}]}
  return Response(json.dumps(m),mimetype='application/json')

@app.route('/sw.js')
def sw():
  sw_code="""
const CACHE='zeroshell-v7';
const OFFLINE=['/'];
self.addEventListener('install',e=>{
 e.waitUntil(caches.open(CACHE).then(c=>c.addAll(OFFLINE)));
 self.skipWaiting();
});
self.addEventListener('activate',e=>{
 e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))));
 self.clients.claim();
});
self.addEventListener('fetch',e=>{
 if(e.request.method!=='GET') return;
 e.respondWith(fetch(e.request).catch(()=>caches.match(e.request).then(r=>r||caches.match('/'))));
});
"""
  return Response(sw_code,mimetype='application/javascript')

# ━━━ PUBLIC API ━━━
def api_auth():
  key=request.headers.get('X-API-Key') or request.args.get('api_key','')
  if not key: return None
  db=get_db(); user=db.execute("SELECT * FROM users WHERE api_key=?",(key,)).fetchone(); db.close()
  return user


@app.route('/api/v1/docs')
def api_docs():
  base_url="https://zeroshell-paste.up.railway.app"
  c=f'''<div style="max-width:800px;margin:0 auto;">
<div style="font-size:18px;font-weight:700;color:var(--p);letter-spacing:2px;margin-bottom:20px;">🌐 ZeroShell Public API v1</div>
<div class="card">
<div style="font-size:13px;font-weight:700;color:var(--yellow);margin-bottom:10px;">Authentication</div>
<p style="font-size:12px;color:var(--dim);margin-bottom:8px;">Get your API key from Settings page. Pass as header or query param:</p>
<div class="code">X-API-Key: your_api_key_here
# or
{base_url}/api/v1/pastes?api_key=your_key</div></div>
<div class="card">
<div style="font-size:13px;font-weight:700;color:var(--green);margin-bottom:12px;">Endpoints</div>
<div style="margin-bottom:14px;"><span style="background:rgba(0,204,102,.15);border:1px solid var(--green);border-radius:4px;padding:2px 7px;font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--green);">GET</span> <code style="font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--p);margin-left:8px;">/api/v1/pastes</code>
<p style="font-size:11px;color:var(--dim);margin-top:4px;">List your pastes. Params: page, limit</p></div>
<div style="margin-bottom:14px;"><span style="background:rgba(0,204,102,.15);border:1px solid var(--green);border-radius:4px;padding:2px 7px;font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--green);">GET</span> <code style="font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--p);margin-left:8px;">/api/v1/paste/&lt;slug&gt;</code>
<p style="font-size:11px;color:var(--dim);margin-top:4px;">Get a specific paste by slug</p></div>
<div style="margin-bottom:14px;"><span style="background:rgba(41,121,255,.15);border:1px solid #2979ff;border-radius:4px;padding:2px 7px;font-family:'Share Tech Mono',monospace;font-size:11px;color:#2979ff;">POST</span> <code style="font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--p);margin-left:8px;">/api/v1/paste</code>
<p style="font-size:11px;color:var(--dim);margin-top:4px;">Create a new paste. Body: title, content, syntax, visibility, tags</p></div>
<div style="margin-bottom:14px;"><span style="background:rgba(255,45,85,.15);border:1px solid var(--red);border-radius:4px;padding:2px 7px;font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--red);">DELETE</span> <code style="font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--p);margin-left:8px;">/api/v1/paste/&lt;slug&gt;</code>
<p style="font-size:11px;color:var(--dim);margin-top:4px;">Delete a paste (owner only)</p></div>
<div><span style="background:rgba(0,204,102,.15);border:1px solid var(--green);border-radius:4px;padding:2px 7px;font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--green);">GET</span> <code style="font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--p);margin-left:8px;">/api/v1/me</code>
<p style="font-size:11px;color:var(--dim);margin-top:4px;">Get your profile info</p></div>
</div>
<div class="card">
<div style="font-size:12px;font-weight:700;color:var(--p);margin-bottom:8px;">Example Response</div>
<div class="code">{{"slug":"abc12345","title":"My Paste","syntax":"python","views":42,"created_at":"2025-01-01T00:00:00"}}</div>
</div></div>'''
  return base(c,"API Docs",session.get('theme','cyan'))

@app.route('/api/v1/me')
def api_me():
  user=api_auth()
  if not user: return jsonify({'error':'Unauthorized'}),401
  return jsonify({'id':user['id'],'username':user['username'],'email':user['email'],'total_views':user['total_views'],'created_at':user['created_at']})

@app.route('/api/v1/pastes')
def api_pastes():
  user=api_auth()
  if not user: return jsonify({'error':'Unauthorized'}),401
  page=max(1,int(request.args.get('page',1)))
  limit=min(50,int(request.args.get('limit',20)))
  offset=(page-1)*limit
  db=get_db()
  pastes=db.execute("SELECT slug,title,syntax,visibility,views,likes,created_at,tags FROM pastes WHERE user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?",(user['id'],limit,offset)).fetchall()
  total=db.execute("SELECT COUNT(*) FROM pastes WHERE user_id=?",(user['id'],)).fetchone()[0]
  db.close()
  return jsonify({'pastes':[dict(p) for p in pastes],'total':total,'page':page,'limit':limit})

@app.route('/api/v1/paste/<slug>')
def api_get_paste(slug):
  user=api_auth()
  db=get_db(); paste=db.execute("SELECT * FROM pastes WHERE slug=?",(slug,)).fetchone(); db.close()
  if not paste: return jsonify({'error':'Not found'}),404
  if paste['visibility']=='private' and (not user or user['id']!=paste['user_id']): return jsonify({'error':'Forbidden'}),403
  return jsonify({'slug':paste['slug'],'title':paste['title'],'content':paste['content'],'syntax':paste['syntax'],'visibility':paste['visibility'],'views':paste['views'],'likes':paste['likes'],'tags':paste['tags'],'created_at':paste['created_at']})

@app.route('/api/v1/paste',methods=['POST'])
def api_create_paste():
  user=api_auth()
  if not user: return jsonify({'error':'Unauthorized'}),401
  data=request.get_json() or {}
  title=str(data.get('title','')).strip()[:200]
  content=str(data.get('content','')).strip()
  syntax=str(data.get('syntax','text'))
  visibility=str(data.get('visibility','public'))
  tags=str(data.get('tags',''))[:200]
  if not title or not content: return jsonify({'error':'title and content required'}),400
  if visibility not in ('public','private'): visibility='public'
  slug=rand_slug()
  db=get_db(); db.execute("INSERT INTO pastes(slug,title,content,syntax,visibility,tags,user_id) VALUES(?,?,?,?,?,?,?)",(slug,title,content,syntax,visibility,tags,user['id'])); db.commit(); db.close()
  return jsonify({'slug':slug,'url':f'/paste/{slug}'}),201

@app.route('/api/v1/paste/<slug>',methods=['DELETE'])
def api_delete_paste(slug):
  user=api_auth()
  if not user: return jsonify({'error':'Unauthorized'}),401
  db=get_db(); p=db.execute("SELECT * FROM pastes WHERE slug=?",(slug,)).fetchone()
  if not p: db.close(); return jsonify({'error':'Not found'}),404
  if p['user_id']!=user['id']: db.close(); return jsonify({'error':'Forbidden'}),403
  db.execute("DELETE FROM pastes WHERE slug=?",(slug,)); db.commit(); db.close()
  return jsonify({'deleted':True})

# ━━━ TOGGLE MODE ━━━

# ━━━ ALL PASTES ━━━
@app.route('/pastes')
def all_pastes():
  page=max(1,int(request.args.get('page',1)))
  per=20; offset=(page-1)*per
  syntax=request.args.get('syntax','')
  db=get_db()
  if syntax:
    pastes=db.execute("SELECT p.*,u.username,u.avatar,u.is_premium FROM pastes p LEFT JOIN users u ON p.user_id=u.id WHERE p.visibility='public' AND p.syntax=? ORDER BY u.is_premium DESC,p.created_at DESC LIMIT ? OFFSET ?",(syntax,per,offset)).fetchall()
    total=db.execute("SELECT COUNT(*) FROM pastes WHERE visibility='public' AND syntax=?",(syntax,)).fetchone()[0]
  else:
    pastes=db.execute("SELECT p.*,u.username,u.avatar,u.is_premium FROM pastes p LEFT JOIN users u ON p.user_id=u.id WHERE p.visibility='public' ORDER BY u.is_premium DESC,p.created_at DESC LIMIT ? OFFSET ?",(per,offset)).fetchall()
    total=db.execute("SELECT COUNT(*) FROM pastes WHERE visibility='public'").fetchone()[0]
  db.close()
  pages=max(1,(total+per-1)//per)
  pl=''.join(f'<a href="/paste/{p["slug"]}" class="pi"><div><div class="pt">{"🔒 " if p["password"] else ""}{p["title"]}</div><div class="pm">{p["avatar"] or "👤"} {p["username"] or "Anon"} · {p["created_at"][:10]} · {p["syntax"]}</div></div><div class="pv">👁 {p["views"]}</div></a>' for p in pastes if not is_expired(p)) or '<div style="text-align:center;color:var(--dim);padding:24px;">No pastes!</div>'
  syn_opts='<option value="">All</option>'+"".join(f'<option value="{s}" {"selected" if syntax==s else ""}>{s}</option>' for s in ["python","javascript","html","css","bash","json","sql","text"])
  # pagination
  prev_btn=f'<a href="/pastes?page={page-1}&syntax={syntax}" class="btn btn-o">← Prev</a>' if page>1 else ''
  next_btn=f'<a href="/pastes?page={page+1}&syntax={syntax}" class="btn btn-o">Next →</a>' if page<pages else ''
  c=f'''<div style="max-width:860px;margin:0 auto;">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;flex-wrap:wrap;gap:10px;">
 <div>
  <div style="font-size:22px;font-weight:800;color:var(--text);">📝 All Pastes</div>
  <div style="font-size:12px;color:var(--dim);margin-top:2px;">{total} public pastes</div>
 </div>
 <form method="GET" style="display:flex;gap:7px;align-items:center;">
  <select name="syntax" style="width:auto;padding:6px 10px;font-size:13px;">{syn_opts}</select>
  <button type="submit" class="btn btn-o" style="font-size:12px;">Filter</button>
 </form>
</div>
<div class="card">{pl}</div>
<div style="display:flex;justify-content:space-between;align-items:center;margin-top:10px;">
 <div>{prev_btn}</div>
 <span style="font-size:12px;color:var(--dim);">Page {page} / {pages}</span>
 <div>{next_btn}</div>
</div>
</div>'''
  return base(c,"All Pastes",session.get('theme','cyan'))

# ━━━ ALL USERS (Premium Only) ━━━
@app.route('/users')
def all_users():
  q=request.args.get('q','').strip()
  db=get_db()
  if q:
    users=db.execute(
      "SELECT u.*,COUNT(p.id) as pc FROM users u LEFT JOIN pastes p ON u.id=p.user_id WHERE u.is_premium=1 AND u.username LIKE ? GROUP BY u.id ORDER BY u.total_views DESC",
      (f'%{q}%',)).fetchall()
  else:
    users=db.execute(
      "SELECT u.*,COUNT(p.id) as pc FROM users u LEFT JOIN pastes p ON u.id=p.user_id WHERE u.is_premium=1 GROUP BY u.id ORDER BY u.total_views DESC"
    ).fetchall()
  total_all=db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
  db.close()

  def _row(u):
    note=u['premium_note'] or 'Premium'
    bio_short=u['bio'][:50]+'...' if u['bio'] and len(u['bio'])>50 else (u['bio'] or '')
    tg_link=f'<a href="https://t.me/{u["telegram"]}" target="_blank" style="color:#229ed9;font-size:11px;text-decoration:none;">✈️ @{u["telegram"]}</a>' if u['telegram'] else ''
    return f'''<div style="display:flex;align-items:center;gap:14px;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-left:3px solid #ffd700;border-radius:10px;margin-bottom:8px;transition:all .15s;" onmouseover="this.style.transform='translateX(3px)'" onmouseout="this.style.transform='translateX(0)'">
<div style="font-size:30px;flex-shrink:0;filter:drop-shadow(0 0 6px #ffd70066);">{u["avatar"] or "👤"}</div>
<div style="flex:1;min-width:0;">
 <div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:3px;">
  <a href="/profile/{u["username"]}" style="color:var(--p);text-decoration:none;font-size:16px;font-weight:700;">{u["username"]}</a>
  <span style="background:linear-gradient(135deg,#ffd700,#ff8c00);color:#000;border-radius:99px;padding:1px 9px;font-size:10px;font-weight:800;letter-spacing:.5px;">VIP</span>
  {"<span style='background:rgba(63,185,80,.15);color:#3fb950;border:1px solid rgba(63,185,80,.3);border-radius:99px;padding:1px 7px;font-size:10px;font-weight:700;'> Verified</span>" if u["email_verified"] else ""}
 </div>
 <div style="font-size:12px;color:var(--dim);margin-bottom:3px;">{bio_short}</div>
 {tg_link}
</div>
<div style="text-align:right;flex-shrink:0;">
 <div style="font-family:monospace;color:var(--green);font-size:14px;font-weight:700;">👁 {u["total_views"]}</div>
 <div style="font-size:11px;color:var(--dim);margin-top:2px;">{u["pc"]} pastes</div>
</div>
</div>'''

  rows=''.join(_row(u) for u in users)
  empty=f'''<div style="text-align:center;padding:60px 20px;">
<div style="font-size:56px;margin-bottom:14px;">💎</div>
<div style="font-size:18px;font-weight:700;color:var(--text);margin-bottom:6px;">No Premium Members Yet</div>
<div style="font-size:13px;color:var(--dim);">Premium members will appear here.</div>
</div>'''

  c=f'''<div style="max-width:760px;margin:0 auto;">
<!-- Header -->
<div style="text-align:center;padding:28px 0 20px;">
 <div style="font-size:40px;margin-bottom:8px;">💎</div>
 <div style="font-size:26px;font-weight:800;color:var(--text);">Premium Members</div>
 <div style="font-size:13px;color:var(--dim);margin-top:5px;">{len(users)} premium · {total_all} total members</div>
</div>
<!-- Search -->
<form method="GET" style="display:flex;gap:8px;margin-bottom:18px;">
 <input name="q" value="{q}" placeholder="Search premium members..." style="flex:1;">
 <button type="submit" class="btn btn-o">🔍 Search</button>
</form>
<!-- Premium badge info -->
<div style="background:linear-gradient(135deg,rgba(255,215,0,.08),rgba(255,140,0,.06));border:1px solid rgba(255,215,0,.25);border-radius:10px;padding:12px 16px;margin-bottom:18px;display:flex;align-items:center;gap:10px;">
 <span style="font-size:20px;">💎</span>
 <div>
  <div style="font-size:13px;font-weight:700;color:#ffd700;">Premium Members</div>
  <div style="font-size:11px;color:var(--dim);">Verified members by Admin. Contact Admin to get a Premium badge.</div>
 </div>
 <a href="mailto:zeroshellx@gmail.com" class="btn" style="background:#ea4335;color:#fff;border-color:#ea4335;font-size:12px;margin-left:auto;flex-shrink:0;">✉️ Email</a>
</div>
<!-- List -->
{rows or empty}
</div>'''
  return base(c,"Premium Members",session.get('theme','cyan'))

# ━━━ AUTO VERIFY ━━━
PAYMENT_ADDRS={'USDT':'TBWUnddB2J5cckALZenPo6KQJwLzysEohE','BTC':'1N39KVvVK8itaGr7odbrTKnBdbwt4n7PoY','ETH':'0x4382fd71bd5a4d921c27d851764d8c76ccc5d143','LTC':'LcU6RqsSHQ8XUUP6xDEWDBWUts8wUe5adf'}
PLAN_PRICES={'3month':20,'6month':40,'lifetime':60}

def auto_verify_tx(coin,tx_hash,plan):
  import urllib.request,json as _j
  addr=PAYMENT_ADDRS.get(coin,''); expected=PLAN_PRICES.get(plan,0)
  try:
    if coin=='USDT':
      url=f"https://apilist.tronscanapi.com/api/transaction-info?hash={tx_hash}"
      with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'}),timeout=8) as r:
        d=_j.loads(r.read())
        for t in d.get('trc20TransferInfo',[]):
          if t.get('to_address','').lower()==addr.lower():
            amt=float(t.get('amount_str','0'))/1e6
            if amt>=expected*0.95: return True,amt
    elif coin=='BTC':
      url=f"https://blockstream.info/api/tx/{tx_hash}"
      with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'}),timeout=8) as r:
        d=_j.loads(r.read())
        for out in d.get('vout',[]):
          if out.get('scriptpubkey_address','').lower()==addr.lower(): return True,out.get('value',0)/1e8
    elif coin=='ETH':
      url=f"https://api.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash={tx_hash}"
      with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'}),timeout=8) as r:
        d=_j.loads(r.read()); res=d.get('result',{})
        if res and res.get('to','').lower()==addr.lower(): return True,int(res.get('value','0x0'),16)/1e18
    elif coin=='LTC':
      url=f"https://api.blockcypher.com/v1/ltc/main/txs/{tx_hash}"
      with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'}),timeout=8) as r:
        d=_j.loads(r.read())
        for out in d.get('outputs',[]):
          if addr in out.get('addresses',[]): return True,out.get('value',0)/1e8
  except: pass
  return False,0

# ━━━ SUBMIT PAYMENT ━━━
ADMIN_EMAIL='zeroshellx@gmail.com'

@app.route('/submit-payment',methods=['POST'])
def submit_payment():
  if not session.get('user_id'):
    flash('Please login first!','error'); return redirect('/login')
  uid=session['user_id']; plan=request.form.get('plan',''); coin=request.form.get('coin',''); tx=request.form.get('tx_hash','').strip()
  if not tx: flash('Please enter your transaction hash!','error'); return redirect('/premium')
  db=get_db()
  dup=db.execute("SELECT id FROM payment_requests WHERE tx_hash=?",(tx,)).fetchone()
  if dup: db.close(); flash('This TX has already been submitted!','error'); return redirect('/premium')
  verified,amount=auto_verify_tx(coin,tx,plan)
  username=session.get('user','?')
  user_email=db.execute("SELECT email FROM users WHERE id=?",(uid,)).fetchone()
  user_email=user_email['email'] if user_email else ''
  if verified:
    db.execute("INSERT INTO payment_requests(user_id,plan,coin,tx_hash,status,amount) VALUES(?,?,?,?,'approved',?)",(uid,plan,coin,tx,str(amount)))
    db.execute("UPDATE users SET is_premium=1,premium_note=? WHERE id=?",(plan,uid))
    db.execute("INSERT INTO notifications(user_id,message,link) VALUES(?,?,?)",(uid,'Payment verified! You are now a Premium Member!','/premium'))
    db.commit(); db.close()
    # ── Email to admin ──
    send_email(ADMIN_EMAIL,
      f'✅ [ZeroShell] Payment AUTO-VERIFIED — {username}',
      f'''<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#0d1117;color:#e6edf3;padding:32px;border-radius:12px;border:1px solid #30363d;">
<div style="font-size:22px;font-weight:800;color:#3fb950;margin-bottom:4px;">✅ Payment Auto-Verified!</div>
<div style="font-size:13px;color:#8b949e;margin-bottom:24px;">ZeroShell Premium Notification</div>
<table style="width:100%;border-collapse:collapse;font-size:14px;">
<tr><td style="padding:8px 0;color:#8b949e;width:120px;">User</td><td style="padding:8px 0;color:#f0f6fc;font-weight:700;">{username}</td></tr>
<tr><td style="padding:8px 0;color:#8b949e;">Email</td><td style="padding:8px 0;color:#f0f6fc;">{user_email or '—'}</td></tr>
<tr><td style="padding:8px 0;color:#8b949e;">Plan</td><td style="padding:8px 0;color:#ffd700;font-weight:700;">{plan.upper()}</td></tr>
<tr><td style="padding:8px 0;color:#8b949e;">Coin</td><td style="padding:8px 0;color:#f0f6fc;">{coin}</td></tr>
<tr><td style="padding:8px 0;color:#8b949e;">Amount</td><td style="padding:8px 0;color:#3fb950;font-weight:700;">{amount}</td></tr>
<tr><td style="padding:8px 0;color:#8b949e;">TX Hash</td><td style="padding:8px 0;font-family:monospace;font-size:12px;color:#79c0ff;word-break:break-all;">{tx}</td></tr>
</table>
<div style="margin-top:20px;padding:12px 16px;background:#161b22;border-radius:8px;border-left:4px solid #3fb950;font-size:13px;">
  User has been <strong style="color:#3fb950;">automatically granted Premium</strong>. No action needed.
</div>
<div style="margin-top:16px;text-align:center;">
  <a href="https://zeroshell-paste.up.railway.app/admin/payments" style="display:inline-block;padding:10px 24px;background:#3fb950;color:#000;font-weight:800;border-radius:8px;text-decoration:none;font-size:14px;">View Admin Panel →</a>
</div>
</div>''')
    flash('Payment auto-verified! You are now Premium! ','green')
  else:
    db.execute("INSERT INTO payment_requests(user_id,plan,coin,tx_hash,status) VALUES(?,?,?,?,'pending')",(uid,plan,coin,tx))
    for a in db.execute("SELECT id FROM users WHERE is_admin=1").fetchall():
      db.execute("INSERT INTO notifications(user_id,message,link) VALUES(?,?,?)",(a['id'],f"💳 New payment: {username} ({coin} · {plan})",'/admin/payments'))
    db.commit(); db.close()
    # ── Email to admin ──
    send_email(ADMIN_EMAIL,
      f'💳 [ZeroShell] New Payment Request — {username}',
      f'''<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#0d1117;color:#e6edf3;padding:32px;border-radius:12px;border:1px solid #30363d;">
<div style="font-size:22px;font-weight:800;color:#ffd700;margin-bottom:4px;">💳 New Payment Request</div>
<div style="font-size:13px;color:#8b949e;margin-bottom:24px;">Manual verification required</div>
<table style="width:100%;border-collapse:collapse;font-size:14px;">
<tr><td style="padding:8px 0;color:#8b949e;width:120px;">User</td><td style="padding:8px 0;color:#f0f6fc;font-weight:700;">{username}</td></tr>
<tr><td style="padding:8px 0;color:#8b949e;">Email</td><td style="padding:8px 0;color:#f0f6fc;">{user_email or '—'}</td></tr>
<tr><td style="padding:8px 0;color:#8b949e;">Plan</td><td style="padding:8px 0;color:#ffd700;font-weight:700;">{plan.upper()}</td></tr>
<tr><td style="padding:8px 0;color:#8b949e;">Coin</td><td style="padding:8px 0;color:#f0f6fc;">{coin}</td></tr>
<tr><td style="padding:8px 0;color:#8b949e;">TX Hash</td><td style="padding:8px 0;font-family:monospace;font-size:12px;color:#79c0ff;word-break:break-all;">{tx}</td></tr>
</table>
<div style="margin-top:20px;padding:12px 16px;background:#161b22;border-radius:8px;border-left:4px solid #ffd700;font-size:13px;color:#ffd700;">
  ⚠️ Auto-verification failed. Please check the TX manually and approve or reject.
</div>
<div style="margin-top:16px;text-align:center;">
  <a href="https://zeroshell-paste.up.railway.app/admin/payments" style="display:inline-block;padding:10px 24px;background:#ffd700;color:#000;font-weight:800;border-radius:8px;text-decoration:none;font-size:14px;">Review Payment →</a>
</div>
</div>''')
    flash('Submitted! Verifying on blockchain... Admin will confirm soon ⏳','green')
  return redirect('/premium')

# ━━━ ADMIN PAYMENTS ━━━
@app.route('/admin/payments')
def admin_payments():
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  reqs=db.execute("SELECT pr.*,u.username,u.email FROM payment_requests pr JOIN users u ON pr.user_id=u.id ORDER BY pr.created_at DESC").fetchall()
  db.close()
  def _row(r):
    status_col={'pending':'#ffd700','approved':'#3fb950','rejected':'#f85149'}.get(r['status'],'#7d8590')
    btns=''
    if r['status']=='pending':
      btns=f'<a href="/admin/approve-payment/{r["id"]}" class="btn btn-g" style="font-size:11px;padding:4px 10px;">Approve</a> <a href="/admin/reject-payment/{r["id"]}" class="btn btn-r" style="font-size:11px;padding:4px 10px;">Reject</a>'
    return f'<tr><td>{r["id"]}</td><td><a href="/profile/{r["username"]}" style="color:var(--p);">{r["username"]}</a></td><td style="color:#ffd700;">{r["plan"]}</td><td style="color:{status_col};">{r["coin"]}</td><td style="font-family:monospace;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;" title="{r["tx_hash"]}">{r["tx_hash"][:20]}...</td><td style="color:{status_col};font-weight:700;">{r["status"].upper()}</td><td>{r["created_at"][:16]}</td><td>{btns}</td></tr>'
  rows=''.join(_row(r) for r in reqs) or '<tr><td colspan=8 style="text-align:center;color:var(--dim);padding:24px;">No payment requests</td></tr>'
  c=f'''<div style="max-width:1000px;margin:0 auto;">
<div style="font-size:22px;font-weight:800;margin-bottom:18px;">&#128200; Payment Requests</div>
<div class="card" style="overflow-x:auto;">
<table class="at">
<thead><tr><th>ID</th><th>User</th><th>Plan</th><th>Coin</th><th>TX Hash</th><th>Status</th><th>Date</th><th>Action</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>
</div>'''
  return base(c,"Payments",session.get('theme','cyan'))

@app.route('/admin/approve-payment/<int:rid>')
def approve_payment(rid):
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  req=db.execute("SELECT * FROM payment_requests WHERE id=?",(rid,)).fetchone()
  if req:
    db.execute("UPDATE payment_requests SET status='approved' WHERE id=?",(rid,))
    db.execute("UPDATE users SET is_premium=1,premium_note=? WHERE id=?",(req['plan'],req['user_id']))
    db.execute("INSERT INTO notifications(user_id,message,link) VALUES(?,?,?)",(req['user_id'],'&#128142; Your Premium has been approved! Welcome to Premium!','/premium'))
    db.commit()
    admin_log(f'Approved payment #{rid} ({req["coin"]} {req["plan"]})',f'user_id={req["user_id"]}')
    flash(f'Payment approved! User is now Premium ','green')
  db.close()
  return redirect('/admin/payments')

@app.route('/admin/reject-payment/<int:rid>')
def reject_payment(rid):
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  req=db.execute("SELECT * FROM payment_requests WHERE id=?",(rid,)).fetchone()
  if req:
    db.execute("UPDATE payment_requests SET status='rejected' WHERE id=?",(rid,))
    db.execute("INSERT INTO notifications(user_id,message,link) VALUES(?,?,?)",(req['user_id'],'&#10060; Your payment request was rejected. Please try again with the correct TX hash.','/premium'))
    db.commit()
    admin_log(f'Rejected payment #{rid} ({req["coin"]} {req["plan"]})',f'user_id={req["user_id"]}')
    flash('Payment rejected.','green')
  db.close()
  return redirect('/admin/payments')


# ━━━ ADMIN LOGS PAGE ━━━
@app.route('/admin/logs')
def admin_logs_page():
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  logs=db.execute("SELECT * FROM admin_logs ORDER BY created_at DESC LIMIT 200").fetchall()
  db.close()
  action_icons={'Banned':'🔴','Unbanned':'🟢','Deleted':'🗑️','Approved':'✅','Rejected':'❌','Granted':'⭐','Removed':'⚠️','Made admin':'👑','IP Banned':'🚫','IP Unbanned':'✔️'}
  def icon_for(action):
    for k,v in action_icons.items():
      if k.lower() in action.lower(): return v
    return '📋'
  rows=''.join(
    f'<tr>'
    f'<td style="font-size:16px;text-align:center;">{icon_for(l["action"])}</td>'
    f'<td style="color:var(--p);font-weight:700;">{l["admin_username"]}</td>'
    f'<td style="font-size:12px;">{l["action"]}</td>'
    f'<td style="font-family:monospace;font-size:10px;color:var(--dim);">{l["target"]}</td>'
    f'<td style="font-family:monospace;font-size:10px;color:var(--dim);">{l["ip"]}</td>'
    f'<td style="font-size:10px;color:var(--dim);">{l["created_at"][:16]}</td>'
    f'</tr>'
    for l in logs
  ) or '<tr><td colspan=6 style="text-align:center;color:var(--dim);padding:24px;">No logs yet.</td></tr>'
  c=f'''<div style="max-width:1100px;margin:0 auto;">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
  <div style="font-size:22px;font-weight:800;">📋 Admin Logs</div>
  <div style="display:flex;gap:8px;"><a href="/admin/security" class="btn btn-o" style="font-size:12px;">🔒 Security</a><a href="/admin" class="btn btn-o" style="font-size:12px;">← Back</a></div>
</div>
<div class="card" style="overflow-x:auto;">
<table class="at">
<thead><tr><th></th><th>Admin</th><th>Action</th><th>Target</th><th>IP</th><th>Time</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div></div>'''
  return base(c,"Admin Logs",session.get('theme','cyan'))

# ━━━ SECURITY ADMIN PAGE ━━━
@app.route('/admin/security')
def admin_security():
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  banned_ips=db.execute("SELECT * FROM banned_ips ORDER BY created_at DESC").fetchall()
  # Login attempts — last 200, group suspicious IPs
  attempts=db.execute("SELECT * FROM login_attempts ORDER BY created_at DESC LIMIT 200").fetchall()
  # Suspicious IPs: 3+ fails in last hour
  susp=db.execute("""SELECT ip,COUNT(*) as fails,MAX(created_at) as last_seen
    FROM login_attempts WHERE success=0 AND created_at>datetime('now','-1 hour')
    GROUP BY ip HAVING fails>=3 ORDER BY fails DESC""").fetchall()
  db.close()
  # Banned IPs table
  brows=''.join(
    f'<tr>'
    f'<td style="font-family:monospace;color:var(--red);">{b["ip"]}</td>'
    f'<td style="font-size:12px;color:var(--dim);">{b["reason"] or "—"}</td>'
    f'<td style="font-size:11px;color:var(--dim);">{b["banned_by"]}</td>'
    f'<td style="font-size:11px;color:var(--dim);">{b["created_at"][:16]}</td>'
    f'<td><a href="/admin/unban-ip/{b["ip"]}" class="btn" style="font-size:9px;padding:2px 7px;background:rgba(63,185,80,.15);border-color:#3fb950;color:#3fb950;">Unban</a></td>'
    f'</tr>'
    for b in banned_ips
  ) or '<tr><td colspan=5 style="text-align:center;color:var(--dim);padding:16px;">No banned IPs.</td></tr>'
  # Suspicious IPs
  srows=''.join(
    f'<tr>'
    f'<td style="font-family:monospace;color:var(--yellow);">{s["ip"]}</td>'
    f'<td style="color:var(--red);font-weight:700;">{s["fails"]} fails</td>'
    f'<td style="font-size:11px;color:var(--dim);">{s["last_seen"][:16]}</td>'
    f'<td><form method="POST" action="/admin/ban-ip" style="display:inline;margin:0;">'
    f'<input type="hidden" name="ip" value="{s["ip"]}">'
    f'<input type="hidden" name="reason" value="Brute force detected">'
    f'<button type="submit" class="btn btn-r" style="font-size:9px;padding:2px 7px;">Ban IP</button>'
    f'</form></td>'
    f'</tr>'
    for s in susp
  ) or '<tr><td colspan=4 style="text-align:center;color:var(--dim);padding:16px;">No suspicious activity.</td></tr>'
  # Login attempts log
  arows=''.join(
    f'<tr>'
    f'<td style="font-family:monospace;font-size:11px;color:{"var(--red)" if not a["success"] else "var(--green)"};">{a["ip"]}</td>'
    f'<td style="font-size:12px;">{a["username"] or "—"}</td>'
    f'<td style="font-size:12px;">{"✅ Success" if a["success"] else "❌ Failed"}</td>'
    f'<td style="font-size:11px;color:var(--dim);">{a["created_at"][:16]}</td>'
    f'</tr>'
    for a in attempts
  ) or '<tr><td colspan=4 style="text-align:center;color:var(--dim);padding:16px;">No attempts logged.</td></tr>'
  c=f'''<div style="max-width:1100px;margin:0 auto;">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:8px;">
  <div style="font-size:22px;font-weight:800;">🔒 Security Center</div>
  <a href="/admin" class="btn btn-o" style="font-size:12px;">← Back</a>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;">
  <div class="card"><div style="font-size:28px;font-weight:900;color:var(--red);">{len(banned_ips)}</div><div style="font-size:11px;color:var(--dim);">Banned IPs</div></div>
  <div class="card"><div style="font-size:28px;font-weight:900;color:var(--yellow);">{len(susp)}</div><div style="font-size:11px;color:var(--dim);">Suspicious IPs (1h)</div></div>
</div>

<!-- Manual IP ban form -->
<div class="card" style="margin-bottom:14px;">
<div style="font-size:13px;font-weight:700;color:var(--p);margin-bottom:12px;">🚫 Ban an IP Manually</div>
<form method="POST" action="/admin/ban-ip" style="display:flex;gap:8px;flex-wrap:wrap;">
  <input name="ip" placeholder="IP address (e.g. 1.2.3.4)" style="flex:1;min-width:180px;">
  <input name="reason" placeholder="Reason (optional)" style="flex:2;min-width:200px;">
  <button type="submit" class="btn btn-r" style="font-size:12px;padding:8px 18px;">Ban IP</button>
</form>
</div>

<div class="card" style="margin-bottom:14px;">
<div style="font-size:12px;font-weight:700;color:var(--red);margin-bottom:8px;">🔴 Banned IPs ({len(banned_ips)})</div>
<div style="overflow-x:auto;"><table class="at">
<thead><tr><th>IP</th><th>Reason</th><th>Banned By</th><th>Date</th><th></th></tr></thead>
<tbody>{brows}</tbody>
</table></div></div>

<div class="card" style="margin-bottom:14px;">
<div style="font-size:12px;font-weight:700;color:var(--yellow);margin-bottom:8px;">⚠️ Suspicious IPs — Brute Force (last 1h)</div>
<div style="overflow-x:auto;"><table class="at">
<thead><tr><th>IP</th><th>Failed Attempts</th><th>Last Seen</th><th></th></tr></thead>
<tbody>{srows}</tbody>
</table></div></div>

<div class="card">
<div style="font-size:12px;font-weight:700;color:var(--p);margin-bottom:8px;">📋 Recent Login Attempts (200)</div>
<div style="overflow-x:auto;"><table class="at">
<thead><tr><th>IP</th><th>Username</th><th>Result</th><th>Time</th></tr></thead>
<tbody>{arows}</tbody>
</table></div></div>
</div>'''
  return base(c,'Security Center',session.get('theme','cyan'))

@app.route('/admin/ban-ip', methods=['POST'])
def admin_ban_ip():
  if not session.get('is_admin'): return redirect('/')
  ip=request.form.get('ip','').strip()
  reason=request.form.get('reason','').strip()
  if not ip: flash('IP required!','error'); return redirect('/admin/security')
  try:
    db=get_db()
    db.execute("INSERT OR IGNORE INTO banned_ips(ip,reason,banned_by) VALUES(?,?,?)",(ip,reason,session.get('user','')))
    db.commit(); db.close()
    admin_log(f'IP Banned: {ip}',reason)
    flash(f'IP {ip} banned.','green')
  except Exception as e:
    flash(f'Error: {e}','error')
  return redirect('/admin/security')

@app.route('/admin/unban-ip/<ip>')
def admin_unban_ip(ip):
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  db.execute("DELETE FROM banned_ips WHERE ip=?",(ip,))
  db.commit(); db.close()
  admin_log(f'IP Unbanned: {ip}','')
  flash(f'IP {ip} unbanned.','green')
  return redirect('/admin/security')

# ━━━ BACKUP ROUTES ━━━
@app.route('/admin/otp-debug')
def admin_otp_debug():
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  otps=db.execute("SELECT * FROM email_otps ORDER BY created_at DESC LIMIT 50").fetchall()
  db.close()
  rows=''.join(
    f'<tr>'
    f'<td style="font-family:monospace;color:var(--p);">{o["email"]}</td>'
    f'<td style="font-family:monospace;font-size:20px;font-weight:900;color:#ffd700;letter-spacing:4px;">{o["otp"]}</td>'
    f'<td style="color:var(--dim);font-size:11px;">{o["action"]}</td>'
    f'<td style="color:var(--dim);font-size:11px;">{o["created_at"][:19]}</td>'
    f'<td style="color:{"#3fb950" if not o["used"] else "var(--dim)"};font-size:11px;">{"✅ Active" if not o["used"] else "Used"}</td>'
    f'</tr>'
    for o in otps
  ) or '<tr><td colspan=5 style="text-align:center;padding:24px;color:var(--dim);">No OTPs found.</td></tr>'
  c=f'''<div style="max-width:900px;margin:0 auto;">
<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
  <a href="/admin" style="color:var(--dim);text-decoration:none;font-size:13px;">← Admin</a>
  <div style="font-size:18px;font-weight:800;color:var(--t);">🔑 OTP Debug Panel</div>
</div>
<div class="card" style="background:rgba(255,215,0,.05);border-color:rgba(255,215,0,.2);">
  <div style="font-size:12px;color:#ffd700;margin-bottom:12px;">⚠️ This panel shows OTPs when email is not configured. Remove or restrict this in production!</div>
  <div style="overflow-x:auto;">
  <table class="at"><tr><th>Email</th><th>OTP Code</th><th>Type</th><th>Created</th><th>Status</th></tr>
  {rows}
  </table>
  </div>
</div>
</div>'''
  return base(c,'OTP Debug',session.get('theme','cyan'))

@app.route('/admin/backups')
def admin_backups():
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  bkps=db.execute("SELECT * FROM backups ORDER BY created_at DESC LIMIT 50").fetchall()
  db.close()
  rows=''.join(
    f'<tr>'
    f'<td style="font-family:monospace;font-size:11px;">{b["filename"]}</td>'
    f'<td style="color:var(--green);">{b["size"]//1024} KB</td>'
    f'<td style="color:var(--dim);font-size:11px;">{b["created_at"][:16]}</td>'
    f'<td><a href="/admin/backups/download/{b["filename"]}" class="btn btn-o" style="font-size:10px;padding:3px 8px;">⬇ Download</a></td>'
    f'</tr>'
    for b in bkps
  ) or '<tr><td colspan=4 style="text-align:center;color:var(--dim);padding:24px;">No backups yet.</td></tr>'
  db_size=os.path.getsize(DB)//1024 if os.path.exists(DB) else 0
  c=f'''<div style="max-width:900px;margin:0 auto;">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
  <div style="font-size:22px;font-weight:800;">💾 Database Backups</div>
  <div style="display:flex;gap:8px;">
    <form method="POST" action="/admin/backups/run" style="margin:0;">
      <button type="submit" class="btn btn-p" style="font-size:12px;">▶ Run Backup Now</button>
    </form>
    <a href="/admin" class="btn btn-o" style="font-size:12px;">← Back</a>
  </div>
</div>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:18px;">
  <div class="sb"><span class="sn" style="color:var(--p);">{db_size} KB</span><span class="sl">DB Size</span></div>
  <div class="sb"><span class="sn" style="color:var(--green);">{len(bkps)}</span><span class="sl">Backups</span></div>
  <div class="sb"><span class="sn" style="color:var(--yellow);">Daily</span><span class="sl">Auto Schedule</span></div>
</div>
<div class="card" style="overflow-x:auto;">
<table class="at">
<thead><tr><th>Filename</th><th>Size</th><th>Created</th><th>Action</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>
<div style="margin-top:12px;padding:12px 16px;background:rgba(0,245,255,.05);border:1px solid rgba(0,245,255,.15);border-radius:8px;font-size:12px;color:var(--dim);">
  💡 Backups auto-run every 24 hours. Files saved to <code style="color:var(--p);">{BACKUP_DIR}/</code> · Kept for {BACKUP_KEEP_DAYS} days.
</div>
</div>'''
  return base(c,"Backups",session.get('theme','cyan'))

@app.route('/admin/backups/run',methods=['POST'])
def run_backup():
  if not session.get('is_admin'): return redirect('/')
  fname,size=do_backup()
  if fname:
    admin_log(f'Manual backup created: {fname}',f'size={size//1024}KB')
    flash(f'✅ Backup created: {fname} ({size//1024} KB)','green')
  else:
    flash('❌ Backup failed! Check server logs.','red')
  return redirect('/admin/backups')

@app.route('/admin/backups/download/<filename>')
def download_backup(filename):
  if not session.get('is_admin'): return redirect('/')
  # Security: only alphanumeric, underscore, dot — no path traversal
  if not re.match(r'^[\w\-.]+\.db$',filename): return redirect('/admin/backups')
  fpath=os.path.join(BACKUP_DIR,filename)
  if not os.path.exists(fpath): flash('File not found!','red'); return redirect('/admin/backups')
  with open(fpath,'rb') as f:
    data=f.read()
  admin_log(f'Downloaded backup: {filename}','')
  return Response(data,mimetype='application/octet-stream',
    headers={'Content-Disposition':f'attachment; filename="{filename}"'})


@app.route('/announcements')
def announcements():
  db=get_db()
  ads=db.execute("SELECT * FROM ads WHERE active=1 ORDER BY created_at DESC").fetchall()
  db.close()
  def _ann(a):
    return f'''<div class="card">
<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;flex-wrap:wrap;">
 <div style="font-size:16px;font-weight:700;color:var(--p);">📢 {a["title"]}</div>
 <div style="font-size:10px;color:var(--dim);font-family:monospace;flex-shrink:0;">{a["created_at"][:10]}</div>
</div>
<div style="font-size:13px;color:var(--text);margin:8px 0;line-height:1.6;">{a["content"]}</div>
{f'<a href="{a["url"]}" target="_blank" class="btn btn-o" style="font-size:12px;">🔗 Learn more</a>' if a["url"] else ""}
</div>'''
  rows=''.join(_ann(a) for a in ads) or '<div style="text-align:center;padding:48px;color:var(--dim);"><div style="font-size:48px;margin-bottom:10px;">📢</div><div>No announcements yet.</div></div>'
  c=f'''<div style="max-width:760px;margin:0 auto;">
<div style="text-align:center;padding:24px 0 20px;">
 <div style="font-size:36px;margin-bottom:8px;">📢</div>
 <div style="font-size:24px;font-weight:800;color:var(--text);">Announcements</div>
 <div style="font-size:13px;color:var(--dim);margin-top:4px;">Latest news from ZeroShell</div>
</div>
{rows}
<div style="text-align:center;margin-top:20px;">
 <a href="mailto:zeroshellx@gmail.com" class="btn" style="background:#ea4335;color:#fff;border-color:#ea4335;font-size:13px;padding:8px 20px;">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="white" style="flex-shrink:0;"><path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.894 8.221l-1.97 9.28c-.145.658-.537.818-1.084.508l-3-2.21-1.447 1.394c-.16.16-.295.295-.605.295l.213-3.053 5.56-5.023c.242-.213-.054-.333-.373-.12l-6.871 4.326-2.962-.924c-.643-.204-.657-.643.136-.953l11.57-4.461c.537-.194 1.006.131.833.941z"/></svg>
  Join Telegram for live updates
 </a>
</div>
</div>'''
  return base(c,"Announcements",session.get('theme','cyan'))


# ━━━ PREMIUM PAGE ━━━
@app.route('/premium')
def premium_page():
  uid=session.get('user_id')
  is_prem=False
  if uid:
    db=get_db(); u=db.execute("SELECT is_premium,premium_note FROM users WHERE id=?",(uid,)).fetchone(); db.close()
    is_prem = u and u['is_premium']
  db2=get_db(); prem_count=db2.execute("SELECT COUNT(*) FROM users WHERE is_premium=1").fetchone()[0]; db2.close()

  plans=[
    {"label":"3 MONTHS","price":"$20","period":"/ 3 months","dur":"3 Months","color":"#3fb950","icon":"plant","perks":["VIP Badge","10 posts/day","Glowing pastes","5 profile links","Premium banner"]},
    {"label":"6 MONTHS","price":"$40","period":"/ 6 months","dur":"6 Months","color":"#00f5ff","icon":"bolt","perks":["VIP Badge","10 posts/day","Glowing pastes","5 profile links","Premium banner","Save $20!"],"pop":True},
    {"label":"LIFETIME","price":"$60","period":"/ forever","dur":"Lifetime","color":"#ffd700","icon":"crown","perks":["VIP Badge FOREVER","10 posts/day","Glowing pastes","5 profile links","Premium banner","Best Value!"]},
  ]

  def plan_card(p):
    pop=p.get('pop',False)
    pop_badge='<div style="position:absolute;top:-13px;left:50%;transform:translateX(-50%);background:var(--p);color:#000;font-size:10px;font-weight:800;padding:3px 14px;border-radius:99px;letter-spacing:1px;white-space:nowrap;">MOST POPULAR</div>' if pop else ''
    ic={'plant':'&#127807;','bolt':'&#9889;','crown':'&#128081;','star':'&#9733;'}.get(p['icon'],'&#9733;')
    perks=''.join(f'<div style="display:flex;align-items:center;gap:6px;padding:4px 0;font-size:12px;"><span style="color:{p["color"]};">&#10003;</span> {k}</div>' for k in p['perks'])
    bdr=f'border-color:{p["color"]};box-shadow:0 0 24px {p["color"]}22;' if pop else ''
    return f'<div style="position:relative;background:var(--card);border:2px solid var(--border);{bdr}border-radius:14px;padding:28px 22px;text-align:center;transition:transform .2s;" onmouseover="this.style.transform=\'translateY(-4px)\'" onmouseout="this.style.transform=\'translateY(0)\'">{pop_badge}<div style="font-size:36px;margin-bottom:8px;">{ic}</div><div style="font-size:11px;font-weight:800;color:{p["color"]};letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;">{p["label"]}</div><div style="font-size:44px;font-weight:800;color:var(--text);line-height:1;">{p["price"]}</div><div style="font-size:12px;color:var(--dim);margin-bottom:18px;">{p["period"]}</div><div style="border-top:1px solid var(--border);padding-top:14px;margin-bottom:18px;text-align:left;">{perks}</div><a href="mailto:zeroshellx@gmail.com" class="btn" style="width:100%;justify-content:center;background:{p["color"]};color:#000;border-color:{p["color"]};font-weight:800;font-size:13px;padding:10px;display:flex;">Get {p["dur"]}</a></div>'

  cards=''.join(plan_card(p) for p in plans)

  # coin cards
  COINS=[('USDT','TBWUnddB2J5cckALZenPo6KQJwLzysEohE','TRC20 · Tron','#26a17b'),('BTC','1N39KVvVK8itaGr7odbrTKnBdbwt4n7PoY','Bitcoin','#f7931a'),('ETH','0x4382fd71bd5a4d921c27d851764d8c76ccc5d143','ERC20 · Ethereum','#627eea'),('LTC','LcU6RqsSHQ8XUUP6xDEWDBWUts8wUe5adf','Litecoin','#bfbbbb')]
  coin_cards=''.join(
    '<div style="background:var(--card);border:1px solid var(--border);border-top:3px solid '+cl+';border-radius:12px;padding:16px;text-align:center;">'
    '<div style="font-size:14px;font-weight:800;color:'+cl+';margin-bottom:10px;">'+cn+'</div>'
    '<img src="https://api.qrserver.com/v1/create-qr-code/?size=140x140&data='+addr+'" style="width:120px;height:120px;border-radius:6px;background:#fff;padding:5px;margin-bottom:8px;" loading="lazy">'
    '<div style="font-size:10px;color:var(--dim);margin-bottom:6px;">'+net+'</div>'
    '<div style="background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:6px;font-family:monospace;font-size:10px;word-break:break-all;margin-bottom:8px;">'+addr+'</div>'
    '<button onclick="navigator.clipboard.writeText(\''+addr+'\').then(()=>{this.textContent=\'Copied!\';setTimeout(()=>this.textContent=\'Copy\',1500)})" style="background:'+cl+';color:#000;border:none;border-radius:6px;padding:6px 14px;font-size:12px;font-weight:700;cursor:pointer;width:100%;">Copy</button></div>'
    for cn,addr,net,cl in COINS)

  already=''
  if is_prem:
    already='<div style="background:linear-gradient(135deg,#3d2b00,#5a3f00);border:2px solid #ffd700;border-radius:14px;padding:18px 22px;margin-bottom:24px;display:flex;align-items:center;gap:16px;"><div style="font-size:36px;">&#128081;</div><div><div style="font-weight:800;color:#ffd700;font-size:17px;">You are a Premium Member!</div><div style="font-size:13px;color:rgba(255,255,255,.7);margin-top:3px;">Thank you for your support!</div></div></div>'

  pay_form=''
  if uid and not is_prem:
    pay_form='''<div id="pay" style="background:linear-gradient(135deg,#0a1520,#0d2035);border:1px solid rgba(0,245,255,.2);border-radius:16px;padding:24px;margin-bottom:22px;">
<div style="font-size:18px;font-weight:800;color:#fff;margin-bottom:6px;">Submit Payment</div>
<div style="font-size:13px;color:rgba(255,255,255,.55);margin-bottom:18px;">Pay to the address, enter TxID, auto verify will happen!</div>
<form method="POST" action="/submit-payment">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">
<div><label style="color:rgba(255,255,255,.6);font-size:11px;font-weight:700;display:block;margin-bottom:5px;letter-spacing:.5px;">PLAN</label>
<select name="plan" style="background:#0a1525;border:1px solid rgba(0,245,255,.25);border-radius:8px;color:#fff;padding:9px 12px;width:100%;font-size:13px;outline:none;">
<option value="3month">3 Months - $20</option>
<option value="6month">6 Months - $40</option>
<option value="lifetime">Lifetime - $60</option>
</select></div>
<div><label style="color:rgba(255,255,255,.6);font-size:11px;font-weight:700;display:block;margin-bottom:5px;letter-spacing:.5px;">COIN</label>
<select name="coin" style="background:#0a1525;border:1px solid rgba(0,245,255,.25);border-radius:8px;color:#fff;padding:9px 12px;width:100%;font-size:13px;outline:none;">
<option value="USDT">USDT (TRC20)</option>
<option value="BTC">BTC (Bitcoin)</option>
<option value="ETH">ETH (ERC20)</option>
<option value="LTC">LTC (Litecoin)</option>
</select></div>
</div>
<div style="margin-bottom:14px;"><label style="color:rgba(255,255,255,.6);font-size:11px;font-weight:700;display:block;margin-bottom:5px;letter-spacing:.5px;">TRANSACTION HASH / TxID</label>
<input type="text" name="tx_hash" placeholder="Paste your TxID here..." required style="background:#0a1525;border:1px solid rgba(0,245,255,.25);border-radius:8px;color:#fff;padding:10px 14px;width:100%;font-size:13px;outline:none;">
<div style="font-size:11px;color:rgba(255,255,255,.35);margin-top:5px;">Copy TxID from your blockchain explorer</div>
</div>
<button type="submit" style="width:100%;padding:13px;background:linear-gradient(135deg,#00c8ff,#0066cc);color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:800;cursor:pointer;letter-spacing:.5px;">Verify &amp; Get Premium</button>
</form></div>'''
  login_note='' if uid else '<div style="background:#1a2030;border:1px solid #ffd70044;border-radius:10px;padding:12px 16px;margin-bottom:16px;font-size:13px;color:#ffd700;"><a href="/login" style="color:#ffd700;font-weight:800;">Login</a> then submit your payment.</div>'
  c=f'''<div style="max-width:1000px;margin:0 auto;padding:20px 0 40px;">

<div style="text-align:center;padding:28px 20px 22px;margin-bottom:24px;">
<div style="font-size:11px;font-weight:800;color:#ffd700;letter-spacing:4px;text-transform:uppercase;margin-bottom:8px;">ZEROSHELL PREMIUM</div>
<div style="font-size:32px;font-weight:900;color:#fff;margin-bottom:6px;">Upgrade Your Account</div>
<div style="font-size:14px;color:rgba(255,255,255,.4);">{prem_count} active premium members</div>
</div>

{already}

<!-- 3 plan cards in 1 row -->
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:28px;">
{cards}
</div>

<!-- 4 crypto QR cards in one row -->
<div style="font-size:18px;font-weight:800;color:#fff;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid rgba(255,255,255,.08);">Pay with Crypto</div>
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px;">
{coin_cards}
</div>

{login_note}
{pay_form}

<!-- How it works -->
<div style="background:rgba(0,245,255,.04);border:1px solid rgba(0,245,255,.12);border-radius:12px;padding:18px;margin-bottom:20px;">
  <div style="font-size:14px;font-weight:800;color:#00f5ff;margin-bottom:14px;">How it works</div>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;text-align:center;">
    <div style="padding:14px;background:rgba(255,255,255,.04);border-radius:10px;"><div style="font-size:22px;font-weight:900;color:#fff;margin-bottom:6px;">1</div><div style="font-size:12px;font-weight:700;color:#fff;margin-bottom:3px;">Choose Plan</div><div style="font-size:11px;color:rgba(255,255,255,.4);">3M / 6M / 1Y / LT</div></div>
    <div style="padding:14px;background:rgba(255,255,255,.04);border-radius:10px;"><div style="font-size:22px;font-weight:900;color:#fff;margin-bottom:6px;">2</div><div style="font-size:12px;font-weight:700;color:#fff;margin-bottom:3px;">Send Crypto</div><div style="font-size:11px;color:rgba(255,255,255,.4);">Scan QR or copy address</div></div>
    <div style="padding:14px;background:rgba(255,255,255,.04);border-radius:10px;"><div style="font-size:22px;font-weight:900;color:#fff;margin-bottom:6px;">3</div><div style="font-size:12px;font-weight:700;color:#fff;margin-bottom:3px;">Enter TxID</div><div style="font-size:11px;color:rgba(255,255,255,.4);">Paste in the form</div></div>
    <div style="padding:14px;background:rgba(0,245,255,.08);border-radius:10px;border:1px solid rgba(0,245,255,.2);"><div style="font-size:18px;font-weight:900;color:#00f5ff;margin-bottom:6px;">Auto</div><div style="font-size:12px;font-weight:800;color:#00f5ff;margin-bottom:3px;">Verified!</div><div style="font-size:11px;color:rgba(255,255,255,.4);">Instant Premium</div></div>
  </div>
  <div style="text-align:center;margin-top:12px;font-size:11px;color:rgba(255,255,255,.25);">Help: <a href="mailto:zeroshellx@gmail.com" style="color:#ea4335;">zeroshellx@gmail.com</a></div>
</div>
</div>'''
  return base(c,"Premium",session.get('theme','cyan'))


# ━━━ AI SUMMARY ━━━

# ━━━ AI CHAT ━━━
@app.route('/ai-chat', methods=['POST'])
def ai_chat():
  data = request.get_json() or {}
  messages = data.get('messages', [])
  if not messages: return jsonify({'error': 'No messages'}), 400
  messages = messages[-10:]
  api_key = os.environ.get('ANTHROPIC_API_KEY', '')
  if not api_key:
    return jsonify({'reply': 'AI is not configured. Please set ANTHROPIC_API_KEY.'})
  try:
    payload = json.dumps({
      "model": "claude-haiku-4-5-20251001",
      "max_tokens": 300,
      "system": "You are ZeroShell AI, a helpful assistant for ZeroShell paste site. Help users with coding, text, and general questions. Be concise and friendly.",
      "messages": [{"role": m['role'], "content": str(m['content'])[:1000]} for m in messages if m.get('role') in ('user','assistant')]
    }).encode()
    req = urllib.request.Request(
      "https://api.anthropic.com/v1/messages",
      data=payload,
      headers={"Content-Type":"application/json","x-api-key":api_key,"anthropic-version":"2023-06-01"},
      method='POST'
    )
    with urllib.request.urlopen(req, timeout=15) as r:
      resp = json.loads(r.read())
      reply = resp['content'][0]['text']
  except Exception as e:
    reply = "Sorry, I couldn't process that. Please try again!"
  return jsonify({'reply': reply})

# ━━━ DIFF TOOL ━━━
@app.route('/diff',methods=['GET','POST'])
def diff_tool():
  result=''
  a_text=request.form.get('a','')
  b_text=request.form.get('b','')
  slug_a=request.args.get('a','')
  slug_b=request.args.get('b','')
  if slug_a and slug_b and request.method=='GET':
    db=get_db()
    pa=db.execute("SELECT * FROM pastes WHERE slug=?",(slug_a,)).fetchone()
    pb=db.execute("SELECT * FROM pastes WHERE slug=?",(slug_b,)).fetchone()
    db.close()
    if pa: a_text=pa['content']
    if pb: b_text=pb['content']
  if (a_text or b_text) and request.method=='POST':
    al=a_text.splitlines(); bl=b_text.splitlines()
    adds=dels=same=0
    html_lines=[]
    i,j=0,0
    # simple LCS-based diff
    import difflib
    matcher=difflib.SequenceMatcher(None,al,bl)
    for op,i1,i2,j1,j2 in matcher.get_opcodes():
      if op=='equal':
        for l in al[i1:i2]: html_lines.append(f'<span class="diff-eq"> {__import__("html").escape(l) or " "}</span>'); same+=1
      elif op=='replace':
        for l in al[i1:i2]: html_lines.append(f'<span class="diff-del">- {__import__("html").escape(l) or " "}</span>'); dels+=1
        for l in bl[j1:j2]: html_lines.append(f'<span class="diff-add">+ {__import__("html").escape(l) or " "}</span>'); adds+=1
      elif op=='delete':
        for l in al[i1:i2]: html_lines.append(f'<span class="diff-del">- {__import__("html").escape(l) or " "}</span>'); dels+=1
      elif op=='insert':
        for l in bl[j1:j2]: html_lines.append(f'<span class="diff-add">+ {__import__("html").escape(l) or " "}</span>'); adds+=1
    result=f'<div style="display:flex;gap:12px;margin-bottom:10px;flex-wrap:wrap;"><span style="color:var(--green);font-size:12px;font-weight:700;">+{adds} added</span><span style="color:var(--red);font-size:12px;font-weight:700;">-{dels} removed</span><span style="color:var(--dim);font-size:12px;">={same} same</span></div><div class="code" style="font-size:11px;">{"".join(html_lines) or "No differences found!"}</div>'
  import html as html_mod
  c=f'''<div style="max-width:900px;margin:0 auto;">
<div style="font-size:16px;font-weight:700;color:var(--p);letter-spacing:2px;margin-bottom:16px;">🔀 DIFF / COMPARE</div>
<div class="card">
<form method="POST">
<div class="g2">
<div class="fg"><label>Text A (Original)</label><textarea name="a" rows="10" style="font-family:'Share Tech Mono',monospace;font-size:11px;resize:vertical;" placeholder="Paste original text here...">{html_mod.escape(a_text)}</textarea></div>
<div class="fg"><label>Text B (Modified)</label><textarea name="b" rows="10" style="font-family:'Share Tech Mono',monospace;font-size:11px;resize:vertical;" placeholder="Paste modified text here...">{html_mod.escape(b_text)}</textarea></div>
</div>
<button type="submit" class="btn btn-p" style="width:100%;padding:10px;font-size:13px;">🔀 Compare</button>
</form></div>
{f'<div class="card"><div style="font-size:12px;font-weight:700;color:var(--p);letter-spacing:2px;margin-bottom:10px;">📊 RESULT</div>{result}</div>' if result else ''}
</div>'''
  return base(c,"Diff Tool",session.get('theme','cyan'))

# ━━━ HOME ━━━
@app.route('/')
def home():
  cleanup_expired()
  tag=request.args.get('tag','')
  page=max(1,int(request.args.get('page',1) or 1))
  per=20
  db=get_db()
  if tag:
    total=db.execute("SELECT COUNT(*) FROM pastes p WHERE p.visibility='public' AND p.tags LIKE ?",(f'%{tag}%',)).fetchone()[0]
  else:
    total=db.execute("SELECT COUNT(*) FROM pastes WHERE visibility='public'").fetchone()[0]
  pages=max(1,(total+per-1)//per); page=min(page,pages)
  offset=(page-1)*per
  if tag:
    pastes=db.execute("SELECT p.*,u.username,u.avatar,u.is_premium FROM pastes p LEFT JOIN users u ON p.user_id=u.id WHERE p.visibility='public' AND p.tags LIKE ? ORDER BY p.pinned DESC,p.created_at DESC LIMIT ? OFFSET ?",(f'%{tag}%',per,offset)).fetchall()
  else:
    pastes=db.execute("SELECT p.*,u.username,u.avatar,u.is_premium FROM pastes p LEFT JOIN users u ON p.user_id=u.id WHERE p.visibility='public' ORDER BY p.pinned DESC,p.created_at DESC LIMIT ? OFFSET ?",(per,offset)).fetchall()
  tp=db.execute("SELECT COUNT(*) FROM pastes").fetchone()[0]
  tv=db.execute("SELECT COALESCE(SUM(views),0) FROM pastes").fetchone()[0]
  tu=db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
  db.close()
  base_url=f'/?tag={tag}' if tag else '/?'
  def exp_tag(p):
    if not p['expires_at']: return ''
    try:
      d=datetime.fromisoformat(str(p['expires_at']))-datetime.now(); h=int(d.total_seconds()//3600)
      return f'<span style="color:var(--yellow);font-size:9px;"> ⏰{h}h</span>' if h>=0 else ''
    except: return ''
  def _prem_star(p):
    try: return '<span style="display:inline-flex;align-items:center;padding:1px 5px;border-radius:99px;font-size:8px;font-weight:800;background:linear-gradient(135deg,#7b2ff7,#ffd700);color:#fff;vertical-align:middle;margin-left:3px;">⭐</span>' if dict(p).get('is_premium') else ''
    except: return ''
  pl=''.join(f'<a href="/paste/{p["slug"]}" class="pi {"pinned" if p["pinned"] else ""}"><div><div class="pt">{"📌 " if p["pinned"] else ""}{"🔒 " if p["password"] else ""}{p["title"]}{exp_tag(p)}</div><div class="pm">{p["avatar"] or "👤"} {p["username"] or "Anon"}{_prem_star(p)} · {p["created_at"][:10]} · {p["syntax"]}{" · ❤️"+str(p["likes"]) if p["likes"]>0 else ""}</div></div><div class="pv">👁 {p["views"]}</div></a>' for p in pastes if not is_expired(p)) or '<div style="text-align:center;color:var(--dim);padding:20px;">No pastes yet!</div>'
  tag_links=''.join(f'<a href="/?tag={t}" class="tag {"active" if tag==t else ""}">{t}</a>' for t in ALL_TAGS)

  # sidebar
  try:
    _db=get_db()
    _hot=_db.execute("SELECT slug,title,views,likes FROM pastes WHERE visibility='public' ORDER BY views DESC LIMIT 5").fetchall()
    _top=_db.execute("SELECT username,avatar,total_views FROM users ORDER BY total_views DESC LIMIT 5").fetchall()
    _db.close()
  except: _hot=[]; _top=[]
  hot_html=''
  for _p in _hot:
    hot_html+=f'<div style="padding:6px 0;border-bottom:1px solid var(--border);"><a href="/paste/{_p["slug"]}" style="color:var(--p);text-decoration:none;font-size:13px;font-weight:600;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{_p["title"]}</a><span style="font-size:11px;color:var(--dim);">👁 {_p["views"]} ❤️ {_p["likes"]}</span></div>'
  top_html=''
  for _u in _top:
    top_html+=f'<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);"><span style="font-size:17px;">{_u["avatar"] or "👤"}</span><a href="/profile/{_u["username"]}" style="color:var(--p);text-decoration:none;font-size:13px;font-weight:600;flex:1;">{_u["username"]}</a><span style="font-family:monospace;color:var(--green);font-size:12px;">👁 {_u["total_views"]}</span></div>'
  tl_html=''
  tl_html_v=''
  for t in ALL_TAGS:
    active_class='active' if tag==t else ''
    tl_html+=f'<a href="/?tag={t}" class="tag {active_class}">{t}</a>'
    bc='var(--p)' if tag==t else 'transparent'
    tc='var(--p)' if tag==t else 'var(--t)'
    tl_html_v+=f'<a href="/?tag={t}" style="display:block;padding:6px 14px;color:{tc};text-decoration:none;font-size:12px;font-weight:600;border-left:3px solid {bc};">{t}</a>'
  sidebar=f'''<div style="display:flex;flex-direction:column;gap:12px;width:280px;flex-shrink:0;">
<div class="card" style="padding:14px;">
 <div style="font-size:11px;font-weight:700;color:var(--dim);letter-spacing:.7px;text-transform:uppercase;margin-bottom:10px;padding-bottom:7px;border-bottom:1px solid var(--border);"> Trending Pastes</div>
 {hot_html or '<p style="color:var(--dim);font-size:13px;">No pastes yet</p>'}
</div>
<div class="card" style="padding:14px;">
 <div style="font-size:11px;font-weight:700;color:var(--dim);letter-spacing:.7px;text-transform:uppercase;margin-bottom:10px;padding-bottom:7px;border-bottom:1px solid var(--border);">🏆 Top Users</div>
 {top_html or '<p style="color:var(--dim);font-size:13px;">No users yet</p>'}
 <a href="/leaderboard" style="display:block;text-align:center;margin-top:10px;color:var(--p);font-size:12px;font-weight:600;text-decoration:none;">View all →</a>
</div>
<div class="card" style="padding:14px;">
 <div style="font-size:11px;font-weight:700;color:var(--dim);letter-spacing:.7px;text-transform:uppercase;margin-bottom:10px;padding-bottom:7px;border-bottom:1px solid var(--border);">📊 Stats</div>
 <div style="display:grid;grid-template-columns:1fr 1fr;gap:7px;">
  <div class="sb"><span class="sn" style="color:var(--p);font-size:18px;">{tp}</span><span class="sl">Pastes</span></div>
  <div class="sb"><span class="sn" style="color:var(--green);font-size:18px;">{tv}</span><span class="sl">Views</span></div>
  <div class="sb"><span class="sn" style="color:var(--yellow);font-size:18px;">{tu}</span><span class="sl">Users</span></div>
  <div class="sb"><span class="sn" style="color:var(--dim);font-size:11px;">v9.0</span><span class="sl">Version</span></div>
 </div>
</div>

</div>'''
  c=f'''
<div style="display:grid;grid-template-columns:200px 1fr 280px;gap:16px;align-items:start;">

<!-- LEFT SIDEBAR -->
<div style="display:flex;flex-direction:column;gap:8px;position:sticky;top:70px;">
  <a href="/new" style="display:flex;align-items:center;justify-content:center;gap:7px;padding:10px 14px;background:var(--p);color:#000;border-radius:9px;font-weight:800;font-size:14px;text-decoration:none;transition:opacity .15s;" onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">
    + New Paste
  </a>

  <!-- Menu -->
  <div style="background:var(--card);border:1px solid var(--bd);border-radius:10px;overflow:hidden;margin-top:4px;">
    <div style="font-size:10px;font-weight:800;color:var(--s);text-transform:uppercase;letter-spacing:1px;padding:10px 14px 6px;">Menu</div>
    <a href="/" style="display:flex;align-items:center;gap:8px;padding:9px 14px;color:var(--t);text-decoration:none;font-size:13px;font-weight:600;border-left:3px solid {"var(--p)" if not tag else "transparent"};background:{"rgba(128,128,128,.06)" if not tag else "transparent"};" onmouseover="this.style.background='rgba(128,128,128,.06)'" onmouseout="this.style.background='{"rgba(128,128,128,.06)" if not tag else "transparent"}'">
      <span style="font-size:15px;">&#9776;</span> Home
    </a>
    <a href="/pastes" style="display:flex;align-items:center;gap:8px;padding:9px 14px;color:var(--t);text-decoration:none;font-size:13px;font-weight:600;" onmouseover="this.style.background='rgba(128,128,128,.06)'" onmouseout="this.style.background='transparent'">
      <span style="font-size:15px;">&#128196;</span> Archive
    </a>
    <a href="/leaderboard" style="display:flex;align-items:center;gap:8px;padding:9px 14px;color:var(--t);text-decoration:none;font-size:13px;font-weight:600;" onmouseover="this.style.background='rgba(128,128,128,.06)'" onmouseout="this.style.background='transparent'">
      <span style="font-size:15px;">&#127942;</span> Board
    </a>
    <a href="/search" style="display:flex;align-items:center;gap:8px;padding:9px 14px;color:var(--t);text-decoration:none;font-size:13px;font-weight:600;" onmouseover="this.style.background='rgba(128,128,128,.06)'" onmouseout="this.style.background='transparent'">
      <span style="font-size:15px;">&#128269;</span> Search
    </a>
    {'<a href="/bookmarks" style="display:flex;align-items:center;gap:8px;padding:9px 14px;color:var(--t);text-decoration:none;font-size:13px;font-weight:600;"><span style="font-size:15px;">&#9733;</span> Saved</a>' if session.get("user_id") else ""}
  </div>

  <!-- Filter tags -->
  <div style="background:var(--card);border:1px solid var(--bd);border-radius:10px;overflow:hidden;">
    <div style="font-size:10px;font-weight:800;color:var(--s);text-transform:uppercase;letter-spacing:1px;padding:10px 14px 6px;">Filter</div>
    {tl_html_v}
  </div>

</div>

<!-- MAIN CONTENT -->
<div>
  <!-- Search Bar -->
  <form method="GET" action="/search" style="display:flex;gap:8px;margin-bottom:14px;">
    <input name="q" placeholder="🔍 Search by title, content, or tag..." autocomplete="off"
      style="flex:1;padding:9px 14px;background:var(--card);border:1px solid var(--bd);border-radius:9px;color:#fff;font-size:13px;outline:none;transition:border-color .2s;"
      onfocus="this.style.borderColor='var(--p)'" onblur="this.style.borderColor='var(--bd)'">
    <button type="submit" class="btn btn-p" style="padding:9px 18px;font-size:13px;border-radius:9px;">Search</button>
  </form>
  <div style="font-size:12px;font-weight:700;color:var(--s);letter-spacing:.7px;text-transform:uppercase;margin-bottom:10px;">Recent Pastes{f" · #{tag}" if tag else f" · {total} total"}</div>
  {pl}
  {pg_nav(page,pages,base_url)}
</div>

<!-- RIGHT SIDEBAR -->
{sidebar}
</div>'''
  return base(c,"Home",session.get('theme','cyan'))


# ━━━ TAGS / LEADERBOARD / FEED ━━━
@app.route('/tags')
def tags():
  db=get_db()
  tc={t:db.execute("SELECT COUNT(*) FROM pastes WHERE visibility='public' AND tags LIKE ?",(f'%{t}%',)).fetchone()[0] for t in ALL_TAGS}
  db.close()
  rows=''.join(f'<a href="/?tag={t}" class="pi"><div><div class="pt">#{t}</div></div><div class="pv">{tc[t]} pastes</div></a>' for t in ALL_TAGS)
  c=f'<div style="max-width:600px;margin:0 auto;"><div style="font-size:15px;font-weight:700;color:var(--p);letter-spacing:2px;margin-bottom:14px;">🏷️ TAGS</div><div class="card">{rows}</div></div>'
  return base(c,"Tags",session.get('theme','cyan'))

@app.route('/leaderboard')
def leaderboard():
  db=get_db()
  users=db.execute("SELECT u.*,COUNT(p.id) as pc FROM users u LEFT JOIN pastes p ON u.id=p.user_id GROUP BY u.id ORDER BY u.total_views DESC LIMIT 20").fetchall()
  db.close()
  def _lbrow(i,u2):
    medals2=['🥇','🥈','🥉']; mc2=['#ffd700','#c0c0c0','#cd7f32']
    rank2=medals2[i] if i<3 else '#'+str(i+1); rc2=mc2[i] if i<3 else 'var(--dim)'; bc2='border-color:'+mc2[i]+'44;' if i<3 else ''
    ud2=dict(u2)
    is_p=ud2.get('is_premium',0)
    prem_bc='border-color:rgba(255,215,0,.5);box-shadow:0 0 12px rgba(255,215,0,.15);' if is_p else ''
    prem_b=('<span class="prem-badge" style="font-size:9px;padding:1px 6px 1px 4px;gap:2px;">'
            '<svg width="9" height="9" viewBox="0 0 24 24" fill="#fff"><path d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6z"/></svg>'
            ' Premium</span>') if is_p else ''
    name_style='background:linear-gradient(90deg,#ffd700,#f107a3);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;' if is_p else 'color:var(--p);'
    return ('<div style="display:flex;align-items:center;gap:14px;padding:13px 16px;background:var(--bg);border:1px solid var(--border);'
            +bc2+prem_bc+'border-radius:10px;margin-bottom:8px;">'
            '<div style="font-size:20px;width:34px;text-align:center;font-weight:700;color:'+rc2+';">'+rank2+'</div>'
            '<div style="font-size:26px;">'+(ud2["avatar"] or "👤")+'</div>'
            '<div style="flex:1;min-width:0;">'
            '<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">'
            '<a href="/profile/'+ud2["username"]+'" style="text-decoration:none;font-size:15px;font-weight:700;'+name_style+'">'+ud2["username"]+'</a>'
            +prem_b+'</div>'
            '<div style="font-size:12px;color:var(--dim);">'+str(ud2["pc"])+' pastes</div></div>'
            '<div style="text-align:right;"><div style="font-family:monospace;color:var(--green);font-size:16px;font-weight:700;">👁 '+str(ud2["total_views"])+'</div></div></div>')
  rows=''.join(_lbrow(i,u) for i,u in enumerate(users)) or f'<div style="text-align:center;padding:48px;color:var(--dim);"><div style="font-size:52px;margin-bottom:12px;">🏆</div><div>No users yet! <a href="/register" style="color:var(--p);">Register →</a></div></div>'
  c=f'''<div style="max-width:680px;margin:0 auto;">
<div style="text-align:center;padding:24px 0 20px;">
<div style="font-size:44px;margin-bottom:8px;">🏆</div>
<div style="font-size:26px;font-weight:800;color:var(--text);">Leaderboard</div>
<div style="font-size:13px;color:var(--dim);margin-top:4px;">Top users by total paste views</div>
</div>
<div class="card">{rows}</div>
</div>'''
  return base(c,"Leaderboard",session.get('theme','cyan'))

@app.route('/feed')
def feed():
  db=get_db()
  acts=db.execute("SELECT a.*,u.username,u.avatar FROM activity a LEFT JOIN users u ON a.user_id=u.id ORDER BY a.created_at DESC LIMIT 40").fetchall()
  db.close()
  icons={'paste':'📝','like':'❤️','comment':'💬','follow':'👥','fork':'🔎'}
  rows=''.join(f'<div style="display:flex;align-items:flex-start;gap:9px;padding:8px 12px;border-left:2px solid var(--border);margin-bottom:7px;"><div style="font-size:16px;">{icons.get(a["target_type"],"⚡")}</div><div style="flex:1;"><div style="font-size:11px;font-weight:700;"><a href="/profile/{a["username"]}" style="color:var(--p);text-decoration:none;">{a["avatar"] or "👤"} {a["username"]}</a> {a["action"]}</div><div style="font-size:9px;color:var(--dim);font-family:\'Share Tech Mono\',monospace;margin-top:1px;">{a["created_at"][:16]}</div></div></div>' for a in acts) or '<div style="text-align:center;color:var(--dim);padding:16px;">No activity!</div>'
  c=f'<div style="max-width:640px;margin:0 auto;"><div style="font-size:15px;font-weight:700;color:var(--p);letter-spacing:2px;margin-bottom:14px;">📊 ACTIVITY FEED</div><div class="card">{rows}</div></div>'
  return base(c,"Feed",session.get('theme','cyan'))

# ━━━ NEW PASTE ━━━
@app.route('/new',methods=['GET','POST'])
def new_paste():
  fork_slug=request.args.get('fork',''); fork_data={}
  if fork_slug:
    db=get_db(); fp=db.execute("SELECT * FROM pastes WHERE slug=?",(fork_slug,)).fetchone(); db.close()
    if fp: fork_data={'title':f"Fork of {fp['title']}",'content':fp['content'],'syntax':fp['syntax']}
  if request.method=='POST':
    # ── Rate limit: 5 pastes/minute ──
    rl_key=str(session.get('user_id')) if session.get('user_id') else get_real_ip()
    allowed,remaining,reset_in=check_rate_limit('paste',PASTE_LIMIT,PASTE_WINDOW,rl_key)
    if not allowed:
      flash(f'Slow down! Max {PASTE_LIMIT} pastes/minute. Try again in {reset_in}s.','red')
      return redirect('/new')
    title=request.form.get('title','').strip()
    syntax=request.form.get('syntax','text'); vis=request.form.get('visibility','public')
    pw=request.form.get('paste_pw','').strip(); exp=request.form.get('expire','')
    tags=','.join(t.strip() for t in request.form.getlist('tags') if t.strip())
    file_type=''
    # ── File upload handling ──
    uploaded=request.files.get('upload_file')
    if uploaded and uploaded.filename:
      if not allowed_file(uploaded.filename):
        flash('Only .txt .log .json .cfg .csv .xml .md .ini files allowed!','red'); return redirect('/new')
      raw=uploaded.read()
      if len(raw)>MAX_FILE_BYTES:
        flash('File too large! Max 2MB.','red'); return redirect('/new')
      try: content=raw.decode('utf-8')
      except: content=raw.decode('latin-1','replace')
      ext=os.path.splitext(uploaded.filename)[1].lower()
      file_type=uploaded.filename  # store original filename
      if not title: title=uploaded.filename
      syntax=syntax_from_ext(ext)
    else:
      content=request.form.get('content','').strip()
    # ── Size limit: 1 MB ──
    size_ok,size_err=check_paste_size(content,title)
    if not size_ok: flash(size_err,'red'); return redirect('/new')
    expires_at=None
    if exp=='1h': expires_at=(datetime.now()+timedelta(hours=1)).isoformat()
    elif exp=='1d': expires_at=(datetime.now()+timedelta(days=1)).isoformat()
    elif exp=='1w': expires_at=(datetime.now()+timedelta(weeks=1)).isoformat()
    elif exp=='1m': expires_at=(datetime.now()+timedelta(days=30)).isoformat()
    if not title or not content: flash('Fill all fields!','red')
    else:
      slug=rand_slug(); db=get_db()
      db.execute("INSERT INTO pastes(slug,title,content,syntax,visibility,password,tags,user_id,expires_at,file_type) VALUES(?,?,?,?,?,?,?,?,?,?)",(slug,title,content,syntax,vis,hash_pw(pw) if pw else '',tags,session.get('user_id'),expires_at,file_type))
      db.commit()
      if session.get('user_id'):
        pid=db.execute("SELECT id FROM pastes WHERE slug=?",(slug,)).fetchone()[0]
        log_activity(session['user_id'],f'created "{title}"',pid,'paste')
        fols=db.execute("SELECT follower_id FROM follows WHERE following_id=?",(session['user_id'],)).fetchall()
        for f in fols: send_notif(f['follower_id'],f'📝 {session["user"]} created "{title}"',f'/paste/{slug}')
      db.close(); return redirect(f'/paste/{slug}')
  exp_opts=''.join(f'<option value="{v}">{l}</option>' for v,l in EXPIRE_OPTS)
  tag_checks=''.join(f'<label style="display:inline-flex;align-items:center;gap:4px;margin:3px;cursor:pointer;font-size:11px;text-transform:none;letter-spacing:0;"><input type="checkbox" name="tags" value="{t}" style="width:auto;"> #{t}</label>' for t in ALL_TAGS)
  c=f'''<div style="max-width:800px;margin:0 auto;"><div class="card">
<div style="font-size:14px;font-weight:700;color:var(--p);letter-spacing:2px;margin-bottom:13px;">📝 {"FORK" if fork_data else "NEW PASTE"}</div>
<!-- Tab switcher -->
<div style="display:flex;gap:0;margin-bottom:14px;border:1px solid var(--bd);border-radius:8px;overflow:hidden;">
  <button type="button" onclick="switchTab('text')" id="tab-text" style="flex:1;padding:8px;background:var(--p);color:#000;border:none;cursor:pointer;font-size:12px;font-weight:700;">📝 Text</button>
  <button type="button" onclick="switchTab('file')" id="tab-file" style="flex:1;padding:8px;background:transparent;color:var(--s);border:none;cursor:pointer;font-size:12px;font-weight:700;border-left:1px solid var(--bd);">📁 File Upload</button>
</div>
<form method="POST" enctype="multipart/form-data">
<div class="fg"><label>Title</label><input name="title" id="f-title" value="{fork_data.get('title','')}" placeholder="Paste title..."></div>
<!-- Text pane -->
<div id="pane-text">
<div class="fg"><label>Content</label>
<textarea name="content" id="pc" rows="11" style="font-family:'Share Tech Mono',monospace;font-size:12px;resize:vertical;" oninput="lc(this)">{fork_data.get('content','')}</textarea>
<div class="lc-bar"><span>📄 <span class="lc-num" id="ll">0</span> lines</span><span>📝 <span class="lc-num" id="lc2">0</span> chars</span><span>📦 <span class="lc-num" id="lw">0</span> words</span><span>💾 <span class="lc-num" id="ls" style="color:var(--green);">0 B</span> / 1 MB</span></div></div>
</div>
<!-- File pane -->
<div id="pane-file" style="display:none;">
<div class="fg">
<label>Upload File</label>
<div id="drop-zone" style="border:2px dashed var(--bd);border-radius:10px;padding:36px 20px;text-align:center;cursor:pointer;transition:border-color .2s;"
  ondragover="event.preventDefault();this.style.borderColor='var(--p)'"
  ondragleave="this.style.borderColor='var(--bd)'"
  ondrop="handleDrop(event)"
  onclick="document.getElementById('upload_file').click()">
  <div style="font-size:40px;margin-bottom:8px;">📁</div>
  <div style="color:var(--s);font-size:13px;">Drag & drop or <span style="color:var(--p);font-weight:700;">click to browse</span></div>
  <div style="color:var(--dim);font-size:11px;margin-top:6px;">Supported: .txt .log .json .cfg .csv .xml .md .ini (max 2MB)</div>
  <div id="file-name" style="margin-top:10px;color:var(--p);font-weight:700;font-size:13px;"></div>
</div>
<input type="file" name="upload_file" id="upload_file" accept=".txt,.log,.json,.cfg,.csv,.xml,.md,.ini" style="display:none;" onchange="fileSelected(this)">
</div>
</div>
<div class="g2">
<div class="fg"><label>Syntax</label><select name="syntax"><option value="text">Plain Text</option><option value="python">Python</option><option value="javascript">JavaScript</option><option value="html">HTML</option><option value="css">CSS</option><option value="bash">Bash</option><option value="json">JSON</option><option value="sql">SQL</option></select></div>
<div class="fg"><label>Visibility</label><select name="visibility"><option value="public">🌐 Public</option><option value="private">🔒 Private</option></select></div></div>
<div class="g2">
<div class="fg"><label>🔒 Password</label><input name="paste_pw" type="password" placeholder="Optional..."></div>
<div class="fg"><label>⏰ Expires</label><select name="expire">{exp_opts}</select></div></div>
<div class="fg"><label>🏷️ Tags</label><div style="margin-top:4px;">{tag_checks}</div></div>
<button type="submit" class="btn btn-p" style="width:100%;font-size:13px;padding:10px;">🚀 Create</button>
</form></div></div>
<script>
function switchTab(t){{
  const isText=t==='text';
  document.getElementById('pane-text').style.display=isText?'':'none';
  document.getElementById('pane-file').style.display=isText?'none':'';
  document.getElementById('tab-text').style.background=isText?'var(--p)':'transparent';
  document.getElementById('tab-text').style.color=isText?'#000':'var(--s)';
  document.getElementById('tab-file').style.background=isText?'transparent':'var(--p)';
  document.getElementById('tab-file').style.color=isText?'var(--s)':'#000';
}}
function fileSelected(inp){{
  if(inp.files[0]){{
    document.getElementById('file-name').textContent='✅ '+inp.files[0].name+' ('+Math.round(inp.files[0].size/1024)+' KB)';
    if(!document.getElementById('f-title').value) document.getElementById('f-title').value=inp.files[0].name;
  }}
}}
function handleDrop(e){{
  e.preventDefault();
  document.getElementById('drop-zone').style.borderColor='var(--bd)';
  const f=e.dataTransfer.files[0];
  if(f){{document.getElementById('upload_file').files=e.dataTransfer.files;fileSelected(document.getElementById('upload_file'));}}
}}
function lc(el){{const v=el.value,l=v?v.split('\\n').length:0,c=v.length,w=v.trim()?v.trim().split(/\\s+/).length:0,sz=new Blob([v]).size,ss=sz>1024?(sz/1024).toFixed(1)+' KB':sz+' B';const lse=document.getElementById('ls');document.getElementById('ll').textContent=l;document.getElementById('lc2').textContent=c;document.getElementById('lw').textContent=w;if(lse){{lse.textContent=ss+' / 1 MB';lse.style.color=sz>900*1024?'var(--red)':sz>700*1024?'var(--yellow)':'var(--green)';}}}}
{f"window.onload=()=>lc(document.getElementById('pc'));" if fork_data else ""}
</script>'''
  return base(c,"New",session.get('theme','cyan'))

# ━━━ VIEW PASTE ━━━
@app.route('/paste/<slug>',methods=['GET','POST'])
def view_paste(slug):
  db=get_db(); paste=db.execute("SELECT * FROM pastes WHERE slug=?",(slug,)).fetchone()
  if not paste: db.close(); return base('<div class="card" style="text-align:center;padding:36px;"><div style="font-size:36px;">🔍</div><p style="color:var(--dim);margin-top:7px;">Not found!</p></div>',"404")
  if is_expired(paste): db.close(); return base('<div class="card" style="text-align:center;padding:36px;"><div style="font-size:36px;">⌛</div><p style="color:var(--dim);margin-top:7px;">Expired!</p></div>',"Expired")
  if paste['password']:
    entered=session.get(f'pw_{slug}','')
    if request.method=='POST' and request.form.get('paste_pw'):
      if hash_pw(request.form.get('paste_pw',''))==paste['password']: session[f'pw_{slug}']=paste['password']; return redirect(f'/paste/{slug}')
      else: db.close(); return base(f'<div style="max-width:360px;margin:44px auto;"><div class="card"><div style="text-align:center;font-size:30px;margin-bottom:8px;">🔒</div><div style="text-align:center;font-size:14px;font-weight:700;color:var(--p);margin-bottom:12px;">{paste["title"]}</div><div class="alert ar">Wrong password!</div><form method="POST"><div class="fg"><label>Password</label><input name="paste_pw" type="password" autofocus required></div><button type="submit" class="btn btn-p" style="width:100%;padding:9px;">🔓 Unlock</button></form></div></div>',"Locked")
    if not entered or entered!=paste['password']: db.close(); return base(f'<div style="max-width:360px;margin:44px auto;"><div class="card"><div style="text-align:center;font-size:30px;margin-bottom:8px;">🔒</div><div style="text-align:center;font-size:14px;font-weight:700;color:var(--p);margin-bottom:12px;">{paste["title"]}</div><form method="POST"><div class="fg"><label>Password</label><input name="paste_pw" type="password" autofocus required></div><button type="submit" class="btn btn-p" style="width:100%;padding:9px;">🔓 Unlock</button></form></div></div>',"Locked")
  if request.method=='POST' and request.form.get('comment_text'):
    if not session.get('user_id'): flash('Login to comment!','red')
    else:
      # ── Rate limit: 10 comments/minute ──
      allowed,_,reset_in=check_rate_limit('comment',COMMENT_LIMIT,COMMENT_WINDOW,str(session['user_id']))
      if not allowed:
        flash(f'Slow down! Max {COMMENT_LIMIT} comments/minute. Wait {reset_in}s.','red')
        return redirect(f'/paste/{slug}')
      ctxt=request.form.get('comment_text','').strip()[:500]
      if ctxt:
        db.execute("INSERT INTO comments(paste_id,user_id,content) VALUES(?,?,?)",(paste['id'],session['user_id'],ctxt))
        db.commit()
        log_activity(session['user_id'],f'commented on "{paste["title"]}"',paste['id'],'paste')
        # Notify paste owner
        if paste['user_id'] and paste['user_id']!=session['user_id']:
          send_notif(paste['user_id'],f'💬 {session["user"]} commented on "{paste["title"]}"',f'/paste/{slug}')
        # @mention notifications
        mentioned=re.findall(r'@(\w+)',ctxt)
        for uname in set(mentioned):
          if uname.lower()==session.get('user','').lower(): continue
          mu=db.execute("SELECT id FROM users WHERE username=?",(uname,)).fetchone()
          if mu and mu['id']!=paste.get('user_id'):
            send_notif(mu['id'],f'🔔 {session["user"]} mentioned you in a comment on "{paste["title"]}"',f'/paste/{slug}')
        flash('Comment added!','green')
    return redirect(f'/paste/{slug}')
  count_unique_view(paste['id'],slug)
  paste=db.execute("SELECT * FROM pastes WHERE slug=?",(slug,)).fetchone()
  auth=None; av='👤'; ath='cyan'; auth_prem=0
  if paste['user_id']:
    db.execute("UPDATE users SET total_views=(SELECT COALESCE(SUM(views),0) FROM pastes WHERE user_id=?) WHERE id=?",(paste['user_id'],paste['user_id']))
    u2=db.execute("SELECT username,avatar,theme,is_premium FROM users WHERE id=?",(paste['user_id'],)).fetchone()
    if u2: auth=u2['username']; av=u2['avatar'] or '👤'; ath=u2['theme'] or 'cyan'; auth_prem=u2['is_premium'] or 0
  comments=db.execute("SELECT c.*,u.username,u.avatar FROM comments c LEFT JOIN users u ON c.user_id=u.id WHERE c.paste_id=? ORDER BY c.created_at ASC",(paste['id'],)).fetchall()
  user_vote=None
  if session.get('user_id'):
    v=db.execute("SELECT vote FROM paste_likes WHERE paste_id=? AND user_id=?",(paste['id'],session['user_id'])).fetchone()
    if v: user_vote=v['vote']
  db.commit(); db.close()
  lc2=len(paste['content'].split('\n')); chars=len(paste['content']); words=len(paste['content'].split())
  sz=len(paste['content'].encode()); ss=f"{sz/1024:.1f} KB" if sz>1024 else f"{sz} B"
  is_owner=session.get('user_id')==paste['user_id']
  # ── Report button (logged in, not owner) ──
  report_btn=''
  file_badge=''
  try:
    ft=dict(paste).get('file_type','')
    if ft: file_badge=f'<span style="background:rgba(0,245,255,.1);border:1px solid var(--p);border-radius:4px;padding:1px 7px;font-size:9px;font-family:monospace;color:var(--p);">📁 {ft}</span>'
  except: pass
  if session.get('user_id') and not is_owner:
    report_btn=(
      f'<button onclick="document.getElementById(\'report-modal\').style.display=\'flex\'" '
      f'class="btn btn-r" style="font-size:9px;padding:3px 7px;">🚨</button>'
    )
  report_modal=''
  if session.get('user_id') and not is_owner:
    report_modal=(
      f'<div id="report-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:999;align-items:center;justify-content:center;">'
      f'<div style="background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:28px;max-width:400px;width:90%;">'
      f'<div style="font-size:16px;font-weight:800;color:var(--red);margin-bottom:14px;">🚨 Report Paste</div>'
      f'<form method="POST" action="/report/{slug}">'
      f'<div class="fg"><label>Reason</label>'
      f'<select name="reason" style="margin-bottom:10px;">'
      f'<option value="Illegal content">Illegal content</option>'
      f'<option value="Spam or scam">Spam or scam</option>'
      f'<option value="Malware or malicious code">Malware or malicious code</option>'
      f'<option value="Harassment or hate speech">Harassment or hate speech</option>'
      f'<option value="Copyright violation">Copyright violation</option>'
      f'<option value="Other">Other</option>'
      f'</select></div>'
      f'<div style="display:flex;gap:8px;">'
      f'<button type="submit" class="btn btn-r" style="flex:1;padding:8px;">Submit Report</button>'
      f'<button type="button" onclick="document.getElementById(\'report-modal\').style.display=\'none\'" class="btn btn-o" style="flex:1;padding:8px;">Cancel</button>'
      f'</div></form></div></div>'
    )
  del_btn=f'<a href="/delete/{slug}" class="btn btn-r" style="font-size:9px;padding:3px 7px;" onclick="return confirm(\'Delete?\')">🗑</a>' if is_owner else ''
  edit_btn=f'<a href="/edit/{slug}" class="btn btn-y" style="font-size:9px;padding:3px 7px;">✏️</a>' if is_owner else ''
  pin_btn=f'<a href="/pin/{slug}" class="btn btn-o" style="font-size:9px;padding:3px 7px;">{"📌✓" if paste["pinned"] else "📌"}</a>' if is_owner else ''
  # ── Save/Bookmark button ──
  save_btn=''
  if session.get('user_id'):
    db2=get_db()
    is_saved=db2.execute("SELECT id FROM bookmarks WHERE user_id=? AND paste_id=?",(session['user_id'],paste['id'])).fetchone()
    is_prem2=db2.execute("SELECT is_premium FROM users WHERE id=?",(session['user_id'],)).fetchone()
    is_prem2=is_prem2['is_premium'] if is_prem2 else 0
    bcount=db2.execute("SELECT COUNT(*) FROM bookmarks WHERE user_id=?",(session['user_id'],)).fetchone()[0]
    db2.close()
    at_limit = (not is_prem2) and (bcount>=5) and (not is_saved)
    save_btn=(
      f'<button id="save-btn-{slug}" onclick="toggleSave(\'{slug}\')" class="btn" style="font-size:9px;padding:3px 7px;'
      f'background:{"rgba(255,215,0,.15)" if is_saved else "rgba(255,255,255,.05)"};'
      f'border-color:{"#ffd700" if is_saved else "var(--bd)"};'
      f'color:{"#ffd700" if is_saved else "var(--dim)"};cursor:pointer;" '
      f'title="{"Unsave" if is_saved else ("Limit reached — upgrade to Premium" if at_limit else "Save")}">'
      f'{"🔖✓" if is_saved else "🔖"}</button>'
      f'<script>'
      f'async function toggleSave(slug){{'
      f'  const btn=document.getElementById("save-btn-"+slug);'
      f'  btn.disabled=true; btn.style.opacity=".5";'
      f'  try{{'
      f'    const r=await fetch("/bookmark/"+slug,{{method:"POST",headers:{{"Content-Type":"application/json","X-Requested-With":"XMLHttpRequest"}}}});'
      f'    const d=await r.json();'
      f'    if(d.ok){{'
      f'      btn.textContent=d.saved?"🔖✓":"🔖";'
      f'      btn.style.background=d.saved?"rgba(255,215,0,.15)":"rgba(255,255,255,.05)";'
      f'      btn.style.borderColor=d.saved?"#ffd700":"var(--bd)";'
      f'      btn.style.color=d.saved?"#ffd700":"var(--dim)";'
      f'      toast(d.msg, d.saved?"#ffd700":"var(--p)");'
      f'    }} else {{'
      f'      toast(d.msg,"#ff2d55");'
      f'    }}'
      f'  }}catch(e){{toast("Connection error!","#ff2d55");}} '
      f'  btn.disabled=false; btn.style.opacity="1";'
      f'}}'
      f'</script>'
    )
  _auth_badge=('<span class="prem-badge" style="font-size:9px;padding:1px 6px 1px 4px;gap:2px;">'
    '<svg width="9" height="9" viewBox="0 0 24 24" fill="#fff"><path d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6z"/></svg>'
    ' Premium</span>') if auth_prem else ''
  al=(f'<a href="/profile/{auth}" style="text-decoration:none;display:inline-flex;align-items:center;gap:5px;">'
      f'<span style="color:var(--p);">{av} {auth}</span>{_auth_badge}</a>') if auth else 'Anonymous'
  tag_html=''.join(f'<a href="/?tag={t}" class="tag">{t}</a>' for t in paste['tags'].split(',') if t.strip()) if paste['tags'] else ''
  url=f"https://zeroshell-paste.up.railway.app/paste/{slug}"
  tg_url=f"https://t.me/share/url?url={url}&text={paste['title']}"
  highlighted=highlight(paste['content'],paste['syntax'])
  cmts_html=''.join(f'<div class="comment"><div style="display:flex;justify-content:space-between;margin-bottom:4px;"><a href="/profile/{cm["username"]}" style="color:var(--p);text-decoration:none;font-size:10px;font-weight:700;">{cm["avatar"] or "👤"} {cm["username"]}</a><span style="font-size:9px;color:var(--dim);font-family:\'Share Tech Mono\',monospace;">{cm["created_at"][:16]}</span></div><div style="font-size:12px;">{cm["content"]}</div></div>' for cm in comments)
  cmt_form=f'<form method="POST" style="margin-top:10px;"><div class="fg"><textarea name="comment_text" rows="2" placeholder="Comment..." style="resize:vertical;font-size:12px;"></textarea></div><button type="submit" class="btn btn-p" style="font-size:11px;padding:6px 14px;">💬 Post</button></form>' if session.get('user') else f'<div style="text-align:center;padding:10px;color:var(--dim);font-size:11px;"><a href="/login" style="color:var(--p);">Login</a> to comment</div>'
  exp_info=''
  if paste['expires_at']:
    try:
      d=datetime.fromisoformat(str(paste['expires_at']))-datetime.now(); h=int(d.total_seconds()//3600)
      exp_info=f'<span style="color:var(--yellow);font-size:9px;font-family:\'Share Tech Mono\',monospace;">⏰{h}h left</span>'
    except: pass
  c=f'''<div style="max-width:880px;margin:0 auto;">
<div class="card">
<div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:7px;">
<div><div style="font-size:16px;font-weight:700;color:var(--p);margin-bottom:3px;">{"📌 " if paste["pinned"] else ""}{"🔒 " if paste["password"] else ""}{paste["title"]}</div>
<div style="font-size:9px;color:var(--dim);font-family:'Share Tech Mono',monospace;">by {al} · {paste["created_at"][:16]} · {paste["syntax"]}</div>
{f'<div style="margin-top:4px;">{tag_html}</div>' if tag_html else ''}</div>
<div style="display:flex;gap:3px;align-items:center;flex-wrap:wrap;">
<span style="font-family:'Share Tech Mono',monospace;color:var(--green);font-size:10px;">👁{paste["views"]}</span>
<button class="like-btn {"active" if user_vote==1 else ""}" onclick="vote(1)" id="likeBtn">❤️{paste["likes"]}</button>
<button class="like-btn dislike {"active" if user_vote==-1 else ""}" onclick="vote(-1)" id="disBtn">👎{paste["dislikes"]}</button>
<a href="/raw/{slug}" class="btn btn-o" style="font-size:9px;padding:3px 7px;" target="_blank">Raw</a>
<button onclick="cp()" class="btn btn-o" style="font-size:9px;padding:3px 7px;">📋</button>
<button onclick="shareLink()" class="btn btn-o" style="font-size:9px;padding:3px 7px;">🔗</button>
<a href="{tg_url}" target="_blank" class="btn btn-o" style="font-size:9px;padding:3px 7px;">✈️</a>
<a href="/download/{slug}" class="btn btn-g" style="font-size:9px;padding:3px 7px;">📥</a>
<a href="/new?fork={slug}" class="btn btn-o" style="font-size:9px;padding:3px 7px;">🔎Fork</a>
{edit_btn}{pin_btn}{del_btn}{report_btn}{save_btn}
</div></div>
<div style="display:flex;gap:8px;margin-top:7px;flex-wrap:wrap;align-items:center;">
<span style="font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--dim);">📄{lc2}·📝{chars}·💾{ss}</span>{exp_info}{file_badge}</div>
</div>
<div class="card" style="padding:0;">
<div style="padding:7px 13px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;">
<span style="font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--dim);">{paste["syntax"].upper()}</span>
<span style="font-size:9px;color:var(--dim);">{lc2} lines·{ss}</span></div>
<div class="code" id="pc">{highlighted}</div></div>
<div class="card"><div style="font-size:11px;font-weight:700;color:var(--p);letter-spacing:2px;margin-bottom:9px;">💬 COMMENTS ({len(comments)})</div>
{cmts_html or '<div style="text-align:center;color:var(--dim);padding:9px;font-size:11px;">No comments!</div>'}
{cmt_form}</div></div>
<script>
const SLUG="{slug}",URL2="{url}";
function cp(){{navigator.clipboard.writeText(document.getElementById('pc').innerText).then(()=>toast('Copied!'));}}
function shareLink(){{navigator.clipboard.writeText(URL2).then(()=>toast('🔗 Copied!'));}}
function vote(v){{fetch('/vote/'+SLUG+'/'+v,{{method:'POST'}}).then(r=>r.json()).then(d=>{{document.getElementById('likeBtn').textContent='❤️'+d.likes;document.getElementById('disBtn').textContent='👎'+d.dislikes;toast(v==1?'❤️ Liked!':'👎 Disliked!');}}); }}
function aiSum(){{
 const btn=document.getElementById('aiBtn');
 if(btn)btn.textContent='⏳...';
.then(r=>r.json()).then(d=>{{
  const box=document.getElementById('aiBox');
  if(box){{box.style.display='block';box.innerHTML='🤖 '+(d.summary||d.error);}}
  if(btn)btn.style.display='none';
 }});
}}
</script>{report_modal}'''
  return base(c,paste['title'],ath)

# ━━━ VOTE ━━━
@app.route('/vote/<slug>/<int:vote>',methods=['POST'])
def vote_paste(slug,vote):
  if not session.get('user_id'): return jsonify({'error':'login'}),401
  if vote not in (1,-1): return jsonify({'error':'invalid'}),400
  db=get_db(); paste=db.execute("SELECT * FROM pastes WHERE slug=?",(slug,)).fetchone()
  if not paste: db.close(); return jsonify({'error':'nf'}),404
  ex=db.execute("SELECT * FROM paste_likes WHERE paste_id=? AND user_id=?",(paste['id'],session['user_id'])).fetchone()
  if ex:
    if ex['vote']==vote: db.execute("DELETE FROM paste_likes WHERE paste_id=? AND user_id=?",(paste['id'],session['user_id']))
    else: db.execute("UPDATE paste_likes SET vote=? WHERE paste_id=? AND user_id=?",(vote,paste['id'],session['user_id']))
  else:
    db.execute("INSERT INTO paste_likes(paste_id,user_id,vote) VALUES(?,?,?)",(paste['id'],session['user_id'],vote))
    if paste['user_id'] and paste['user_id']!=session['user_id']:
      send_notif(paste['user_id'],f'{"❤️" if vote==1 else "👎"} {session["user"]} {"liked" if vote==1 else "disliked"} "{paste["title"]}"',f'/paste/{slug}')
  likes=db.execute("SELECT COUNT(*) FROM paste_likes WHERE paste_id=? AND vote=1",(paste['id'],)).fetchone()[0]
  dislikes=db.execute("SELECT COUNT(*) FROM paste_likes WHERE paste_id=? AND vote=-1",(paste['id'],)).fetchone()[0]
  db.execute("UPDATE pastes SET likes=?,dislikes=? WHERE id=?",(likes,dislikes,paste['id']))
  db.commit(); db.close()
  return jsonify({'likes':likes,'dislikes':dislikes})

# ━━━ RAW / DOWNLOAD ━━━
@app.route('/raw/<slug>')
def raw_paste(slug):
  db=get_db(); p=db.execute("SELECT * FROM pastes WHERE slug=?",(slug,)).fetchone(); db.close()
  if not p or is_expired(p): return Response("Not found",status=404,mimetype='text/plain')
  if p['password'] and not session.get(f'pw_{slug}'): return Response("Password required",status=403,mimetype='text/plain')
  return Response(p['content'],mimetype='text/plain')

@app.route('/download/<slug>')
def download_paste(slug):
  db=get_db(); p=db.execute("SELECT * FROM pastes WHERE slug=?",(slug,)).fetchone(); db.close()
  if not p or is_expired(p): return Response("Not found",status=404,mimetype='text/plain')
  if p['password'] and not session.get(f'pw_{slug}'): return Response("Password required",status=403,mimetype='text/plain')
  ext={'python':'py','javascript':'js','html':'html','css':'css','bash':'sh','json':'json','sql':'sql'}.get(p['syntax'],'txt')
  fn=p['title'].replace(' ','_')[:40]+'.'+ext
  return Response(p['content'],mimetype='text/plain',headers={"Content-Disposition":f"attachment; filename={fn}"})

# ━━━ EDIT / PIN / DELETE ━━━
@app.route('/edit/<slug>',methods=['GET','POST'])
def edit_paste(slug):
  if not session.get('user_id'): return redirect('/login')
  db=get_db(); paste=db.execute("SELECT * FROM pastes WHERE slug=?",(slug,)).fetchone()
  if not paste or paste['user_id']!=session['user_id']: db.close(); flash('Not allowed!','red'); return redirect('/')
  if request.method=='POST':
    t=request.form.get('title','').strip(); ct=request.form.get('content','').strip()
    sy=request.form.get('syntax','text'); vi=request.form.get('visibility','public')
    tags=','.join(x.strip() for x in request.form.getlist('tags') if x.strip())
    if t and ct: db.execute("UPDATE pastes SET title=?,content=?,syntax=?,visibility=?,tags=?,ai_summary='' WHERE slug=?",(t,ct,sy,vi,tags,slug)); db.commit(); db.close(); flash('Updated!','green'); return redirect(f'/paste/{slug}')
    flash('Fill all fields!','red')
  db.close()
  cur_tags=paste['tags'].split(',') if paste['tags'] else []
  tag_checks=''.join(f'<label style="display:inline-flex;align-items:center;gap:4px;margin:3px;cursor:pointer;font-size:11px;text-transform:none;letter-spacing:0;"><input type="checkbox" name="tags" value="{t}" style="width:auto;" {"checked" if t in cur_tags else ""}> #{t}</label>' for t in ALL_TAGS)
  c=f'''<div style="max-width:800px;margin:0 auto;"><div class="card">
<div style="font-size:14px;font-weight:700;color:var(--yellow);letter-spacing:2px;margin-bottom:12px;">✏️ EDIT</div>
<form method="POST">
<div class="fg"><label>Title</label><input name="title" value="{paste['title']}" required></div>
<div class="fg"><label>Content</label><textarea name="content" id="pc" rows="11" required style="font-family:'Share Tech Mono',monospace;font-size:12px;resize:vertical;" oninput="lc(this)">{paste['content']}</textarea>
<div class="lc-bar"><span>📄 <span class="lc-num" id="ll">0</span></span><span>📝 <span class="lc-num" id="lc2">0</span></span></div></div>
<div class="g2"><div class="fg"><label>Syntax</label><select name="syntax"><option value="text" {"selected" if paste["syntax"]=="text" else ""}>Plain</option><option value="python" {"selected" if paste["syntax"]=="python" else ""}>Python</option><option value="javascript" {"selected" if paste["syntax"]=="javascript" else ""}>JS</option><option value="html" {"selected" if paste["syntax"]=="html" else ""}>HTML</option><option value="bash" {"selected" if paste["syntax"]=="bash" else ""}>Bash</option><option value="json" {"selected" if paste["syntax"]=="json" else ""}>JSON</option><option value="sql" {"selected" if paste["syntax"]=="sql" else ""}>SQL</option></select></div>
<div class="fg"><label>Visibility</label><select name="visibility"><option value="public" {"selected" if paste["visibility"]=="public" else ""}>🌐 Public</option><option value="private" {"selected" if paste["visibility"]=="private" else ""}>🔒 Private</option></select></div></div>
<div class="fg"><label>Tags</label><div style="margin-top:4px;">{tag_checks}</div></div>
<div style="display:flex;gap:7px;"><button type="submit" class="btn btn-p" style="flex:1;font-size:12px;padding:9px;">💾 Save</button><a href="/paste/{slug}" class="btn btn-o" style="padding:9px 14px;font-size:12px;">Cancel</a></div>
</form></div></div>
<script>function lc(el){{const v=el.value;document.getElementById('ll').textContent=v?v.split('\\n').length:0;document.getElementById('lc2').textContent=v.length;}}window.onload=()=>lc(document.getElementById('pc'));</script>'''
  return base(c,"Edit",session.get('theme','cyan'))

@app.route('/pin/<slug>')
def pin_paste(slug):
  if not session.get('user_id'): return redirect('/login')
  db=get_db(); p=db.execute("SELECT * FROM pastes WHERE slug=?",(slug,)).fetchone()
  if p and p['user_id']==session['user_id']: db.execute("UPDATE pastes SET pinned=1-pinned WHERE slug=?",(slug,)); db.commit()
  db.close(); return redirect(f'/paste/{slug}')

@app.route('/delete/<slug>')
def delete_paste(slug):
  if not session.get('user_id'): return redirect('/login')
  db=get_db(); p=db.execute("SELECT * FROM pastes WHERE slug=?",(slug,)).fetchone()
  if p and p['user_id']==session['user_id']: db.execute("DELETE FROM pastes WHERE slug=?",(slug,)); db.commit()
  db.close(); return redirect('/')

# ━━━ FOLLOW ━━━
@app.route('/follow/<username>')
def follow_user(username):
  if not session.get('user_id'): return redirect('/login')
  db=get_db(); target=db.execute("SELECT id FROM users WHERE username=?",(username,)).fetchone()
  if target and target['id']!=session['user_id']:
    ex=db.execute("SELECT id FROM follows WHERE follower_id=? AND following_id=?",(session['user_id'],target['id'])).fetchone()
    if ex: db.execute("DELETE FROM follows WHERE follower_id=? AND following_id=?",(session['user_id'],target['id']))
    else:
      db.execute("INSERT INTO follows(follower_id,following_id) VALUES(?,?)",(session['user_id'],target['id']))
      send_notif(target['id'],f'👥 {session["user"]} followed you!',f'/profile/{session["user"]}')
    db.commit()
  db.close(); return redirect(f'/profile/{username}')

# ━━━ NOTIFICATIONS ━━━
@app.route('/notifications')
def notifications():
  if not session.get('user_id'): return redirect('/login')
  db=get_db()
  notifs=db.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50",(session['user_id'],)).fetchall()
  db.execute("UPDATE notifications SET read=1 WHERE user_id=?",(session['user_id'],)); db.commit(); db.close()
  rows=''.join(f'<div class="notif {"unread" if not n["read"] else ""}"><div style="flex:1;"><div style="font-size:11px;font-weight:600;">{n["message"]}</div><div style="font-size:9px;color:var(--dim);font-family:\'Share Tech Mono\',monospace;margin-top:2px;">{n["created_at"][:16]}</div></div>{"<div class=notif-dot></div>" if not n["read"] else ""}{"<a href=\'"+n["link"]+"\' style=color:var(--p);text-decoration:none;font-size:10px;>→</a>" if n["link"] else ""}</div>' for n in notifs) or '<div style="text-align:center;color:var(--dim);padding:16px;">No notifications!</div>'
  c=f'<div style="max-width:640px;margin:0 auto;"><div style="font-size:15px;font-weight:700;color:var(--p);letter-spacing:2px;margin-bottom:13px;">🔔 NOTIFICATIONS</div><div class="card">{rows}</div></div>'
  return base(c,"Notifications",session.get('theme','cyan'))

# ━━━ PROFILE ━━━
@app.route('/profile/<username>')
def profile(username):
  db=get_db(); user=db.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
  if not user: db.close(); return redirect('/')
  pastes=db.execute("SELECT * FROM pastes WHERE user_id=? AND visibility='public' ORDER BY pinned DESC,created_at DESC",(user['id'],)).fetchall()
  p30=db.execute("SELECT COUNT(*) FROM pastes WHERE user_id=? AND created_at>=?",(user['id'],(datetime.now()-timedelta(days=30)).strftime('%Y-%m-%d'))).fetchone()[0]
  followers=db.execute("SELECT COUNT(*) FROM follows WHERE following_id=?",(user['id'],)).fetchone()[0]
  following=db.execute("SELECT COUNT(*) FROM follows WHERE follower_id=?",(user['id'],)).fetchone()[0]
  is_following=False
  if session.get('user_id') and session['user_id']!=user['id']:
    is_following=bool(db.execute("SELECT id FROM follows WHERE follower_id=? AND following_id=?",(session['user_id'],user['id'])).fetchone())
  chart_labels=[]; pd2=[]; vd=[]
  for i in range(6,-1,-1):
    day=(datetime.now()-timedelta(days=i)); lbl=day.strftime('%b %d'); ds=day.strftime('%Y-%m-%d')
    pc=db.execute("SELECT COUNT(*) FROM pastes WHERE user_id=? AND DATE(created_at)=?",(user['id'],ds)).fetchone()[0]
    vc=db.execute("SELECT COALESCE(SUM(views),0) FROM pastes WHERE user_id=? AND DATE(created_at)=?",(user['id'],ds)).fetchone()[0]
    chart_labels.append(lbl); pd2.append(pc); vd.append(vc)
  db.close()
  theme=user['theme'] or 'cyan'; av=user['avatar'] or '👤'
  p=THEMES.get(theme,'#00f5ff')
  all_b=[('Active','🏃','#00f5ff',p30>=5),('Popular','','#ff2d55',user['total_views']>=1000),('Famous','⚡','#ff6b00',user['total_views']>=5000),('Legendary','👑','#ffd700',user['total_views']>=10000)]
  bh=''.join(f'<span class="badge" style="background:{b[2]}{"22" if b[3] else "08"};color:{b[2] if b[3] else "#4a6a80"};border:1px solid {b[2]}{"44" if b[3] else "18"};">{b[1]} {b[0]}</span>' for b in all_b)
  pl=''.join(f'<a href="/paste/{p2["slug"]}" class="pi {"pinned" if p2["pinned"] else ""}"><div><div class="pt">{"📌 " if p2["pinned"] else ""}{p2["title"]}</div><div class="pm">{p2["created_at"][:10]} · {p2["syntax"]}</div></div><div class="pv">👁{p2["views"]}</div></a>' for p2 in pastes if not is_expired(p2)) or '<div style="text-align:center;color:var(--dim);padding:10px;">No pastes.</div>'
  eb=f'<a href="/settings" class="btn btn-o" style="font-size:10px;padding:3px 8px;">⚙️</a>' if session.get('user')==username else ''
  fb=''
  if session.get('user') and session['user']!=username:
    fc='follow-btn following' if is_following else 'follow-btn'
    ft='✓ Following' if is_following else '+ Follow'
    fb=f'<a href="/follow/{username}" class="{fc}">{ft}</a>'
  tg=f'<a href="https://t.me/{user["telegram"]}" target="_blank" style="color:#00aaff;font-size:10px;text-decoration:none;">✈️ @{user["telegram"]}</a>' if user['telegram'] else ''
  lj=json.dumps(chart_labels); pj=json.dumps(pd2); vj=json.dumps(vd)
  # badge progress
  badges=[
    ('Active','#00f5ff',p30,15,'Pastes last 30 days'),
    ('Popular','#ff2d55',user['total_views'],1000,'Views last 30 days'),
    ('Famous','#ff6b00',user['total_views'],5000,'Total views'),
    ('Legendary','#ffd700',user['total_views'],10000,'All Badges Together'),
  ]
  def badge_card(name,col,val,target,desc):
    done=val>=target
    pct=min(100,int(val/target*100)) if target else 100
    op='1' if done else '.5'
    return (f'<div style="background:var(--card);border:1px solid {col}{"44" if done else "18"};border-radius:12px;padding:18px;opacity:{op};">'
      f'<div style="display:flex;justify-content:space-between;margin-bottom:6px;">'
      f'<div style="font-size:15px;font-weight:800;color:{col};">{name}</div>'
      f'<div style="font-size:10px;color:rgba(255,255,255,.4);">{desc}</div></div>'
      f'<div style="font-size:24px;font-weight:900;color:#fff;">{val}<span style="font-size:13px;color:rgba(255,255,255,.3);">/{target}</span></div>'
      f'<div style="background:rgba(255,255,255,.08);border-radius:99px;height:4px;margin-top:10px;">'
      f'<div style="background:{col};width:{pct}%;height:4px;border-radius:99px;"></div>'
      f'</div></div>')
  badge_cards=''.join(badge_card(*b) for b in badges)
  # social links
  _ud=dict(user); avatar_url=_ud.get('avatar_url','') or ''; links_raw=[_ud.get('link1','') or '',_ud.get('link2','') or '',_ud.get('link3','') or '',_ud.get('link4','') or '',_ud.get('link5','') or '']
  def mk_link(url):
    if not url: return ''
    ul=url.lower()
    if 'github' in ul: lbl='GitHub'
    elif 't.me' in ul or 'telegram' in ul: lbl='Telegram'
    elif 'twitter' in ul or 'x.com' in ul: lbl='Twitter/X'
    elif 'youtube' in ul: lbl='YouTube'
    elif 'instagram' in ul: lbl='Instagram'
    elif 'linkedin' in ul: lbl='LinkedIn'
    else:
      try:
        from urllib.parse import urlparse; lbl=urlparse(url).netloc or url[:20]
      except: lbl=url[:20]
    return (f'<a href="{url}" target="_blank" rel="noopener" '
      f'style="display:flex;align-items:center;gap:8px;padding:9px 14px;'
      f'background:var(--bg);border:1px solid var(--bd);border-radius:8px;'
      f'font-size:13px;font-weight:600;color:var(--p);text-decoration:none;">'
      f'<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
      f'<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>'
      f'<path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>{lbl}</a>')
  links_html=''.join(mk_link(l) for l in links_raw if l)
  is_own=session.get('user')==username
  # premium banner (own profile, is premium)
  # ── Premium display elements ──
  is_prem_user=bool(_ud.get('is_premium',0))
  prem_note=_ud.get('premium_note','') or 'Premium'
  # ⭐ Small inline badge (next to username everywhere)
  prem_badge_html=(
    '<span class="prem-badge" title="ZeroShell Premium Member">'
    '<svg width="11" height="11" viewBox="0 0 24 24" fill="#fff" style="flex-shrink:0;">'
    '<path d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6z"/></svg>'
    ' Premium</span>'
  ) if is_prem_user else ''
  # Golden ring on avatar if premium
  avatar_ring_cls='prem-avatar-ring' if is_prem_user else ''
  # Name class
  name_cls='prem-name' if is_prem_user else ''
  prem_banner=''
  if is_prem_user:
    prem_banner=(
      '<div style="background:linear-gradient(135deg,rgba(123,47,247,.18),rgba(241,7,163,.12),rgba(255,215,0,.1));'
      'border:1px solid rgba(255,215,0,.4);border-radius:12px;padding:12px 16px;margin-bottom:12px;'
      'display:flex;align-items:center;gap:12px;position:relative;overflow:hidden;'
      '><div style="position:absolute;top:0;left:-100%;width:50%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.06),transparent);animation:pbShimmer 3s infinite;"></div>'
      '<div style="width:42px;height:42px;border-radius:50%;background:linear-gradient(135deg,#7b2ff7,#ffd700);display:flex;align-items:center;justify-content:center;flex-shrink:0;">'
      '<svg width="20" height="20" viewBox="0 0 24 24" fill="#fff"><path d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6z"/></svg></div>'
      '<div style="flex:1;">'
      '<div style="font-size:13px;font-weight:800;background:linear-gradient(90deg,#ffd700,#f107a3);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">⭐ ZeroShell Premium</div>'
      f'<div style="font-size:11px;color:rgba(255,255,255,.5);margin-top:1px;">{prem_note} · VIP Member</div>'
      '</div>'
      '<div style="background:linear-gradient(135deg,#ffd700,#ff8c00);color:#000;font-size:10px;font-weight:900;'
      'padding:4px 12px;border-radius:99px;letter-spacing:.5px;flex-shrink:0;">VIP</div>'
      '</div>'
    )
  # premium CTA for non-premium (own profile only)
  prem_cta=''
  if is_own and not _ud.get('is_premium',0):
    prem_cta=(
      '<div style="background:linear-gradient(135deg,rgba(123,47,247,.15),rgba(241,7,163,.1));border:1px solid rgba(123,47,247,.35);border-radius:16px;padding:24px;text-align:center;">'
      '<div style="font-size:11px;font-weight:800;color:rgba(255,215,0,.6);letter-spacing:2px;margin-bottom:4px;">UPGRADE ACCOUNT</div>'
      '<div style="font-size:18px;font-weight:900;color:#ffd700;margin-bottom:4px;">⭐ ZeroShell Premium</div>'
      '<div style="font-size:12px;color:rgba(255,255,255,.5);margin-bottom:20px;">VIP badge · 10 posts/day · Glowing pastes · 5 profile links</div>'
      '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:20px;">'
      '<div style="background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.3);border-radius:12px;padding:14px 8px;">'
      '<div style="font-size:10px;font-weight:700;color:#3fb950;letter-spacing:1px;margin-bottom:6px;">3 MONTHS</div>'
      '<div style="font-size:26px;font-weight:900;color:#fff;line-height:1;">$20</div>'
      '<div style="font-size:10px;color:rgba(255,255,255,.4);margin-top:3px;">/ 3 months</div></div>'
      '<div style="background:rgba(0,245,255,.08);border:2px solid rgba(0,245,255,.45);border-radius:12px;padding:14px 8px;position:relative;">'
      '<div style="position:absolute;top:-10px;left:50%;transform:translateX(-50%);background:#ffd700;color:#000;font-size:9px;font-weight:900;padding:2px 10px;border-radius:99px;white-space:nowrap;">BEST VALUE</div>'
      '<div style="font-size:10px;font-weight:700;color:#00f5ff;letter-spacing:1px;margin-bottom:6px;">6 MONTHS</div>'
      '<div style="font-size:26px;font-weight:900;color:#ffd700;line-height:1;">$40</div>'
      '<div style="font-size:10px;color:rgba(255,255,255,.4);margin-top:3px;">/ 6 months</div></div>'
      '<div style="background:rgba(255,215,0,.06);border:1px solid rgba(255,215,0,.25);border-radius:12px;padding:14px 8px;">'
      '<div style="font-size:10px;font-weight:700;color:#ffd700;letter-spacing:1px;margin-bottom:6px;">LIFETIME</div>'
      '<div style="font-size:26px;font-weight:900;color:#fff;line-height:1;">$60</div>'
      '<div style="font-size:10px;color:rgba(255,255,255,.4);margin-top:3px;">/ forever &#9854;</div></div>'
      '</div>'
      '<a href="/premium" style="display:flex;align-items:center;justify-content:center;gap:8px;background:linear-gradient(135deg,#7b2ff7,#f107a3);color:#fff;text-decoration:none;padding:12px 32px;border-radius:10px;font-size:13px;font-weight:800;">&#11088; Upgrade to Premium &#8594;</a>'
      '</div>'
    )
  # sidebar menu (own profile)
  def ml(href,label,active=False,danger=False):
    col='#ff453a' if danger else ('var(--p)' if active else 'var(--t)')
    bg='rgba(128,128,128,.12)' if active else 'transparent'
    hov='rgba(255,69,58,.08)' if danger else 'rgba(128,128,128,.08)'
    return (f'<a href="{href}" style="display:flex;align-items:center;padding:11px 14px;'
      f'border-radius:8px;background:{bg};color:{col};text-decoration:none;font-size:13px;font-weight:{"700" if active else "600"};'
      f'transition:background .15s;" onmouseover="this.style.background=\'{hov}\'" onmouseout="this.style.background=\'{bg}\'">{label}</a>')
  own_menu=''
  if is_own:
    own_menu=(
      '<div style="background:var(--card);border:1px solid var(--bd);border-radius:12px;overflow:hidden;padding:5px;">'
      +ml(f'/profile/{username}','📊 Dashboard',active=True)
      +ml('/settings','⚙️ Profile Settings')
      +ml('/new','📝 My Pastes')
      +ml('/api/v1/docs','⟨/⟩ API')
      +ml('/logout','→ Logout',danger=True)
      +'</div>'
    )
  follow_btn=(f'<a href="/follow/{username}" class="btn {'follow-btn following' if is_following else 'follow-btn'}" style="width:100%;justify-content:center;display:flex;padding:10px;margin-top:8px;">{"✓ Following" if is_following else "+ Follow"}</a>') if not is_own and session.get('user_id') else ''
  c=f'''<div style="max-width:1100px;margin:0 auto;display:grid;grid-template-columns:230px 1fr;gap:18px;align-items:start;">
<div style="position:sticky;top:70px;display:flex;flex-direction:column;gap:10px;">
{own_menu}{follow_btn}
</div>
<div style="display:flex;flex-direction:column;gap:14px;">
  <div style="background:var(--card);border:1px solid var(--bd);border-radius:14px;overflow:hidden;">
    <div style="height:72px;background:linear-gradient(135deg,{p}22,{p}06);"></div>
    <div style="padding:0 20px 20px;">
      <div style="display:flex;align-items:flex-end;gap:12px;margin-top:-30px;margin-bottom:10px;">
        {('<div style="width:60px;height:60px;background:var(--bg);border:3px solid var(--bd);border-radius:50%;overflow:hidden;flex-shrink:0;" class="'+avatar_ring_cls+'"><img src="'+avatar_url+'" style="width:100%;height:100%;object-fit:cover;"></div>') if avatar_url else ('<div style="width:60px;height:60px;background:var(--bg);border:3px solid var(--bd);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:28px;flex-shrink:0;" class="'+avatar_ring_cls+'">'+av+'</div>')}
        <div style="flex:1;padding-bottom:2px;">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <div style="font-size:20px;font-weight:800;" class="{name_cls}">{username}</div>
            {prem_badge_html}
          </div>
          <div style="font-size:12px;color:var(--s);">{followers} followers · {following} following</div>
        </div>
        <div style="display:flex;gap:6px;">{fb}{eb}</div>
      </div>
      {prem_banner}
      {('<div style="font-size:13px;color:var(--s);margin-bottom:10px;">'+user["bio"]+'</div>') if user["bio"] else ''}
      {('<div style="display:flex;flex-direction:column;gap:6px;margin-bottom:10px;">'+links_html+'</div>') if links_html else ''}
      {tg}
    </div>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">{badge_cards}</div>
  {prem_cta}
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
    <div class="card"><div style="font-size:10px;font-weight:700;color:var(--p);letter-spacing:1px;margin-bottom:8px;">PASTES 7d</div><canvas id="pc2" height="100"></canvas></div>
    <div class="card"><div style="font-size:10px;font-weight:700;color:#00cc66;letter-spacing:1px;margin-bottom:8px;">VIEWS 7d</div><canvas id="vc2" height="100"></canvas></div>
  </div>
  <div class="card"><div style="font-size:11px;font-weight:700;color:var(--s);letter-spacing:1px;text-transform:uppercase;margin-bottom:10px;">Pastes ({len(pastes)})</div>{pl}</div>
</div></div>
<script>
const lb={lj},pd={pj},vd2={vj};
const co={{plugins:{{legend:{{display:false}}}},scales:{{x:{{ticks:{{color:"#4a6a80",font:{{size:8}}}},grid:{{color:"rgba(128,128,128,.07)"}}}},y:{{ticks:{{color:"#4a6a80",font:{{size:8}},stepSize:1}},grid:{{color:"rgba(128,128,128,.07)"}}}}}}}}; 
new Chart(document.getElementById('pc2'),{{type:'bar',data:{{labels:lb,datasets:[{{data:pd,backgroundColor:'{p}33',borderColor:'{p}',borderWidth:2,borderRadius:4}}]}},options:co}});
new Chart(document.getElementById('vc2'),{{type:'line',data:{{labels:lb,datasets:[{{data:vd2,backgroundColor:'#00cc6618',borderColor:'#00cc66',borderWidth:2,pointBackgroundColor:'#00cc66',tension:.4,fill:true}}]}},options:co}});
</script>'''
  return base(c,username,theme)

# ━━━ USER DASHBOARD ━━━
@app.route('/dashboard')
def dashboard():
  if not session.get('user_id'): flash('Please login!','error'); return redirect('/login')
  uid=session['user_id']; theme=session.get('theme','cyan')
  db=get_db()
  user=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
  if not user: db.close(); return redirect('/login')
  ud=dict(user)

  # ── Core stats ──
  total_pastes=db.execute("SELECT COUNT(*) FROM pastes WHERE user_id=?",(uid,)).fetchone()[0]
  total_views=ud.get('total_views',0)
  total_likes=db.execute("SELECT COALESCE(SUM(likes),0) FROM pastes WHERE user_id=?",(uid,)).fetchone()[0]
  total_comments=db.execute("SELECT COUNT(*) FROM comments c JOIN pastes p ON c.paste_id=p.id WHERE p.user_id=?",(uid,)).fetchone()[0]
  total_followers=db.execute("SELECT COUNT(*) FROM follows WHERE following_id=?",(uid,)).fetchone()[0]
  total_following=db.execute("SELECT COUNT(*) FROM follows WHERE follower_id=?",(uid,)).fetchone()[0]
  unread=db.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND read=0",(uid,)).fetchone()[0]

  # ── Top pastes ──
  top_pastes=db.execute("SELECT slug,title,views,likes,syntax,created_at FROM pastes WHERE user_id=? ORDER BY views DESC LIMIT 5",(uid,)).fetchall()

  # ── Recent activity (last 7 days chart) ──
  chart_labels=[]; chart_views=[]; chart_pastes=[]
  for i in range(6,-1,-1):
    day=(datetime.now()-timedelta(days=i)); ds=day.strftime('%Y-%m-%d')
    chart_labels.append(day.strftime('%b %d'))
    chart_views.append(db.execute("SELECT COALESCE(SUM(views),0) FROM pastes WHERE user_id=? AND DATE(created_at)=?",(uid,ds)).fetchone()[0])
    chart_pastes.append(db.execute("SELECT COUNT(*) FROM pastes WHERE user_id=? AND DATE(created_at)=?",(uid,ds)).fetchone()[0])

  # ── Recent notifications ──
  notifs=db.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 8",(uid,)).fetchall()

  # ── Syntax breakdown ──
  syn_data=db.execute("SELECT syntax,COUNT(*) as c FROM pastes WHERE user_id=? GROUP BY syntax ORDER BY c DESC LIMIT 6",(uid,)).fetchall()

  # ── Recent comments on my pastes ──
  recent_comments=db.execute("""SELECT c.content,c.created_at,u.username,u.avatar,p.title,p.slug
    FROM comments c JOIN users u ON c.user_id=u.id JOIN pastes p ON c.paste_id=p.id
    WHERE p.user_id=? ORDER BY c.created_at DESC LIMIT 5""",(uid,)).fetchall()

  db.close()

  p=THEMES.get(theme,'#00f5ff')
  av=ud.get('avatar') or '👤'
  avatar_url=ud.get('avatar_url','') or ''

  # ── Stat cards ──
  def stat_card(icon,label,value,color,link=None):
    inner=(f'<div style="display:flex;align-items:center;gap:14px;padding:18px 20px;">'
      f'<div style="width:46px;height:46px;border-radius:12px;background:{color}18;display:flex;align-items:center;justify-content:center;font-size:22px;flex-shrink:0;">{icon}</div>'
      f'<div><div style="font-size:26px;font-weight:900;color:{color};line-height:1;">{value}</div>'
      f'<div style="font-size:11px;color:var(--dim);margin-top:2px;">{label}</div></div>'
      f'</div>')
    if link:
      return f'<a href="{link}" style="display:block;background:var(--card);border:1px solid {color}28;border-radius:12px;text-decoration:none;transition:border-color .2s,transform .15s;" onmouseover="this.style.borderColor=\'{color}88\';this.style.transform=\'translateY(-2px)\'" onmouseout="this.style.borderColor=\'{color}28\';this.style.transform=\'none\'">{inner}</a>'
    return f'<div style="background:var(--card);border:1px solid {color}28;border-radius:12px;">{inner}</div>'

  stats_html=(
    '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px;margin-bottom:20px;">'
    +stat_card('📝','Total Pastes',total_pastes,p,f'/profile/{ud["username"]}')
    +stat_card('👁','Total Views',total_views,p)
    +stat_card('❤️','Total Likes',total_likes,'#ff2d55')
    +stat_card('💬','Comments Received',total_comments,'#00f5ff')
    +stat_card('👥','Followers',total_followers,'#3fb950',f'/profile/{ud["username"]}')
    +stat_card('🔔','Unread Notifs',unread,'#ffd700','/notifications')
    +'</div>'
  )

  # ── Top pastes table ──
  top_rows=''.join(
    f'<tr>'
    f'<td><a href="/paste/{p2["slug"]}" style="color:var(--p);text-decoration:none;font-weight:600;">{p2["title"][:28]}</a></td>'
    f'<td style="font-family:monospace;font-size:11px;color:var(--p);">{p2["syntax"]}</td>'
    f'<td style="color:var(--green);font-weight:700;">👁 {p2["views"]}</td>'
    f'<td style="color:#ff2d55;">❤️ {p2["likes"]}</td>'
    f'<td style="font-size:11px;color:var(--dim);">{p2["created_at"][:10]}</td>'
    f'</tr>'
    for p2 in top_pastes
  ) or '<tr><td colspan=5 style="text-align:center;color:var(--dim);padding:20px;">No pastes yet. <a href="/new" style="color:var(--p);">Create one →</a></td></tr>'

  # ── Syntax pills ──
  syn_pills=''.join(
    f'<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--bd);">'
    f'<span style="font-family:monospace;font-size:12px;color:var(--p);">{s["syntax"]}</span>'
    f'<span style="font-size:12px;color:var(--dim);">{s["c"]} pastes</span>'
    f'</div>'
    for s in syn_data
  ) or '<div style="color:var(--dim);font-size:12px;text-align:center;padding:12px;">No pastes yet.</div>'

  # ── Recent comments ──
  comment_rows=''.join(
    f'<div style="padding:10px 0;border-bottom:1px solid var(--bd);">'
    f'<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">'
    f'<span style="font-size:15px;">{c2["avatar"] or "👤"}</span>'
    f'<a href="/profile/{c2["username"]}" style="color:var(--p);font-size:12px;font-weight:700;text-decoration:none;">{c2["username"]}</a>'
    f'<span style="font-size:10px;color:var(--dim);">on <a href="/paste/{c2["slug"]}" style="color:var(--s);text-decoration:none;">{c2["title"][:20]}</a></span>'
    f'</div>'
    f'<div style="font-size:12px;color:var(--t);padding-left:22px;">{c2["content"][:80]}{"…" if len(c2["content"])>80 else ""}</div>'
    f'</div>'
    for c2 in recent_comments
  ) or '<div style="color:var(--dim);font-size:12px;text-align:center;padding:16px;">No comments yet.</div>'

  # ── Notifications list ──
  notif_rows=''.join(
    f'<div style="padding:8px 0;border-bottom:1px solid var(--bd);display:flex;align-items:flex-start;gap:8px;">'
    f'<div style="width:6px;height:6px;border-radius:50%;background:{"var(--p)" if not n["read"] else "var(--dim)"};flex-shrink:0;margin-top:5px;"></div>'
    f'<div style="flex:1;">'
    f'<div style="font-size:12px;color:{"var(--t)" if not n["read"] else "var(--dim)"};">{n["message"]}</div>'
    f'<div style="font-size:10px;color:var(--dim);margin-top:2px;">{n["created_at"][:16]}</div>'
    f'</div>'
    f'</div>'
    for n in notifs
  ) or '<div style="color:var(--dim);font-size:12px;text-align:center;padding:16px;">No notifications.</div>'

  lj=__import__('json').dumps(chart_labels)
  vj=__import__('json').dumps(chart_views)
  pj=__import__('json').dumps(chart_pastes)

  # ── Premium status bar ──
  prem_html=''
  if ud.get('is_premium'):
    prem_html=(f'<div style="background:linear-gradient(135deg,rgba(123,47,247,.15),rgba(255,215,0,.1));border:1px solid rgba(255,215,0,.35);border-radius:10px;padding:10px 16px;margin-bottom:16px;display:flex;align-items:center;gap:10px;">'
      f'<span style="font-size:20px;">⭐</span>'
      f'<div><div style="font-size:13px;font-weight:800;background:linear-gradient(90deg,#ffd700,#f107a3);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">Premium Member</div>'
      f'<div style="font-size:11px;color:var(--dim);">{ud.get("premium_note","VIP")} plan</div></div>'
      f'<div style="margin-left:auto;background:linear-gradient(135deg,#ffd700,#ff8c00);color:#000;font-size:10px;font-weight:900;padding:3px 10px;border-radius:99px;">VIP</div>'
      f'</div>')

  c=f'''<div style="max-width:1100px;margin:0 auto;">
<!-- Header -->
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:12px;">
  <div style="display:flex;align-items:center;gap:14px;">
    {('<div style="width:52px;height:52px;border-radius:50%;overflow:hidden;border:3px solid '+p+';"><img src="'+avatar_url+'" style="width:100%;height:100%;object-fit:cover;"></div>') if avatar_url else ('<div style="width:52px;height:52px;border-radius:50%;background:var(--card);border:3px solid '+p+';display:flex;align-items:center;justify-content:center;font-size:26px;">'+av+'</div>')}
    <div>
      <div style="font-size:20px;font-weight:900;color:var(--t);">My Dashboard</div>
      <div style="font-size:13px;color:var(--dim);">@{ud["username"]} · Joined {ud["created_at"][:10]}</div>
    </div>
  </div>
  <div style="display:flex;gap:8px;">
    <a href="/new" class="btn btn-p" style="font-size:13px;padding:8px 18px;">+ New Paste</a>
    <a href="/profile/{ud["username"]}" class="btn btn-o" style="font-size:13px;padding:8px 18px;">View Profile</a>
    <a href="/settings" class="btn btn-o" style="font-size:13px;padding:8px 18px;">⚙️ Settings</a>
  </div>
</div>

{prem_html}

<!-- Stats grid -->
{stats_html}

<!-- Charts + breakdown -->
<div style="display:grid;grid-template-columns:1fr 220px;gap:14px;margin-bottom:14px;align-items:start;">
  <div class="card">
    <div style="font-size:11px;font-weight:800;color:var(--p);letter-spacing:1px;margin-bottom:12px;">📈 ACTIVITY (LAST 7 DAYS)</div>
    <canvas id="dash-views" height="80"></canvas>
    <canvas id="dash-pastes" height="60" style="margin-top:10px;"></canvas>
  </div>
  <div class="card">
    <div style="font-size:11px;font-weight:800;color:var(--s);letter-spacing:1px;margin-bottom:10px;">📂 BY SYNTAX</div>
    {syn_pills}
  </div>
</div>

<!-- Bottom grid -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;">
  <!-- Top pastes -->
  <div class="card">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
      <div style="font-size:11px;font-weight:800;color:var(--p);letter-spacing:1px;">🏆 TOP PASTES</div>
      <a href="/profile/{ud["username"]}" style="font-size:11px;color:var(--dim);text-decoration:none;">See all →</a>
    </div>
    <div style="overflow-x:auto;"><table class="at">
      <thead><tr><th>Title</th><th>Syntax</th><th>Views</th><th>Likes</th><th>Date</th></tr></thead>
      <tbody>{top_rows}</tbody>
    </table></div>
  </div>
  <!-- Recent comments -->
  <div class="card">
    <div style="font-size:11px;font-weight:800;color:#00f5ff;letter-spacing:1px;margin-bottom:10px;">💬 RECENT COMMENTS</div>
    {comment_rows}
  </div>
</div>

<!-- Notifications -->
<div class="card">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
    <div style="font-size:11px;font-weight:800;color:var(--yellow);letter-spacing:1px;">🔔 RECENT NOTIFICATIONS</div>
    <a href="/notifications" style="font-size:11px;color:var(--dim);text-decoration:none;">See all →</a>
  </div>
  {notif_rows}
</div>
</div>

<script>
const _lb={lj},_vd={vj},_pd={pj};
const _co={{plugins:{{legend:{{display:false}}}},scales:{{x:{{ticks:{{color:"#4a6a80",font:{{size:8}}}},grid:{{color:"rgba(128,128,128,.06)"}}}},y:{{ticks:{{color:"#4a6a80",font:{{size:8}},stepSize:1}},grid:{{color:"rgba(128,128,128,.06)"}}}}}}}}; 
new Chart(document.getElementById('dash-views'),{{type:'line',data:{{labels:_lb,datasets:[{{data:_vd,label:'Views',backgroundColor:'{p}18',borderColor:'{p}',borderWidth:2,pointBackgroundColor:'{p}',tension:.4,fill:true}}]}},options:{{..._co,plugins:{{legend:{{display:true,labels:{{color:'#4a6a80',font:{{size:10}}}}}}}}}}}});
new Chart(document.getElementById('dash-pastes'),{{type:'bar',data:{{labels:_lb,datasets:[{{data:_pd,label:'Pastes',backgroundColor:'#3fb95033',borderColor:'#3fb950',borderWidth:1.5,borderRadius:4}}]}},options:{{..._co,plugins:{{legend:{{display:true,labels:{{color:'#4a6a80',font:{{size:10}}}}}}}}}}}});
</script>'''
  return base(c,'Dashboard',theme)

# ━━━ SETTINGS + 2FA ━━━
@app.route('/settings',methods=['GET','POST'])
def settings():
  if not session.get('user'): return redirect('/login')
  db=get_db(); user=db.execute("SELECT * FROM users WHERE username=?",(session['user'],)).fetchone(); db.close()
  if not user: return redirect('/login')
  if request.method=='POST':
    action=request.form.get('action','profile')
    if action=='profile':
      bio=request.form.get('bio','').strip(); tg=request.form.get('telegram','').strip().lstrip('@')
      l1=request.form.get('link1','').strip(); l2=request.form.get('link2','').strip(); l3=request.form.get('link3','').strip(); l4=request.form.get('link4','').strip(); l5=request.form.get('link5','').strip()
      av=request.form.get('avatar','👤'); th=request.form.get('theme','cyan')
      if th not in THEMES: th='cyan'
      avatar_url=''
      if 'avatar_file' in request.files:
        f2=request.files['avatar_file']
        if f2 and f2.filename:
          import base64 as _b64
          ext=f2.filename.rsplit('.',1)[-1].lower()
          if ext in ('jpg','jpeg','png','gif','webp'):
            data=f2.read(500*1024)  # max 500KB
            avatar_url='data:image/'+ext+';base64,'+_b64.b64encode(data).decode()
      db=get_db()
      if avatar_url:
        db.execute("UPDATE users SET bio=?,telegram=?,avatar=?,theme=?,avatar_url=?,link1=?,link2=?,link3=?,link4=?,link5=? WHERE username=?",(bio,tg,av,th,avatar_url,l1,l2,l3,l4,l5,session['user']))
      else:
        db.execute("UPDATE users SET bio=?,telegram=?,avatar=?,theme=?,link1=?,link2=?,link3=?,link4=?,link5=? WHERE username=?",(bio,tg,av,th,l1,l2,l3,l4,l5,session['user']))
      db.commit(); db.close()
      session['avatar']=av; session['theme']=th; flash('Saved!','green')
    elif action=='change_password':
      old_pw=request.form.get('old_password',''); new_pw=request.form.get('new_password',''); new_pw2=request.form.get('new_password2','')
      db=get_db(); u2=db.execute("SELECT password FROM users WHERE username=?",(session['user'],)).fetchone(); db.close()
      if not u2 or u2['password']!=hash_pw(old_pw): flash('Current password is wrong!','red')
      elif len(new_pw)<6: flash('New password must be at least 6 characters!','red')
      elif new_pw!=new_pw2: flash('Passwords do not match!','red')
      else:
        db=get_db(); db.execute("UPDATE users SET password=? WHERE username=?",(hash_pw(new_pw),session['user'])); db.commit(); db.close()
        flash('Password changed successfully!','green')
    elif action=='gen_api':
      new_key='zs_'+secrets.token_hex(20)
      db=get_db(); db.execute("UPDATE users SET api_key=? WHERE username=?",(new_key,session['user'])); db.commit(); db.close()
      flash(f'API Key: {new_key}','green')
      return redirect('/settings')
    elif action=='enable_2fa':
      code=request.form.get('totp_code','').strip()
      secret=session.get('totp_setup_secret','')
      if secret and totp_verify(secret,code):
        db=get_db(); db.execute("UPDATE users SET totp_secret=?,totp_enabled=1 WHERE username=?",(secret,session['user'])); db.commit(); db.close()
        session.pop('totp_setup_secret',None); flash('2FA Enabled!','green')
      else: flash('Wrong code!','red')
    elif action=='disable_2fa':
      db=get_db(); db.execute("UPDATE users SET totp_enabled=0,totp_secret='' WHERE username=?",(session['user'],)); db.commit(); db.close()
      flash('2FA Disabled!','green')
    elif action=='setup_2fa':
      secret=totp_gen_secret(); session['totp_setup_secret']=secret; flash('Scan QR then enter code!','green')
    return redirect('/settings')
  ct=user['theme'] or 'cyan'; ca=user['avatar'] or '👤'
  api_key=user['api_key'] or ''
  th_html=''.join(f'<div class="th-btn {"act" if k==ct else ""}" style="background:{v};" onclick="st(\'{k}\')" title="{k}"></div>' for k,v in THEMES.items())
  av_html=''.join(f'<span class="ao {"sel" if a==ca else ""}" onclick="sa(\'{a}\')">{a}</span>' for a in AVATARS)
  # 2FA section
  setup_secret=session.get('totp_setup_secret','')
  if setup_secret:
    qr_uri=totp_uri(setup_secret,session['user'])
    import urllib.parse as _up
    qr_encoded=_up.quote(qr_uri,safe='')
    totp_html=f'''<div style="background:rgba(0,245,255,.05);border:1px solid rgba(0,245,255,.2);border-radius:10px;padding:16px;margin-top:10px;">
<div style="font-size:11px;font-weight:700;color:var(--p);margin-bottom:12px;letter-spacing:1px;">📱 SETUP AUTHENTICATOR APP</div>
<div style="display:grid;grid-template-columns:auto 1fr;gap:16px;align-items:start;margin-bottom:12px;">
  <div style="background:#fff;padding:10px;border-radius:8px;display:inline-block;">
    <div id="qrcode" style="width:140px;height:140px;"></div>
  </div>
  <div>
    <div style="font-size:11px;color:var(--dim);margin-bottom:6px;">1. Install <strong style="color:var(--text);">Google Authenticator</strong> or <strong style="color:var(--text);">Authy</strong></div>
    <div style="font-size:11px;color:var(--dim);margin-bottom:6px;">2. Scan the QR code or enter key manually:</div>
    <div style="font-family:'Share Tech Mono',monospace;font-size:10px;background:rgba(0,0,0,.4);padding:8px 10px;border-radius:6px;word-break:break-all;color:var(--p);border:1px solid var(--border);">{setup_secret}</div>
    <div style="font-size:10px;color:var(--dim);margin-top:6px;">3. Enter the 6-digit code below to activate</div>
  </div>
</div>
<form method="POST"><input type="hidden" name="action" value="enable_2fa">
<div style="display:flex;gap:8px;align-items:center;">
  <input name="totp_code" placeholder="Enter 6-digit code" maxlength="6" style="max-width:180px;letter-spacing:6px;text-align:center;font-size:18px;font-weight:700;" autofocus>
  <button type="submit" class="btn btn-p" style="font-size:12px;padding:9px 16px;">✓ Activate 2FA</button>
</div>
</form></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script>new QRCode(document.getElementById("qrcode"),{{text:"{qr_uri}",width:140,height:140,colorDark:"#000000",colorLight:"#ffffff",correctLevel:QRCode.CorrectLevel.M}});</script>'''
  elif user['totp_enabled']:
    totp_html=f'''<div style="background:rgba(0,204,102,.05);border:1px solid rgba(0,204,102,.2);border-radius:8px;padding:12px;margin-top:10px;">
<div style="color:var(--green);font-size:12px;font-weight:700;margin-bottom:7px;"> 2FA is ENABLED</div>
<form method="POST"><input type="hidden" name="action" value="disable_2fa">
<button type="submit" class="btn btn-r" style="font-size:11px;" onclick="return confirm('Disable 2FA?')">🔓 Disable 2FA</button></form></div>'''
  else:
    totp_html=f'''<div style="background:rgba(255,45,85,.05);border:1px solid rgba(255,45,85,.2);border-radius:8px;padding:12px;margin-top:10px;">
<div style="color:var(--dim);font-size:11px;margin-bottom:7px;">2FA is disabled. Enable for extra security.</div>
<form method="POST"><input type="hidden" name="action" value="setup_2fa">
<button type="submit" class="btn btn-o" style="font-size:11px;">🔒 Setup 2FA</button></form></div>'''
  api_html=f'''<div style="margin-top:10px;"><div style="font-size:10px;color:var(--dim);margin-bottom:5px;text-transform:uppercase;letter-spacing:1px;">API Key</div>
<div style="font-family:'Share Tech Mono',monospace;font-size:11px;background:rgba(0,0,0,.3);padding:7px 10px;border-radius:5px;word-break:break-all;color:var(--p);margin-bottom:6px;">{api_key or "Not generated"}</div>
<form method="POST"><input type="hidden" name="action" value="gen_api"><button type="submit" class="btn btn-o" style="font-size:10px;"> Generate New Key</button></form>
<div style="margin-top:5px;font-size:9px;color:var(--dim);">Use at <a href="/api/v1/docs" style="color:var(--p);">API docs</a></div></div>'''
  c=f'''<div style="max-width:540px;margin:0 auto;">
<div class="card">
<div style="font-size:14px;font-weight:700;color:var(--p);letter-spacing:2px;margin-bottom:13px;">⚙️ SETTINGS</div>
<form method="POST" enctype="multipart/form-data"><input type="hidden" name="action" value="profile">
<input type="hidden" name="avatar" id="ai" value="{ca}">
<input type="hidden" name="theme" id="ti" value="{ct}">
<div class="fg"><label>Profile Photo</label>
<div style="display:flex;align-items:center;gap:12px;margin-top:6px;">
<div id="av-preview" style="width:52px;height:52px;border-radius:50%;border:2px solid var(--bd);overflow:hidden;display:flex;align-items:center;justify-content:center;font-size:26px;background:var(--bg);">{('<img src="'+dict(user).get("avatar_url","")+'" style="width:100%;height:100%;object-fit:cover;">') if dict(user).get("avatar_url","") else ca}</div>
<div style="flex:1;">
<input type="file" name="avatar_file" accept="image/*" id="avfile" style="display:none;" onchange="previewAv(this)">
<button type="button" onclick="document.getElementById('avfile').click()" class="btn btn-o" style="font-size:11px;padding:6px 12px;">📷 Upload Photo</button>
<div style="font-size:10px;color:var(--s);margin-top:4px;">JPG, PNG, GIF · max 500KB</div>
</div></div></div>
<div class="fg"><label>Avatar Emoji</label><div style="display:flex;flex-wrap:wrap;gap:3px;margin-top:3px;">{av_html}</div></div>
<div class="fg"><label>Theme</label><div style="display:flex;gap:5px;margin-top:3px;">{th_html}</div></div>
<div class="fg"><label>Bio</label><input name="bio" value="{user['bio'] or ''}" placeholder="Short bio..."></div>
<div class="fg"><label>Telegram</label><input name="telegram" value="{user['telegram'] or ''}" placeholder="without @"></div>
<div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin:8px 0 6px;">Profile Links (up to 5)</div>
<div class="fg"><input name="link1" value="{user['link1'] or ''}" placeholder="https://yourwebsite.com"></div>
<div class="fg"><input name="link2" value="{user['link2'] or ''}" placeholder="https://github.com/you"></div>
<div class="fg"><input name="link3" value="{user['link3'] or ''}" placeholder="https://twitter.com/you"></div>
<div class="fg"><input name="link4" value="{user['link4'] or ''}" placeholder="https://youtube.com/@you"></div>
<div class="fg"><input name="link5" value="{user['link5'] or ''}" placeholder="https://custom-link.com"></div>
<button type="submit" class="btn btn-p" style="width:100%;padding:10px;font-size:12px;">💾 Save Profile</button>
</form></div>
<div class="card"><div style="font-size:12px;font-weight:700;color:var(--yellow);margin-bottom:6px;">🔒 TWO-FACTOR AUTH</div>{totp_html}</div>
<div class="card"><div style="font-size:12px;font-weight:700;color:var(--red);margin-bottom:10px;">🔑 CHANGE PASSWORD</div>
<form method="POST"><input type="hidden" name="action" value="change_password">
<div class="fg"><label>Current Password</label><input type="password" name="old_password" placeholder="Current password" required></div>
<div class="fg"><label>New Password</label><input type="password" name="new_password" placeholder="Min 6 characters" required></div>
<div class="fg"><label>Confirm New Password</label><input type="password" name="new_password2" placeholder="Repeat new password" required></div>
<button type="submit" class="btn btn-r" style="font-size:12px;padding:9px 18px;">Change Password</button>
</form></div>
<div class="card"><div style="font-size:12px;font-weight:700;color:var(--green);margin-bottom:6px;">🌐 API ACCESS</div>{api_html}</div>
</div>
<script>
function previewAv(i){{if(i.files&&i.files[0]){{var r=new FileReader();r.onload=function(e){{var pp=document.getElementById('av-preview');if(pp)pp.innerHTML='<img src="'+e.target.result+'" style="width:100%;height:100%;object-fit:cover;">';}};r.readAsDataURL(i.files[0]);}}}}
function sa(a){{document.getElementById('ai').value=a;document.querySelectorAll('.ao').forEach(e=>e.classList.remove('sel'));event.target.classList.add('sel');}}
function st(t){{document.getElementById('ti').value=t;document.querySelectorAll('.th-btn').forEach(e=>e.classList.remove('act'));event.target.classList.add('act');}}
</script>'''
  return base(c,"Settings",ct)

# ━━━ ADMIN + ANALYTICS ━━━

@app.route('/admin/ban/<int:uid>')
def admin_ban(uid):
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  cur=db.execute("SELECT is_banned,username FROM users WHERE id=?",(uid,)).fetchone()
  new_val=0 if (cur and cur['is_banned']) else 1
  db.execute("UPDATE users SET is_banned=? WHERE id=?",(new_val,uid)); db.commit(); db.close()
  action='Unbanned' if new_val==0 else 'Banned'
  admin_log(f'{action} user: {cur["username"] if cur else uid}',f'user_id={uid}')
  flash(f'{action}!','green')
  return redirect('/admin')

@app.route('/admin/make-admin/<int:uid>')
def admin_make_admin(uid):
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  cur=db.execute("SELECT is_admin,username FROM users WHERE id=?",(uid,)).fetchone()
  new_val=0 if (cur and cur['is_admin']) else 1
  db.execute("UPDATE users SET is_admin=? WHERE id=?",(new_val,uid)); db.commit(); db.close()
  admin_log(f'{"Removed admin from" if not new_val else "Made admin"}: {cur["username"] if cur else uid}',f'user_id={uid}')
  flash('Done!','green')
  return redirect('/admin')

@app.route('/admin')
def admin():
  if not session.get('is_admin'): flash('Admin only!','red'); return redirect('/')
  cleanup_expired()
  upage=max(1,int(request.args.get('upage',1) or 1)); pper=30
  ppage=max(1,int(request.args.get('ppage',1) or 1)); per2=25
  db=get_db()
  utotal=db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
  upages=max(1,(utotal+pper-1)//pper); upage=min(upage,upages)
  users=db.execute("SELECT * FROM users ORDER BY total_views DESC LIMIT ? OFFSET ?",(pper,(upage-1)*pper)).fetchall()
  ptotal=db.execute("SELECT COUNT(*) FROM pastes").fetchone()[0]
  ppages=max(1,(ptotal+per2-1)//per2); ppage=min(ppage,ppages)
  pastes=db.execute("SELECT p.*,u.username FROM pastes p LEFT JOIN users u ON p.user_id=u.id ORDER BY p.created_at DESC LIMIT ? OFFSET ?",(per2,(ppage-1)*per2)).fetchall()
  ads=db.execute("SELECT * FROM ads ORDER BY created_at DESC").fetchall()
  tv=db.execute("SELECT COALESCE(SUM(views),0) FROM pastes").fetchone()[0]
  tc=db.execute("SELECT COUNT(*) FROM comments").fetchone()[0]
  tf=db.execute("SELECT COUNT(*) FROM follows").fetchone()[0]
  # analytics data - last 14 days
  an_labels=[]; an_pastes=[]; an_views=[]; an_users=[]
  for i in range(13,-1,-1):
    day=(datetime.now()-timedelta(days=i)); ds=day.strftime('%Y-%m-%d')
    an_labels.append(day.strftime('%d %b'))
    an_pastes.append(db.execute("SELECT COUNT(*) FROM pastes WHERE DATE(created_at)=?",(ds,)).fetchone()[0])
    an_views.append(db.execute("SELECT COUNT(*) FROM paste_views WHERE DATE(created_at)=?",(ds,)).fetchone()[0])
    an_users.append(db.execute("SELECT COUNT(*) FROM users WHERE DATE(created_at)=?",(ds,)).fetchone()[0])
  # syntax distribution
  syn_data=db.execute("SELECT syntax,COUNT(*) as c FROM pastes GROUP BY syntax ORDER BY c DESC").fetchall()
  syn_labels=json.dumps([s['syntax'] for s in syn_data])
  syn_vals=json.dumps([s['c'] for s in syn_data])
  db.close()
  def _urow(u):
    ud=dict(u)
    av3=ud.get('avatar') or '👤'
    avd=f'<img src="{av3}" style="width:20px;height:20px;border-radius:50%;object-fit:cover;vertical-align:middle;">' if av3.startswith('data:') else av3
    is_banned=ud.get('is_banned',0)
    bb=(f'<a href="/admin/unban-user/{ud["id"]}" class="btn" style="font-size:8px;padding:2px 5px;background:rgba(0,200,100,.15);border-color:#00cc66;color:#00cc66;">Unban</a>' if is_banned else f'<a href="/admin/ban-user/{ud["id"]}" class="btn btn-y" style="font-size:8px;padding:2px 5px;">Ban</a>')
    db2=('' if ud.get('is_admin') else f'<a href="/admin/del-user/{ud["id"]}" class="btn btn-r" style="font-size:8px;padding:2px 5px;" onclick="return confirm(chr(39)+chr(39))">Del</a>')
    vip=('<span style="color:#ffd700;font-size:9px;margin-left:3px;">VIP</span>' if ud.get('is_premium') else '')
    btag=('<span style="color:#ff453a;font-size:8px;margin-left:3px;">BANNED</span>' if is_banned else '')
    ev=('<span style="color:#3fb950;font-size:8px;margin-left:2px;">✓</span>' if ud.get('email_verified') else '')
    return f'<tr><td><a href="/profile/{ud["username"]}" style="color:var(--p);text-decoration:none;">{avd} {ud["username"]}{btag}{ev}</a></td><td style="color:var(--dim)">{ud["created_at"][:10]}</td><td style="color:var(--green)">{ud["total_views"]}</td><td>{"Admin" if ud.get("is_admin") else "User"}{vip}</td><td style="display:flex;gap:3px;">{bb} {db2}</td></tr>'
  uh=''.join(_urow(u) for u in users)
  ph=''.join(f'<tr><td><a href="/paste/{p["slug"]}" style="color:var(--p);text-decoration:none;">{p["title"][:20]}</a></td><td style="color:var(--dim)">{p["username"] or "Anon"}</td><td style="color:var(--green)">{p["views"]}</td><td style="color:var(--dim)">{p["created_at"][:10]}</td><td><a href="/admin/del-paste/{p["slug"]}" class="btn btn-r" style="font-size:8px;padding:2px 5px;">Del</a></td></tr>' for p in pastes)
  adh=''.join(f'<tr><td>{a["title"]}</td><td style="color:var(--dim)">{a["content"][:26]}</td><td style="color:{"var(--green)" if a["active"] else "var(--red)"}">{"● Active" if a["active"] else "○ Off"}</td><td><a href="/admin/toggle-ad/{a["id"]}" class="btn btn-o" style="font-size:8px;padding:2px 5px;">Toggle</a> <a href="/admin/del-ad/{a["id"]}" class="btn btn-r" style="font-size:8px;padding:2px 5px;">Del</a></td></tr>' for a in ads)
  lj=json.dumps(an_labels); pj=json.dumps(an_pastes); vj=json.dumps(an_views); uj=json.dumps(an_users)
  _db2=get_db()
  pending_pay=_db2.execute("SELECT COUNT(*) FROM payment_requests WHERE status='pending'").fetchone()[0]
  log_count=_db2.execute("SELECT COUNT(*) FROM admin_logs").fetchone()[0]
  rl_count=_db2.execute("SELECT COUNT(*) FROM rate_limits WHERE created_at > datetime('now','-1 minute')").fetchone()[0]
  _db2.close()
  c=f'''<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;"><div style="font-size:18px;font-weight:800;color:var(--t);">⚙️ Admin Panel</div><div style="display:flex;gap:8px;flex-wrap:wrap;"><a href="/admin/payments" class="btn btn-p" style="font-size:12px;position:relative;">💳 Payments{f'<span style="position:absolute;top:-6px;right:-6px;background:#ff453a;color:#fff;font-size:9px;font-weight:900;border-radius:99px;padding:1px 5px;">{pending_pay}</span>' if pending_pay else ''}</a><a href="/admin/logs" class="btn btn-o" style="font-size:12px;">📋 Logs</a><a href="/admin/backups" class="btn btn-o" style="font-size:12px;">💾 Backup</a><a href="/admin/security" class="btn btn-r" style="font-size:12px;">🔒 Security</a><a href="/admin/reports" class="btn btn-r" style="font-size:12px;">🚨 Reports</a><a href="/pastes" class="btn btn-o" style="font-size:12px;">📝 Pastes</a></div></div>
<div class="g4" style="margin-bottom:13px;">
<div class="sb"><span class="sn" style="color:var(--p);">{utotal}</span><span class="sl">Total Users</span></div>
<div class="sb"><span class="sn" style="color:var(--green);">{ptotal}</span><span class="sl">Total Pastes</span></div>
<div class="sb"><span class="sn" style="color:var(--yellow);">{tv}</span><span class="sl">Total Views</span></div>
<div class="sb"><span class="sn" style="color:var(--dim);">{tc}</span><span class="sl">Comments</span></div>
</div>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:13px;">
<div class="sb"><span class="sn" style="color:{"var(--red)" if rl_count>20 else "var(--green)"};font-size:20px;">{rl_count}</span><span class="sl">Requests/min</span></div>
<div class="sb"><span class="sn" style="color:var(--p);font-size:20px;">{log_count}</span><span class="sl">Admin Actions</span></div>
<div class="sb"><span class="sn" style="color:var(--yellow);font-size:20px;">{pending_pay}</span><span class="sl">Pending Payments</span></div>
</div>
<div class="card"><div style="font-size:11px;font-weight:700;color:var(--p);letter-spacing:2px;margin-bottom:10px;">📊 ANALYTICS — 14 DAYS</div>
<div style="margin-bottom:14px;"><canvas id="ac" height="70"></canvas></div>
<div class="g2"><div><canvas id="ac2" height="100"></canvas></div><div><canvas id="ac3" height="100"></canvas></div></div>
</div>
<div class="card"><div style="font-size:11px;font-weight:700;color:var(--yellow);margin-bottom:8px;">📢 Add Ad</div>
<form method="POST" action="/admin/add-ad"><div class="g2"><div class="fg"><label>Title</label><input name="title" required></div><div class="fg"><label>URL</label><input name="url"></div></div>
<div class="fg"><label>Content</label><input name="content" required></div>
<button type="submit" class="btn btn-p" style="font-size:10px;">Add</button></form></div>
<div class="card"><div style="font-size:10px;font-weight:700;color:var(--yellow);margin-bottom:7px;">📢 ADS</div><div style="overflow-x:auto;"><table class="at"><tr><th>Title</th><th>Content</th><th>Status</th><th>Action</th></tr>{adh}</table></div></div>
<div class="card"><div style="font-size:10px;font-weight:700;color:var(--p);margin-bottom:7px;">👤 USERS ({utotal})</div><div style="overflow-x:auto;"><table class="at"><tr><th>Username</th><th>Joined</th><th>Views</th><th>Role</th><th>Del</th></tr>{uh}</table></div>{pg_nav(upage,upages,"/admin?ppage="+str(ppage)+"&upage")}</div>
<div class="card"><div style="font-size:10px;font-weight:700;color:var(--p);margin-bottom:7px;">📝 PASTES ({ptotal})</div><div style="overflow-x:auto;"><table class="at"><tr><th>Title</th><th>Author</th><th>Views</th><th>Date</th><th>Del</th></tr>{ph}</table></div>{pg_nav(ppage,ppages,"/admin?upage="+str(upage)+"&ppage")}</div>
<script>
const lb={lj},pad={pj},vad={vj},uad={uj},sl={syn_labels},sv={syn_vals};
const colors=['#00f5ff','#ff79c6','#50fa7b','#bd93f9','#f1fa8c','#ff5555','#8be9fd','#ffb86c'];
const base_opts={{plugins:{{legend:{{display:false}}}},scales:{{x:{{ticks:{{color:"#4a6a80",font:{{size:8}}}},grid:{{color:"rgba(128,128,128,.06)"}}}},y:{{ticks:{{color:"#4a6a80",font:{{size:8}}}},grid:{{color:"rgba(128,128,128,.06)"}}}}}} }};
new Chart(document.getElementById('ac'),{{type:'line',data:{{labels:lb,datasets:[{{label:'Pastes',data:pad,borderColor:'#00f5ff',tension:.4,fill:false}},{{label:'Views',data:vad,borderColor:'#00cc66',tension:.4,fill:false}},{{label:'Users',data:uad,borderColor:'#bd93f9',tension:.4,fill:false}}]}},options:{{...base_opts,plugins:{{legend:{{display:true,labels:{{color:'#4a6a80',font:{{size:9}}}}}}}}}}}});
new Chart(document.getElementById('ac2'),{{type:'bar',data:{{labels:lb,datasets:[{{label:'New Users',data:uad,backgroundColor:'#bd93f933',borderColor:'#bd93f9',borderWidth:2,borderRadius:4}}]}},options:{{...base_opts,plugins:{{legend:{{display:true,labels:{{color:'#4a6a80',font:{{size:9}}}}}}}}}} }});
new Chart(document.getElementById('ac3'),{{type:'doughnut',data:{{labels:sl,datasets:[{{data:sv,backgroundColor:colors.map(c=>c+'88'),borderColor:colors,borderWidth:2}}]}},options:{{plugins:{{legend:{{position:'right',labels:{{color:'#4a6a80',font:{{size:9}}}}}}}}}} }});
</script>'''
  return base(c,"Admin",session.get('theme','cyan'))

@app.route('/admin/add-ad',methods=['POST'])
def add_ad():
  if not session.get('is_admin'): return redirect('/')
  t=request.form.get('title',''); ct=request.form.get('content',''); u=request.form.get('url','')
  if t and ct:
    db=get_db(); db.execute("INSERT INTO ads(title,content,url) VALUES(?,?,?)",(t,ct,u)); db.commit(); db.close(); flash('Ad added!','green')
  return redirect('/admin')
@app.route('/admin/toggle-ad/<int:i>')
def toggle_ad(i):
  if not session.get('is_admin'): return redirect('/')
  db=get_db(); db.execute("UPDATE ads SET active=1-active WHERE id=?",(i,)); db.commit(); db.close(); return redirect('/admin')
@app.route('/admin/del-ad/<int:i>')
def del_ad(i):
  if not session.get('is_admin'): return redirect('/')
  db=get_db(); db.execute("DELETE FROM ads WHERE id=?",(i,)); db.commit(); db.close(); return redirect('/admin')
@app.route('/admin/del-user/<int:i>')
def del_user(i):
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  u=db.execute("SELECT username FROM users WHERE id=?",(i,)).fetchone()
  db.execute("DELETE FROM users WHERE id=?",(i,)); db.execute("DELETE FROM pastes WHERE user_id=?",(i,)); db.commit(); db.close()
  admin_log(f'Deleted user: {u["username"] if u else i}',f'user_id={i}')
  flash('Deleted!','green'); return redirect('/admin')

@app.route('/admin/ban-user/<int:uid>')
def ban_user(uid):
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  u=db.execute("SELECT username,is_admin FROM users WHERE id=?",(uid,)).fetchone()
  if u and not u['is_admin']:
    db.execute("UPDATE users SET is_banned=1 WHERE id=?",(uid,)); db.commit()
    admin_log(f'Banned user: {u["username"]}',f'user_id={uid}')
    flash('Banned!','green')
  db.close(); return redirect('/admin')

@app.route('/admin/unban-user/<int:uid>')
def unban_user(uid):
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  u=db.execute("SELECT username FROM users WHERE id=?",(uid,)).fetchone()
  db.execute("UPDATE users SET is_banned=0 WHERE id=?",(uid,)); db.commit(); db.close()
  admin_log(f'Unbanned user: {u["username"] if u else uid}',f'user_id={uid}')
  flash('Unbanned!','green'); return redirect('/admin')

@app.route('/admin/premium/<int:uid>')
def admin_premium(uid):
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  u=db.execute("SELECT is_premium,username FROM users WHERE id=?",(uid,)).fetchone()
  if u:
    new_val=0 if u['is_premium'] else 1
    note='Lifetime' if new_val else ''
    db.execute("UPDATE users SET is_premium=?,premium_note=? WHERE id=?",(new_val,note,uid))
    db.commit()
    admin_log(f'{"Granted Premium" if new_val else "Removed Premium"}: {u["username"]}',f'user_id={uid}')
    flash(f'{"✅ Premium ON" if new_val else "❌ Premium OFF"}: {u["username"]}','green' if new_val else 'red')
  db.close()
  return redirect('/admin')

@app.route('/admin/del-paste/<slug>')
def del_paste(slug):
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  p=db.execute("SELECT title FROM pastes WHERE slug=?",(slug,)).fetchone()
  db.execute("DELETE FROM pastes WHERE slug=?",(slug,)); db.commit(); db.close()
  admin_log(f'Deleted paste: {p["title"][:40] if p else slug}',f'slug={slug}')
  return redirect('/admin')

# ━━━ AUTH ━━━
@app.route('/register',methods=['GET','POST'])
def register():
  import html as hm
  if request.method=='POST':
    step=request.form.get('step','1')
    if step=='1':
      allowed,_,reset_in=check_rate_limit('register',REGISTER_LIMIT,REGISTER_WINDOW)
      if not allowed:
        flash(f'Too many attempts. Wait {reset_in}s and try again.','error'); return redirect('/register')
      import re as _re
      raw_name=request.form.get('username','').strip()
      raw_u=request.form.get('username','').strip()
      u=_re.sub(r'[^a-zA-Z0-9_]','',raw_u)[:20]
      email=request.form.get('email','').strip().lower()
      pw=request.form.get('password',''); pw2=request.form.get('password2','')
      if not raw_name or len(raw_name)<3:
        flash('Name must be at least 3 characters.','error'); return redirect('/register')
      if not u or len(u)<3:
        flash('Username must be at least 3 characters.','error'); return redirect('/register')
      if u!=raw_u:
        flash('Username can only contain letters, numbers and underscore.','error'); return redirect('/register')
      if not email or '@' not in email:
        flash('Please enter a valid Google (Gmail) account.','error'); return redirect('/register')
      if not email.endswith('@gmail.com'):
        flash('Only Google (Gmail) accounts are accepted. Please use yourname@gmail.com.','error'); return redirect('/register')
      if not pw: flash('Password is required.','error'); return redirect('/register')
      if len(pw)<8: flash('Password must be at least 8 characters.','error'); return redirect('/register')
      if pw!=pw2: flash('Passwords do not match.','error'); return redirect('/register')
      db=get_db()
      if db.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone():
        db.close(); flash('This Gmail is already registered. Try logging in.','error'); return redirect('/register')
      if db.execute("SELECT id FROM users WHERE username=?",(u,)).fetchone():
        db.close(); flash('Username already taken. Please choose another.','error'); return redirect('/register')
      tg=''
      db.execute("DELETE FROM pending_users WHERE email=?",(email,))
      db.execute("INSERT INTO pending_users(username,email,password,telegram) VALUES(?,?,?,?)",(u,email,hash_pw(pw),tg))
      db.commit(); db.close()
      otp=gen_otp(); save_otp(email,otp,'register')
      sent=send_email(email,'ZeroShell — Verify Your Email',otp_email_html(otp,'register'))
      if not sent:
        db2=get_db(); pend=db2.execute("SELECT * FROM pending_users WHERE email=?",(email,)).fetchone()
        if pend:
          ia=1 if db2.execute("SELECT COUNT(*) FROM users").fetchone()[0]==0 else 0
          db2.execute("INSERT INTO users(username,email,password,telegram,is_admin,email_verified) VALUES(?,?,?,?,?,1)",(pend['username'],pend['email'],pend['password'],pend['telegram'],ia))
          db2.execute("DELETE FROM pending_users WHERE email=?",(email,))
          db2.commit(); user2=db2.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone(); db2.close()
          session.update({'user':user2['username'],'user_id':user2['id'],'is_admin':user2['is_admin'],'avatar':user2['avatar'] or '👤','theme':user2['theme'] or 'cyan','is_premium':bool(dict(user2).get('is_premium',0))})
          return redirect(f'/profile/{user2["username"]}')
        db2.close()
      return _auth('Register','',mode='otp_verify',hidden_user=email)
    elif step=='otp':
      email=request.form.get('email','').strip().lower()
      otp=request.form.get('otp_code','').strip()
      if not verify_otp(email,otp,'register'):
        return _auth('Register','Invalid or expired code. Please try again.',mode='otp_verify',hidden_user=email)
      db=get_db(); pend=db.execute("SELECT * FROM pending_users WHERE email=?",(email,)).fetchone()
      if not pend: db.close(); flash('Session expired. Please register again.','error'); return redirect('/register')
      ia=1 if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]==0 else 0
      db.execute("INSERT INTO users(username,email,password,telegram,is_admin,email_verified) VALUES(?,?,?,?,?,1)",(pend['username'],pend['email'],pend['password'],pend['telegram'],ia))
      db.execute("DELETE FROM pending_users WHERE email=?",(email,))
      db.commit(); user=db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone(); db.close()
      session.update({'user':user['username'],'user_id':user['id'],'is_admin':user['is_admin'],'avatar':user['avatar'] or '👤','theme':user['theme'] or 'cyan','is_premium':bool(dict(user).get('is_premium',0))})
      flash('Account created! Welcome to ZeroShell ⚡','green')
      return redirect(f'/profile/{user["username"]}')
  # GET — show any flashed error in form
  err=''.join(m for c,m in get_flashed_messages(with_categories=True) if c=='error')
  return _auth('Register',err)

@app.route('/login',methods=['GET','POST'])
def login():
  if request.method=='POST':
    ip=get_real_ip()
    if is_login_locked(ip):
      fails=login_fail_count(ip)
      flash(f'Too many failed attempts ({fails}/5). Try again in 10 minutes.','error'); return redirect('/login')
    lid=request.form.get('username','').strip(); pw=request.form.get('password','')
    totp_code=request.form.get('totp_code','').strip()
    db=get_db()
    user=db.execute("SELECT * FROM users WHERE (username=? OR email=?) AND password=?",(lid,lid.lower(),hash_pw(pw))).fetchone()
    db.close()
    if not user:
      log_login_attempt(ip,lid,False)
      fails=login_fail_count(ip)
      warn=f' ({fails}/5 attempts)' if fails>=3 else ''
      flash(f'Wrong username/email or password.{warn}','error'); return redirect('/login')
    try:
      if user['is_banned']:
        log_login_attempt(ip,lid,False)
        flash('This account has been suspended. Contact support.','error'); return redirect('/login')
    except: pass
    if user['totp_enabled']:
      if not totp_code: return _auth('Login','','2fa_needed',user['username'])
      if not totp_verify(user['totp_secret'],totp_code):
        log_login_attempt(ip,lid,False)
        return _auth('Login','Wrong 2FA code! Try again.','2fa_needed',user['username'])
    log_login_attempt(ip,lid,True)
    session.update({'user':user['username'],'user_id':user['id'],'is_admin':user['is_admin'],'avatar':user['avatar'] or '👤','theme':user['theme'] or 'cyan','is_premium':bool(dict(user).get('is_premium',0))})
    return redirect(f'/profile/{user["username"]}')
  err=''.join(m for c,m in get_flashed_messages(with_categories=True) if c=='error')
  return _auth('Login',err)

# ━━━ FORGOT PASSWORD ━━━
@app.route('/forgot-password',methods=['GET','POST'])
def forgot_password():
  import html as hm
  err=''; success=''
  if request.method=='POST':
    step=request.form.get('step','1')
    if step=='1':
      email=request.form.get('email','').strip().lower()
      if not email or '@' not in email:
        err='Please enter a valid email address.'
      else:
        db=get_db(); user=db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone(); db.close()
        if user:
          otp=gen_otp(); save_otp(email,otp,'reset')
          sent=send_email(email,'ZeroShell — Password Reset',otp_email_html(otp,'reset'))
          if not sent:
            print(f'[OTP DEBUG] Reset OTP for {email}: {otp}')
            try:
              _db=get_db()
              _db.execute("INSERT INTO admin_logs(admin_id,admin_username,action,target,ip) VALUES(0,'system',?,?,?)",
                (f'OTP_DEBUG reset',f'email={email} CODE={otp}','server'))
              _db.commit(); _db.close()
            except: pass
            c=_fp_page(step='2',email=hm.escape(email),err='',info=f'Email not configured — your code is: <b style="font-size:22px;letter-spacing:6px;color:var(--p);">{otp}</b>')
            return base(c,'Forgot Password',auth_page=True)
        c=_fp_page(step='2',email=hm.escape(email),err='',info='If that email is registered, a 6-digit code has been sent.')
        return base(c,'Forgot Password',auth_page=True)
    elif step=='2':
      email=request.form.get('email','').strip().lower()
      otp=request.form.get('otp_code','').strip()
      new_pw=request.form.get('new_password','')
      new_pw2=request.form.get('new_password2','')
      if not otp or not new_pw:
        c=_fp_page(step='2',email=hm.escape(email),err='All fields are required.')
        return base(c,'Forgot Password',auth_page=True)
      if len(new_pw)<6:
        c=_fp_page(step='2',email=hm.escape(email),err='Password must be at least 6 characters.')
        return base(c,'Forgot Password',auth_page=True)
      if new_pw!=new_pw2:
        c=_fp_page(step='2',email=hm.escape(email),err='Passwords do not match.')
        return base(c,'Forgot Password',auth_page=True)
      if not verify_otp(email,otp,'reset'):
        c=_fp_page(step='2',email=hm.escape(email),err='Invalid or expired code. Please try again.')
        return base(c,'Forgot Password',auth_page=True)
      db=get_db()
      db.execute("UPDATE users SET password=? WHERE email=?",(hash_pw(new_pw),email)); db.commit()
      user=db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone(); db.close()
      if user:
        session.update({"user":user["username"],"user_id":user["id"],"is_admin":bool(user["is_admin"]),"avatar":user["avatar"] or "👤","theme":user["theme"] or "cyan","is_premium":bool(dict(user).get("is_premium",0))})
        return redirect(f'/profile/{user["username"]}')
      return redirect('/login')
  c=_fp_page(step='1',err=err)
  return base(c,'Forgot Password',auth_page=True)

def _fp_page(step='1',email='',err='',info=''):
  import html as hm
  err_html=f'<div class="alert ar">{hm.escape(err)}</div>' if err else ''
  info_html=f'<div class="alert ag">{hm.escape(info)}</div>' if info else ''
  if step=='1':
    body=f'''{err_html}
<form method="POST">
<input type="hidden" name="step" value="1">
<div class="fg"><label>Registered Email</label><input name="email" type="email" placeholder="your@gmail.com" required autofocus></div>
<button type="submit" class="btn btn-p" style="width:100%;padding:10px;font-size:13px;">Send Reset Code →</button>
</form>
<div style="text-align:center;margin-top:10px;"><a href="/login" style="color:var(--dim);font-size:11px;">Back to Login</a></div>'''
  else:
    body=f'''{info_html}{err_html}
<form method="POST">
<input type="hidden" name="step" value="2">
<input type="hidden" name="email" value="{email}">
<div class="fg"><label>6-Digit Code</label><input name="otp_code" placeholder="Enter code from email" maxlength="6" required autofocus style="letter-spacing:6px;text-align:center;font-size:20px;"></div>
<div class="fg"><label>New Password</label><input name="new_password" type="password" placeholder="Min 6 characters" required></div>
<div class="fg"><label>Confirm New Password</label><input name="new_password2" type="password" placeholder="Repeat password" required></div>
<button type="submit" class="btn btn-p" style="width:100%;padding:10px;font-size:13px;">Reset Password →</button>
</form>
<div style="text-align:center;margin-top:10px;"><a href="/forgot-password" style="color:var(--dim);font-size:11px;">Resend Code</a></div>'''
  return f'''<div style="max-width:360px;margin:38px auto;"><div class="card">
<div style="text-align:center;font-size:28px;margin-bottom:6px;">🔑</div>
<div style="text-align:center;font-size:15px;font-weight:700;color:var(--p);letter-spacing:2px;margin-bottom:12px;">FORGOT PASSWORD</div>
{body}</div></div>'''

def _auth(title,err='',mode='',hidden_user=''):
  import html as hm

  # ── input with icon helper ──
  def inp(name,label,typ,placeholder,extra_attrs='',icon_svg=''):
    icon_html=(f'<div style="position:absolute;left:12px;top:50%;transform:translateY(-50%);opacity:.4;line-height:0;">{icon_svg}</div>' if icon_svg else '')
    pad='38px' if icon_svg else '12px'
    return (f'<div style="margin-bottom:14px;">'
      f'<label style="display:block;font-size:11px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px;">{label}</label>'
      f'<div style="position:relative;">'
      f'{icon_html}'
      f'<input name="{name}" type="{typ}" placeholder="{placeholder}" {extra_attrs}'
      f' style="width:100%;padding:10px 12px 10px {pad};background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:9px;color:#fff;font-size:13px;outline:none;box-sizing:border-box;transition:border-color .2s;"'
      f' onfocus="this.style.borderColor=\'var(--p)\'" onblur="this.style.borderColor=\'rgba(255,255,255,.1)\'">'
      f'</div></div>')

  icon_user='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>'
  icon_lock='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>'
  icon_mail='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m2 7 10 7 10-7"/></svg>'

  extra=''; totp_field=''

  if title=='Register':
    extra=(f'{csrf_field()}'
            f'{inp("username","Username","text","Choose a username (letters, numbers, _)","required minlength=3 maxlength=20 pattern=[a-zA-Z0-9_]+",icon_user)}'
      f'<div style="font-size:10px;color:var(--dim);margin:-10px 0 12px 2px;">Letters, numbers and _ only · no spaces</div>'
      f'{inp("email","Google account","email","yourname@gmail.com","required autocomplete=email",icon_mail)}'
      f'<div style="margin-bottom:14px;">'
      f'<label style="display:block;font-size:11px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px;">Password</label>'
      f'<div style="position:relative;">'
      f'<div style="position:absolute;left:12px;top:50%;transform:translateY(-50%);opacity:.4;line-height:0;">{icon_lock}</div>'
      f'<input name="password" type="password" placeholder="At least 8 characters" required oninput="updatePwStrength(this)" autocomplete="new-password"'
      f' style="width:100%;padding:10px 12px 10px 38px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:9px;color:#fff;font-size:13px;outline:none;box-sizing:border-box;transition:border-color .2s;"'
      f' onfocus="this.style.borderColor=\'var(--p)\'" onblur="this.style.borderColor=\'rgba(255,255,255,.1)\'">'
      f'</div>'
      f'<div style="height:3px;background:rgba(255,255,255,.07);border-radius:99px;margin-top:7px;"><div id="pw-strength-bar" style="height:100%;border-radius:99px;width:0%;transition:width .3s,background .3s;"></div></div>'
      f'<div id="pw-strength-txt" style="font-size:10px;margin-top:3px;min-height:13px;color:var(--dim);"></div>'
      f'</div>'
      f'{inp("password2","Confirm password","password","Repeat your password","required autocomplete=new-password",icon_lock)}'
      f'<input type="hidden" name="step" value="1">'
      f'{PW_STRENGTH_JS}')

  elif mode=='2fa_needed':
    totp_field=f'''<input type="hidden" name="username" value="{hm.escape(hidden_user)}">
<div style="text-align:center;margin-bottom:16px;">
  <div style="font-size:38px;margin-bottom:8px;">🔐</div>
  <div style="font-size:14px;font-weight:700;color:var(--t);margin-bottom:4px;">Two-factor authentication</div>
  <div style="font-size:12px;color:var(--dim);">Open your authenticator app and enter the 6-digit code</div>
</div>
<input name="totp_code" placeholder="000000" maxlength="6" autofocus required
  style="width:100%;letter-spacing:14px;text-align:center;font-size:26px;font-weight:900;padding:14px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:9px;color:#fff;outline:none;box-sizing:border-box;"
  onfocus="this.style.borderColor=\'var(--p)\'" onblur="this.style.borderColor=\'rgba(255,255,255,.1)\'">'''
    err=err or 'Enter the 6-digit code from your authenticator app.'

  elif mode=='otp_verify':
    totp_field=f'''<input type="hidden" name="email" value="{hm.escape(hidden_user)}">
<input type="hidden" name="step" value="otp">
<div style="background:rgba(0,200,255,.05);border:1px solid rgba(0,200,255,.15);border-radius:10px;padding:16px;margin-bottom:16px;text-align:center;">
  <div style="font-size:30px;margin-bottom:6px;">📧</div>
  <div style="font-size:12px;color:var(--dim);margin-bottom:4px;">We sent a 6-digit code to</div>
  <div style="font-size:13px;font-weight:700;color:var(--p);">{hm.escape(hidden_user)}</div>
  <div style="font-size:10px;color:var(--dim);margin-top:5px;opacity:.7;">Valid for 15 minutes · Check your spam folder too</div>
</div>
<div style="margin-bottom:14px;">
  <label style="display:block;font-size:11px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px;">Verification code</label>
  <input name="otp_code" placeholder="000000" maxlength="6" autofocus required
    style="width:100%;letter-spacing:14px;text-align:center;font-size:26px;font-weight:900;padding:14px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:9px;color:#fff;outline:none;box-sizing:border-box;"
    onfocus="this.style.borderColor=\'var(--p)\'" onblur="this.style.borderColor=\'rgba(255,255,255,.1)\'">
</div>'''
    err=err or 'Check your inbox for the verification code.'

  # Login fields
  un_field = inp('username','Email or username','text','you@gmail.com or your username','required autocomplete=username',icon_user) if mode not in ('2fa_needed','otp_verify') and title!='Register' else ''
  pw_field = inp('password','Password','password','Your password','required autocomplete=current-password',icon_lock) if mode not in ('2fa_needed','otp_verify') and title!='Register' else ''
  csrf_inp = csrf_field() if mode not in ('2fa_needed','otp_verify') and title!='Register' else ''

  eh=(f'<div style="background:rgba({"0,200,80" if not err or mode=="otp_verify" else "255,45,85"},.08);'
    f'border:1px solid rgba({"0,200,80" if not err or mode=="otp_verify" else "255,45,85"},.25);'
    f'border-radius:8px;padding:10px 13px;font-size:12px;color:{"#3fb950" if not err or mode=="otp_verify" else "#ff6b6b"};margin-bottom:14px;">{err}</div>') if err else ''

  btn_label={'2fa_needed':'Verify code →','otp_verify':'Confirm email →','Register':'Create account','Login':'Log in'}.get(mode) or {'Register':'Create account','Login':'Log in'}.get(title,title)
  display_title={'2fa_needed':'Two-factor auth','otp_verify':'Check your email'}.get(mode) or {'Login':'Welcome back','Register':'Create account'}.get(title,title)

  # Google OAuth button
  _g_svg='<svg width="18" height="18" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>'
  if mode not in ('2fa_needed','otp_verify'):
    google_btn=('<div style="display:flex;align-items:center;gap:10px;margin:16px 0 8px;">'
      '<div style="flex:1;height:1px;background:rgba(255,255,255,.08);"></div>'
      '<span style="font-size:11px;color:var(--dim);white-space:nowrap;">or continue with</span>'
      '<div style="flex:1;height:1px;background:rgba(255,255,255,.08);"></div></div>'
      f'<a href="/auth/google" style="display:flex;align-items:center;justify-content:center;gap:10px;'
      f'width:100%;padding:11px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);'
      f'border-radius:9px;color:#fff;font-size:13px;font-weight:600;text-decoration:none;'
      f'box-sizing:border-box;" onmouseover="this.style.background=\'rgba(255,255,255,.09)\'" '
      f'onmouseout="this.style.background=\'rgba(255,255,255,.04)\'">'
      f'{_g_svg} Continue with Google</a>')
  else:
    google_btn=''

  if title=='Register':
    bottom='<p style="text-align:center;font-size:12px;color:var(--dim);margin:16px 0 0;">Already have an account? <a href="/login" style="color:var(--p);font-weight:700;">Log in</a></p>'
  elif mode in ('2fa_needed','otp_verify'):
    bottom=''
  else:
    bottom=(f'<div style="display:flex;justify-content:space-between;align-items:center;margin-top:14px;">'
      f'<span style="font-size:12px;color:var(--dim);">No account? <a href="/register" style="color:var(--p);font-weight:700;">Sign up free</a></span>'
      f'<a href="/forgot-password" style="font-size:12px;color:var(--dim);">Forgot password?</a></div>')

  c=f'''<div style="min-height:80vh;display:flex;align-items:center;justify-content:center;padding:24px 16px;">
<div style="width:100%;max-width:380px;">

  <div class="card" style="padding:32px 26px 26px;">

    <!-- Header -->
    <div style="margin-bottom:22px;">
      <div style="font-size:22px;font-weight:800;color:var(--t);margin-bottom:4px;">{display_title}</div>
      {'<div style="font-size:13px;color:var(--dim);">ZeroShell &mdash; paste, share, collaborate</div>' if mode=='' else ''}
    </div>

    {eh}

    <form method="POST">
      {un_field}{pw_field}{extra}{totp_field}{csrf_inp}
      <button type="submit" class="btn btn-p"
        style="width:100%;padding:12px;font-size:14px;font-weight:700;border-radius:9px;margin-top:4px;letter-spacing:.3px;">
        {btn_label}
      </button>
    </form>

    {bottom}

    {google_btn}
  </div>



</div>
</div>'''
  return base(c,title,auth_page=True)

  totp_field=''
  if mode=='2fa_needed':
    totp_field=f'''<input type="hidden" name="username" value="{hm.escape(hidden_user)}">
<div style="text-align:center;margin-bottom:14px;">
  <div style="font-size:36px;margin-bottom:8px;">🔐</div>
  <div style="font-size:13px;font-weight:600;color:var(--t);margin-bottom:4px;">Two-factor authentication</div>
  <div style="font-size:12px;color:var(--dim);">Open your authenticator app and enter the 6-digit code</div>
</div>
<div class="fg"><input name="totp_code" placeholder="000000" maxlength="6" autofocus required style="letter-spacing:10px;text-align:center;font-size:24px;font-weight:900;padding:12px;"></div>'''
    err=err or 'Enter the 6-digit code from your authenticator app.'
  elif mode=='otp_verify':
    totp_field=f'''<input type="hidden" name="email" value="{hm.escape(hidden_user)}">
<input type="hidden" name="step" value="otp">
<div style="background:rgba(0,245,255,.06);border:1px solid rgba(0,245,255,.18);border-radius:10px;padding:14px;margin-bottom:14px;text-align:center;">
  <div style="font-size:28px;margin-bottom:6px;">📧</div>
  <div style="font-size:12px;color:var(--dim);">We sent a 6-digit code to</div>
  <div style="font-size:13px;font-weight:700;color:var(--p);margin-top:3px;">{hm.escape(hidden_user)}</div>
  <div style="font-size:11px;color:var(--dim);margin-top:4px;">Valid for 15 minutes</div>
</div>
<div class="fg"><label>Verification code</label><input name="otp_code" placeholder="000000" maxlength="6" autofocus required style="letter-spacing:10px;text-align:center;font-size:24px;font-weight:900;padding:12px;"></div>'''
    err=err or 'Check your inbox for the verification code.'

  eh=f'<div class="alert {"ag" if not err or mode=="otp_verify" else "ar"}" style="font-size:12px;padding:9px 12px;">{err}</div>' if err else ''
  un_field='' if mode in ('2fa_needed','otp_verify') else '<div class="fg"><label>Email or username</label><input name="username" type="text" placeholder="you@gmail.com or username" required autocomplete="username"></div>'
  pw_field='' if mode in ('2fa_needed','otp_verify') else '<div class="fg"><label>Password</label><input name="password" type="password" required autocomplete="current-password"></div>'
  csrf_inp=csrf_field() if mode not in ('2fa_needed','otp_verify') else ''

  btn_labels={'2fa_needed':'Verify →','otp_verify':'Confirm email →','Register':'Create account','Login':'Log in'}
  btn_label=btn_labels.get(mode) or btn_labels.get(title,title)

  # Bottom links
  if title=='Register':
    bottom=f'<p style="text-align:center;font-size:12px;color:var(--dim);margin:14px 0 0;">Already have an account? <a href="/login" style="color:var(--p);font-weight:600;">Log in</a></p>'
  elif mode in ('2fa_needed','otp_verify'):
    bottom=''
  else:
    bottom=f'<div style="display:flex;justify-content:space-between;align-items:center;margin-top:12px;"><p style="font-size:12px;color:var(--dim);margin:0;">No account? <a href="/register" style="color:var(--p);font-weight:600;">Sign up</a></p><a href="/forgot-password" style="color:var(--dim);font-size:12px;">Forgot password?</a></div>'

  # Page title & icon
  icons={'Login':'🔑','Register':'✨','2fa_needed':'🔐','otp_verify':'📧'}
  icon=icons.get(mode) or icons.get(title,'⚡')
  display_title={'Login':'Welcome back','Register':'Create your account','2fa_needed':'Two-factor auth','otp_verify':'Verify your email'}.get(mode) or {'Login':'Welcome back','Register':'Create your account'}.get(title,title)

  c=f'''<div style="min-height:80vh;display:flex;align-items:center;justify-content:center;padding:24px 16px;">
<div style="width:100%;max-width:400px;">

  <!-- Card -->
  <div class="card" style="padding:32px 28px;">
    <div style="text-align:center;margin-bottom:24px;">
      <div style="font-size:36px;margin-bottom:10px;">{icon}</div>
      <div style="font-size:20px;font-weight:800;color:var(--t);margin-bottom:4px;">{display_title}</div>
      {'<div style="font-size:13px;color:var(--dim);">ZeroShell — share code, store pastes</div>' if title in ('Login','Register') and mode=='' else ''}
    </div>

    {eh}

    <form method="POST" style="margin-top:4px;">
      {un_field}{pw_field}{extra}{totp_field}{csrf_inp}
      <button type="submit" class="btn btn-p" style="width:100%;padding:12px;font-size:14px;border-radius:9px;margin-top:6px;">{btn_label}</button>
    </form>

    {bottom}

    {'<div style="display:flex;align-items:center;gap:10px;margin:16px 0 4px;"><div style="flex:1;height:1px;background:rgba(255,255,255,.08);"></div><span style="font-size:11px;color:var(--dim);white-space:nowrap;">or continue with</span><div style="flex:1;height:1px;background:rgba(255,255,255,.08);"></div></div><a href="/auth/google" style="display:flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:11px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:9px;color:var(--t);font-size:13px;font-weight:600;text-decoration:none;transition:all .2s;box-sizing:border-box;" onmouseover="this.style.background=\'rgba(255,255,255,.09)\'" onmouseout="this.style.background=\'rgba(255,255,255,.04)\'"><svg width=\"18\" height=\"18\" viewBox=\"0 0 24 24\"><path d=\"M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z\" fill=\"#4285F4\"/><path d=\"M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z\" fill=\"#34A853\"/><path d=\"M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z\" fill=\"#FBBC05\"/><path d=\"M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z\" fill=\"#EA4335\"/></svg>Continue with Google</a>' if mode not in ('2fa_needed','otp_verify') else ''}
  </div>



</div>
</div>'''
  return base(c,title,auth_page=True)


@app.route('/auth/google')
def auth_google():
  if not GOOGLE_CLIENT_ID:
    flash('Google login is not configured yet.','error'); return redirect('/login')
  state=secrets.token_hex(16); session['oauth_state']=state
  return redirect(google_auth_url())

@app.route('/auth/google/callback')
def auth_google_callback():
  if not GOOGLE_CLIENT_ID:
    return redirect('/login')
  code=request.args.get('code','')
  if not code:
    flash('Google login cancelled.','error'); return redirect('/login')
  info=google_exchange_code(code)
  if not info or not info.get('email'):
    flash('Could not get info from Google. Try again.','error'); return redirect('/login')
  email=info['email'].lower()
  db=get_db()
  user=db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
  if user:
    # Existing user — log in
    try:
      if user['is_banned']:
        db.close(); flash('This account has been suspended.','error'); return redirect('/login')
    except: pass
    session.update({'user':user['username'],'user_id':user['id'],'is_admin':user['is_admin'],
      'avatar':user['avatar'] or '👤','theme':user['theme'] or 'cyan','is_premium':bool(dict(user).get('is_premium',0))})
    db.close()
    return redirect(f'/profile/{user["username"]}')
  else:
    # New user — auto register
    import re as _re
    base_u=_re.sub(r'[^a-zA-Z0-9_]','',email.split('@')[0])[:20] or 'user'
    u=base_u; n=1
    while db.execute("SELECT id FROM users WHERE username=?",(u,)).fetchone():
      u=f'{base_u}{n}'; n+=1
    pw_hash=hashlib.sha256(secrets.token_bytes(32)).hexdigest()  # random pw
    ia=1 if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]==0 else 0
    db.execute("INSERT INTO users(username,email,password,is_admin,email_verified,google_id) VALUES(?,?,?,?,1,?)",
      (u,email,pw_hash,ia,info.get('google_id','')))
    db.commit()
    user=db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone(); db.close()
    session.update({'user':user['username'],'user_id':user['id'],'is_admin':user['is_admin'],
      'avatar':user['avatar'] or '👤','theme':user['theme'] or 'cyan','is_premium':bool(dict(user).get('is_premium',0))})
    return redirect(f'/profile/{user["username"]}')

@app.route('/logout')
def logout():
  session.clear(); return redirect('/')

# ━━━ FILE UPLOAD HELPER ━━━
ALLOWED_UPLOAD_EXT={'.txt','text','.log','log','.json','json','.cfg','cfg','.csv','csv','.xml','xml','.md','md','.ini','ini'}
MAX_FILE_BYTES = 2 * 1024 * 1024  # 2MB for file uploads

def allowed_file(filename):
  ext=os.path.splitext(filename)[1].lower()
  return ext in {'.txt','.log','.json','.cfg','.csv','.xml','.md','.ini'}

def syntax_from_ext(ext):
  return {'.json':'json','.xml':'html','.md':'text','.csv':'text','.ini':'text','.cfg':'text','.log':'text','.txt':'text'}.get(ext.lower(),'text')

# ━━━ BOOKMARK / SAVE ━━━
@app.route('/bookmark/<slug>', methods=['GET','POST'])
def bookmark_toggle(slug):
  is_ajax = request.headers.get('X-Requested-With')=='XMLHttpRequest' or request.method=='POST'
  if not session.get('user_id'):
    if is_ajax: return jsonify({'ok':False,'msg':'Login to save!','action':None})
    flash('Login to save!','error'); return redirect(f'/paste/{slug}')
  uid=session['user_id']; db=get_db()
  paste=db.execute("SELECT * FROM pastes WHERE slug=?",(slug,)).fetchone()
  if not paste:
    db.close()
    if is_ajax: return jsonify({'ok':False,'msg':'Paste not found','action':None})
    return redirect('/')
  existing=db.execute("SELECT id FROM bookmarks WHERE user_id=? AND paste_id=?",(uid,paste['id'])).fetchone()
  if existing:
    db.execute("DELETE FROM bookmarks WHERE user_id=? AND paste_id=?",(uid,paste['id']))
    db.commit()
    count=db.execute("SELECT COUNT(*) FROM bookmarks WHERE user_id=?",(uid,)).fetchone()[0]
    db.close()
    if is_ajax: return jsonify({'ok':True,'saved':False,'msg':'Removed from saved!','count':count})
    flash('Removed from saved!','green'); return redirect(f'/paste/{slug}')
  # Check limit
  is_prem=db.execute("SELECT is_premium FROM users WHERE id=?",(uid,)).fetchone()
  is_prem=is_prem['is_premium'] if is_prem else 0
  count=db.execute("SELECT COUNT(*) FROM bookmarks WHERE user_id=?",(uid,)).fetchone()[0]
  if not is_prem and count>=5:
    db.close()
    msg='⭐ Free users can save up to 5 pastes. Upgrade to Premium for unlimited!'
    if is_ajax: return jsonify({'ok':False,'saved':False,'msg':msg,'limit':True,'count':count})
    flash(msg,'error'); return redirect(f'/paste/{slug}')
  db.execute("INSERT INTO bookmarks(user_id,paste_id) VALUES(?,?)",(uid,paste['id']))
  db.commit()
  count=db.execute("SELECT COUNT(*) FROM bookmarks WHERE user_id=?",(uid,)).fetchone()[0]
  db.close()
  if is_ajax: return jsonify({'ok':True,'saved':True,'msg':'Saved! 🔖','count':count,'is_prem':bool(is_prem)})
  flash('Saved! 🔖','green'); return redirect(f'/paste/{slug}')

@app.route('/bookmarks')
def bookmarks():
  if not session.get('user_id'): return redirect('/login')
  uid=session['user_id']; db=get_db()
  is_prem=db.execute("SELECT is_premium FROM users WHERE id=?",(uid,)).fetchone()
  is_prem=is_prem['is_premium'] if is_prem else 0
  count=db.execute("SELECT COUNT(*) FROM bookmarks WHERE user_id=?",(uid,)).fetchone()[0]
  rows=db.execute("""SELECT p.*,u.username,u.avatar,u.is_premium as auth_prem,b.created_at as saved_at
    FROM bookmarks b JOIN pastes p ON b.paste_id=p.id LEFT JOIN users u ON p.user_id=u.id
    WHERE b.user_id=? ORDER BY b.created_at DESC""",(uid,)).fetchall()
  db.close()
  def _bcard(p2):
    pd=dict(p2)
    prem_b=('<span style="font-size:9px;background:linear-gradient(135deg,#7b2ff7,#ffd700);color:#fff;border-radius:99px;padding:1px 5px;font-weight:800;margin-left:4px;">⭐</span>' if pd.get('auth_prem') else '')
    return (f'<div style="background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 14px;margin-bottom:8px;display:flex;align-items:center;gap:10px;">'
      f'<div style="flex:1;min-width:0;">'
      f'<a href="/paste/{pd["slug"]}" style="font-size:14px;font-weight:700;color:var(--p);text-decoration:none;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{pd["title"]}</a>'
      f'<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:4px;">'
      f'<span style="font-size:11px;color:var(--s);">{pd.get("avatar") or "👤"} {pd.get("username") or "Anon"}{prem_b}</span>'
      f'<span style="font-size:11px;color:var(--p);font-family:monospace;">[{pd["syntax"]}]</span>'
      f'<span style="font-size:11px;color:var(--dim);">👁 {pd["views"]}</span>'
      f'<span style="font-size:11px;color:#ff2d55;">❤️ {pd["likes"]}</span>'
      f'<span style="font-size:10px;color:var(--dim);">Saved {pd["saved_at"][:10]}</span>'
      f'</div></div>'
      f'<a href="/bookmark/{pd["slug"]}" class="btn btn-r" style="font-size:9px;padding:3px 8px;flex-shrink:0;" title="Remove">✕</a>'
      f'</div>')
  items=''.join(_bcard(r) for r in rows if not is_expired(r)) or '<div style="text-align:center;padding:40px;color:var(--dim);">No saved pastes yet. Click 🔖 on any paste to save it.</div>'
  limit_bar=''
  if not is_prem:
    pct=min(100,count*20)
    limit_bar=(f'<div style="background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 16px;margin-bottom:16px;display:flex;align-items:center;gap:12px;">'
      f'<div style="flex:1;">'
      f'<div style="display:flex;justify-content:space-between;margin-bottom:6px;"><span style="font-size:12px;color:var(--t);font-weight:600;">Saved Pastes</span><span style="font-size:12px;color:{"#ff2d55" if count>=5 else "var(--dim)"};">{count}/5</span></div>'
      f'<div style="height:4px;background:rgba(255,255,255,.08);border-radius:99px;overflow:hidden;">'
      f'<div style="width:{pct}%;height:100%;background:{"#ff2d55" if count>=5 else "var(--p)"};border-radius:99px;transition:width .3s;"></div></div>'
      f'{"<div style=\'font-size:10px;color:#ff2d55;margin-top:5px;\'>Limit reached!</div>" if count>=5 else ""}'
      f'</div>'
      f'<a href="/premium" style="background:linear-gradient(135deg,#ffd700,#ff8c00);color:#000;font-size:11px;font-weight:800;padding:6px 14px;border-radius:8px;text-decoration:none;flex-shrink:0;">⭐ Unlimited</a>'
      f'</div>')
  c=f'''<div style="max-width:760px;margin:0 auto;">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
  <div style="font-size:22px;font-weight:900;color:var(--t);">🔖 Saved Pastes</div>
  <a href="/" class="btn btn-o" style="font-size:12px;">← Browse</a>
</div>
{limit_bar}
{items}
</div>'''
  return base(c,'Saved Pastes',session.get('theme','cyan'))


@app.route('/search')
def search():
  q=request.args.get('q','').strip()
  tab=request.args.get('tab','pastes')
  page=max(1,request.args.get('page',1,type=int))
  per=20; results=[]; total=0; user_results=[]

  db=get_db()
  if q:
    like=f'%{q}%'
    if tab=='users':
      user_results=db.execute(
        "SELECT * FROM users WHERE (username LIKE ? OR bio LIKE ?) AND is_banned=0 ORDER BY total_views DESC LIMIT 30",
        (like,like)).fetchall()
    else:
      total=db.execute("SELECT COUNT(*) FROM pastes WHERE visibility='public' AND (title LIKE ? OR content LIKE ? OR tags LIKE ?)",(like,like,like)).fetchone()[0]
      pag=paginate(total,page,per)
      rows=db.execute("SELECT p.*,u.username,u.avatar,u.is_premium FROM pastes p LEFT JOIN users u ON p.user_id=u.id WHERE p.visibility='public' AND (p.title LIKE ? OR p.content LIKE ? OR p.tags LIKE ?) ORDER BY p.views DESC LIMIT ? OFFSET ?",(like,like,like,per,pag['offset'])).fetchall()
      results=[r for r in rows if not is_expired(r)]
      pages=pag['pages']
  db.close()
  if not q: pag=paginate(0,1,per); pages=1

  def _prow(p2):
    pd=dict(p2)
    prem=('<span style="font-size:9px;background:linear-gradient(135deg,#7b2ff7,#ffd700);color:#fff;border-radius:99px;padding:1px 5px;font-weight:800;margin-left:4px;">⭐</span>' if pd.get('is_premium') else '')
    snip=pd['content'][:120].replace('<','&lt;')
    return (f'<a href="/paste/{pd["slug"]}" style="display:block;text-decoration:none;background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 14px;margin-bottom:8px;transition:border-color .15s;" onmouseover="this.style.borderColor=\'var(--p)\'" onmouseout="this.style.borderColor=\'var(--bd)\'">'
      f'<div style="font-size:14px;font-weight:700;color:var(--t);margin-bottom:4px;">{pd["title"][:60]}</div>'
      f'<div style="font-size:11px;color:var(--dim);margin-bottom:6px;font-family:monospace;">{snip}{"…" if len(pd["content"])>120 else ""}</div>'
      f'<div style="display:flex;gap:10px;flex-wrap:wrap;">'
      f'<span style="font-size:11px;color:var(--s);">{pd.get("avatar") or "👤"} {pd.get("username") or "Anon"}{prem}</span>'
      f'<span style="font-size:11px;color:var(--p);">[{pd["syntax"]}]</span>'
      f'<span style="font-size:11px;color:var(--dim);">👁 {pd["views"]}</span>'
      f'<span style="font-size:11px;color:#ff2d55;">❤️ {pd["likes"]}</span>'
      f'</div></a>')

  def _urow(u2):
    ud=dict(u2)
    av=ud.get('avatar_url','') or ''
    av_html=(f'<img src="{av}" style="width:40px;height:40px;border-radius:50%;object-fit:cover;border:2px solid var(--p);">'
      if av else f'<div style="width:40px;height:40px;border-radius:50%;background:var(--card);border:2px solid var(--bd);display:flex;align-items:center;justify-content:center;font-size:20px;">{ud.get("avatar") or "👤"}</div>')
    prem_b=('<span style="font-size:9px;background:linear-gradient(135deg,#7b2ff7,#ffd700);color:#fff;border-radius:99px;padding:1px 6px;font-weight:800;">⭐ VIP</span>' if ud.get('is_premium') else '')
    bio=ud.get('bio','')[:60]
    return (f'<a href="/profile/{ud["username"]}" style="display:flex;align-items:center;gap:12px;text-decoration:none;background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 14px;margin-bottom:8px;transition:border-color .15s;" onmouseover="this.style.borderColor=\'var(--p)\'" onmouseout="this.style.borderColor=\'var(--bd)\'">'
      f'{av_html}'
      f'<div style="flex:1;min-width:0;">'
      f'<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;"><span style="font-size:14px;font-weight:700;color:var(--p);">{ud["username"]}</span>{prem_b}</div>'
      f'<div style="font-size:11px;color:var(--dim);margin-top:2px;">{bio}{"…" if len(ud.get("bio",""))>60 else ""}</div>'
      f'</div>'
      f'<div style="text-align:right;flex-shrink:0;"><div style="font-size:12px;color:var(--green);">👁 {ud["total_views"]}</div></div>'
      f'</a>')

  tab_style_active='background:var(--p);color:#000;font-weight:800;border-radius:7px;padding:6px 16px;font-size:13px;text-decoration:none;'
  tab_style_idle='color:var(--dim);font-weight:600;padding:6px 16px;font-size:13px;text-decoration:none;border-radius:7px;transition:background .15s;'
  tabs_html=(f'<div style="display:flex;gap:4px;background:var(--card);border:1px solid var(--bd);border-radius:9px;padding:4px;width:fit-content;margin-bottom:16px;">'
    f'<a href="/search?q={q}&tab=pastes" style="{tab_style_active if tab=="pastes" else tab_style_idle}">📝 Pastes{f" ({total})" if tab=="pastes" and q else ""}</a>'
    f'<a href="/search?q={q}&tab=users" style="{tab_style_active if tab=="users" else tab_style_idle}">👤 Users{f" ({len(user_results)})" if tab=="users" and q else ""}</a>'
    f'</div>')

  if tab=='users':
    res_html=''.join(_urow(u2) for u2 in user_results) if user_results else f'<div style="text-align:center;padding:40px;color:var(--dim);">{"No users found for <b>" + q + "</b>" if q else "Search for users above."}</div>'
    nav_html=''
  else:
    res_html=''.join(_prow(r) for r in results) if results else f'<div style="text-align:center;padding:40px;color:var(--dim);">{"No pastes found for <b style=\'color:var(--t);\'>" + q + "</b>" if q else "Search pastes above."}</div>'
    nav_html=pg_nav(page,pages,f'/search?q={q}&tab=pastes&')

  c=f'''<div style="max-width:860px;margin:0 auto;">
<div style="margin-bottom:16px;">
  <div style="font-size:22px;font-weight:900;color:var(--t);margin-bottom:12px;">🔍 Search</div>
  <form method="GET" action="/search" style="display:flex;gap:8px;margin-bottom:14px;">
    <input type="hidden" name="tab" value="{tab}">
    <input name="q" value="{q}" placeholder="Search {tab}…"
      style="flex:1;padding:10px 14px;background:var(--card);border:1px solid var(--bd);border-radius:9px;color:#fff;font-size:14px;outline:none;"
      autofocus>
    <button type="submit" class="btn btn-p" style="padding:10px 20px;font-size:14px;">Search</button>
  </form>
  {tabs_html}
</div>
{res_html}
{nav_html}
</div>'''
  return base(c,'Search',session.get('theme','cyan'))

# ━━━ TRENDING PAGE ━━━
@app.route('/trending')
def trending():
  db=get_db()
  # Hot: most views in last 7 days
  hot7=db.execute("""SELECT p.*,u.username,u.avatar,u.is_premium,
    (SELECT COUNT(*) FROM paste_views pv WHERE pv.paste_id=p.id AND pv.created_at>datetime('now','-7 days')) as week_views
    FROM pastes p LEFT JOIN users u ON p.user_id=u.id
    WHERE p.visibility='public'
    ORDER BY week_views DESC, p.likes DESC LIMIT 30""").fetchall()
  # Rising: best likes/views ratio today
  rising=db.execute("""SELECT p.*,u.username,u.avatar,u.is_premium
    FROM pastes p LEFT JOIN users u ON p.user_id=u.id
    WHERE p.visibility='public' AND p.created_at>datetime('now','-48 hours')
    ORDER BY p.likes DESC, p.views DESC LIMIT 10""").fetchall()
  db.close()
  def _tcard(p,rank=None):
    pd=dict(p)
    wv=pd.get('week_views',0)
    prem_b=('<span class="prem-badge" style="font-size:8px;padding:1px 5px;gap:2px;">'
      '<svg width="8" height="8" viewBox="0 0 24 24" fill="#fff"><path d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6z"/></svg>'
      ' VIP</span>') if pd.get('is_premium') else ''
    rank_html=''
    if rank is not None:
      c2=['#ffd700','#c0c0c0','#cd7f32']
      rank_html=f'<div style="position:absolute;top:10px;left:10px;font-size:{"22" if rank<3 else "13"}px;font-weight:900;color:{c2[rank] if rank<3 else "var(--dim)"};">{"🥇🥈🥉"[rank] if rank<3 else "#"+str(rank+1)}</div>'
    week_html=f'<span style="color:var(--green);font-size:10px;">🔥 {wv} this week</span>' if wv else ''
    return (f'<a href="/paste/{pd["slug"]}" style="display:block;text-decoration:none;background:var(--card);border:1px solid var(--bd);'
      f'border-radius:12px;padding:14px 14px 14px 44px;position:relative;transition:border-color .15s,transform .15s;margin-bottom:8px;"'
      f' onmouseover="this.style.borderColor=\'var(--p)\';this.style.transform=\'translateX(3px)\'"'
      f' onmouseout="this.style.borderColor=\'var(--bd)\';this.style.transform=\'none\'">'
      f'{rank_html}'
      f'<div style="font-size:14px;font-weight:700;color:var(--t);margin-bottom:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{pd["title"]}</div>'
      f'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">'
      f'<span style="font-size:11px;color:var(--s);">{pd["avatar"] or "👤"} {pd["username"] or "Anon"}</span>'
      f'{prem_b}'
      f'<span style="font-size:11px;color:var(--dim);">👁 {pd["views"]}</span>'
      f'<span style="font-size:11px;color:var(--red);">❤️ {pd["likes"]}</span>'
      f'<span style="font-size:10px;color:var(--p);">[{pd["syntax"]}]</span>'
      f'{week_html}'
      f'</div></a>')
  hot_html=''.join(_tcard(p,i) for i,p in enumerate(hot7) if not is_expired(p)) or '<div style="text-align:center;color:var(--dim);padding:32px;">No trending pastes yet.</div>'
  rising_html=''.join(_tcard(p) for p in rising if not is_expired(p)) or '<div style="text-align:center;color:var(--dim);padding:16px;">No new pastes in 48h.</div>'
  c=f'''<div style="max-width:860px;margin:0 auto;">
<div style="text-align:center;padding:24px 0 28px;">
  <div style="font-size:48px;margin-bottom:8px;">🔥</div>
  <div style="font-size:28px;font-weight:900;color:var(--t);">Trending</div>
  <div style="font-size:13px;color:var(--dim);margin-top:4px;">Most popular pastes this week</div>
</div>
<div style="display:grid;grid-template-columns:1fr 360px;gap:18px;align-items:start;">
<div>
  <div style="font-size:11px;font-weight:800;color:var(--p);letter-spacing:2px;margin-bottom:12px;">🏆 TOP THIS WEEK</div>
  {hot_html}
</div>
<div style="position:sticky;top:70px;">
  <div class="card" style="margin-bottom:14px;">
    <div style="font-size:11px;font-weight:800;color:var(--yellow);letter-spacing:2px;margin-bottom:12px;">⚡ RISING (48h)</div>
    {rising_html}
  </div>
</div>
</div>
</div>'''
  return base(c,'Trending',session.get('theme','cyan'))

# ━━━ ABUSE REPORT SYSTEM ━━━
@app.route('/report/<slug>', methods=['POST'])
def report_paste(slug):
  if not session.get('user_id'): flash('Login to report!','error'); return redirect(f'/paste/{slug}')
  reason=request.form.get('reason','').strip()
  if not reason: flash('Please provide a reason.','error'); return redirect(f'/paste/{slug}')
  db=get_db()
  paste=db.execute("SELECT * FROM pastes WHERE slug=?",(slug,)).fetchone()
  if not paste: db.close(); flash('Paste not found.','error'); return redirect('/')
  # Check duplicate report from same user
  dup=db.execute("SELECT id FROM reports WHERE paste_id=? AND reporter_id=?",(paste['id'],session['user_id'])).fetchone()
  if dup: db.close(); flash('You already reported this paste.','red'); return redirect(f'/paste/{slug}')
  db.execute("INSERT INTO reports(paste_id,reporter_id,reason) VALUES(?,?,?)",(paste['id'],session['user_id'],reason))
  # Notify all admins
  admins=db.execute("SELECT id FROM users WHERE is_admin=1").fetchall()
  for a in admins:
    db.execute("INSERT INTO notifications(user_id,message,link) VALUES(?,?,?)",
      (a['id'],f'🚨 Paste reported: "{paste["title"]}" — {reason[:60]}',f'/admin/reports'))
  db.commit(); db.close()
  flash('Report submitted. Admin will review it.','green')
  return redirect(f'/paste/{slug}')

@app.route('/admin/reports')
def admin_reports():
  if not session.get('is_admin'): return redirect('/')
  db=get_db()
  reports=db.execute("""SELECT r.*,p.title,p.slug,u.username as reporter
    FROM reports r
    JOIN pastes p ON r.paste_id=p.id
    JOIN users u ON r.reporter_id=u.id
    ORDER BY r.created_at DESC""").fetchall()
  db.close()
  def _rrow(r):
    rd=dict(r)
    sc={'pending':'var(--yellow)','reviewed':'var(--green)','dismissed':'var(--dim)'}.get(rd['status'],'var(--dim)')
    return (f'<tr>'
      f'<td><a href="/paste/{rd["slug"]}" style="color:var(--p);">{rd["title"][:30]}</a></td>'
      f'<td style="font-size:12px;">{rd["reporter"]}</td>'
      f'<td style="font-size:12px;max-width:200px;">{rd["reason"][:60]}</td>'
      f'<td style="color:{sc};font-weight:700;font-size:11px;">{rd["status"].upper()}</td>'
      f'<td style="font-size:11px;color:var(--dim);">{rd["created_at"][:16]}</td>'
      f'<td style="display:flex;gap:4px;">'
      f'<a href="/admin/report-action/{rd["id"]}/reviewed" class="btn" style="font-size:9px;padding:2px 7px;background:rgba(63,185,80,.15);border-color:#3fb950;color:#3fb950;">✓</a>'
      f'<a href="/admin/report-action/{rd["id"]}/dismissed" class="btn" style="font-size:9px;padding:2px 7px;background:rgba(128,128,128,.12);border-color:var(--dim);color:var(--dim);">✕</a>'
      f'<a href="/admin/del-paste/{rd["slug"]}" class="btn btn-r" style="font-size:9px;padding:2px 7px;" onclick="return confirm(\'Delete paste?\')">🗑</a>'
      f'</td></tr>')
  rows=''.join(_rrow(r) for r in reports) or '<tr><td colspan=6 style="text-align:center;color:var(--dim);padding:24px;">No reports yet.</td></tr>'
  pending=sum(1 for r in reports if dict(r)['status']=='pending')
  c=f'''<div style="max-width:1100px;margin:0 auto;">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
  <div style="font-size:22px;font-weight:800;">🚨 Abuse Reports <span style="font-size:14px;color:var(--red);">({pending} pending)</span></div>
  <a href="/admin" class="btn btn-o" style="font-size:12px;">← Back</a>
</div>
<div class="card" style="overflow-x:auto;">
<table class="at">
<thead><tr><th>Paste</th><th>Reporter</th><th>Reason</th><th>Status</th><th>Date</th><th>Action</th></tr></thead>
<tbody>{rows}</tbody>
</table></div></div>'''
  return base(c,'Abuse Reports',session.get('theme','cyan'))

@app.route('/admin/report-action/<int:rid>/<action>')
def report_action(rid,action):
  if not session.get('is_admin'): return redirect('/')
  if action not in ('reviewed','dismissed'): return redirect('/admin/reports')
  db=get_db(); db.execute("UPDATE reports SET status=? WHERE id=?",(action,rid)); db.commit(); db.close()
  return redirect('/admin/reports')

# ━━━ AI CHAT ━━━
@app.route('/api/ai-chat', methods=['POST'])
def ai_chat():
  data=request.get_json(silent=True) or {}
  q=str(data.get('q','')).strip()[:400]
  if not q: return jsonify({'reply':'Please type a message!'})
  allowed,_,reset_in = check_rate_limit('ai_chat',15,60)
  if not allowed: return jsonify({'reply':f'⏳ Too many requests! Try again in {reset_in}s.'})

  # Build multi-turn history (last 12 messages)
  raw_hist=data.get('history',[])
  messages=[]
  for m in raw_hist[-12:]:
    role=m.get('role',''); content=str(m.get('content',''))[:500]
    if role in ('user','assistant') and content:
      messages.append({'role':role,'content':content})
  # Ensure last message is the current question
  if not messages or messages[-1].get('content')!=q:
    messages.append({'role':'user','content':q})

  SYSTEM="""You are ZeroShell AI — the official smart assistant built into the ZeroShell platform.

PLATFORM INFO:
- ZeroShell is a pastebin/code sharing platform with: public/private/unlisted pastes, syntax highlighting (100+ languages), tags, expiry, paste password, views, likes, comments, bookmarks, follow system, notifications, leaderboard, trending page, user profiles, avatar, bio, themes (cyan/red/green/gold/purple/blue), 2FA, PWA support
- Free users: up to 5 saved pastes, standard rate limits
- Premium users: unlimited saves, premium badge, custom note, priority features
- API: POST /api/v1/paste (key, title, content, syntax, visibility, tags, expires_in, password), GET /api/v1/paste/<slug>, GET /api/v1/user (api_key required)
- Admin panel: user management, paste moderation, ban/unban, ads, logs, backups, reports, payments
- Contact: zeroshellx@gmail.com | Telegram: t.me/ZeroShell | Discord: discord.gg/9QMQWcCM

PERSONALITY:
- Friendly, helpful, concise
- Reply in the SAME language the user uses (Bengali = Bengali, English = English)
- Use **bold**, `code`, bullet points when helpful
- If asked something unrelated to ZeroShell, gently redirect
- Never make up features that don't exist
- For account issues, suggest contact: zeroshellx@gmail.com"""

  try:
    import anthropic as _ant
    client=_ant.Anthropic()
    msg=client.messages.create(
      model='claude-haiku-4-5-20251001',
      max_tokens=400,
      system=SYSTEM,
      messages=messages)
    reply=msg.content[0].text if msg.content else 'Sorry, no response available.'
  except Exception as e:
    reply='⚠️ AI is temporarily unavailable. Please try again later or email us at zeroshellx@gmail.com.'
  return jsonify({'reply':reply})

# ━━━ API /api/create ALIAS ━━━
@app.route('/api/create', methods=['POST'])
def api_create_alias():
  """Alias for POST /api/v1/paste — developer-friendly endpoint."""
  return api_create_paste()

# ━━━ CLOUDFLARE MIDDLEWARE ━━━
@app.before_request
def cloudflare_middleware():
  """Block banned IPs on every request."""
  ip=get_real_ip()
  if is_ip_banned(ip):
    theme=session.get('theme','cyan')
    c=('<div style="text-align:center;padding:100px 20px;">'
       '<div style="font-size:72px;margin-bottom:16px;">🚫</div>'
       '<div style="font-size:26px;font-weight:800;color:#ff453a;margin-bottom:8px;">Access Denied</div>'
       '<div style="color:var(--dim);margin-bottom:4px;">Your IP has been banned.</div>'
       '<div style="font-size:11px;color:var(--dim);">Contact support if you think this is a mistake.</div>'
       '</div>')
    return base(c,'Banned',theme),403

@app.after_request
def security_headers(response):
  """Add security headers recommended for Cloudflare + general security."""
  response.headers['X-Content-Type-Options']='nosniff'
  response.headers['X-Frame-Options']='SAMEORIGIN'
  response.headers['X-XSS-Protection']='1; mode=block'
  response.headers['Referrer-Policy']='strict-origin-when-cross-origin'
  response.headers['Permissions-Policy']='geolocation=(), microphone=(), camera=()'
  if request.path.startswith('/api/'):
    response.headers['Cache-Control']='no-store'
  elif request.method=='GET' and response.status_code==200:
    response.headers['Cache-Control']='public, max-age=60'
  return response

@app.errorhandler(404)
def err_404(e):
  c=f'<div style="text-align:center;padding:80px 20px;"><div style="width:90px;height:90px;border-radius:50%;background:linear-gradient(135deg,#04080f,#0b1623);border:2px solid #00c8ff;box-shadow:0 0 24px rgba(0,200,255,0.3);display:flex;align-items:center;justify-content:center;margin:0 auto 20px;">{BAT_SVG.replace("width=","w=").replace("height=","h=").replace("w=","width=20 ").replace("h=","height=20 ")}</div><div style="font-size:28px;font-weight:800;color:var(--p);margin-bottom:8px;">404 — Not Found</div><div style="color:var(--dim);margin-bottom:24px;">This page doesn\'t exist.</div><a href="/" class="btn btn-p" style="padding:10px 28px;font-size:14px;">← Home</a></div>'
  return base(c,'404',session.get('theme','cyan')),404

@app.errorhandler(429)
def err_429(e):
  c='<div style="text-align:center;padding:80px 20px;"><div style="font-size:72px;margin-bottom:16px;">🚦</div><div style="font-size:28px;font-weight:800;color:var(--red);margin-bottom:8px;">429 — Too Many Requests</div><div style="color:var(--dim);margin-bottom:24px;">Slow down! Please wait before trying again.</div><a href="/" class="btn btn-p" style="padding:10px 28px;font-size:14px;">← Home</a></div>'
  return base(c,'Rate Limited',session.get('theme','cyan')),429

@app.errorhandler(500)
def err_500(e):
  import traceback
  print(f'[500 ERROR] {request.path}: {e}')
  traceback.print_exc()
  bat=f'<div style="width:90px;height:90px;border-radius:50%;background:linear-gradient(135deg,#04080f,#0b1623);border:2px solid #ff2d55;box-shadow:0 0 24px rgba(255,45,85,0.3);display:flex;align-items:center;justify-content:center;margin:0 auto 20px;">{BAT_SVG.replace("stroke:#00c8ff","stroke:#ff2d55").replace("fill:#00c8ff","fill:#ff2d55")}</div>'
  c=f'<div style="text-align:center;padding:80px 20px;">{bat}<div style="font-size:28px;font-weight:800;color:var(--red);margin-bottom:8px;">500 — Server Error</div><div style="color:var(--dim);margin-bottom:8px;">Something went wrong. Please try again.</div><div style="font-family:monospace;font-size:11px;color:var(--dim);margin-bottom:24px;">{str(e)[:120]}</div><a href="/" class="btn btn-p" style="padding:10px 28px;font-size:14px;">← Home</a></div>'
  return base(c,'Error',session.get('theme','cyan')),500

if __name__=='__main__':
  init_db()
  # Initial backup on startup if none exists
  try:
    db=get_db()
    bc=db.execute("SELECT COUNT(*) FROM backups").fetchone()[0]
    db.close()
    if bc==0:
      fname,sz=do_backup()
      if fname: print(f"[BACKUP] Initial backup: {fname}")
  except: pass
  # Start daily backup thread ONLY in main process (not gunicorn workers)
  # gunicorn sets SERVER_SOFTWARE env var; check to avoid duplicate threads
  in_gunicorn = 'gunicorn' in os.environ.get('SERVER_SOFTWARE','').lower()
  is_werkzeug_reloader = os.environ.get('WERKZEUG_RUN_MAIN')=='true'
  if not in_gunicorn or os.environ.get('WEB_CONCURRENCY','1')=='1':
    t=threading.Thread(target=backup_scheduler,daemon=True,name='backup-thread')
    t.start()
    print("[BACKUP] Daily backup scheduler started")
  cleaned=cleanup_expired()
  if cleaned: print(f"[CLEANUP] {cleaned} expired pastes removed")
  port=int(os.environ.get('PORT',5000))
  print(f"""
{'='*52}
  ⚡  ZEROSHELL v9.0
  🌐  http://localhost:{port}
  🛡️   Rate Limit: {PASTE_LIMIT} pastes/{PASTE_WINDOW}s
  📦  Max Size: {MAX_PASTE_BYTES//1024//1024} MB per paste
  💾  Auto Backup: every 24h → ./{BACKUP_DIR}/
  ☁️   Cloudflare: real IP detection enabled
{'='*52}
""")
  app.run(host='0.0.0.0',port=port,debug=False)
