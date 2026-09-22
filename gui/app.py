import os, sys, sqlite3, secrets, hashlib, hmac, functools, re, subprocess, time
from datetime import datetime, timedelta, timezone
from flask import Flask, request, redirect, url_for, session, g, render_template_string, abort, Response
import vpn

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('VDS_DB', os.path.join(APP_DIR, 'panel.db'))
SCHEMA_PATH = os.path.join(APP_DIR, 'schema.sql')
ADMIN_USER = os.environ.get('VDS_ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('VDS_ADMIN_PASS', 'admin')
GUEST_PASS = os.environ.get('VDS_GUEST_PASS', 'guest')
BASE_URL = os.environ.get('VDS_BASE_URL', 'http://127.0.0.1:8010')
BIND = os.environ.get('VDS_BIND', '127.0.0.1:8010')

app = Flask(__name__)
app.secret_key = os.environ.get('VDS_SECRET') or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=True)

def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db

@app.teardown_appcontext
def _close(exc):
    d = g.pop('db', None)
    if d is not None:
        d.close()

def hash_pw(pw):
    s = secrets.token_hex(16)
    return 'pbkdf2$' + s + '$' + hashlib.pbkdf2_hmac('sha256', pw.encode(), s.encode(), 120000).hex()

def verify_pw(pw, stored):
    try:
        _, s, h = stored.split('$')
    except Exception:
        return False
    return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256', pw.encode(), s.encode(), 120000).hex(), h)

def gen_code(con=None):
    while True:
        c = ''.join(secrets.choice('23456789') for _ in range(6))
        if con is None:
            return c
        if not con.execute('SELECT 1 FROM members WHERE code=?', (c,)).fetchone():
            return c

APPS = [
 ('pc','Windows','OpenVPN Connect','https://openvpn.net/client/'),
 ('pc','macOS','Tunnelblick (OpenVPN)','https://tunnelblick.net/'),
 ('pc','Linux','OpenVPN','https://openvpn.net/community-downloads/'),
 ('mobile','Android','OpenVPN Connect','https://play.google.com/store/apps/details?id=net.openvpn.openvpn'),
 ('mobile','iOS','OpenVPN Connect','https://apps.apple.com/app/openvpn-connect/id590379981'),
]

def init_db():
    con = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH, 'r') as f:
        con.executescript(f.read())
    cols = [r[1] for r in con.execute('PRAGMA table_info(members)')]
    if 'code' not in cols:
        con.execute('ALTER TABLE members ADD COLUMN code TEXT')
    dcols = [r[1] for r in con.execute('PRAGMA table_info(devices)')]
    for col, decl in (('token', 'TEXT'), ('traffic_up', 'INTEGER DEFAULT 0'), ('traffic_down', 'INTEGER DEFAULT 0'),
                      ('sess_up', 'INTEGER DEFAULT 0'), ('sess_down', 'INTEGER DEFAULT 0'),
                      ('online', 'INTEGER DEFAULT 0'), ('last_seen', 'TEXT')):
        if col not in dcols:
            con.execute('ALTER TABLE devices ADD COLUMN %s %s' % (col, decl))
    for r in con.execute('SELECT id FROM members WHERE code IS NULL OR code=?', ('',)).fetchall():
        con.execute('UPDATE members SET code=? WHERE id=?', (gen_code(con), r[0]))
    con.execute('DELETE FROM client_apps')
    for i, r in enumerate(APPS):
        con.execute('INSERT INTO client_apps(category,os,app,url,sort) VALUES (?,?,?,?,?)', (r[0], r[1], r[2], r[3], i))
    for k, v in (('guest_password', hash_pw(GUEST_PASS)), ('support_target', '1500'), ('support_note', ''), ('support_sbp_url', ''), ('admin_user', ADMIN_USER)):
        con.execute('INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)', (k, v))
    con.commit()
    con.close()

def setting(k, d=None):
    r = db().execute('SELECT value FROM settings WHERE key=?', (k,)).fetchone()
    return r['value'] if r else d

def set_setting(k, v):
    db().execute('INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (k, v))
    db().commit()

def audit(actor, action, target, meta=''):
    db().execute('INSERT INTO audit(actor,action,target,meta) VALUES (?,?,?,?)', (actor, action, target, meta))
    db().commit()

def cur_member():
    mid = session.get('member_id')
    return db().execute('SELECT * FROM members WHERE id=?', (mid,)).fetchone() if mid else None

def require_login(f):
    @functools.wraps(f)
    def w(*a, **k):
        if not (session.get('guest') or session.get('admin')):
            return redirect(url_for('login'))
        return f(*a, **k)
    return w

def require_admin(f):
    @functools.wraps(f)
    def w(*a, **k):
        if not session.get('admin'):
            return redirect(url_for('login'))
        return f(*a, **k)
    return w

def csrf_token():
    t = session.get('csrf')
    if not t:
        t = secrets.token_hex(16)
        session['csrf'] = t
    return t

def check_csrf():
    if request.form.get('csrf') != session.get('csrf'):
        abort(400, 'bad csrf')

LAYOUT = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#151517">
<title>{{ title }} - {{ brand }}</title>
<style>
:root{--bg:#151517;--card:#1d1d21;--card2:#26262c;--line:#2c2c33;--fg:#ecedf1;--mut:#989aa4;--acc:#4d6bfe;--ok:#2ecc71;--err:#e74c3c;--r:14px}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;font-size:clamp(15px,0.25vw + 14.2px,17px);line-height:1.5;
padding-bottom:calc(72px + env(safe-area-inset-bottom))}
header{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:10px;
background:rgba(21,21,23,.93);backdrop-filter:blur(12px);border-bottom:1px solid var(--line);
padding:calc(10px + env(safe-area-inset-top)) 14px 10px}
header .brand{font-weight:650;font-size:16px;letter-spacing:.1px}
header .sp{flex:1}
header a{color:var(--fg);text-decoration:none;opacity:.7;font-size:14px;padding:6px 2px}
main{max-width:820px;margin:0 auto;padding:14px 14px 28px}
h1{font-size:20px;margin:6px 0 12px}h2{font-size:15px;margin:18px 0 8px;color:var(--mut);font-weight:600;text-transform:uppercase;letter-spacing:.4px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:14px;margin:12px 0}
label{display:block;margin:12px 0 6px;color:var(--mut);font-size:13px}
input,select{width:100%;padding:13px;border-radius:11px;border:1px solid #34343d;background:#101012;color:var(--fg);font-size:16px}
input:focus,select:focus{outline:none;border-color:var(--acc)}
button,.btn{display:inline-flex;align-items:center;justify-content:center;min-height:46px;background:var(--acc);color:#fff;
border:0;border-radius:12px;padding:11px 16px;margin:10px 8px 0 0;cursor:pointer;text-decoration:none;font-size:15px;font-weight:550}
.btn:active,button:active{transform:scale(.98)}
.btn.sec{background:var(--card2)}.btn.ok{background:var(--ok)}.btn.err{background:var(--err)}
.btn.block{display:flex;width:100%;margin-right:0}
table{width:100%;border-collapse:collapse;font-size:15px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--mut);font-size:13px;font-weight:600}
.tag{display:inline-block;font-size:12px;padding:3px 10px;border-radius:20px;background:var(--card2)}
.pending{background:#4a3c10}.approved{background:#14432a}.rejected,.revoked{background:#4a1a1a}
.mut{color:var(--mut)}code{background:#101012;padding:2px 7px;border-radius:7px;word-break:break-all;font-size:14px}
.row{display:flex;gap:10px;flex-wrap:wrap}.row>*{flex:1;min-width:150px}
img.qr{background:#fff;padding:8px;border-radius:12px;max-width:100%;height:auto}
.hint{color:var(--mut);font-size:13px}a{color:#8fb0ff}
nav.tabs{position:fixed;left:0;right:0;bottom:0;z-index:30;display:flex;
background:rgba(29,29,33,.97);backdrop-filter:blur(14px);border-top:1px solid var(--line);
padding:6px 4px calc(6px + env(safe-area-inset-bottom))}
nav.tabs a{flex:1;display:flex;flex-direction:column;align-items:center;gap:2px;color:var(--mut);
text-decoration:none;font-size:11px;padding:6px 2px;border-radius:10px}
nav.tabs a.on{color:var(--acc)}
nav.tabs svg{width:1.55em;height:1.55em;min-width:20px;min-height:20px;stroke:currentColor;fill:none;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}
.topnav{display:none;gap:2px;margin-left:8px;flex-wrap:wrap}
.topnav a{font-size:.92em;padding:7px 10px;border-radius:9px;color:var(--mut);text-decoration:none}
.topnav a.on{color:var(--fg);background:var(--card2)}
@media (min-width:641px){body{padding-bottom:28px}nav.tabs{display:none}header .only-mobile{display:none}}
@media (max-width:640px){
thead{display:none}
table,tbody,tr,td{display:block;width:100%}
tr{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:10px 12px;margin:10px 0}
td{border:0;padding:5px 0;display:flex;justify-content:space-between;gap:12px;align-items:center;text-align:right}
td:first-child{font-weight:600;text-align:left;justify-content:flex-start;font-size:16px;padding-bottom:8px;border-bottom:1px solid var(--line);margin-bottom:4px}
td[data-label]::before{content:attr(data-label);color:var(--mut);font-size:13px;font-weight:400;text-align:left;margin-right:auto}
td:empty{display:none}
td .btn{margin:4px 0 4px 6px;min-height:40px;font-size:14px;padding:8px 13px}
}
</style></head><body>
<header><span class="brand">{{ brand }}</span><span class="sp"></span>
{% if session.get('guest') or session.get('admin') %}<a href="/logout">Выйти</a>{% endif %}
</header><main>{{ body|safe }}</main>
{% if session.get('guest') or session.get('admin') %}
<nav class="tabs">
<a href="/cabinet" class="{% if request.path.startswith('/cabinet') or request.path.startswith('/device') %}on{% endif %}"><svg viewBox="0 0 24 24"><path d="M3 10.4 12 3l9 7.4"/><path d="M5.5 9.6V21h13V9.6"/></svg>Кабинет</a>
<a href="/connect" class="{% if request.path.startswith('/connect') %}on{% endif %}"><svg viewBox="0 0 24 24"><path d="M12 3v12"/><path d="m7.5 10.5 4.5 4.5 4.5-4.5"/><path d="M4 21h16"/></svg>Подключение</a>
<a href="/support" class="{% if request.path.startswith('/support') %}on{% endif %}"><svg viewBox="0 0 24 24"><path d="M12 20s-7-4.4-7-9.3A3.7 3.7 0 0 1 12 8a3.7 3.7 0 0 1 7 2.7C19 15.6 12 20 12 20Z"/></svg>Поддержка</a>
{% if session.get('admin') %}<a href="/admin" class="{% if request.path.startswith('/admin') %}on{% endif %}"><svg viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6l7-3Z"/></svg>Админка</a>{% endif %}
</nav>{% endif %}
</body></html>"""

def page(title, body):
    return render_template_string(LAYOUT, title=title, body=body, brand=setting('brand', 'Доступ'))

def apps(cat):
    return db().execute('SELECT * FROM client_apps WHERE category=? ORDER BY sort', (cat,)).fetchall()

@app.route('/healthz')
def healthz():
    return 'ok'

@app.route('/login', methods=['GET', 'POST'])
def login():
    err = ''
    if request.method == 'POST':
        pw = request.form.get('password', '')
        if pw and verify_pw(pw, setting('guest_password', '')):
            session.clear(); session['guest'] = True; session['csrf'] = secrets.token_hex(16)
            return redirect(url_for('cabinet'))
        _au = setting('admin_user') or ADMIN_USER
        _ah = setting('admin_password')
        if request.form.get('username') == _au and ((verify_pw(pw, _ah) if _ah else pw == ADMIN_PASS)):
            session.clear(); session['admin'] = True; session['guest'] = True; session['csrf'] = secrets.token_hex(16)
            return redirect(url_for('admin'))
        err = 'Неверный пароль'
    b = render_template_string("""<div class="card" style="max-width:420px;margin:60px auto">
<h1>Вход</h1><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
<label>Гостевой пароль</label><input type="password" name="password" autofocus>
<label>Логин (только для админа)</label><input type="text" name="username">
<button>Войти</button></form>{% if err %}<p style="color:#e74c3c">{{ err }}</p>{% endif %}
<p class="hint">Доступ только для участников. Новых добавляет администратор.</p></div>""", csrf=csrf_token(), err=err)
    return page('Вход', b)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/claim', methods=['POST'])
@require_login
def claim():
    check_csrf()
    code = (request.form.get('code') or '').strip()
    r = db().execute('SELECT id FROM members WHERE code=?', (code,)).fetchone()
    if r:
        session['member_id'] = r['id']
    return redirect(url_for('cabinet'))

@app.route('/')
def index():
    return redirect(url_for('cabinet') if session.get('guest') else url_for('login'))

@app.route('/join/<token>', methods=['GET', 'POST'])
@require_login
def join(token):
    inv = db().execute('SELECT * FROM invites WHERE token=?', (token,)).fetchone()
    if not inv:
        return page('Приглашение', '<div class="card"><h1>Приглашение не найдено</h1></div>'), 404
    if inv['expires_at'] and inv['expires_at'] < datetime.utcnow().isoformat():
        return page('Приглашение', '<div class="card"><h1>Приглашение истекло</h1></div>'), 410
    if inv['uses'] >= inv['max_uses']:
        return page('Приглашение', '<div class="card"><h1>Приглашение уже использовано</h1></div>'), 410
    err = ''
    if request.method == 'POST':
        check_csrf()
        name = (request.form.get('name') or '').strip()[:60]
        tg = (request.form.get('telegram') or '').strip()[:60]
        proto = request.form.get('protocol') or 'ovpn'
        label = (request.form.get('label') or 'устройство').strip()[:60]
        if not name:
            err = 'Укажите имя'
        else:
            mid = db().execute('INSERT INTO members(name,telegram) VALUES (?,?)', (name, tg)).lastrowid
            vpn_name = 'm%d-%s' % (mid, re.sub(r'[^A-Za-z0-9]+', '-', name).strip('-')[:20] or 'user')
            db().execute('INSERT INTO devices(member_id,label,protocol,platform,vpn_name,status) VALUES (?,?,?,?,?,?)',
                         (mid, label, proto, request.headers.get('User-Agent', '')[:200], vpn_name, 'pending'))
            db().execute('UPDATE invites SET uses=uses+1 WHERE id=?', (inv['id'],))
            db().commit()
            session['member_id'] = mid
            audit('guest', 'join', vpn_name, 'invite ' + token[:6])
            return redirect(url_for('cabinet'))
    b = render_template_string("""<div class="card" style="max-width:520px;margin:40px auto">
<h1>Регистрация</h1><p class="hint">После регистрации устройство уходит на одобрение. До одобрения ключ не выдаётся.</p>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
<label>Как вас зовут</label><input name="name" autofocus>
<label>Telegram</label><input name="telegram">
<label>Название устройства</label><input name="label" placeholder="телефон, ноутбук...">
<label>Протокол</label><select name="protocol"><option value="ovpn">OpenVPN</option></select>
<button>Отправить заявку</button></form>{% if err %}<p style="color:#e74c3c">{{ err }}</p>{% endif %}</div>""",
        csrf=csrf_token(), err=err)
    return page('Регистрация', b)

@app.route('/cabinet')
@require_login
def cabinet():
    m = cur_member()
    rows = db().execute('SELECT * FROM devices WHERE member_id=? ORDER BY id DESC', (m['id'],)).fetchall() if m else []
    items = []
    for d in rows:
        url = (BASE_URL.rstrip('/') + '/p/' + (d['token'] or '')) if d['protocol'] == 'ovpn' else (d['link'] or '')
        items.append({'id': d['id'], 'label': d['label'] or d['vpn_name'], 'proto': d['protocol'],
                      'status': d['status'], 'url': url})
    b = render_template_string("""<h1>Доступ</h1>
{% if not member %}<div class="card"><p>Введите личный код, чтобы увидеть свой доступ.</p>
<form method="post" action="/claim"><input type="hidden" name="csrf" value="{{ csrf }}">
<label>Личный код</label><input name="code" inputmode="numeric" autofocus>
<button>Открыть</button></form></div>
{% else %}
{% for d in items %}{% if d['status'] == 'approved' %}<div class="card">
<p><b>{{ d['label'] }}</b> <span class="mut">{{ d['proto'] }}</span></p>
<img class="qr" src="/device/{{ d['id'] }}/qr.png" alt="QR">
{% if d['url'] %}<p><a class="btn" href="{{ d['url'] }}" target="_blank" rel="noopener">Ссылка</a></p>
<p><code>{{ d['url'] }}</code></p>{% else %}<p><a class="btn" href="/device/{{ d['id'] }}/download">Скачать конфиг</a></p>{% endif %}
</div>{% elif d['status'] == 'pending' %}<div class="card"><p class="hint">Ожидает одобрения.</p></div>{% endif %}{% endfor %}
<div class="card">
<img class="qr" src="/support/qr.png" alt="QR СБП">
<p><a class="btn" href="{{ sbp }}" target="_blank" rel="noopener">Перевести</a></p>
<p><code>{{ sbp }}</code></p>
</div>
{% endif %}""", member=m, csrf=csrf_token(), items=items, sbp=setting('support_sbp_url', ''))
    return page('Кабинет', b)

def _dev(did):
    d = db().execute('SELECT * FROM devices WHERE id=?', (did,)).fetchone()
    if not d:
        abort(404)
    if not session.get('admin'):
        m = cur_member()
        if not m or d['member_id'] != m['id']:
            abort(403)
    return d

@app.route('/device/<int:did>/download')
@require_login
def dl(did):
    d = _dev(did)
    if d['status'] != 'approved':
        abort(403)
    if d['protocol'] == 'awg':
        text, ext = d['config'], '.conf'
    elif d['protocol'] == 'ovpn':
        text, ext = d['config'], '.ovpn'
    else:
        text, ext = d['link'], '.txt'
    mt = 'application/x-openvpn-profile' if d['protocol'] == 'ovpn' else 'application/octet-stream'
    fn = (d['vpn_name'] or 'config') + ext
    cd = 'attachment; filename="%s"; filename*=UTF-8\'\'%s' % (fn, fn)
    return Response(text or '', mimetype=mt, headers={'Content-Disposition': cd, 'X-Content-Type-Options': 'nosniff'})

@app.route('/device/<int:did>/qr.png')
@require_login
def qr(did):
    d = _dev(did)
    if d['status'] != 'approved':
        abort(403)
    return Response(vpn.qr_png(_qr_data(d)), mimetype='image/png')

def _qr_data(d):
    if d['protocol'] == 'ovpn':
        return BASE_URL.rstrip('/') + '/p/' + (d['token'] or '')
    return d['config'] if d['protocol'] == 'awg' else d['link']

QRTMPL = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>QR - {{ d['vpn_name'] }}</title>
<style>body{margin:0;background:#fff;color:#111;font:16px/1.5 system-ui,Segoe UI,Roboto,sans-serif;text-align:center;padding:24px}
h1{font-size:20px;margin:0 0 2px}p{color:#555;margin:6px 0 16px}
img{width:min(86vw,420px);height:auto;image-rendering:pixelated}
.btn{display:inline-block;margin:14px 6px 0;background:#4f7cff;color:#fff;text-decoration:none;padding:12px 18px;border-radius:10px;font-size:15px}
.btn.sec{background:#777}</style></head><body>
<h1>{{ d['label'] or d['vpn_name'] }}</h1><p>{{ d['protocol'] }} · {{ d['vpn_name'] }}</p>
<img src="/device/{{ did }}/qr.png" alt="QR">
<div><a class="btn" href="/device/{{ did }}/download">Скачать конфиг</a>
<a class="btn sec" href="/cabinet">В кабинет</a></div>
<p>Отсканируйте QR в приложении VPN.</p></body></html>"""

@app.route('/device/<int:did>/qr')
@require_login
def device_qr_page(did):
    d = _dev(did)
    if d['status'] != 'approved':
        abort(403)
    m = db().execute('SELECT code FROM members WHERE id=?', (d['member_id'],)).fetchone()
    return render_template_string(QRTMPL, d=d, did=did, code=(m['code'] if m else ''))

@app.route('/connect')
@require_login
def connect():
    b = render_template_string("""<h1>Подключение</h1>
<p class="hint">Установите приложение под своё устройство и импортируйте ключ из кабинета.</p>
<h2>PC</h2><div class="card"><table><thead><tr><th>ОС</th><th>Приложение</th><th></th></tr></thead>
{% for a in pc %}<tr><td>{{ a['os'] }}</td><td data-label="Приложение">{{ a['app'] }}</td><td><a class="btn sec" href="{{ a['url'] }}" target="_blank" rel="noopener">Скачать</a></td></tr>{% endfor %}</table></div>
<h2>Мобильные</h2><div class="card"><table><thead><tr><th>ОС</th><th>Приложение</th><th></th></tr></thead>
{% for a in mob %}<tr><td>{{ a['os'] }}</td><td data-label="Приложение">{{ a['app'] }}</td><td><a class="btn sec" href="{{ a['url'] }}" target="_blank" rel="noopener">Скачать</a></td></tr>{% endfor %}</table></div>
<p class="hint">Ссылки ведут на официальные источники. Установщики мы не хостим.</p>
""", pc=apps('pc'), mob=apps('mobile'))
    return page('Подключение', b)

@app.route('/help')
@require_login
def help_page():
    b = render_template_string("""<h1>Как подключиться</h1>
<div class="card"><h2>1. Установите приложение</h2>
<p class="hint">VLESS: Hiddify или v2rayNG (Android), Streisand (iPhone), NekoRay (ПК).<br>AmneziaWG: AmneziaVPN.</p>
<a class="btn sec" href="/connect">Открыть список приложений</a></div>
<div class="card"><h2>2. Откройте свой QR</h2>
<p>В кабинете нажмите <b>«Показать QR крупно»</b> — откроется код вашего устройства.</p>
<a class="btn sec" href="/cabinet">Перейти в кабинет</a></div>
<div class="card"><h2>3. Отсканируйте QR</h2>
<p>В приложении выберите «Добавить из QR» / «Сканировать» и наведите камеру на код.</p>
<p class="hint">Если приложение не умеет QR — нажмите «Скачать конфиг» и импортируйте файл вручную.</p></div>
<div class="card"><h2>Если не работает</h2>
<p class="hint">Напишите администратору (в семейный чат) — посмотрим вместе.</p></div>""")
    return page('Помощь', b)

@app.route('/support', methods=['GET', 'POST'])
@require_login
def support():
    m = cur_member()
    if request.method == 'POST':
        check_csrf()
        try:
            amount = float((request.form.get('amount') or '0').replace(',', '.'))
        except Exception:
            amount = 0
        db().execute('INSERT INTO contributions(member_id,amount,method,status,public,message) VALUES (?,?,?,?,?,?)',
                     (m['id'] if m else None, amount, request.form.get('method') or 'sbp', 'pledged',
                      1 if request.form.get('public') else 0, (request.form.get('message') or '')[:200]))
        db().commit()
        return redirect(url_for('support'))
    conf = db().execute("SELECT c.*, m.name FROM contributions c LEFT JOIN members m ON m.id=c.member_id WHERE c.status='confirmed' ORDER BY c.id DESC LIMIT 50").fetchall()
    total = db().execute("SELECT COALESCE(SUM(amount),0) s FROM contributions WHERE status='confirmed'").fetchone()['s']
    target = float(setting('support_target', '0') or 0)
    pct = int(min(100, (total / target * 100) if target else 0))
    b = render_template_string("""<h1>Поддержка проекта</h1>
<div class="card"><p>Доступ участникам бесплатный. Поддержка добровольна и не влияет на доступ.</p>
<p class="hint">Средства идут на: {{ note }}</p>
<p>Собрано: <strong>{{ total }} RUB</strong> из {{ target }} RUB</p>
<div style="background:#0d1020;border-radius:8px;height:14px;overflow:hidden"><div style="width:{{ pct }}%;height:100%;background:#2ecc71"></div></div></div>
{% if sbp %}<div class="card"><h2>Оплатить по СБП</h2>
<p><a class="btn" href="{{ sbp }}" target="_blank" rel="noopener">Открыть в приложении банка</a></p>
<img class="qr" src="/support/qr.png" width="220" height="220" alt="QR СБП">
<p class="hint">Отсканируйте QR в приложении банка или откройте ссылку.</p></div>{% endif %}
<div class="card"><h2>Поддержать</h2><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
<div class="row"><div><label>Сумма, RUB</label><input name="amount" placeholder="300"></div>
<div><label>Способ</label><select name="method"><option value="sbp">СБП</option><option value="card">Карта</option><option value="crypto">Крипта</option></select></div></div>
<label>Сообщение</label><input name="message">
<label><input type="checkbox" name="public" style="width:auto"> показывать меня в списке</label>
<button>Я поддержал</button></form>
<p class="hint">После подтверждения администратором взнос появится в списке.</p></div>
<div class="card"><h2>Спасибо</h2>
{% for c in conf %}<div>{{ c['name'] or 'Участник' }}: {{ c['amount'] }} RUB{% if c['message'] %} - {{ c['message'] }}{% endif %}</div>{% else %}<p class="hint">Пока пусто.</p>{% endfor %}</div>""",
        note=setting('support_note', ''), total=total, target=target, pct=pct, conf=conf, csrf=csrf_token(), sbp=setting('support_sbp_url', ''))
    return page('Поддержка', b)

@app.route('/support/qr.png')
@require_login
def support_qr():
    url = setting('support_sbp_url', '')
    if not url:
        abort(404)
    return Response(vpn.qr_png(url), mimetype='image/png')

@app.route('/admin')
@require_admin
def admin():
    devices = db().execute("""SELECT d.*, m.name AS mn, m.telegram AS mt, m.code AS code FROM devices d JOIN members m ON m.id=d.member_id
        ORDER BY CASE d.status WHEN 'pending' THEN 0 ELSE 1 END, d.id DESC""").fetchall()
    members_list = db().execute("""SELECT m.id, m.name, m.code, COUNT(d.id) AS n FROM members m
        LEFT JOIN devices d ON d.member_id=m.id GROUP BY m.id ORDER BY m.id DESC""").fetchall()
    invites = db().execute('SELECT * FROM invites ORDER BY id DESC').fetchall()
    contrib = db().execute('SELECT * FROM contributions ORDER BY id DESC LIMIT 50').fetchall()
    b = render_template_string("""<h1>Админка</h1>
<div class="card"><a class="btn sec" href="/admin/stats">Статистика и трафик</a> <a class="btn sec" href="/admin/account">Логин и пароль</a></div>
<div class="card"><h2>Участники и личные коды</h2>
<table><thead><tr><th>Имя</th><th>Личный код</th><th>Устройств</th><th></th></tr></thead>
{% for m in members %}<tr><td>{{ m['name'] }}</td><td data-label="Личный код"><code>{{ m['code'] or '-' }}</code></td><td data-label="Устройств">{{ m['n'] }}</td>
<td><a class="btn sec" href="/admin/member/{{ m['id'] }}/revoke_code" onclick="return confirm('Выпустить новый код? Старый сразу перестанет работать.')">Отозвать код</a>
<a class="btn err" href="/admin/member/{{ m['id'] }}/delete" onclick="return confirm('Удалить участника и все его ключи?')">Удалить</a></td></tr>
{% else %}<tr><td colspan="4" class="hint">Пока никого.</td></tr>{% endfor %}</table>
<p class="hint">Личный код участник вводит в кабинете, чтобы увидеть свой QR. Отдайте код лично.</p></div>
<div class="card"><h2>Устройства</h2><table><thead><tr><th>Участник</th><th>Устройство</th><th>Протокол</th><th>Статус</th><th></th></tr></thead>
{% for d in devices %}<tr><td>{{ d['mn'] }}{% if d['mt'] %}<br><span class="mut">{{ d['mt'] }}</span>{% endif %}<br><span class="mut">код: {{ d['code'] or '-' }}</span></td>
<td data-label="Устройство">{{ d['label'] }}<br><span class="mut">{{ d['vpn_name'] }}</span></td><td data-label="Протокол">{{ d['protocol'] }}</td>
<td data-label="Статус"><span class="tag {{ d['status'] }}">{{ d['status'] }}</span>{% if d['note'] %}<br><span class="mut">{{ d['note'] }}</span>{% endif %}</td>
<td>{% if d['status'] == 'pending' %}<a class="btn ok" href="/admin/device/{{ d['id'] }}/approve">Одобрить</a>
<a class="btn err" href="/admin/device/{{ d['id'] }}/reject">Отклонить</a>
{% elif d['status'] == 'approved' %}<a class="btn err" href="/admin/device/{{ d['id'] }}/revoke">Отозвать</a>
{% else %}<a class="btn ok" href="/admin/device/{{ d['id'] }}/approve">Включить</a>{% endif %}
<a class="btn sec" href="/device/{{ d['id'] }}/qr" target="_blank">QR</a>
<a class="btn sec" href="/admin/device/{{ d['id'] }}/reissue" onclick="return confirm('Перевыпустить профиль? Старый сразу перестанет работать.')">Перевыпустить</a>
<a class="btn sec" href="/admin/device/{{ d['id'] }}/delete" onclick="return confirm('Удалить устройство и ключ?')">Удалить</a></td></tr>{% endfor %}
</table></div>
<div class="card"><h2>Добавить участника</h2>
<form method="post" action="/admin/member/add"><input type="hidden" name="csrf" value="{{ csrf }}">
<div class="row"><div><label>Имя</label><input name="name" placeholder="Имя"></div>
<div><label>Устройство</label><input name="label" placeholder="телефон"></div>
<div><label>Протокол</label><select name="protocol"><option value="ovpn">OpenVPN</option></select></div></div>
<button>Создать и показать QR</button></form>
<p class="hint">Устройство создаётся и одобряется сразу, ключ генерируется тут же. После создания откроется QR, который можно дать отсканировать. Личный код (6 цифр) для входа участника в панель виден в таблице устройств.</p></div>
{% if False %}<div class="card"><h2>Приглашения</h2><form method="post" action="/admin/invites"><input type="hidden" name="csrf" value="{{ csrf }}">
<div class="row"><div><label>Использований</label><input name="max_uses" value="1"></div>
<div><label>Срок, дней</label><input name="days" value="7"></div>
<div><label>Заметка</label><input name="note"></div></div><button>Создать приглашение</button></form>
<table><thead><tr><th>Токен</th><th>Исп.</th><th>Срок</th><th>QR</th></tr></thead>
{% for i in invites %}<tr><td><code>{{ i['token'] }}</code></td><td>{{ i['uses'] }}/{{ i['max_uses'] }}</td><td>{{ i['expires_at'] or '-' }}</td>
<td><a class="btn sec" href="/admin/invite/{{ i['token'] }}/qr.png" target="_blank">QR</a></td></tr>{% endfor %}</table>
<p class="hint">QR ведёт на страницу регистрации. Покажите его новому участнику.</p></div>
<div class="card"><h2>Взносы</h2><table><thead><tr><th>Сумма</th><th>Способ</th><th>Статус</th><th>Сообщение</th><th></th></tr></thead>
{% for c in contrib %}<tr><td>{{ c['amount'] }}</td><td>{{ c['method'] }}</td><td>{{ c['status'] }}</td><td>{{ c['message'] or '' }}</td>
<td>{% if c['status'] != 'confirmed' %}<a class="btn ok" href="/admin/contribution/{{ c['id'] }}/confirm">Подтвердить</a>{% endif %}</td></tr>{% endfor %}</table></div>
<div class="card"><h2>Настройки</h2><form method="post" action="/admin/settings"><input type="hidden" name="csrf" value="{{ csrf }}">
<div class="row"><div><label>Цель поддержки, RUB</label><input name="support_target" value="{{ st }}"></div>
<div><label>Описание расходов</label><input name="support_note" value="{{ sn }}"></div></div>
<label>Название панели</label><input name="brand" value="{{ bd }}">
<label>Ссылка СБП</label><input name="support_sbp_url" value="{{ sbp }}">
<label>Новый гостевой пароль</label><input name="guest_password"><button>Сохранить</button></form></div>{% endif %}""",
        devices=devices, members=members_list, invites=invites, contrib=contrib, csrf=csrf_token(),
        st=setting('support_target', ''), sn=setting('support_note', ''), sbp=setting('support_sbp_url', ''), bd=setting('brand', 'Доступ'))
    return page('Админка', b)

@app.route('/admin/member/<int:mid>/revoke_code')
@require_admin
def admin_member_revoke_code(mid):
    con = db()
    m = con.execute('SELECT * FROM members WHERE id=?', (mid,)).fetchone()
    if not m:
        abort(404)
    new_code = gen_code(con)
    con.execute('UPDATE members SET code=? WHERE id=?', (new_code, mid))
    con.commit()
    audit('admin', 'revoke_code', m['name'] or str(mid))
    return redirect(url_for('admin'))

@app.route('/admin/member/<int:mid>/delete')
@require_admin
def admin_member_delete(mid):
    con = db()
    m = con.execute('SELECT * FROM members WHERE id=?', (mid,)).fetchone()
    if not m:
        abort(404)
    for d in con.execute('SELECT * FROM devices WHERE member_id=?', (mid,)).fetchall():
        try:
            vpn.deprovision(d['protocol'], d['vpn_name'])
        except Exception:
            pass
    con.execute('DELETE FROM devices WHERE member_id=?', (mid,))
    con.execute('DELETE FROM members WHERE id=?', (mid,))
    con.commit()
    audit('admin', 'delete_member', m['name'] or str(mid))
    return redirect(url_for('admin'))

@app.route('/admin/device/<int:did>/<action>')
@require_admin
def admin_device(did, action):
    d = db().execute('SELECT * FROM devices WHERE id=?', (did,)).fetchone()
    if not d:
        abort(404)
    if action == 'approve':
        try:
            if d['config'] and d['vpn_name'] and d['protocol'] != 'ovpn':
                vpn.set_active(d['protocol'], d['vpn_name'], True, d['config'])
            else:
                primary, _ = vpn.provision(d['protocol'], d['vpn_name'])
                tok = secrets.token_urlsafe(18) if d['protocol'] == 'ovpn' else None
                db().execute('UPDATE devices SET config=?, link=?, token=? WHERE id=?',
                             (primary, primary if d['protocol'] == 'vless' else '', tok, did))
            db().execute("UPDATE devices SET status='approved', decided_at=datetime('now'), decided_by='admin' WHERE id=?", (did,))
            db().commit()
            audit('admin', 'approve', d['vpn_name'])
        except Exception as e:
            db().execute('UPDATE devices SET note=? WHERE id=?', (str(e)[:200], did))
            db().commit()
    elif action == 'reject':
        db().execute("UPDATE devices SET status='rejected', decided_at=datetime('now'), decided_by='admin' WHERE id=?", (did,))
        db().commit()
    elif action == 'revoke':
        try:
            vpn.set_active(d['protocol'], d['vpn_name'], False, d['config'])
        except Exception:
            pass
        db().execute("UPDATE devices SET status='revoked', decided_at=datetime('now'), decided_by='admin' WHERE id=?", (did,))
        db().commit()
    elif action == 'reissue':
        try:
            vpn.deprovision(d['protocol'], d['vpn_name'])
            if d['protocol'] == 'ovpn':
                conf = vpn.ovpn_add(d['vpn_name'])
                tok = d['token'] or secrets.token_urlsafe(18)
                db().execute('UPDATE devices SET config=?, token=? WHERE id=?', (conf, tok, did))
            elif d['protocol'] == 'vless':
                primary, _ = vpn.provision('vless', d['vpn_name'])
                db().execute('UPDATE devices SET config=?, link=? WHERE id=?', (primary, primary, did))
            elif d['protocol'] == 'awg':
                conf = vpn.awg_add(d['vpn_name'])
                db().execute('UPDATE devices SET config=? WHERE id=?', (conf, did))
            db().commit()
            audit('admin', 'reissue', d['vpn_name'])
        except Exception as e:
            db().execute('UPDATE devices SET note=? WHERE id=?', (str(e)[:200], did))
            db().commit()
    elif action == 'delete':
        try:
            vpn.deprovision(d['protocol'], d['vpn_name'])
        except Exception:
            pass
        db().execute('DELETE FROM devices WHERE id=?', (did,))
        db().commit()
    return redirect(url_for('admin'))

@app.route('/admin/member/add', methods=['POST'])
@require_admin
def admin_member_add():
    check_csrf()
    name = (request.form.get('name') or '').strip()[:60]
    label = (request.form.get('label') or 'устройство').strip()[:60]
    proto = request.form.get('protocol') or 'ovpn'
    if not name:
        return redirect(url_for('admin'))
    con = db()
    code = gen_code(con)
    mid = con.execute('INSERT INTO members(name, telegram, code) VALUES (?,?,?)', (name, '', code)).lastrowid
    vpn_name = 'm%d-%s' % (mid, re.sub(r'[^A-Za-z0-9]+', '-', name).strip('-')[:20] or 'user')
    did = con.execute('INSERT INTO devices(member_id,label,protocol,vpn_name,status) VALUES (?,?,?,?,?)',
                      (mid, label, proto, vpn_name, 'pending')).lastrowid
    con.commit()
    try:
        primary, _ = vpn.provision(proto, vpn_name)
        tok = secrets.token_urlsafe(18) if proto == 'ovpn' else None
        con.execute("UPDATE devices SET config=?, link=?, token=?, status='approved', decided_at=datetime('now'), decided_by='admin' WHERE id=?",
                    (primary, primary if proto == 'vless' else '', tok, did))
        con.commit()
    except Exception as e:
        con.execute('UPDATE devices SET note=? WHERE id=?', (str(e)[:200], did))
        con.commit()
    return redirect(url_for('device_qr_page', did=did))

@app.route('/admin/invites', methods=['POST'])
@require_admin
def admin_invites():
    check_csrf()
    token = secrets.token_urlsafe(9)
    try:
        mx = int(request.form.get('max_uses') or 1)
    except Exception:
        mx = 1
    try:
        days = int(request.form.get('days') or 0)
    except Exception:
        days = 0
    db().execute('INSERT INTO invites(token,max_uses,expires_at,note) VALUES (?,?,?,?)',
                 (token, mx, (datetime.utcnow() + timedelta(days=days)).isoformat() if days else None, (request.form.get('note') or '')[:100]))
    db().commit()
    return redirect(url_for('admin'))

@app.route('/admin/invite/<token>/qr.png')
@require_admin
def invite_qr(token):
    return Response(vpn.qr_png(BASE_URL.rstrip('/') + '/join/' + token), mimetype='image/png')

@app.route('/admin/contribution/<int:cid>/<action>')
@require_admin
def admin_contrib(cid, action):
    db().execute('UPDATE contributions SET status=? WHERE id=?', ('confirmed' if action == 'confirm' else 'failed', cid))
    db().commit()
    return redirect(url_for('admin'))

@app.route('/admin/settings', methods=['POST'])
@require_admin
def admin_settings():
    check_csrf()
    if request.form.get('support_target'):
        set_setting('support_target', request.form.get('support_target'))
    if request.form.get('support_note') is not None:
        set_setting('support_note', request.form.get('support_note'))
    if request.form.get('support_sbp_url') is not None:
        set_setting('support_sbp_url', request.form.get('support_sbp_url').strip())
    if request.form.get('brand') is not None and request.form.get('brand').strip():
        set_setting('brand', request.form.get('brand').strip()[:40])
    gp = request.form.get('guest_password')
    if gp:
        set_setting('guest_password', hash_pw(gp))
    return redirect(url_for('admin'))

# ---------------- DSH-like mobile UI (overrides earlier LAYOUT/page) ----------------
LAYOUT = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#151517">
<title>{{ title }} · {{ brand }}</title>
<style>
:root{--bg:#151517;--surf:#1c1c1f;--surf2:#26262a;--tx:#f9fafb;--tx2:#cfd3d6;--tx3:#adb2b8;--bd:rgba(255,255,255,.12);--acc:#4d6bfe;--acc2:#3f5be8;--ok:#3fb950;--warn:#d29922;--err:#f85149;--r:12px}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;padding-bottom:calc(74px + env(safe-area-inset-bottom))}
header{position:sticky;top:0;z-index:10;background:rgba(21,21,23,.85);backdrop-filter:blur(14px);border-bottom:1px solid var(--bd);padding:calc(10px + env(safe-area-inset-top)) 16px 10px;display:flex;align-items:center;gap:10px}
header .logo{width:28px;height:28px;border-radius:9px;background:var(--acc);display:grid;place-items:center;font-weight:700;font-size:14px;color:#fff}
header .name{font-weight:600;font-size:16px}
header .out{margin-left:auto;color:var(--tx3);text-decoration:none;font-size:14px;padding:6px 2px}
main{max-width:760px;margin:0 auto;padding:14px}
.card{background:var(--surf);border:1px solid var(--bd);border-radius:var(--r);padding:16px;margin:12px 0}
h1{font-size:20px;margin:4px 0 12px;font-weight:650}
h2{font-size:16px;margin:2px 0 10px;font-weight:600}
label{display:block;margin:12px 0 6px;color:var(--tx3);font-size:13px}
input,select,textarea{width:100%;padding:13px;border-radius:10px;border:1px solid var(--bd);background:var(--surf2);color:var(--tx);font-size:16px;appearance:none}
input:focus,select:focus{outline:none;border-color:var(--acc)}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;background:var(--acc);color:#fff;border:0;border-radius:10px;padding:13px 16px;margin:10px 8px 0 0;font-size:15px;font-weight:550;text-decoration:none;cursor:pointer;font-family:inherit}
button:active,.btn:active{background:var(--acc2)}
.btn.sec{background:var(--surf2);color:var(--tx);border:1px solid var(--bd)}
.btn.ok{background:var(--ok)}.btn.err{background:var(--err)}
table{width:100%;border-collapse:collapse;font-size:14px;margin-top:6px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--bd);vertical-align:top}
th{color:var(--tx3);font-weight:500;font-size:12px}
.tag{font-size:12px;padding:3px 9px;border-radius:20px;background:var(--surf2);color:var(--tx2);white-space:nowrap}
.pending{background:rgba(210,153,34,.16);color:#e3b341}.approved{background:rgba(63,185,80,.16);color:#56d364}
.rejected,.revoked{background:rgba(248,81,73,.16);color:#ff7b72}
.mut{color:var(--tx3)}code{background:var(--surf2);padding:3px 7px;border-radius:7px;word-break:break-all;font-size:13px;display:inline-block}
.row{display:flex;gap:10px;flex-wrap:wrap}.row>*{flex:1;min-width:150px}
img.qr{background:#fff;padding:10px;border-radius:14px;width:min(76vw,250px);height:auto;display:block;margin:12px auto}
.hint{color:var(--tx3);font-size:13px;margin:8px 0 0}
a{color:var(--acc)}
.nav{position:fixed;left:0;right:0;bottom:0;z-index:20;background:rgba(28,28,31,.97);backdrop-filter:blur(16px);border-top:1px solid var(--bd);display:flex;padding:6px 4px calc(6px + env(safe-area-inset-bottom))}
.nav a{flex:1;display:flex;flex-direction:column;align-items:center;gap:3px;padding:6px 2px;text-decoration:none;color:var(--tx3);font-size:11px;border-radius:10px}
.nav a.on{color:var(--acc)}
.nav a i{font-size:19px;font-style:normal;line-height:1}
/* --- адаптивность и масштабирование --- */
body{font-size:clamp(15px,0.26vw + 14.2px,17px)}
.topnav{display:none;gap:2px;margin-left:14px;flex-wrap:wrap}
.topnav a{font-size:.92em;color:var(--tx3);text-decoration:none;padding:7px 10px;border-radius:9px}
.topnav a.on{color:var(--tx);background:var(--surf2)}
.nav a{font-size:clamp(9.5px,2.8vw,12px);white-space:nowrap;overflow:hidden}
.nav svg{width:1.6em;height:1.6em;min-width:20px;min-height:20px;stroke:currentColor;fill:none;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}
main{max-width:min(760px,100%);margin:0 auto;padding:14px}
img.qr{width:min(76vw,260px)}
@media (min-width:641px){.nav{display:none}body{padding-bottom:26px}.topnav{display:flex}main{max-width:820px;padding:18px}}
@media (min-width:1200px){main{max-width:960px}}
@media (max-width:640px){
thead{display:none}
table,tbody,tr,td{display:block;width:100%}
tr{background:var(--surf);border:1px solid var(--bd);border-radius:var(--r);padding:10px 12px;margin:10px 0}
td{border:0;padding:5px 0;display:flex;justify-content:space-between;gap:12px;align-items:center;text-align:right}
td:first-child{font-weight:600;text-align:left;justify-content:flex-start;font-size:1.05em;padding-bottom:8px;border-bottom:1px solid var(--bd);margin-bottom:4px}
td[data-label]::before{content:attr(data-label);color:var(--tx3);font-size:.85em;font-weight:400;text-align:left;margin-right:auto}
td:empty{display:none}
td .btn{margin:4px 0 4px 6px;min-height:40px;font-size:.9em;padding:8px 13px}
}
@media (max-width:360px){.nav a{font-size:9px}.nav svg{min-width:18px;min-height:18px}}
.nav a{min-width:0;text-overflow:ellipsis}
@media (max-width:640px){
tr:has(th){display:none}
td{flex-wrap:wrap}
td:last-child{justify-content:flex-end}
td .btn{flex:0 0 auto}
}
</style></head><body>
<header><div class="logo">{{ brand[:1] }}</div><div class="name">{{ brand }}</div>
{% if session.get('guest') or session.get('admin') %}<nav class="topnav"><a href="/cabinet" class="{{ 'on' if active=='cabinet' else '' }}">Кабинет</a><a href="/connect" class="{{ 'on' if active=='connect' else '' }}">Приложения</a>{% if session.get('admin') %}<a href="/admin" class="{{ 'on' if active=='admin' else '' }}">Админка</a>{% endif %}</nav><a class="out" href="/logout">Выйти</a>{% endif %}</header>
<main>{{ body|safe }}</main>
{% if session.get('guest') or session.get('admin') %}
<nav class="nav">
<a href="/cabinet" class="{{ 'on' if active=='cabinet' else '' }}"><svg viewBox="0 0 24 24"><path d="M3 10.4 12 3l9 7.4"/><path d="M5.5 9.6V21h13V9.6"/></svg>Кабинет</a>
<a href="/connect" class="{{ 'on' if active=='connect' else '' }}"><svg viewBox="0 0 24 24"><path d="M12 3v12"/><path d="m7.5 10.5 4.5 4.5 4.5-4.5"/><path d="M4 21h16"/></svg>Приложения</a>
{% if session.get('admin') %}<a href="/admin" class="{{ 'on' if active=='admin' else '' }}"><svg viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6l7-3Z"/></svg>Админка</a>{% endif %}
</nav>{% endif %}
</body></html>"""

def page(title, body):
    p = request.path
    active = ('cabinet' if p.startswith('/cabinet') or p.startswith('/device')
              else 'connect' if p.startswith('/connect')
              else 'support' if p.startswith('/support')
              else 'admin' if p.startswith('/admin') else '')
    return render_template_string(LAYOUT, title=title, body=body, brand=setting('brand', 'Доступ'), active=active)

QRTMPL = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>QR · {{ d['vpn_name'] }}</title>
<style>body{margin:0;background:#fff;color:#111;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;text-align:center;padding:24px}
h1{font-size:20px;margin:0 0 2px;font-weight:650}p{color:#666;margin:6px 0 14px}
img{width:min(84vw,400px);height:auto;border-radius:14px}
.btn{display:inline-flex;align-items:center;justify-content:center;margin:16px 5px 0;background:#4d6bfe;color:#fff;text-decoration:none;padding:13px 18px;border-radius:12px;font-size:15px;font-weight:550}
.btn.sec{background:#eee;color:#111}</style></head><body>
<h1>{{ d['label'] or d['vpn_name'] }}</h1><p>{{ d['protocol'] }} · {{ d['vpn_name'] }}</p>
<p>Личный код: <b>{{ code }}</b></p>
<img src="/device/{{ did }}/qr.png" alt="QR">
<div><a class="btn" href="/device/{{ did }}/download">Скачать конфиг</a>
<a class="btn sec" href="/cabinet">В кабинет</a></div>
<p>Отсканируйте QR в приложении VPN.</p></body></html>"""

APPS = [
 ('pc', 'Windows', 'OpenVPN Connect', 'https://openvpn.net/client/'),
 ('pc', 'Linux', 'OpenVPN', 'https://openvpn.net/community-downloads/'),
 ('mobile', 'Android', 'OpenVPN Connect', 'https://play.google.com/store/apps/details?id=net.openvpn.openvpn'),
 ('mobile', 'iOS', 'OpenVPN Connect', 'https://apps.apple.com/app/openvpn-connect/id590379981'),
]

@app.route('/p/<token>')
def profile(token):
    d = db().execute("SELECT * FROM devices WHERE token=? AND protocol='ovpn'", (token,)).fetchone()
    if not d or d['status'] != 'approved':
        abort(404)
    fn = (d['vpn_name'] or 'config') + '.ovpn'
    return Response(d['config'] or '', mimetype='application/x-openvpn-profile',
                    headers={'Content-Disposition': 'attachment; filename="%s"; filename*=UTF-8\'\'%s' % (fn, fn),
                             'X-Content-Type-Options': 'nosniff'})

# ---------------- stats & account ----------------
def fmt_bytes(n):
    try:
        n = float(n or 0)
    except Exception:
        n = 0
    if n < 1024:
        return '%d Б' % int(n)
    for u in ('КБ', 'МБ', 'ГБ', 'ТБ'):
        n /= 1024.0
        if n < 1024 or u == 'ТБ':
            return '%.1f %s' % (n, u)

def _ovpn_status():
    # AntiZapret держит статус каждого инстанса в /run/openvpn-server/status-*.log
    return vpn.ovpn_status()

def _awg_status():
    out = {}
    base = '/etc/amnezia/awg/clients'
    names = {}
    if os.path.isdir(base):
        for d in os.listdir(base):
            f = os.path.join(base, d, 'public.key')
            if os.path.isfile(f):
                try:
                    names[open(f).read().strip()] = d
                except Exception:
                    pass
    try:
        r = subprocess.run(['awg', 'show', 'wg0', 'dump'], capture_output=True, text=True, timeout=20)
    except Exception:
        return out
    for line in (r.stdout or '').strip().splitlines()[1:]:
        f = line.split('\t')
        if len(f) >= 7:
            try:
                hs = int(f[4] or 0); rx = int(f[5] or 0); tx = int(f[6] or 0)
            except Exception:
                continue
            out[names.get(f[0], f[0])] = {'hs': hs, 'rx': rx, 'tx': tx}
    return out

def collect_stats():
    ovpn = _ovpn_status(); awg = _awg_status()
    now = time.time()
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        for d in con.execute('SELECT * FROM devices').fetchall():
            name = d['vpn_name']; proto = d['protocol']
            rx = tx = 0; online = 0
            if proto == 'ovpn' and name in ovpn:
                rx = ovpn[name]['rx']; tx = ovpn[name]['tx']; online = 1
            elif proto == 'awg' and name in awg:
                a = awg[name]; rx = a['rx']; tx = a['tx']
                online = 1 if (a['hs'] and (now - a['hs']) < 180) else 0
            pu = int(d['sess_up'] or 0); pd = int(d['sess_down'] or 0)
            du = (rx - pu) if rx >= pu else rx
            dd = (tx - pd) if tx >= pd else tx
            last = datetime.now(timezone.utc).isoformat() if online else d['last_seen']
            con.execute('UPDATE devices SET traffic_up=COALESCE(traffic_up,0)+?, traffic_down=COALESCE(traffic_down,0)+?, sess_up=?, sess_down=?, online=?, last_seen=? WHERE id=?',
                        (du, dd, rx, tx, online, last, d['id']))
        con.commit()
    finally:
        con.close()

@app.route('/admin/stats')
@require_admin
def admin_stats():
    collect_stats()
    rows = db().execute("""SELECT d.*, m.name AS mn FROM devices d JOIN members m ON m.id=d.member_id
        ORDER BY d.online DESC, d.id DESC""").fetchall()
    b = render_template_string("""<h1>Статистика</h1>
<div class="card"><table><thead><tr><th>Участник</th><th>Устройство</th><th>Протокол</th><th>Статус</th><th>Скачано</th><th>Отдано</th><th>Был(а)</th><th></th></tr></thead>
{% for d in rows %}<tr><td>{{ d['mn'] }}</td><td data-label="Устройство">{{ d['vpn_name'] }}</td><td data-label="Протокол">{{ d['protocol'] }}</td>
<td data-label="Статус">{% if d['online'] %}<span class="tag approved">онлайн</span>{% else %}<span class="tag">офлайн</span>{% endif %}</td>
<td data-label="Скачано">{{ f(d['traffic_down']) }}<br><span class="mut">сессия {{ f(d['sess_down']) }}</span></td>
<td data-label="Отдано">{{ f(d['traffic_up']) }}<br><span class="mut">сессия {{ f(d['sess_up']) }}</span></td>
<td class="mut">{{ (d['last_seen'] or '-')[:19].replace('T', ' ') }}</td>
<td>{% if d['status'] == 'approved' %}<a class="btn err" href="/admin/device/{{ d['id'] }}/revoke">Отозвать</a>{% else %}<a class="btn ok" href="/admin/device/{{ d['id'] }}/approve">Включить</a>{% endif %}
<a class="btn sec" href="/admin/device/{{ d['id'] }}/reissue" onclick="return confirm('Перевыпустить профиль? Старый сразу перестанет работать.')">Перевыпустить</a>
<a class="btn sec" href="/admin/device/{{ d['id'] }}/delete" onclick="return confirm('Удалить устройство и ключ?')">Удалить</a></td></tr>
{% else %}<tr><td colspan="8" class="hint">Устройств пока нет.</td></tr>{% endfor %}</table>
<p class="hint">Сборщик обновляет данные раз в минуту. «Скачано» - трафик к пользователю, «Отдано» - от пользователя.</p></div>
<p><a class="btn sec" href="/admin">Назад в админку</a></p>""", rows=rows, f=fmt_bytes)
    return page('Статистика', b)

@app.route('/admin/account', methods=['GET', 'POST'])
@require_admin
def admin_account():
    msg = ''; err = ''
    ah = setting('admin_password')
    au = setting('admin_user') or ADMIN_USER
    if request.method == 'POST':
        check_csrf()
        cur = request.form.get('current_password') or ''
        if not (verify_pw(cur, ah) if ah else cur == ADMIN_PASS):
            err = 'Текущий пароль неверен'
        else:
            nl = (request.form.get('login') or '').strip()[:40]
            np1 = request.form.get('new_password') or ''
            np2 = request.form.get('new_password2') or ''
            if np1 != np2:
                err = 'Новые пароли не совпадают'
            elif np1 and len(np1) < 8:
                err = 'Пароль короче 8 символов'
            else:
                if nl and nl != au:
                    set_setting('admin_user', nl); msg += 'логин обновлён; '
                if np1:
                    set_setting('admin_password', hash_pw(np1)); msg += 'пароль обновлён; '
                if not msg:
                    msg = 'изменений нет'
    b = render_template_string("""<h1>Логин и пароль</h1>
{% if msg %}<div class="card"><b>{{ msg }}</b></div>{% endif %}
{% if err %}<div class="card" style="color:#f85149">{{ err }}</div>{% endif %}
<div class="card"><p>Текущий логин: <code>{{ au }}</code></p>
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
<label>Текущий пароль</label><input type="password" name="current_password" required>
<label>Новый логин</label><input name="login" placeholder="оставьте пустым, чтобы не менять">
<label>Новый пароль (минимум 8 символов)</label><input type="password" name="new_password">
<label>Повторите новый пароль</label><input type="password" name="new_password2">
<button>Сохранить</button></form>
<p class="hint">Логин и пароль хранятся в базе панели в виде хеша, в открытом виде нигде не лежат.</p></div>
<p><a class="btn sec" href="/admin">Назад в админку</a></p>""", msg=msg, err=err, csrf=csrf_token(), au=au)
    return page('Аккаунт', b)

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'collect':
        collect_stats()
        sys.exit(0)
    init_db()
    host, _, port = BIND.partition(':')
    from waitress import serve
    serve(app, host=host or '127.0.0.1', port=int(port or 8010))
