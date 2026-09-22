# Адаптер VPN для AntiZapret — только сертификаты OpenVPN.
# Управление через /root/antizapret/client.sh: 1 = добавить, 2 = удалить (отзыв+CRL).
import os, re, glob, subprocess, shutil

class VpnError(RuntimeError):
    pass

AZ_DIR = '/root/antizapret'
CLIENT_SH = os.path.join(AZ_DIR, 'client.sh')
CLIENT_OPENVPN = os.path.join(AZ_DIR, 'client', 'openvpn')
PKI_ISSUED = '/etc/openvpn/easyrsa3/pki/issued'
STATUS_DIR = '/run/openvpn-server'
DEFAULT_FLAVOR = 'antizapret-udp'   # раздельный туннель (Antizapret)
FULL_FLAVOR = 'vpn-udp'             # полный VPN

NAME_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')

def check_name(name):
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise VpnError('Недопустимое имя клиента (1-32: a-z A-Z 0-9 _ -)')
    return name

def _run(args, timeout=300, cwd=None):
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return (p.returncode or 0), (p.stdout or ''), (p.stderr or '')

def _file_name(name):
    n = name
    for pref in ('antizapret-', 'vpn-'):
        if n.startswith(pref):
            n = n[len(pref):]
            break
    return n

def _find_profile(name, flavor=DEFAULT_FLAVOR):
    pat = os.path.join(CLIENT_OPENVPN, flavor, '*%s*.ovpn' % _file_name(name))
    files = sorted(glob.glob(pat), key=os.path.getmtime, reverse=True)
    if not files:
        raise VpnError('Профиль не найден для ' + str(name))
    return files[0]

def ovpn_conf(name, flavor=DEFAULT_FLAVOR):
    with open(_find_profile(name, flavor), encoding='utf-8', errors='replace') as f:
        return f.read()

def ovpn_add(name, days=3650):
    check_name(name)
    rc, out, err = _run([CLIENT_SH, '1', name, str(int(days))], cwd=AZ_DIR, timeout=600)
    if rc != 0:
        raise VpnError('Не удалось выпустить сертификат: ' + ((err or out).strip()[-400:] or ('код %d' % rc)))
    return ovpn_conf(name)

def ovpn_remove(name):
    check_name(name)
    rc, out, err = _run([CLIENT_SH, '2', name], cwd=AZ_DIR, timeout=600)
    if rc != 0:
        raise VpnError('Не удалось удалить клиента: ' + ((err or out).strip()[-400:] or ('код %d' % rc)))
    return True

def ovpn_users():
    if not os.path.isdir(PKI_ISSUED):
        return []
    return sorted(f[:-4] for f in os.listdir(PKI_ISSUED)
                  if f.endswith('.crt') and f != 'antizapret-server.crt')

def _parse_status_file(path, out):
    hdr = None
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            for line in fh:
                f = line.rstrip('\n').split(',')
                if not f or not f[0]:
                    continue
                if f[0] == 'HEADER' and len(f) > 2 and f[1] == 'CLIENT_LIST':
                    hdr = f[2:]
                    continue
                if f[0] == 'Common Name':
                    hdr = f
                    continue
                if hdr and f[0] == 'CLIENT_LIST' and len(f) > len(hdr):
                    try:
                        # в строке данных есть префикс CLIENT_LIST, в заголовке — нет
                        rx = int(f[hdr.index('Bytes Received') + 1] or 0)
                        tx = int(f[hdr.index('Bytes Sent') + 1] or 0)
                    except (ValueError, IndexError):
                        continue
                    name = f[1]
                    prev = out.get(name)
                    if prev is None or (rx + tx) > (prev['rx'] + prev['tx']):
                        out[name] = {'rx': rx, 'tx': tx}
    except OSError:
        pass

def ovpn_status():
    out = {}
    for p in sorted(glob.glob(os.path.join(STATUS_DIR, 'status-*.log'))):
        _parse_status_file(p, out)
    return out

def qr_png(data):
    if not shutil.which('qrencode'):
        raise VpnError('qrencode не установлен')
    p = subprocess.run(['qrencode', '-t', 'PNG', '-o', '-', '-s', '6', '-m', '2'],
                       input=(data or '').encode('utf-8'), stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise VpnError('qrencode: ' + (p.stderr or b'').decode('utf-8', 'replace'))
    return p.stdout

# ---- интерфейс, который использует панель ----
def provision(protocol, vpn_name):
    if protocol != 'ovpn':
        raise VpnError('Поддерживается только OpenVPN')
    return ovpn_add(vpn_name), ''

def set_active(protocol, vpn_name, active, config=None):
    if protocol != 'ovpn':
        raise VpnError('Поддерживается только OpenVPN')
    if active:
        ovpn_add(vpn_name)
        return True
    return ovpn_remove(vpn_name)

def deprovision(protocol, vpn_name):
    if protocol != 'ovpn':
        return True
    try:
        ovpn_remove(vpn_name)
    except VpnError:
        pass
    return True

def awg_add(name):
    raise VpnError('AmneziaWG не используется: только сертификаты OpenVPN')

def awg_conf(name):
    raise VpnError('AmneziaWG не используется')
