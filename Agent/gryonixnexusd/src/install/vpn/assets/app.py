import os, sys, json, base64, subprocess, ipaddress, secrets, re, socket, http.client, urllib.parse, uuid, datetime, time, hashlib, smtplib, email.message, threading
from functools import wraps
from flask import Flask, request, Response, jsonify, send_file, abort, session, redirect

DATA = "/data"
WG_IF = "wgpanel"
WG_CONF = f"/etc/wireguard/{WG_IF}.conf"
CLIENTS = f"{DATA}/clients.json"
STATE = f"{DATA}/state.json"
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PW = os.environ.get("ADMIN_PASSWORD", "")
WG_HOST = os.environ.get("WG_HOST", "vpn.example.com")
WG_PORT = os.environ.get("WG_PORT", "51820")
SUBNET = os.environ.get("WG_SUBNET", "10.9.0.0/24")
SS_CONF = "/protocols/shadowsocks/config.json"
# IPv4 only, deliberately: the tunnel carries no IPv6 address and
# nothing NATs v6, so routing ::/0 into it black-holes every AAAA
# destination — on a dual-stack client that is most of the web, which is
# exactly the "connected, but nothing loads" symptom. v6 traffic stays on
# the client's own connection instead.
CLIENT_ALLOWED_IPS = "0.0.0.0/0"
# Conservative enough to survive a second encapsulation: in the VPS+home
# topology the client's packets are wrapped again by the relay tunnel, and
# an over-large MTU lets handshakes through while stalling real payloads.
CLIENT_MTU = 1280

app = Flask(__name__)
# No request in this API carries more than a short JSON body; anything
# bigger is garbage or an attack.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

def sh(cmd, inp=None):
    return subprocess.run(cmd, shell=True, input=inp, capture_output=True, text=True, check=True).stdout.strip()

def load(path, default):
    try:
        with open(path) as f: return json.load(f)
    except Exception:
        return default

def save(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f: json.dump(obj, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

# Every store is a JSON file rewritten whole, so a handler that reads,
# edits and saves is a read-modify-write. The server is threaded, so two
# overlapping state-changing requests both load the same snapshot and the
# second save silently drops the first one's work — two clients added at
# once lose one, and next_ip()/awg_next_ip() hand BOTH the same tunnel
# address off the same stale list. One process-wide lock around the
# mutating handlers is enough; each is a sub-millisecond file rewrite
# (the openvpn ones wait on easyrsa, which is worth serialising anyway).
STORE_LOCK = threading.RLock()

def serialized(f):
    @wraps(f)
    def w(*a, **k):
        with STORE_LOCK:
            return f(*a, **k)
    return w

# ---- Session auth: a styled form login instead of a browser Basic prompt
# (H1). The signed cookie is HttpOnly + Secure (the user reaches the panel
# over Caddy's HTTPS) + SameSite=Lax; the secret persists so sessions
# survive restarts. Access is still gated to VPN-side sources when the
# dashboard's VPN-only lockdown is on. ----

def ensure_secret():
    st = load(STATE, {})
    if "secret" not in st:
        st["secret"] = secrets.token_hex(32)
        save(STATE, st)
    return st["secret"]

app.secret_key = ensure_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True,
                  SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=7))

# The panel sits behind Caddy, so request.remote_addr is the proxy for
# every visitor — throttling on it would put all clients (including the
# admin) in one bucket. The panel's Caddy site overwrites
# X-Forwarded-For with the real peer address (header_up X-Forwarded-For
# {remote_host}) instead of appending to whatever the client sent, so
# its first entry is always the real client and cannot be spoofed.
def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() or request.remote_addr or "?"

# Per-IP throttle (H3) + fail2ban-style escalating bans: the
# single admin password must not be brute-forced. After MAX_FAILS wrong
# attempts the source is banned; every further ban doubles, up to a day.
#
# Counters are keyed by (scope, ip), not by ip alone. /forgot notes a
# "failure" on EVERY call — it has to, being unauthenticated and cheap to
# abuse — and with one shared bucket eight password-reset requests banned
# the sender from the LOGIN form for fifteen minutes, doubling from there.
# Someone who cannot remember their password would lock themselves out of
# the one thing they still had. The two limits are independent now.
FAILS = {}
BANS = {}
MAX_FAILS, FAIL_WINDOW, BAN_BASE, BAN_MAX = 8, 300, 900, 86400

def rate_limited(scope, ip):
    key = (scope, ip)
    ban = BANS.get(key)
    if ban and time.time() < ban[0]: return True
    c = FAILS.get(key)
    if not c: return False
    if time.time() - c[1] > FAIL_WINDOW:
        FAILS.pop(key, None); return False
    return c[0] >= MAX_FAILS

def note_fail(scope, ip):
    key = (scope, ip)
    now = time.time(); c = FAILS.get(key)
    if not c or now - c[1] > FAIL_WINDOW:
        c = FAILS[key] = [1, now]
    else:
        c[0] += 1
    if c[0] >= MAX_FAILS:
        prior = BANS.get(key)
        strikes = (prior[1] if prior else 0) + 1
        BANS[key] = (now + min(BAN_BASE * (2 ** (strikes - 1)), BAN_MAX), strikes)
        FAILS.pop(key, None)

# ---- Users and roles. One account per person instead of a single
# shared admin login. Roles: "superadmin" (exactly one, never deletable and
# never demotable — the account that can always get back in), "admin" (full
# management, including other users, but cannot touch the superadmin) and
# "user" (manages only the VPN clients it created itself). Passwords are
# PBKDF2-SHA256 with a per-user salt; only the hash is stored. ----

USERS = f"{DATA}/users.json"
ROLES = ("superadmin", "admin", "user")
PBKDF2_ROUNDS = 200000

def hash_pw(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ROUNDS)
    return {"salt": salt, "hash": digest.hex()}

def verify_pw(password, record):
    expected = record.get("hash", "")
    got = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), record.get("salt", "").encode(), PBKDF2_ROUNDS).hex()
    return bool(expected) and secrets.compare_digest(got, expected)

def set_password(record, password, source="panel"):
    """New credentials for `record`, and an end to every session that used the
    old ones.

    A signed session cookie is valid because it was signed, not because the
    password behind it still is: without this, changing a password — or
    RESETTING one because it was lost or stolen — left every session already
    open still working, which is exactly the session the change was meant to
    end. `pw_ver` is stamped into the session at login and re-checked on every
    request, so a change invalidates every session but the one that makes it
    (which restamps itself).
    """
    record.update({"pw_source": source, "pw_ver": record.get("pw_ver", 0) + 1,
                   **hash_pw(password)})
    return record


def users():
    return load(USERS, [])

def find_user(uid):
    for u in users():
        if u["id"] == uid: return u
    return None

def find_user_by_name(name):
    for u in users():
        if u["username"].lower() == name.lower(): return u
    return None

def ensure_superadmin():
    """Bootstraps the superadmin from the setup's ADMIN_USER/ADMIN_PASSWORD.

    The installer rewrites .env on every run, so as long as the password
    still comes from there the record follows it — the credentials printed
    in the setup report keep working. The moment the superadmin changes
    their password inside the panel the record switches to pw_source
    "panel" and the environment stops overriding it.
    """
    if not ADMIN_PW:
        return
    all_users = users()
    current = next((u for u in all_users if u.get("role") == "superadmin"), None)
    if current is None:
        all_users.append({
            "id": secrets.token_hex(8), "username": ADMIN_USER, "role": "superadmin",
            "email": "", "pw_source": "env", **hash_pw(ADMIN_PW),
        })
        save(USERS, all_users)
        return
    if current.get("pw_source") != "env":
        return
    if current["username"] != ADMIN_USER or not verify_pw(ADMIN_PW, current):
        set_password(current, ADMIN_PW, source="env")
        current["username"] = ADMIN_USER
        save(USERS, all_users)

ensure_superadmin()

def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    user = find_user(uid)
    if user is None:
        return None
    # The session was issued against a password that has since been replaced —
    # see set_password. A deleted account already fails above.
    if session.get("pv", 0) != user.get("pw_ver", 0):
        return None
    return user

def logged_in():
    return current_user() is not None

def is_admin(user=None):
    user = user or current_user()
    return bool(user) and user.get("role") in ("superadmin", "admin")

def public_user(u):
    return {"id": u["id"], "username": u["username"], "role": u["role"],
            "email": u.get("email", "")}

# Which clients a plain "user" may see and remove: the panel records what
# each account created, keyed by protocol, because only some protocols keep
# anything resembling an owner in their own configuration.
OWNERS = f"{DATA}/client-owners.json"

def note_owner(proto, cid, uid):
    owners = load(OWNERS, {})
    owners.setdefault(proto, {})[str(cid)] = uid
    save(OWNERS, owners)

def drop_owner(proto, cid):
    owners = load(OWNERS, {})
    owners.get(proto, {}).pop(str(cid), None)
    save(OWNERS, owners)

def owns(proto, cid):
    user = current_user()
    if is_admin(user): return True
    owners = load(OWNERS, {}).get(proto, {})
    return bool(user) and owners.get(str(cid)) == user["id"]

# ---- Password recovery by e-mail ----
#
# The panel sends through whatever SMTP the main administrator configures.
# When mailcow runs on this server its mailboxes are offered as the sender:
# its database credentials are read from the read-only mailcow.conf mount
# and the list is queried through the docker socket, because the panel has
# no way to authenticate to mailcow's API on its own. The mailbox PASSWORD
# is still typed by the administrator — mailcow only stores hashes.

SMTP_CONF = f"{DATA}/smtp.json"
RESETS = f"{DATA}/resets.json"
MAILCOW_CONF = "/protocols/mailcow/mailcow.conf"
RESET_TTL = 3600

def smtp_conf():
    return load(SMTP_CONF, {})

def public_smtp(c):
    # The password is write-only: the UI shows whether one is set, never
    # the value.
    return {"host": c.get("host", ""), "port": c.get("port", 587),
            "security": c.get("security", "starttls"), "username": c.get("username", ""),
            "sender": c.get("sender", ""), "has_password": bool(c.get("password"))}

def mailcow_env():
    env = {}
    try:
        with open(MAILCOW_CONF) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or "=" not in line: continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    except OSError:
        return {}
    return env

def mailcow_mailboxes():
    """Active mailbox addresses, or [] when mailcow is not installed here."""
    env = mailcow_env()
    user, pw, db = env.get("DBUSER"), env.get("DBPASS"), env.get("DBNAME")
    if not (user and pw and db):
        return []
    out = docker_exec_output("mailcowdockerized-mysql-mailcow-1", [
        "mysql", f"-u{user}", f"-p{pw}", db, "-N", "-B", "-e",
        "SELECT username FROM mailbox WHERE active = 1 ORDER BY username",
    ])
    if out is None:
        return []
    return [l.strip() for l in out.splitlines() if "@" in l]

def send_mail(to, subject, body):
    c = smtp_conf()
    host, sender = c.get("host"), c.get("sender")
    if not (host and sender and to):
        return False
    msg = email.message.EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    port = int(c.get("port") or 587)
    security = c.get("security", "starttls")
    try:
        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=20)
        else:
            server = smtplib.SMTP(host, port, timeout=20)
        with server:
            if security == "starttls":
                server.starttls()
            if c.get("username"):
                server.login(c["username"], c.get("password", ""))
            server.send_message(msg)
        return True
    except Exception:
        # Never leak the reason to the caller: /forgot answers the same way
        # whatever happens, so a stranger learns nothing about the setup.
        return False

def issue_reset(user):
    token = secrets.token_urlsafe(32)
    pending = [t for t in load(RESETS, []) if t["exp"] > time.time() and t["uid"] != user["id"]]
    # Stored hashed: a leaked file must not hand out working reset links.
    pending.append({"uid": user["id"], "exp": time.time() + RESET_TTL,
                    "hash": hashlib.sha256(token.encode()).hexdigest()})
    save(RESETS, pending)
    return token

def consume_reset(token):
    digest = hashlib.sha256((token or "").encode()).hexdigest()
    pending = load(RESETS, [])
    match = next((t for t in pending
                  if secrets.compare_digest(t["hash"], digest) and t["exp"] > time.time()), None)
    if not match:
        return None
    save(RESETS, [t for t in pending if t is not match and t["exp"] > time.time()])
    return find_user(match["uid"])

def services():
    return load(f"{DATA}/services.json", {"services": []}).get("services", [])

def svc_meta(pid):
    for s in services():
        if s.get("id") == pid: return s
    abort(404)

def docker_api(method, path, body=None):
    # Talk to the Docker Engine API over the mounted unix socket — no CLI.
    conn = http.client.HTTPConnection("localhost")
    conn.sock = socket.socket(socket.AF_UNIX)
    conn.sock.connect("/var/run/docker.sock")
    payload = json.dumps(body) if body is not None else None
    conn.request(method, path, body=payload,
                 headers={"Content-Type": "application/json"} if payload else {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data

def docker_restart(name):
    try:
        docker_api("POST", f"/v1.41/containers/{name}/restart?t=3")
    except Exception:
        pass

def docker_exec(container, cmd, env=None):
    # Run a command inside a running container and wait for it. The
    # non-detached start streams until the command exits; reading to EOF
    # is the wait. Fails the request if the command fails.
    status, data = docker_api("POST", f"/v1.41/containers/{container}/exec",
                              {"AttachStdout": True, "AttachStderr": True,
                               "Cmd": cmd, "Env": env or []})
    if status >= 300: abort(502)
    eid = json.loads(data)["Id"]
    docker_api("POST", f"/v1.41/exec/{eid}/start", {"Detach": False, "Tty": False})
    status, data = docker_api("GET", f"/v1.41/exec/{eid}/json")
    if status >= 300 or json.loads(data).get("ExitCode") != 0: abort(502)

def docker_exec_output(container, cmd):
    """Same, but returns the command's stdout and never aborts.

    Used for optional lookups (is mailcow here? which mailboxes?), where a
    missing container is an answer rather than an error.
    """
    try:
        status, data = docker_api("POST", f"/v1.41/containers/{container}/exec",
                                  {"AttachStdout": True, "AttachStderr": False,
                                   "Cmd": cmd})
        if status >= 300: return None
        eid = json.loads(data)["Id"]
        status, out = docker_api("POST", f"/v1.41/exec/{eid}/start",
                                 {"Detach": False, "Tty": False})
        if status >= 300: return None
        status, info = docker_api("GET", f"/v1.41/exec/{eid}/json")
        if status >= 300 or json.loads(info).get("ExitCode") != 0: return None
    except Exception:
        return None
    # Without a TTY the stream is framed: 8-byte header (stream id, then a
    # big-endian length) in front of every chunk.
    text, i = "", 0
    while i + 8 <= len(out):
        size = int.from_bytes(out[i + 4:i + 8], "big")
        text += out[i + 8:i + 8 + size].decode("utf-8", "replace")
        i += 8 + size
    return text

# ---- WireGuard (panel runs the interface itself) ----

def ensure_server():
    st = load(STATE, {})
    if "priv" not in st:
        st["priv"] = sh("wg genkey")
        st["pub"] = sh("wg pubkey", inp=st["priv"])
        save(STATE, st)
    return st

def wan_if():
    """The interface the container reaches the internet through.

    Was hard-coded to eth0, which is only right by accident: a container on
    a user-defined compose network can be given any name, and NAT bound to
    the wrong interface silently drops every client packet.
    """
    try:
        out = subprocess.run("ip -4 route show default", shell=True,
                             capture_output=True, text=True).stdout.split()
        if "dev" in out:
            return out[out.index("dev") + 1]
    except Exception:
        pass
    return "eth0"

def wg_apply_nat(wan):
    # NAT/forwarding is applied here, OUTSIDE wg-quick's PostUp, on
    # purpose. wg-quick arms a `trap del_if EXIT` before it runs the PostUp
    # hooks and only clears it once every hook has succeeded, so a SINGLE
    # failing PostUp command tears the freshly-created interface back down
    # on its way out. That turned any iptables hiccup — a missing
    # nat/conntrack module, an nft-vs-legacy backend mismatch, a busy
    # xtables lock — into a tunnel clients could "connect" to while nothing
    # listened: no handshake, every packet into a black hole, no internet
    # and no admin sites. Run here instead, a NAT failure at worst costs
    # one rule (and is logged); it can never take the whole VPN down with
    # it. Forwarding itself is switched on by the compose file
    # (net.ipv4.ip_forward=1): /proc/sys is read-only in the container, so
    # that is the only way that works from here.
    #
    # Each rule is deleted first (failure ignored — the stale copy may not
    # exist) then re-added, so repeated wg_up calls stay idempotent and any
    # leftover PostUp-era rules are cleaned up. The FORWARD accepts are
    # explicit rather than trusting the namespace's default policy; MSS
    # clamping keeps large TCP segments from stalling on the doubly
    # encapsulated VPS+home path.
    # Forwarding is a container-start setting (compose `sysctls:`), not
    # something we can flip at runtime — /proc/sys is read-only here. If it
    # is off anyway (e.g. an OLD compose from before that fix is still
    # running), every routed packet is silently dropped: connected tunnel,
    # no internet, no admin sites. Surface it loudly so `docker logs`
    # names the cause instead of leaving a black hole to guess at.
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            if f.read().strip() != "1":
                sys.stderr.write("ip_forward is 0: the container is not routing. "
                                 "Re-run setup so compose applies "
                                 "sysctls net.ipv4.ip_forward=1, then restart.\n")
                sys.stderr.flush()
    except Exception:
        pass
    rules = [
        ("nat", ["POSTROUTING", "-s", SUBNET, "-o", wan, "-j", "MASQUERADE"]),
        ("filter", ["FORWARD", "-i", WG_IF, "-o", wan, "-j", "ACCEPT"]),
        ("filter", ["FORWARD", "-i", wan, "-o", WG_IF,
                    "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
        ("mangle", ["FORWARD", "-o", WG_IF, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                    "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
    ]
    for table, spec in rules:
        subprocess.run(["iptables", "-t", table, "-D"] + spec, capture_output=True)
        r = subprocess.run(["iptables", "-t", table, "-A"] + spec, capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write("iptables -t %s -A %s failed: %s\n"
                             % (table, " ".join(spec), (r.stderr or "").strip()))
            sys.stderr.flush()

def wg_up(st):
    net = ipaddress.ip_network(SUBNET)
    server_ip = str(list(net.hosts())[0])
    wan = wan_if()
    peers = ""
    for c in load(CLIENTS, []):
        peers += f"\n[Peer]\nPublicKey = {c['pub']}\nAllowedIPs = {c['ip']}/32\n"
    # A BARE interface: no PostUp/PostDown firewall hooks. A failing hook
    # would make wg-quick trap-EXIT and delete the interface, so NAT and
    # forwarding are applied by wg_apply_nat AFTER the interface is
    # confirmed up (see there for the full rationale).
    conf = f"""[Interface]
Address = {server_ip}/{net.prefixlen}
ListenPort = {WG_PORT}
PrivateKey = {st['priv']}
{peers}"""
    os.makedirs("/etc/wireguard", exist_ok=True)
    with open(WG_CONF, "w") as f: f.write(conf)
    os.chmod(WG_CONF, 0o600)
    subprocess.run(f"wg-quick down {WG_IF}", shell=True, capture_output=True)
    r = subprocess.run(f"wg-quick up {WG_IF}", shell=True, capture_output=True, text=True)
    # The exit code used to be dropped on the floor, so an interface that
    # never came up looked exactly like a working one from in here. It is
    # the difference between "VPN is broken" and a line in `docker logs`.
    if r.returncode != 0:
        sys.stderr.write(f"wg-quick up {WG_IF} failed ({r.returncode}): "
                         f"{(r.stderr or '').strip()}\n")
        sys.stderr.flush()
        return False
    wg_apply_nat(wan)
    return True

def next_ip():
    net = ipaddress.ip_network(SUBNET)
    used = {c["ip"] for c in load(CLIENTS, [])}
    used.add(str(list(net.hosts())[0]))
    for h in net.hosts():
        if str(h) not in used: return str(h)
    abort(507)

def require_auth(f):
    @wraps(f)
    def w(*a, **k):
        if not logged_in():
            # API callers get JSON they can act on; page requests are sent
            # to the styled login form.
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required."}), 401
            return redirect("/login")
        return f(*a, **k)
    return w

def require_admin(f):
    @wraps(f)
    def w(*a, **k):
        if not logged_in():
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required."}), 401
            return redirect("/login")
        if not is_admin():
            return jsonify({"error": "Administrator access required."}), 403
        return f(*a, **k)
    return w

def wg_clients():
    return [{"id": c["id"], "name": c["name"], "detail": c["ip"]} for c in load(CLIENTS, [])]

def wg_add_client(name):
    st = ensure_server()
    priv = sh("wg genkey"); pub = sh("wg pubkey", inp=priv)
    clients = load(CLIENTS, [])
    cid = secrets.token_hex(6)
    clients.append({"id": cid, "name": name, "ip": next_ip(), "priv": priv, "pub": pub})
    save(CLIENTS, clients)
    wg_up(st)
    return cid

def wg_del_client(cid):
    save(CLIENTS, [c for c in load(CLIENTS, []) if c["id"] != cid])
    wg_up(ensure_server())

def wg_client_conf(cid):
    st = ensure_server()
    for c in load(CLIENTS, []):
        if c["id"] == cid:
            return (f"[Interface]\nPrivateKey = {c['priv']}\nAddress = {c['ip']}/32\n"
                    f"DNS = 1.1.1.1\nMTU = {CLIENT_MTU}\n\n"
                    f"[Peer]\nPublicKey = {st['pub']}\nEndpoint = {WG_HOST}:{WG_PORT}\n"
                    f"AllowedIPs = {CLIENT_ALLOWED_IPS}\nPersistentKeepalive = 25\n")
    abort(404)

# ---- Shadowsocks (edits the ss container's config.json, then restarts it) ----

def ss_clients():
    return [{"id": u["id"], "name": u["name"], "detail": "shadowsocks"} for u in load(SS_CONF, {}).get("users", [])]

def ss_add_client(name):
    conf = load(SS_CONF, {})
    users = conf.get("users", [])
    uid = secrets.token_hex(6)
    users.append({"id": uid, "name": name, "password": base64.b64encode(secrets.token_bytes(32)).decode()})
    conf["users"] = users
    save(SS_CONF, conf)
    docker_restart("shadowsocks")
    return uid

def ss_del_client(cid):
    conf = load(SS_CONF, {})
    conf["users"] = [u for u in conf.get("users", []) if u["id"] != cid]
    save(SS_CONF, conf)
    docker_restart("shadowsocks")

def ss_client_conf(cid):
    conf = load(SS_CONF, {}); meta = svc_meta("shadowsocks")
    method = conf.get("method", "2022-blake3-aes-256-gcm"); server_psk = conf.get("password", "")
    for u in conf.get("users", []):
        if u["id"] == cid:
            # SIP022 multi-user: client password is server_psk:user_psk.
            pw = urllib.parse.quote(f"{server_psk}:{u['password']}", safe=":")
            # The label is a URI fragment, so it needs escaping just like
            # xray's does — client names may contain spaces (api_add keeps
            # them), and a raw space truncated the link in every importer
            # that parses it as a URI.
            label = urllib.parse.quote(u["name"])
            return f"ss://{method}:{pw}@{meta['host']}:{meta['port']}#{label}"
    abort(404)

# ---- Xray VLESS/Reality (adds client UUIDs to the inbound, then restarts) ----

XR_CONF = "/protocols/xray/config/config.json"
XR_LINK = "/protocols/xray/link.txt"

def xr_inbound(conf):
    for i in conf.get("inbounds", []):
        if i.get("protocol") == "vless": return i
    abort(503)

def xr_link_params():
    # pbk/sid/sni and the public host:port come from the link the setup
    # script wrote. Parsed with a regex (not parse_qsl) so the raw
    # percent-encoding of the values is preserved verbatim.
    try:
        with open(XR_LINK) as f: link = f.read().strip()
    except Exception:
        abort(503)
    m = re.match(r"vless://[^@]+@([^:/?#]+):(\d+)\?([^#]*)", link)
    if not m: abort(503)
    q = dict(p.split("=", 1) for p in m.group(3).split("&") if "=" in p)
    return m.group(1), m.group(2), q

def xr_clients():
    out = []
    for i in load(XR_CONF, {}).get("inbounds", []):
        if i.get("protocol") == "vless":
            out = i.get("settings", {}).get("clients", [])
    return [{"id": c["id"], "name": c.get("email") or "default", "detail": "vless"} for c in out]

def xr_add_client(name):
    conf = load(XR_CONF, {})
    ib = xr_inbound(conf)
    cid = str(uuid.uuid4())
    ib.setdefault("settings", {}).setdefault("clients", []).append(
        {"id": cid, "flow": "xtls-rprx-vision", "email": name})
    save(XR_CONF, conf)
    docker_restart("xray")
    return cid

def xr_del_client(cid):
    conf = load(XR_CONF, {})
    ib = xr_inbound(conf)
    ib["settings"]["clients"] = [c for c in ib.get("settings", {}).get("clients", []) if c["id"] != cid]
    save(XR_CONF, conf)
    docker_restart("xray")

def xr_client_conf(cid):
    host, port, q = xr_link_params()
    for c in xr_clients():
        if c["id"] == cid:
            name = urllib.parse.quote(c["name"])
            return (f"vless://{cid}@{host}:{port}?encryption=none&flow=xtls-rprx-vision"
                    f"&security=reality&sni={q.get('sni', '')}&fp=chrome"
                    f"&pbk={q.get('pbk', '')}&sid={q.get('sid', '')}&type=tcp#{name}")
    abort(404)

# ---- OpenVPN (EasyRSA certificates via exec in the openvpn container) ----

OV_DIR = "/protocols/openvpn"
# Named so api_add can truncate to the same bound instead of guessing.
OV_NAME_MAX = 32
# \Z rather than a trailing $: in Python's re, $ also matches right
# before a final "\n", so "foo\n" would pass this and then interpolate
# into a shell command (ov_write_profile) as three arguments instead of
# one. \Z matches end-of-string only.
OV_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,%d}\Z" % OV_NAME_MAX)

def ov_server_cn():
    return svc_meta("openvpn").get("host", "")

def ov_clients():
    # pki/index.txt is EasyRSA's authoritative state: V = valid, R = revoked.
    # The server's own certificate (CN = the VPN host) is not a client.
    try:
        with open(f"{OV_DIR}/pki/index.txt") as f: lines = f.readlines()
    except Exception:
        return []
    out = []
    for ln in lines:
        cols = ln.strip().split("\t")
        m = re.search(r"/CN=([^/\n]+)", cols[-1]) if cols else None
        if not m or cols[0] != "V": continue
        cn = m.group(1)
        if cn == ov_server_cn(): continue
        out.append({"id": cn, "name": cn, "detail": "certificate"})
    return out

def ov_write_profile(cn):
    docker_exec("openvpn", ["sh", "-c",
                f"mkdir -p /etc/openvpn/panel && ovpn_getclient {cn} > /etc/openvpn/panel/{cn}.ovpn"])

def ov_add_client(name):
    name = name.replace(" ", "-")
    if not OV_NAME.match(name) or name == ov_server_cn(): abort(400)
    if any(c["id"] == name for c in ov_clients()): abort(409)
    docker_exec("openvpn", ["easyrsa", "build-client-full", name, "nopass"], env=["EASYRSA_BATCH=1"])
    ov_write_profile(name)
    return name

def ov_del_client(cid):
    if not OV_NAME.match(cid): abort(400)
    docker_exec("openvpn", ["ovpn_revokeclient", cid, "remove"], env=["EASYRSA_BATCH=1"])
    try: os.remove(f"{OV_DIR}/panel/{cid}.ovpn")
    except OSError: pass
    docker_restart("openvpn")

def ov_client_conf(cid):
    if not OV_NAME.match(cid): abort(400)
    path = f"{OV_DIR}/panel/{cid}.ovpn"
    if not os.path.exists(path):
        # The initial client made by the setup script has no cached profile.
        if not any(c["id"] == cid for c in ov_clients()): abort(404)
        ov_write_profile(cid)
    with open(path) as f: return f.read()

# ---- AmneziaWG (edits the awgvpn container's wg0.json, then restarts it) ----

AWG_CONF = "/protocols/amneziawg/wg0.json"

def awg_clients():
    return [{"id": k, "name": v.get("name", k), "detail": v.get("address", "")}
            for k, v in load(AWG_CONF, {}).get("clients", {}).items()]

def awg_next_ip(conf):
    server_ip = conf.get("server", {}).get("address", "10.10.0.1")
    net = ipaddress.ip_network(f"{server_ip}/24", strict=False)
    used = {server_ip} | {c.get("address") for c in conf.get("clients", {}).values()}
    for h in net.hosts():
        if str(h) not in used: return str(h)
    abort(507)

def awg_add_client(name):
    conf = load(AWG_CONF, {})
    if "server" not in conf: abort(503)
    priv = sh("wg genkey"); pub = sh("wg pubkey", inp=priv); psk = sh("wg genpsk")
    cid = str(uuid.uuid4())
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    conf.setdefault("clients", {})[cid] = {
        "name": name, "address": awg_next_ip(conf),
        "privateKey": priv, "publicKey": pub, "preSharedKey": psk,
        "createdAt": now, "updatedAt": now, "enabled": True,
    }
    save(AWG_CONF, conf)
    docker_restart("awgvpn")
    return cid

def awg_del_client(cid):
    conf = load(AWG_CONF, {})
    conf.get("clients", {}).pop(cid, None)
    save(AWG_CONF, conf)
    docker_restart("awgvpn")

def awg_client_conf(cid):
    conf = load(AWG_CONF, {}); meta = svc_meta("amneziawg")
    server = conf.get("server", {})
    c = conf.get("clients", {}).get(cid)
    if not c: abort(404)
    # The fork keeps the AmneziaWG obfuscation values with the server
    # config; the client [Interface] must carry the same ones.
    extra = ""
    for k in ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"):
        v = server.get(k)
        if v is not None:
            extra += f"{k.capitalize() if k.startswith('j') else k.upper()} = {v}\n"
    return (f"[Interface]\nPrivateKey = {c['privateKey']}\nAddress = {c['address']}/24\n"
            f"DNS = 1.1.1.1\nMTU = {CLIENT_MTU}\n{extra}\n"
            f"[Peer]\nPublicKey = {server.get('publicKey', '')}\nPresharedKey = {c['preSharedKey']}\n"
            f"Endpoint = {meta.get('host', '')}:{meta.get('port', '')}\n"
            f"AllowedIPs = {CLIENT_ALLOWED_IPS}\nPersistentKeepalive = 25\n")

HANDLERS = {
    "wireguard": (wg_clients, wg_add_client, wg_del_client, wg_client_conf),
    "shadowsocks": (ss_clients, ss_add_client, ss_del_client, ss_client_conf),
    "xray": (xr_clients, xr_add_client, xr_del_client, xr_client_conf),
    "openvpn": (ov_clients, ov_add_client, ov_del_client, ov_client_conf),
    "amneziawg": (awg_clients, awg_add_client, awg_del_client, awg_client_conf),
}

# An .ovpn profile is several KB — far past what a phone camera scans.
NO_QR = ["openvpn"]

# Client-config download extension per protocol — what the VPN apps expect
# to import (ss:// and vless:// links are plain text).
EXT = {"wireguard": ".conf", "amneziawg": ".conf", "openvpn": ".ovpn",
       "shadowsocks": ".txt", "xray": ".txt"}

from werkzeug.exceptions import HTTPException

# API errors reach the frontend as JSON with a human message (abort() would
# otherwise return an HTML page the SPA cannot show). 401 never lands here:
# require_auth returns its JSON response / redirect directly.
ERR = {400: "Invalid client name.", 403: "Request blocked.", 404: "Not found.",
       409: "A client with that name already exists.",
       502: "The protocol container could not be updated. It may be restarting — try again in a moment.",
       503: "This VPN service is not ready yet — wait a few seconds and retry.",
       507: "No free addresses left in the VPN subnet."}

@app.errorhandler(HTTPException)
def on_http_error(e):
    return jsonify({"error": ERR.get(e.code, e.description or "Server error.")}), e.code

# CSRF defence in depth: SameSite=Lax already keeps the session
# cookie off cross-site POSTs; on top of that every state-changing request
# must carry a custom header — a cross-origin page cannot attach one
# without a CORS preflight, which this API never answers.
@app.before_request
def csrf_guard():
    # Every state-changing verb, not just the two the panel started with:
    # a route added later (PATCH /api/users/<id>) must not slip past this.
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("X-Gryonix-Auth") != "1":
        abort(403)

# Baseline secure headers on every response, pages and API alike.
# Everything the panel serves is sensitive, so nothing is cacheable; the
# CSP pins all content to the page itself (both pages inline their CSS/JS).
@app.after_request
def secure_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "img-src 'self' data: blob:; connect-src 'self'; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.get("/login")
def login_page():
    if logged_in(): return redirect("/")
    return send_file("/app/login.html")

@app.post("/login")
def login_submit():
    ip = client_ip()
    if rate_limited("login", ip):
        return jsonify({"error": "Too many attempts. Please wait a few minutes."}), 429
    data = request.get_json(silent=True) or request.form
    user = (data.get("username") or "").strip()
    pw = data.get("password") or ""
    # Both fields go through constant-time comparison, and both are always
    # evaluated — neither timing nor short-circuiting reveals which one
    # was wrong.
    record = find_user_by_name(user)
    # An unknown username is still checked against a throwaway hash so a
    # wrong name and a wrong password cost the same time.
    pw_ok = verify_pw(pw, record or hash_pw(secrets.token_hex(8)))
    if record and pw_ok:
        session.clear()          # a fresh session on every login
        session.permanent = True
        session["uid"] = record["id"]
        session["pv"] = record.get("pw_ver", 0)
        FAILS.pop(("login", ip), None); BANS.pop(("login", ip), None)
        return jsonify({"ok": True})
    note_fail("login", ip)
    time.sleep(0.4)              # flat cost per wrong guess
    return jsonify({"error": "Wrong username or password."}), 401

@app.post("/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.get("/")
@require_auth
def index():
    return send_file("/app/index.html")

@app.get("/api/services")
@require_auth
def api_services():
    return jsonify({"services": services(), "manageable": list(HANDLERS.keys()), "noqr": NO_QR})

@app.get("/api/<proto>/clients")
@require_auth
def api_list(proto):
    if proto not in HANDLERS: abort(404)
    found = HANDLERS[proto][0]()
    # A plain user only ever sees the clients it created itself.
    return jsonify(found if is_admin() else [c for c in found if owns(proto, c["id"])])

@app.post("/api/<proto>/clients")
@require_auth
@serialized
def api_add(proto):
    if proto not in HANDLERS: abort(404)
    # 40 was this endpoint's own idea of "long enough"; openvpn turns the
    # name into an X.509 CN and rejects anything past OV_NAME's 32, so a
    # 33-character name got a bare "Invalid client name." after passing
    # the field's own validation. Truncate to what the strictest handler
    # accepts instead of handing it a name it will refuse.
    limit = OV_NAME_MAX if proto == "openvpn" else 40
    name = re.sub(r"[^A-Za-z0-9 _.-]", "", (request.json or {}).get("name", "").strip())[:limit] or "client"
    cid = HANDLERS[proto][1](name)
    note_owner(proto, cid, current_user()["id"])
    return jsonify({"id": cid})

@app.delete("/api/<proto>/clients/<cid>")
@require_auth
@serialized
def api_del(proto, cid):
    if proto not in HANDLERS: abort(404)
    if not owns(proto, cid): abort(403)
    HANDLERS[proto][2](cid)
    drop_owner(proto, cid)
    return ("", 204)

@app.get("/api/<proto>/clients/<cid>/config")
@require_auth
def api_conf(proto, cid):
    if proto not in HANDLERS: abort(404)
    if not owns(proto, cid): abort(403)
    resp = Response(HANDLERS[proto][3](cid), mimetype="text/plain")
    if request.args.get("dl"):
        # ?dl=1 turns the same URL into a real file download: an
        # attachment with the client's name survives mobile browsers that
        # ignore blob-anchor downloads.
        name = next((c["name"] for c in HANDLERS[proto][0]() if c["id"] == cid), cid)
        fname = re.sub(r"[^A-Za-z0-9._-]", "-", name).strip("-.") or "client"
        resp.headers["Content-Disposition"] = f'attachment; filename="{fname}{EXT.get(proto, ".txt")}"'
    return resp

# ---- Accounts ----

@app.get("/api/me")
@require_auth
def api_me():
    return jsonify(public_user(current_user()))

@app.get("/api/users")
@require_admin
def api_users():
    return jsonify([public_user(u) for u in users()])

@app.post("/api/users")
@require_admin
@serialized
def api_user_add():
    data = request.json or {}
    name = re.sub(r"[^A-Za-z0-9_.-]", "", (data.get("username") or "").strip())[:32]
    password = data.get("password") or ""
    role = data.get("role") if data.get("role") in ("admin", "user") else "user"
    if not name or len(password) < 8:
        return jsonify({"error": "A username and a password of at least 8 characters are required."}), 400
    if find_user_by_name(name):
        return jsonify({"error": "That username is already taken."}), 409
    all_users = users()
    all_users.append({"id": secrets.token_hex(8), "username": name, "role": role,
                      "email": (data.get("email") or "").strip()[:120],
                      "pw_source": "panel", "pw_ver": 0, **hash_pw(password)})
    save(USERS, all_users)
    return jsonify({"ok": True})

@app.patch("/api/users/<uid>")
@require_admin
@serialized
def api_user_edit(uid):
    data = request.json or {}
    all_users = users()
    target = next((u for u in all_users if u["id"] == uid), None)
    if not target: abort(404)
    me = current_user()
    # The superadmin is the account that can always get back in: only it may
    # change itself, and its role is fixed.
    if target["role"] == "superadmin" and me["id"] != target["id"]:
        return jsonify({"error": "Only the main administrator can change this account."}), 403
    if "role" in data and target["role"] != "superadmin":
        if data["role"] not in ("admin", "user"):
            return jsonify({"error": "Unknown role."}), 400
        target["role"] = data["role"]
    if "email" in data:
        target["email"] = (data.get("email") or "").strip()[:120]
    if data.get("password"):
        if len(data["password"]) < 8:
            return jsonify({"error": "The password must be at least 8 characters."}), 400
        set_password(target, data["password"])
    save(USERS, all_users)
    return jsonify({"ok": True})

@app.delete("/api/users/<uid>")
@require_admin
@serialized
def api_user_del(uid):
    all_users = users()
    target = next((u for u in all_users if u["id"] == uid), None)
    if not target: abort(404)
    if target["role"] == "superadmin":
        return jsonify({"error": "The main administrator cannot be removed."}), 403
    if target["id"] == session.get("uid"):
        return jsonify({"error": "You cannot remove your own account."}), 400
    save(USERS, [u for u in all_users if u["id"] != uid])
    return ("", 204)

@app.get("/api/email")
@require_admin
def api_email_get():
    return jsonify({"smtp": public_smtp(smtp_conf()), "mailboxes": mailcow_mailboxes()})

@app.put("/api/email")
@require_admin
@serialized
def api_email_put():
    data = request.json or {}
    current = smtp_conf()
    conf = {
        "host": (data.get("host") or "").strip()[:200],
        "port": int(data.get("port") or 587),
        "security": data.get("security") if data.get("security") in ("starttls", "ssl", "none") else "starttls",
        "username": (data.get("username") or "").strip()[:200],
        "sender": (data.get("sender") or "").strip()[:200],
        # An omitted password keeps the stored one — the UI never sees it,
        # so it cannot send it back.
        "password": data.get("password") if data.get("password") else current.get("password", ""),
    }
    save(SMTP_CONF, conf)
    return jsonify({"ok": True, "smtp": public_smtp(conf)})

@app.post("/api/email/test")
@require_admin
def api_email_test():
    me = current_user()
    target = (request.json or {}).get("to") or me.get("email")
    if not target:
        return jsonify({"error": "Add an e-mail address to your account first."}), 400
    if not send_mail(target, "Gryonix VPN test", "Your VPN panel can send e-mail."):
        return jsonify({"error": "Sending failed. Check the server, port and credentials."}), 502
    return jsonify({"ok": True})

@app.post("/forgot")
@serialized
def forgot():
    ip = client_ip()
    # Throttled like the login form: this endpoint is unauthenticated.
    if rate_limited("forgot", ip):
        return jsonify({"error": "Too many attempts. Please wait a few minutes."}), 429
    note_fail("forgot", ip)
    wanted = ((request.json or {}).get("username") or "").strip()
    user = find_user_by_name(wanted) or next(
        (u for u in users() if u.get("email", "").lower() == wanted.lower() and u.get("email")), None)
    if user and user.get("email"):
        token = issue_reset(user)
        # The link is built from the panel's own configured hostname, never
        # from the Host header: a spoofed Host must not steer a valid reset
        # token to an attacker's domain. WG_HOST is the vhost Caddy serves
        # this panel on (and the upstream speaks plain HTTP behind the
        # proxy, so url_root would also get the scheme wrong).
        link = "https://" + WG_HOST + "/reset?token=" + token
        send_mail(user["email"], "Reset your VPN panel password",
                  "Someone asked to reset the password for your VPN panel account "
                  f"({user['username']}).\n\nOpen this link within the hour to choose a new one:\n"
                  f"{link}\n\nIf that was not you, ignore this message — nothing has changed.")
    # Always the same answer: whether an account or a mailbox exists is not
    # something a stranger gets to find out.
    return jsonify({"ok": True})

@app.get("/reset")
def reset_page():
    return send_file("/app/reset.html")

@app.post("/reset")
@serialized
def reset_apply():
    data = request.json or {}
    password = data.get("password") or ""
    if len(password) < 8:
        return jsonify({"error": "The password must be at least 8 characters."}), 400
    user = consume_reset(data.get("token"))
    if not user:
        return jsonify({"error": "This link has expired. Ask for a new one."}), 400
    all_users = users()
    for u in all_users:
        if u["id"] == user["id"]:
            set_password(u, password)
    save(USERS, all_users)
    # Whoever holds an older session for this account is signed out, which is
    # the point of a reset asked for by someone who lost the password.
    return jsonify({"ok": True})

@app.post("/api/account/password")
@require_auth
@serialized
def api_own_password():
    data = request.json or {}
    me = current_user()
    if not verify_pw(data.get("current") or "", me):
        return jsonify({"error": "The current password is wrong."}), 403
    new = data.get("password") or ""
    if len(new) < 8:
        return jsonify({"error": "The password must be at least 8 characters."}), 400
    all_users = users()
    for u in all_users:
        if u["id"] == me["id"]:
            set_password(u, new)
            # The session doing the changing carries on; every other one that
            # was opened with the old password stops here.
            session["pv"] = u["pw_ver"]
    save(USERS, all_users)
    return jsonify({"ok": True})

@app.get("/api/<proto>/clients/<cid>/qr")
@require_auth
def api_qr(proto, cid):
    if proto not in HANDLERS: abort(404)
    if not owns(proto, cid): abort(403)
    png = subprocess.run(["qrencode", "-t", "PNG", "-m", "1", "-s", "6", "-o", "-"],
                         input=HANDLERS[proto][3](cid).encode(), capture_output=True).stdout
    return Response(png, mimetype="image/png")

if __name__ == "__main__":
    svc = load(f"{DATA}/services.json", {"services": []})
    if any(s.get("id") == "wireguard" for s in svc.get("services", [])):
        ensure_server(); wg_up(ensure_server())
    app.run(host="0.0.0.0", port=80)
