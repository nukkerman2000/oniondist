#!/usr/bin/env python3
"""
oniondist coordinator -- a tiny Hashtopolis-style server for distributed
.onion vanity address search.

It hands out contiguous counter ranges (per task) to agents (GPU or CPU),
collects their progress and any hits, and serves a live dashboard.

    python3 server.py --pattern aistorys --port 8080

Config file (default: config.json next to this file, override with --config):
    {
      "host": "0.0.0.0", "port": 8090, "db": "oniondist.db", "keys": "keys",
      "expand": 10,
      "token": "agent-secret", "admin_token": "admin-secret",
      "chunks": {
        "mode": "auto",                                  # auto (default) | manual
        "base": 65536,                                   # auto: size = base * weight[kind]
        "weights": { "gpu": 1024, "cpu": 1 },            # auto weights
        "manual":  { "gpu": 67108864, "cpu": 65536 }     # manual: exact sizes
      }
    }
    Any CLI flag overrides the config file. See config.example.json.


Tasks (multi-task pool):
    * 1 active task   -> every approved worker is auto-assigned to it.
    * >1 active tasks -> an admin must assign each worker to exactly one task
                         (1 worker = 1 task); unassigned workers get no work.

Auth:
    * --token     shared secret. A worker presenting it is auto-approved.
    * No token    the worker still registers and shows up ONLINE as "pending",
                  but receives no work until an admin approves it in /admin.
    * /api/report and /api/found require a valid token OR an approved worker.
    * /admin and /api/admin/* require --admin-token (falls back to --token).

Endpoints:
    GET  /api/work?client=NAME&kind=gpu|cpu&batch=N   -> {pattern,start,count,exp}
    POST /api/report  {client,kind,tested,rate,chunks}
    POST /api/found   {client,key,pattern,counter}
    GET  /api/status                                  -> public snapshot (online workers)
    GET  /api/admin/status                            -> full snapshot (all workers)
    POST /api/admin                                   -> admin actions
    GET  /api/admin/hs/<onion>                        -> zip of the hidden-service dir
    GET  /                                            -> public dashboard (tasks + online workers)
    GET  /admin                                      -> admin panel

No third-party dependencies (stdlib only). Ed25519 .onion rendering uses PyNaCl
if it is installed; otherwise hits are still stored, just without the onion.
"""
import argparse
import io
import json
import os
import re
import sqlite3
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

try:
    import nacl.bindings  # optional
except Exception:
    nacl = None

ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
DEFAULT_CHUNK = {"gpu": 1 << 26, "cpu": 1 << 16}
STALE_SECONDS = 90
CONFIG_DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


def load_config(path):
    """Read a JSON config file. Missing/unreadable/invalid -> {} (all defaults)."""
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg if isinstance(cfg, dict) else {}
    except Exception as e:
        print("config: cannot read %s: %s" % (path, e))
        return {}


def _as_dict(v):
    return v if isinstance(v, dict) else {}


def _as_int(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def save_config(path, updates):
    """Merge `updates` (top-level keys) into the JSON config file at `path`.

    Only called when the file already exists, so we never create one
    unexpectedly. Existing keys not in `updates` are preserved. Atomic write.
    """
    if not path or not os.path.exists(path):
        return False
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            cfg = {}
        cfg.update(updates)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
        return True
    except Exception as e:
        print("config: cannot write %s: %s" % (path, e))
        return False


def onion_from_key(hex_key):
    """64-hex secret key -> base32 .onion hostname (without the .onion suffix)."""
    if nacl is None:
        return None
    try:
        import binascii, hashlib, base64
        pub = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(binascii.unhexlify(hex_key))
        version = b"\x03"
        chk = hashlib.sha3_256(b".onion checksum" + pub + version).digest()[:2]
        return base64.b32encode(pub + chk + version).decode().lower()
    except Exception:
        return None


def save_hs(root, hex_key, pattern):
    """Write a ready-to-use hidden-service dir, same layout as util/genpubs.py:

        <root>/<pattern>/<onion>/hostname
                                 hs_ed25519_secret_key
                                 hs_ed25519_public_key

    Returns the onion hostname, or None if PyNaCl is unavailable/invalid.
    """
    if nacl is None:
        return None
    try:
        import binascii, hashlib, base64, os
        sk = binascii.unhexlify(hex_key)
        pub = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(sk)
        version = b"\x03"
        chk = hashlib.sha3_256(b".onion checksum" + pub + version).digest()[:2]
        onion = base64.b32encode(pub + chk + version).decode().lower()

        name = pattern.split("?")[0].lower() or "any"
        d = os.path.join(root, name, onion)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "hostname"), "w") as f:
            f.write(onion + ".onion\n")
        secret_content = b"== ed25519v1-secret: type0 ==\x00\x00\x00" + sk + os.urandom(32)
        sk_path = os.path.join(d, "hs_ed25519_secret_key")
        with open(sk_path, "wb") as f:
            f.write(secret_content)
        try:
            os.chmod(sk_path, 0o600)
        except Exception:
            pass
        with open(os.path.join(d, "hs_ed25519_public_key"), "wb") as f:
            f.write(b"== ed25519v1-public: type0 ==\x00\x00\x00" + pub)
        return onion
    except Exception:
        return None


def normalise_pattern(p):
    p = p.lower()
    p = p[:32]
    return p + "?" * (32 - len(p))


def clean_name(s):
    """Restrict worker names so they can never inject markup into the admin page."""
    s = re.sub(r"[^A-Za-z0-9._-]", "_", str(s or ""))[:64]
    return s or "anon"


class DB:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS task(
                id INTEGER PRIMARY KEY AUTOINCREMENT, pattern TEXT NOT NULL,
                cursor INTEGER NOT NULL DEFAULT 0, paused INTEGER NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1, created REAL);
            CREATE TABLE IF NOT EXISTS client(
                name TEXT PRIMARY KEY, kind TEXT, first_seen REAL, last_seen REAL,
                tested INTEGER DEFAULT 0, rate REAL DEFAULT 0, chunks INTEGER DEFAULT 0,
                approved INTEGER DEFAULT 0, task_id INTEGER, paused INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS found(
                id INTEGER PRIMARY KEY AUTOINCREMENT, key_hex TEXT, onion TEXT,
                pattern TEXT, task_id INTEGER, client TEXT, counter INTEGER,
                ts REAL, valid INTEGER);
            """
        )
        # migrate columns added by later revisions
        for table, col, decl in (
            ("client", "approved", "INTEGER DEFAULT 0"),
            ("client", "task_id", "INTEGER"),
            ("client", "paused", "INTEGER DEFAULT 0"),
            ("found", "task_id", "INTEGER"),
        ):
            cols = [r[1] for r in self.conn.execute("PRAGMA table_info(%s)" % table)]
            if col not in cols:
                self.conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, decl))
        # migrate a legacy single-pool DB (pattern + cursor lived in meta)
        if self.conn.execute("SELECT COUNT(*) FROM task").fetchone()[0] == 0:
            pat = self.get_meta("pattern")
            if pat:
                cur = int(self.get_meta("cursor", "0") or 0)
                self.conn.execute("INSERT INTO task(pattern,cursor,created) VALUES(?,?,?)",
                                  (pat, cur, time.time()))
        self.conn.commit()

    def get_meta(self, k, default=None):
        cur = self.conn.execute("SELECT v FROM meta WHERE k=?", (k,))
        row = cur.fetchone()
        return row["v"] if row else default

    def set_meta(self, k, v):
        self.conn.execute(
            "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (k, str(v)),
        )

    def ensure_task(self, pattern):
        """Return the id of an existing task with this pattern, or create it.
        An archived (active=0) task with the same pattern is restored."""
        row = self.conn.execute("SELECT id FROM task WHERE pattern=?", (pattern,)).fetchone()
        if row:
            self.conn.execute("UPDATE task SET active=1 WHERE id=?", (row["id"],))
            self.conn.commit()
            return row["id"]
        cur = self.conn.execute("INSERT INTO task(pattern,cursor,created) VALUES(?,?,?)",
                                (pattern, 0, time.time()))
        return cur.lastrowid


class Handler(BaseHTTPRequestHandler):
    server_version = "oniondist/0.2"
    protocol_version = "HTTP/1.1"

    # ---- helpers ----
    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj))

    def _read_json(self):
        n = int(self.headers.get("Content-Length", 0))
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode())
        except Exception:
            return {}

    def log_message(self, fmt, *args):
        pass  # quiet

    # ---- auth ----
    def _auth_token(self):
        h = self.headers.get("Authorization", "") or ""
        if h.startswith("Bearer "):
            return h[7:].strip()
        q = parse_qs(urlparse(self.path).query)
        return (q.get("token", [""])[0] or "").strip()

    def _agent_ok(self, name=None):
        """Valid shared token, OR (token configured and) an already-approved worker."""
        if not self.server.token:
            return True                      # open mode: no --token given
        if self._auth_token() == self.server.token:
            return True
        if name:
            with self.server.db.lock:
                r = self.server.db.conn.execute(
                    "SELECT approved FROM client WHERE name=?", (name,)).fetchone()
            return bool(r and r["approved"])
        return False

    def _admin_ok(self):
        t = self.server.admin_token or self.server.token
        if not t:
            return True
        return self._auth_token() == t

    # ---- routes ----
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/work":
            return self.api_work(parse_qs(u.query))
        if u.path == "/api/status":
            return self._json(self.status_obj("public"))
        if u.path == "/api/admin/status":
            if not self._admin_ok():
                return self._json({"error": "unauthorized"}, 401)
            return self._json(self.status_obj("admin"))
        if u.path.startswith("/api/admin/hs/"):
            if not self._admin_ok():
                return self._json({"error": "unauthorized"}, 401)
            return self.api_admin_hs(u.path[len("/api/admin/hs/"):])
        if u.path in ("/", "/index.html"):
            return self._send(200, DASHBOARD, "text/html; charset=utf-8")
        if u.path == "/admin":
            return self._send(200, ADMIN_PAGE, "text/html; charset=utf-8")
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        data = self._read_json()
        if u.path == "/api/report":
            if not self._agent_ok(data.get("client")):
                return self._json({"error": "unauthorized"}, 401)
            return self.api_report(data)
        if u.path == "/api/found":
            if not self._agent_ok(data.get("client")):
                return self._json({"error": "unauthorized"}, 401)
            return self.api_found(data)
        if u.path == "/api/admin":
            if not self._admin_ok():
                return self._json({"error": "unauthorized"}, 401)
            return self.api_admin(data)
        return self._json({"error": "not found"}, 404)

    # ---- work distribution ----
    def api_work(self, q):
        name = clean_name((q.get("client", ["anon"])[0]) or "anon")
        kind = q.get("kind", ["cpu"])[0]
        if kind not in DEFAULT_CHUNK:
            kind = "cpu"
        now = time.time()
        db = self.server.db
        # open pool (no token configured) auto-approves everyone; otherwise the
        # worker must present the shared token to be auto-approved.
        token_ok = (not self.server.token) or (self._auth_token() == self.server.token)

        with db.lock:
            db.conn.execute(
                "INSERT INTO client(name,kind,first_seen,last_seen) VALUES(?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen, kind=excluded.kind",
                (name, kind, now, now),
            )
            if token_ok:
                db.conn.execute(
                    "UPDATE client SET approved=1 WHERE name=? AND COALESCE(approved,0)=0",
                    (name,))
            row = db.conn.execute("SELECT * FROM client WHERE name=?", (name,)).fetchone()
            tasks = [dict(r) for r in db.conn.execute(
                "SELECT * FROM task WHERE active=1 ORDER BY id")]

            # 1) not approved yet -> visible online, but no work
            if not row["approved"]:
                db.conn.commit()
                return self._json({"pending": True, "client": name})

            # 2) this worker was stopped by the admin
            if row["paused"]:
                db.conn.commit()
                return self._json({"worker_paused": True, "client": name})

            # 3) resolve which task this worker belongs to
            if not tasks:
                db.conn.commit()
                return self._json({"no_tasks": True})

            if len(tasks) == 1:
                task = tasks[0]                     # single pool: everybody goes here
                if row["task_id"] != task["id"]:
                    db.conn.execute("UPDATE client SET task_id=? WHERE name=?",
                                    (task["id"], name))
            else:
                task = next((t for t in tasks if t["id"] == row["task_id"]), None)
                if task is None:
                    db.conn.commit()
                    return self._json({
                        "needs_assignment": True, "client": name,
                        "tasks": [{"id": t["id"], "pattern": t["pattern"]} for t in tasks],
                    })

            # 4) global or per-task pause
            if self.server.paused or task["paused"]:
                db.conn.commit()
                return self._json({"paused": True, "task": task["id"]})

            # 5) hand out a chunk of this task's counter space
            size = self.server.chunk_for(kind)
            start = int(task["cursor"])
            db.conn.execute("UPDATE task SET cursor=? WHERE id=?", (start + size, task["id"]))
            db.conn.commit()

        return self._json({
            "pattern": task["pattern"],
            "start": start,
            "count": size,
            "exp": self.server.expand,
            "task": task["id"],
        })

    def api_report(self, d):
        name = clean_name(d.get("client", "anon"))
        db = self.server.db
        with db.lock:
            db.conn.execute(
                "INSERT INTO client(name,kind,first_seen,last_seen,tested,rate,chunks) "
                "VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen,"
                " tested=excluded.tested, rate=excluded.rate, chunks=excluded.chunks",
                (name, d.get("kind", "cpu"), time.time(), time.time(),
                 int(d.get("tested", 0)), float(d.get("rate", 0)), int(d.get("chunks", 0))),
            )
            db.conn.commit()
        self._json({"ok": True})

    def api_found(self, d):
        key = d.get("key", "")
        pattern = d.get("pattern", "")
        onion = onion_from_key(key) if len(key) == 64 else None
        pref = pattern.replace("?", "").lower()
        valid = 1 if (onion and pref and onion.startswith(pref)) else 0
        if valid:
            saved = save_hs(self.server.keys_root, key, pattern)
            if saved:
                onion = saved
        db = self.server.db
        with db.lock:
            t = db.conn.execute("SELECT id FROM task WHERE pattern=?", (pattern,)).fetchone()
            task_id = t["id"] if t else None
            db.conn.execute(
                "INSERT INTO found(key_hex,onion,pattern,task_id,client,counter,ts,valid) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (key, onion, pattern, task_id, clean_name(d.get("client", "anon")),
                 int(d.get("counter", 0)), time.time(), valid),
            )
            db.conn.commit()
        self._json({"ok": True, "onion": onion, "valid": bool(valid)})

    # ---- admin actions ----
    def api_admin(self, d):
        act = d.get("action", "")
        db = self.server.db

        if act in ("pause", "resume"):
            self.server.paused = (act == "pause")
            return self._json({"ok": True, "paused": self.server.paused})

        if act == "task_create":
            pat = normalise_pattern(str(d.get("pattern", "")).strip())
            bad = [c for c in pat.replace("?", "") if c not in ALPHABET]
            if bad:
                return self._json({"error": "invalid pattern chars: %s" % "".join(bad)})
            with db.lock:
                tid = db.ensure_task(pat)
            return self._json({"ok": True, "task": tid})

        if act == "task_state":
            with db.lock:
                db.conn.execute("UPDATE task SET paused=? WHERE id=?",
                                (1 if d.get("paused") else 0, int(d.get("id", 0))))
                db.conn.commit()
            return self._json({"ok": True})

        if act in ("task_archive", "task_delete"):
            tid = int(d.get("id", 0))
            with db.lock:
                db.conn.execute("UPDATE task SET active=0, paused=0 WHERE id=?", (tid,))
                db.conn.execute("UPDATE client SET task_id=NULL WHERE task_id=?", (tid,))
                db.conn.commit()
            return self._json({"ok": True, "archived": tid})

        if act == "task_restore":
            tid = int(d.get("id", 0))
            with db.lock:
                db.conn.execute("UPDATE task SET active=1 WHERE id=?", (tid,))
                db.conn.commit()
            return self._json({"ok": True, "restored": tid})

        if act == "task_purge":
            tid = int(d.get("id", 0))
            with db.lock:
                db.conn.execute("DELETE FROM task WHERE id=?", (tid,))
                db.conn.execute("UPDATE client SET task_id=NULL WHERE task_id=?", (tid,))
                db.conn.commit()
            return self._json({"ok": True, "purged": tid})

        if act in ("client_approve", "client_revoke"):
            with db.lock:
                db.conn.execute("UPDATE client SET approved=? WHERE name=?",
                                (1 if act == "client_approve" else 0, clean_name(d.get("name", ""))))
                db.conn.commit()
            return self._json({"ok": True})

        if act in ("worker_start", "worker_stop"):
            with db.lock:
                db.conn.execute("UPDATE client SET paused=? WHERE name=?",
                                (0 if act == "worker_start" else 1, clean_name(d.get("name", ""))))
                db.conn.commit()
            return self._json({"ok": True})

        if act == "client_assign":
            tid = d.get("task_id", None)
            if tid is not None:
                tid = int(tid)
            with db.lock:
                db.conn.execute("UPDATE client SET task_id=? WHERE name=?",
                                (tid, clean_name(d.get("name", ""))))
                db.conn.commit()
            return self._json({"ok": True})

        if act == "chunk_config":
            c = self.server.chunk_cfg
            if "mode" in d:
                m = str(d.get("mode", "")).strip().lower()
                if m not in ("auto", "manual"):
                    return self._json({"error": "mode must be auto|manual"})
                c["mode"] = m
            if "base" in d:
                c["base"] = max(1, _as_int(d.get("base"), DEFAULT_CHUNK["cpu"]))
            w = dict(_as_dict(c.get("weights")))
            for k in ("gpu", "cpu"):
                if isinstance(d.get("weights"), dict) and k in d["weights"]:
                    w[k] = max(1, _as_int(d["weights"][k], 1))
            if w:
                c["weights"] = w
            mm = dict(_as_dict(c.get("manual")))
            for k in ("gpu", "cpu"):
                if isinstance(d.get("manual"), dict) and k in d["manual"]:
                    mm[k] = max(1, _as_int(d["manual"][k], DEFAULT_CHUNK.get(k, 1 << 16)))
            if mm:
                c["manual"] = mm
            with db.lock:
                sizes = self.server.recompute_chunks()
            saved = save_config(self.server.config_path, {"chunks": self.server.chunk_cfg})
            return self._json({"ok": True, "chunks": self.server.chunk_cfg,
                               "sizes": sizes, "saved": saved})

        if act == "client_forget":
            with db.lock:
                db.conn.execute("DELETE FROM client WHERE name=?", (clean_name(d.get("name", "")),))
                db.conn.commit()
            return self._json({"ok": True})

        return self._json({"error": "unknown action"})

    # ---- hidden-service certificate download ----
    def find_hs_dir(self, onion):
        root = self.server.keys_root
        if not os.path.isdir(root):
            return None
        for name in os.listdir(root):
            d = os.path.join(root, name, onion)
            if os.path.isdir(d):
                return d
        return None

    def api_admin_hs(self, onion):
        onion = onion.strip().strip("/")
        if not onion or "/" in onion or ".." in onion:
            return self._json({"error": "bad onion"}, 400)
        d = self.find_hs_dir(onion)
        if not d:
            return self._json({"error": "not found"}, 404)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for fn in ("hostname", "hs_ed25519_secret_key", "hs_ed25519_public_key"):
                p = os.path.join(d, fn)
                if os.path.exists(p):
                    z.write(p, os.path.join(onion, fn))
            z.writestr(os.path.join(onion, "README.txt"),
                       "Tor v3 hidden service for " + onion + ".onion\n"
                       "Place this folder inside your torrc HiddenServiceDir:\n"
                       "  HiddenServiceDir /var/lib/tor/" + onion + "\n"
                       "  HiddenServiceVersion 3\n"
                       "  HiddenServicePort 80 127.0.0.1:80\n")
        return self._send(200, buf.getvalue(), "application/zip", {
            "Content-Disposition": 'attachment; filename="%s.zip"' % onion,
        })

    # ---- status ----
    def status_obj(self, scope="public"):
        db = self.server.db
        now = time.time()
        with db.lock:
            clients = [dict(r) for r in db.conn.execute("SELECT * FROM client ORDER BY name")]
            tasks = [dict(r) for r in db.conn.execute(
                "SELECT * FROM task WHERE active=1 ORDER BY id")]
            hits = [dict(r) for r in db.conn.execute(
                "SELECT client, pattern, COUNT(*) AS n FROM found WHERE valid=1 "
                "GROUP BY client, pattern")]
            found = []
            archived = []
            if scope == "admin":
                found = [dict(r) for r in db.conn.execute(
                    "SELECT * FROM found ORDER BY id DESC LIMIT 200")]
                archived = [dict(r) for r in db.conn.execute(
                    "SELECT * FROM task WHERE active=0 ORDER BY id DESC")]

        for c in clients:
            c["online"] = bool(c["last_seen"] and (now - c["last_seen"]) < STALE_SECONDS)
            c["approved"] = bool(c.get("approved"))
            c["paused"] = bool(c.get("paused"))

        task_paused = {t["id"]: bool(t["paused"]) for t in tasks}
        for c in clients:
            work = c["online"] and not c["paused"] and not self.server.paused
            if work and (c["task_id"] is None or task_paused.get(c["task_id"])):
                work = False
            c["working"] = work

        online_clients = [c for c in clients if c["online"]]
        working_clients = [c for c in clients if c["working"]]

        by_client, by_pattern = {}, {}
        for h in hits:
            by_client[h["client"]] = by_client.get(h["client"], 0) + h["n"]
            by_pattern[h["pattern"]] = by_pattern.get(h["pattern"], 0) + h["n"]

        out_tasks = []
        for t in tasks:
            plen = len(t["pattern"].replace("?", ""))
            targets = (32 ** plen) / max(1, self.server.expand)
            rate = sum(c["rate"] for c in working_clients if c["task_id"] == t["id"])
            remaining = max(0.0, targets - t["cursor"])
            out_tasks.append({
                "id": t["id"], "pattern": t["pattern"], "cursor": t["cursor"],
                "paused": bool(t["paused"]), "rate": rate, "targets": targets,
                "remaining": remaining,
                "eta_seconds": (remaining / rate) if rate > 0 else None,
                "found": by_pattern.get(t["pattern"], 0),
                "progress": min(1.0, t["cursor"] / targets) if targets > 0 else 0.0,
                "workers": [c["name"] for c in clients if c["task_id"] == t["id"]],
            })

        task_by_id = {t["id"]: t for t in out_tasks}
        for c in clients:
            c["found"] = by_client.get(c["name"], 0)
            t = task_by_id.get(c["task_id"])
            c["task_pattern"] = t["pattern"] if t else None

        total_rate = sum(c["rate"] for c in working_clients)
        etas = [t["eta_seconds"] for t in out_tasks if t["eta_seconds"] is not None]
        eta = max(etas) if etas else None

        if self.server.paused:
            state = "paused"
        elif working_clients:
            state = "running"
        elif online_clients:
            state = "idle"
        else:
            state = "empty"

        archived_out = []
        for t in archived:
            plen = len(t["pattern"].replace("?", ""))
            targets = (32 ** plen) / max(1, self.server.expand)
            archived_out.append({
                "id": t["id"], "pattern": t["pattern"], "cursor": t["cursor"],
                "created": t.get("created"),
                "targets": targets,
                "found": by_pattern.get(t["pattern"], 0),
            })

        if scope == "public":
            clients_out = [c for c in clients if c["online"]]
        else:
            clients_out = clients

        return {
            "pattern": out_tasks[0]["pattern"] if out_tasks else "",
            "paused": self.server.paused,
            "state": state,
            "online_count": len(online_clients),
            "working_count": len(working_clients),
            "expand": self.server.expand,
            "chunks": {
                "mode": str(self.server.chunk_cfg.get("mode", "auto")),
                "base": self.server.chunk_cfg.get("base"),
                "weights": self.server.chunk_cfg.get("weights"),
                "manual": self.server.chunk_cfg.get("manual"),
                "sizes": self.server.chunk,
            },
            "cursor": out_tasks[0]["cursor"] if out_tasks else 0,
            "total_rate": total_rate,
            "addresses_per_sec": total_rate * self.server.expand,
            "targets": out_tasks[0]["targets"] if out_tasks else 0,
            "eta_seconds": eta,
            "server_time": now,
            "tasks": out_tasks,
            "clients": clients_out,
            "found": found,
            "archived": archived_out,
        }


DASHBOARD = r"""<!doctype html><html><head><meta charset="utf-8">
<title>oniondist</title>
<style>
 body{background:#0d1117;color:#c9d1d9;font:14px/1.5 monospace;margin:0;padding:20px}
 h1{color:#58a6ff;font-size:20px} h2{color:#3fb950;font-size:15px;margin-top:24px}
 table{border-collapse:collapse;width:100%;margin-top:8px}
 th,td{border:1px solid #30363d;padding:6px 10px;text-align:left;vertical-align:middle}
 th{background:#161b22;color:#8b949e} tr:nth-child(even){background:#161b22}
 .big{font-size:20px;color:#f0f6fc} .mut{color:#8b949e}
 .onion{color:#3fb950} a{color:#58a6ff;text-decoration:none}
 .paused{background:#3d1d1d;border:1px solid #f85149;color:#f85149;padding:8px 12px;margin:10px 0;border-radius:6px}
 .live{background:#0f2d1a;border:1px solid #3fb950;color:#3fb950;padding:8px 12px;margin:10px 0;border-radius:6px}
 .warn{background:#3b2f00;border:1px solid #d29922;color:#d29922;padding:8px 12px;margin:10px 0;border-radius:6px}
 .bar{background:#161b22;height:12px;border-radius:6px;overflow:hidden;min-width:120px}
 .fill{background:linear-gradient(90deg,#1f6feb,#3fb950);height:100%}
 .off{color:#f85149} .ond{color:#3fb950}
</style></head><body>
<h1>&#128273; oniondist &mdash; distributed .onion search</h1>
<div class="mut"><a href="/admin">&#9881; admin panel</a></div>
<div id="state"></div>
<div>pool rate: <span class="big" id="rate"></span></div>
<div class="mut" id="eta2"></div>
<div class="mut" id="chunks"></div>
<h2>Tasks</h2><div id="tasks"></div>
<h2>Workers online</h2><div id="clients"></div>
<script>
function fmtEta(s){if(s==null)return "\u221e";s=Math.round(s);
 var d=Math.floor(s/86400);s-=d*86400;var h=Math.floor(s/3600);s-=h*3600;
 var m=Math.floor(s/60);s-=m*60;
 var p=[];if(d)p.push(d+"d");if(h||d)p.push(h+"h");p.push(m+"m");p.push(s+"s");return p.join(" ");}
function esc(s){return (s==null?"":String(s)).replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
function fmtBytes(n){n=Number(n);var u=[["GiB",1<<30],["MiB",1<<20],["KiB",1<<10]];
 for(var i=0;i<u.length;i++){if(n>=u[i][1])return (n/u[i][1]).toFixed(n%u[i][1]?1:0)+" "+u[i][0];}
 return n+" cnt";}
function load(){fetch("/api/status").then(r=>r.json()).then(s=>{
 var st;
 if(s.state==="running")st='<div class="live">\u25b6 WORKING \u2014 '+(s.working_count||0)+' worker(s) searching</div>';
 else if(s.state==="paused")st='<div class="paused">\u23f8 POOL PAUSED by admin \u2014 not searching</div>';
 else if(s.state==="idle")st='<div class="warn">\u23f8 WAITING \u2014 worker(s) online but stopped, no search running</div>';
 else st='<div class="warn">\u23f3 WAITING for workers \u2014 nobody online</div>';
 document.getElementById("state").innerHTML=st;
 document.getElementById("rate").textContent=(s.total_rate/1e6).toFixed(3)+" M keys/s ("+
   (s.addresses_per_sec/1e6).toFixed(1)+" M addr/s)"+(s.total_rate>0?"":" \u2014 idle");
 document.getElementById("eta2").textContent="pool ETA "+fmtEta(s.eta_seconds)+
   "   \u00b7   workers online: "+(s.online_count||0)+", working: "+(s.working_count||0);
 var csz=(s.chunks&&s.chunks.sizes)||{};
 document.getElementById("chunks").textContent="chunks: gpu="+fmtBytes(csz.gpu)+"  cpu="+fmtBytes(csz.cpu)+
   "  (mode "+((s.chunks&&s.chunks.mode)||"auto")+")";
 var t="<table><tr><th>#</th><th>pattern</th><th>progress</th><th>cursor</th><th>found</th><th>workers</th><th>rate (M/s)</th><th>ETA</th><th>state</th></tr>";
 (s.tasks||[]).forEach(x=>{t+="<tr><td>"+x.id+"</td><td class=onion>"+esc(x.pattern.replace(/\?+$/,""))+"</td>"+
   "<td><div class=bar><div class=fill style=width:"+(x.progress*100).toFixed(4)+"%></div></div></td>"+
   "<td>"+x.cursor.toLocaleString()+" / ~"+Math.round(x.targets).toLocaleString()+"</td>"+
   "<td>"+x.found+"</td><td>"+(x.workers.length||0)+"</td><td>"+(x.rate/1e6).toFixed(3)+"</td>"+
   "<td>"+fmtEta(x.eta_seconds)+"</td><td>"+(x.rate>0?"\u25b6 run":"\u23f8 idle")+"</td></tr>";});
 document.getElementById("tasks").innerHTML=t+"</table>";
 var c="<table><tr><th>name</th><th>kind</th><th>task</th><th>state</th><th>tested</th><th>rate (M/s)</th><th>chunks</th><th>found</th><th>last seen</th></tr>";
 (s.clients||[]).forEach(x=>{c+="<tr><td>"+esc(x.name)+"</td><td>"+x.kind+"</td>"+
   "<td>"+(x.task_pattern?esc(x.task_pattern.replace(/\?+$/,"")):"-")+"</td>"+
   "<td>"+(x.working?"\u25b6 working":(x.paused?"\u23f8 stopped":"\u23f8 waiting"))+"</td>"+
   "<td>"+x.tested.toLocaleString()+"</td><td>"+(x.working?(x.rate/1e6).toFixed(3):"0.000")+"</td><td>"+x.chunks+
   "</td><td>"+(x.found||0)+"</td><td class=ond>"+Math.round(s.server_time-x.last_seen)+"s ago</td></tr>";});
 document.getElementById("clients").innerHTML=c+"</table>";
}).catch(e=>{});}
load();setInterval(load,2000);
</script></body></html>
"""


ADMIN_PAGE = r"""<!doctype html><html><head><meta charset="utf-8">
<title>oniondist admin</title>
<style>
 body{background:#0d1117;color:#c9d1d9;font:14px/1.5 monospace;margin:0;padding:20px}
 h1{color:#f0883e;font-size:20px} h2{color:#3fb950;font-size:15px;margin-top:26px}
 table{border-collapse:collapse;width:100%;margin-top:8px}
 th,td{border:1px solid #30363d;padding:6px 10px;text-align:left;vertical-align:middle}
 th{background:#161b22;color:#8b949e} tr:nth-child(even){background:#161b22}
 .big{font-size:18px;color:#f0f6fc} .mut{color:#8b949e}
 .key{color:#d2a8ff;word-break:break-all;max-width:280px;font-size:12px}
 .onion{color:#3fb950} a{color:#58a6ff;text-decoration:none}
 .paused{background:#3d1d1d;border:1px solid #f85149;color:#f85149;padding:8px 12px;margin:10px 0;border-radius:6px}
 .live{background:#0f2d1a;border:1px solid #3fb950;color:#3fb950;padding:8px 12px;margin:10px 0;border-radius:6px}
 button{font:13px monospace;padding:5px 10px;margin:2px 4px 2px 0;border-radius:5px;border:1px solid #30363d;background:#21262d;color:#c9d1d9;cursor:pointer}
 button.go{background:#238636;border-color:#2ea043;color:#fff}
 button.stop{background:#8b1f1f;border-color:#f85149;color:#fff}
 button.warn{background:#6e5100;border-color:#d29922;color:#fff}
 button.danger{background:#21262d;border-color:#f85149;color:#f85149}
 input,select{font:13px monospace;padding:6px;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px}
 input{width:280px}
 .dl{background:#1f6feb;color:#fff;padding:3px 8px;border-radius:4px;text-decoration:none;font-size:12px}
 .bar{background:#161b22;height:12px;border-radius:6px;overflow:hidden;min-width:110px}
 .fill{background:linear-gradient(90deg,#1f6feb,#3fb950);height:100%}
 .tag{font-size:11px;padding:1px 6px;border-radius:8px;border:1px solid #30363d}
 .ok{background:#0f2d1a;color:#3fb950;border-color:#238636}
 .bad{background:#3d1d1d;color:#f85149;border-color:#f85149}
 .pend{background:#3b2f00;color:#d29922;border-color:#6e5100}
 .off{color:#8b949e} .ond{color:#3fb950}
 #loginbox{background:#161b22;border:1px solid #30363d;padding:16px;border-radius:8px;margin:14px 0}
</style></head><body>
<h1>&#9881; oniondist admin</h1>
<div class="mut"><a href="/">&#8592; public dashboard</a></div>

<div id="loginbox">
 <b>Admin token</b> <input id="tok" type="password" placeholder="admin token">
 <button class="go" onclick="saveTok()">Enter</button>
 <div class="mut" style="margin-top:6px">Needed for start/stop, worker approval, tasks and certificate downloads.</div>
</div>

<div id="panel" style="display:none">
 <div id="state"></div>

 <h2>Pool control</h2>
 <button class="go" onclick="post({action:'resume'})">&#9654; Start pool</button>
 <button class="stop" onclick="post({action:'pause'})">&#9208; Stop pool</button>
 <span class="mut">start/stop applies to every task and worker</span>

 <h2>Chunks</h2>
 <div id="chunks"></div>

 <h2>Tasks</h2>
 <div><input id="newpat" placeholder="new pattern, e.g. aistory">
 <button class="go" onclick="addTask()">+ Add task</button>
 <span class="mut">with 1 task all workers go there; with 2+ you assign them manually</span></div>
 <div id="tasks"></div>

 <h2>Archive (hidden tasks)</h2>
 <div id="archive"></div>

 <h2>Workers (all registered)</h2>
 <div id="clients"></div>

 <h2>Found keys &amp; certificates</h2>
 <div id="found"></div>
</div>

<script>
var TOKEN=new URLSearchParams(location.search).get("token")||localStorage.getItem("adminToken")||"";
function saveTok(){TOKEN=document.getElementById("tok").value.trim();
 localStorage.setItem("adminToken",TOKEN);
 if(TOKEN)location.replace(location.pathname+"?token="+encodeURIComponent(TOKEN));
 else load();}
function showLogin(){document.getElementById("loginbox").style.display="block";
 document.getElementById("panel").style.display="none";}
function post(body){return fetch("/api/admin?token="+encodeURIComponent(TOKEN),
 {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})
 .then(r=>r.json()).then(j=>{if(j.error==="unauthorized")showLogin();else load();return j;})
 .catch(e=>{});}
function addTask(){var v=document.getElementById("newpat").value.trim();if(!v)return;
 post({action:"task_create",pattern:v}).then(j=>{if(j.error)alert(j.error);else
  document.getElementById("newpat").value="";});}
function assign(name,el){post({action:"client_assign",name:name,
 task_id:el.value===""?null:parseInt(el.value,10)});}
function fmtBytes(n){n=Number(n);var u=[["GiB",1<<30],["MiB",1<<20],["KiB",1<<10]];
 for(var i=0;i<u.length;i++){if(n>=u[i][1])return (n/u[i][1]).toFixed(n%u[i][1]?1:0)+" "+u[i][0];}
 return n+" cnt";}
function renderChunks(s){
 var c=s.chunks||{},sizes=c.sizes||{},w=c.weights||{},m=c.manual||{};
 var box=document.getElementById("chunks");
 if(!box.dataset.built){
  box.innerHTML=
   'mode <select id="chmode">'+
    '<option value="auto"'+(c.mode!=="manual"?" selected":"")+'>auto (by weights)</option>'+
    '<option value="manual"'+(c.mode==="manual"?" selected":"")+'>manual (exact)</option></select>'+
   ' &nbsp; <span class="mut">auto:</span> base <input id="chbase" style="width:90px" value="'+(c.base!=null?c.base:65536)+'">'+
   ' gpu&#215;<input id="chwg" style="width:60px" value="'+(w.gpu!=null?w.gpu:1024)+'">'+
   ' cpu&#215;<input id="chwc" style="width:60px" value="'+(w.cpu!=null?w.cpu:1)+'">'+
   ' &nbsp; <span class="mut">manual:</span> gpu <input id="chmg" style="width:110px" value="'+(m.gpu!=null?m.gpu:67108864)+'">'+
   ' cpu <input id="chmc" style="width:110px" value="'+(m.cpu!=null?m.cpu:65536)+'">'+
   ' <button class="go" onclick="saveChunks()">Save</button>'+
   '<div id="chunksnow" class="mut" style="margin-top:6px"></div>';
  box.dataset.built="1";
 }
 document.getElementById("chunksnow").innerHTML=
  "now: gpu chunk="+fmtBytes(sizes.gpu)+" &nbsp; cpu chunk="+fmtBytes(sizes.cpu)+
  " &nbsp; (mode "+esc(c.mode||"auto")+")";
}
function saveChunks(){
 var mode=document.getElementById("chmode").value;
 var body={action:"chunk_config",mode:mode};
 if(mode==="auto"){
  body.base=parseInt(document.getElementById("chbase").value,10)||65536;
  body.weights={gpu:parseInt(document.getElementById("chwg").value,10)||1,
                cpu:parseInt(document.getElementById("chwc").value,10)||1};
 }else{
  body.manual={gpu:parseInt(document.getElementById("chmg").value,10)||67108864,
               cpu:parseInt(document.getElementById("chmc").value,10)||65536};
 }
 post(body);
}
function fmtEta(s){if(s==null)return "\u221e";s=Math.round(s);
 var d=Math.floor(s/86400);s-=d*86400;var h=Math.floor(s/3600);s-=h*3600;
 var m=Math.floor(s/60);s-=m*60;
 var p=[];if(d)p.push(d+"d");if(h||d)p.push(h+"h");p.push(m+"m");p.push(s+"s");return p.join(" ");}
function esc(s){return (s==null?"":String(s)).replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
function shortp(p){return esc(String(p).replace(/\?+$/,""));}
function load(){fetch("/api/admin/status?token="+encodeURIComponent(TOKEN)).then(r=>{
 if(r.status==401){showLogin();return null;}return r.json();}).then(s=>{if(!s)return;
 document.getElementById("loginbox").style.display="none";
 document.getElementById("panel").style.display="block";
 document.getElementById("state").innerHTML=s.paused?
   '<div class="paused">\u23f8 POOL PAUSED</div>':'<div class="live">\u25b6 pool running</div>';
 renderChunks(s);

 var t="<table><tr><th>#</th><th>pattern</th><th>progress</th><th>cursor / expected</th><th>found</th><th>workers</th><th>rate (M/s)</th><th>ETA</th><th>state</th><th>control</th></tr>";
 (s.tasks||[]).forEach(x=>{t+="<tr><td>"+x.id+"</td><td class=onion>"+shortp(x.pattern)+"</td>"+
  "<td><div class=bar><div class=fill style=width:"+(x.progress*100).toFixed(4)+"%></div></div></td>"+
  "<td>"+x.cursor.toLocaleString()+" / ~"+Math.round(x.targets).toLocaleString()+"</td>"+
  "<td><b>"+x.found+"</b></td><td>"+(x.workers.length||0)+"</td><td>"+(x.rate/1e6).toFixed(3)+"</td>"+
  "<td>"+fmtEta(x.eta_seconds)+"</td>"+
  "<td>"+(x.paused?'<span class="tag bad">paused</span>':'<span class="tag ok">run</span>')+"</td>"+
   "<td>"+(x.paused?'<button class="go" onclick="post({action:\'task_state\',id:'+x.id+',paused:false})">\u25b6</button>':
    '<button class="stop" onclick="post({action:\'task_state\',id:'+x.id+',paused:true})">\u23f8</button>')+
    '<button class="warn" title="move to archive" onclick="post({action:\'task_archive\',id:'+x.id+'})">\ud83d\udce6 Archive</button></td></tr>';});
 document.getElementById("tasks").innerHTML=t+"</table>";

 var ar=(s.archived||[]);
 if(ar.length){
  var at="<table><tr><th>#</th><th>pattern</th><th>created</th><th>cursor</th><th>found</th><th>actions</th></tr>";
  ar.forEach(function(x){
   at+="<tr><td>"+x.id+"</td><td class=onion>"+shortp(x.pattern)+"</td>"+
    "<td>"+(x.created?new Date(x.created*1000).toLocaleString():"?")+"</td>"+
    "<td>"+x.cursor.toLocaleString()+"</td><td>"+x.found+"</td>"+
    "<td><button class=go onclick=\"post({action:\'task_restore\',id:"+x.id+"})\">\u21ba Restore</button>"+
    "<button class=danger onclick=\"if(confirm(\'Delete task "+x.id+" forever?\'))post({action:\'task_purge\',id:"+x.id+"})\">\u2717 Delete</button></td></tr>";});
  document.getElementById("archive").innerHTML=at+"</table>";
 }else{
  document.getElementById("archive").innerHTML="<div class=mut>(archive is empty) &mdash; archiving a task hides it here instead of deleting it</div>";
 }

 var c="<table><tr><th>name</th><th>kind</th><th>status</th><th>approved</th><th>assigned task</th><th>tested</th><th>rate (M/s)</th><th>chunks</th><th>found</th><th>last seen</th><th>worker control</th><th>&nbsp;</th></tr>";
 (s.clients||[]).forEach(function(x,i){
  var online=x.online;
  var status=x.working?'\u25b6 working':(x.paused?'\u23f8 stopped':(online?'\u23f8 waiting':'\u2014 offline'));
  var statcls=x.working?'ok':(x.paused?'bad':(online?'pend':'off'));
  var appr=x.approved?'<span class="tag ok">approved</span>':'<span class="tag pend">pending</span>';
  var sel='<select onchange="assign(\''+esc(x.name)+'\',this)">';
  sel+='<option value=""'+(x.task_id==null?' selected':'')+'>&mdash; not assigned &mdash;</option>';
  (s.tasks||[]).forEach(function(tk){
   sel+='<option value="'+tk.id+'"'+(x.task_id===tk.id?' selected':'')+'>'+tk.id+': '+shortp(tk.pattern)+'</option>';});
  sel+='</select>';
  var ctl=x.paused
    ? '<button class="go" title="start worker" onclick="post({action:\'worker_start\',name:\''+esc(x.name)+'\'})">\u25b6 Start</button>'
    : '<button class="stop" title="stop worker" onclick="post({action:\'worker_stop\',name:\''+esc(x.name)+'\'})">\u23f8 Stop</button>';
  var apprBtn=x.approved
    ? '<button class="warn" onclick="post({action:\'client_revoke\',name:\''+esc(x.name)+'\'})">Revoke</button>'
    : '<button class="go" onclick="post({action:\'client_approve\',name:\''+esc(x.name)+'\'})">Approve</button>';
  var last=online?('<span class="ond">'+Math.round(s.server_time-x.last_seen)+'s ago</span>'):
                 (x.last_seen?('<span class="off">'+Math.round(s.server_time-x.last_seen)+'s ago</span>'):'never');
  c+="<tr><td>"+esc(x.name)+"</td><td>"+x.kind+"</td>"+
     '<td><span class="tag '+statcls+'">'+status+'</span></td>'+
     "<td>"+appr+"</td><td>"+sel+"</td>"+
     "<td>"+(x.tested||0).toLocaleString()+"</td><td>"+((x.rate||0)/1e6).toFixed(3)+"</td><td>"+(x.chunks||0)+"</td>"+
     "<td><b>"+(x.found||0)+"</b></td><td>"+last+"</td><td>"+ctl+"</td><td>"+apprBtn+"</td></tr>";});
 document.getElementById("clients").innerHTML=c+"</table>";

 var f="<table><tr><th>ok</th><th>onion</th><th>pattern</th><th>found by (worker)</th><th>secret key</th><th>time</th><th>certificate</th></tr>";
 (s.found||[]).forEach(function(x){
  f+="<tr><td>"+(x.valid?"\u2705":"\u26a0\ufe0f")+"</td><td class=onion>"+(x.onion||"?")+".onion</td>"+
     "<td>"+shortp(x.pattern)+"</td><td><b>"+esc(x.client)+"</b></td>"+
     "<td class=key>"+esc(x.key_hex)+"</td><td>"+new Date(x.ts*1000).toLocaleString()+"</td>"+
     "<td>"+(x.onion?'<a class=dl href="/api/admin/hs/'+x.onion+'?token='+encodeURIComponent(TOKEN)+'">\u2b07 zip</a>':'\u2014')+"</td></tr>";});
 document.getElementById("found").innerHTML=f+"</table>";
}).catch(e=>{});}
load();setInterval(load,3000);
</script></body></html>
"""


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, db, expand, chunk_cfg, keys_root="keys",
                 token="", admin_token="", config_path=""):
        super().__init__(addr, Handler)
        self.db = db
        self.expand = expand
        self.keys_root = keys_root
        self.token = token
        self.admin_token = admin_token
        self.paused = False
        self.config_path = config_path
        self.chunk_cfg = dict(chunk_cfg or {})
        self.chunk = dict(DEFAULT_CHUNK)
        self.recompute_chunks()

    def recompute_chunks(self):
        """Resolve the per-kind chunk size.

        * mode 'auto'   -> chunk size = base * weight[kind]   (default mode)
        * mode 'manual' -> exact sizes from chunk_cfg['manual']
        """
        cfg = self.chunk_cfg
        mode = str(cfg.get("mode", "auto")).lower()
        sizes = {}
        if mode == "manual":
            for k, v in _as_dict(cfg.get("manual")).items():
                sizes[k] = max(1, _as_int(v, DEFAULT_CHUNK.get(k, 1 << 16)))
        else:
            base = max(1, _as_int(cfg.get("base"), DEFAULT_CHUNK["cpu"]))
            weights = _as_dict(cfg.get("weights"))
            for k in DEFAULT_CHUNK:
                sizes[k] = max(1, base * max(1, _as_int(weights.get(k), 1)))
        for k, v in DEFAULT_CHUNK.items():
            sizes.setdefault(k, v)
        self.chunk = sizes
        return sizes

    def chunk_for(self, kind):
        return self.chunk.get(kind, DEFAULT_CHUNK["cpu"])


def main():
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", default=CONFIG_DEFAULT_PATH)
    pre_args, _ = pre.parse_known_args()
    cfg = load_config(pre_args.config)
    cchunk = _as_dict(cfg.get("chunks"))

    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=pre_args.config,
                    help="path to a JSON config file (default: config.json next to server.py)")
    ap.add_argument("--pattern", default="",
                    help="seed task, e.g. aistorys (ignored if that task already exists)")
    ap.add_argument("--host", default=cfg.get("host", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=_as_int(cfg.get("port"), 8080))
    ap.add_argument("--db", default=cfg.get("db", "oniondist.db"))
    ap.add_argument("--keys", default=cfg.get("keys", "keys"),
                    help="root dir for generated hidden-service folders")
    ap.add_argument("--expand", type=int, default=_as_int(cfg.get("expand"), 10))
    ap.add_argument("--chunk-mode", choices=["auto", "manual"],
                    default=str(cchunk.get("mode", "auto")).lower(),
                    help="auto = size by weights (default), manual = exact sizes")
    ap.add_argument("--chunk-base", type=int, default=_as_int(cchunk.get("base"), DEFAULT_CHUNK["cpu"]),
                    help="auto mode: base chunk size in counters; size = base * weight")
    ap.add_argument("--gpu-weight", type=int, default=_as_int(_as_dict(cchunk.get("weights")).get("gpu"), 1024),
                    help="auto mode: relative weight for gpu workers")
    ap.add_argument("--cpu-weight", type=int, default=_as_int(_as_dict(cchunk.get("weights")).get("cpu"), 1),
                    help="auto mode: relative weight for cpu workers")
    ap.add_argument("--gpu-chunk", type=int, default=_as_int(_as_dict(cchunk.get("manual")).get("gpu"), DEFAULT_CHUNK["gpu"]),
                    help="manual mode: exact gpu chunk size")
    ap.add_argument("--cpu-chunk", type=int, default=_as_int(_as_dict(cchunk.get("manual")).get("cpu"), DEFAULT_CHUNK["cpu"]),
                    help="manual mode: exact cpu chunk size")
    ap.add_argument("--token", default=cfg.get("token", ""),
                    help="shared secret: workers presenting it are auto-approved")
    ap.add_argument("--admin-token", default=cfg.get("admin_token", cfg.get("admin-token", "")),
                    help="secret for /admin and /api/admin (defaults to --token)")
    args = ap.parse_args()

    db = DB(args.db)

    if args.pattern:
        pattern = normalise_pattern(args.pattern)
        bad = [c for c in pattern.replace("?", "") if c not in ALPHABET]
        if bad:
            print("Invalid pattern chars:", bad)
            return 1
        with db.lock:
            db.ensure_task(pattern)

    with db.lock:
        n_tasks = db.conn.execute("SELECT COUNT(*) FROM task WHERE active=1").fetchone()[0]

    chunk_conf = {
        "mode": args.chunk_mode,
        "base": args.chunk_base,
        "weights": {"gpu": args.gpu_weight, "cpu": args.cpu_weight},
        "manual": {"gpu": args.gpu_chunk, "cpu": args.cpu_chunk},
    }
    srv = Server((args.host, args.port), db, args.expand, chunk_conf, keys_root=args.keys,
                 token=args.token, admin_token=args.admin_token, config_path=args.config)
    source = args.config if os.path.exists(args.config) else "(no config file; defaults + CLI)"
    print(f"oniondist coordinator on http://{args.host}:{args.port}  expand={args.expand}")
    print(f"  config: {source}")
    print(f"  tasks: {n_tasks}   db={args.db}")
    print(f"  chunks: mode={args.chunk_mode}  sizes={srv.chunk}"
          + (f"  (base={args.chunk_base}, weights gpu={args.gpu_weight} cpu={args.cpu_weight})"
             if args.chunk_mode == "auto" else ""))
    if args.token:
        print("  agent token: present -> workers using it are auto-approved")
        print("  admin token: %s" % ("set" if args.admin_token else "same as --token"))
    else:
        print("  WARNING: no --token set: every worker is auto-approved (open pool)")
    if n_tasks == 0:
        print("  no tasks yet -> add one in the admin panel")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

