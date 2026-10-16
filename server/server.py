#!/usr/bin/env python3
"""
oniondist coordinator -- a tiny Hashtopolis-style server for distributed
.onion vanity address search.

It hands out contiguous counter ranges to agents (GPU or CPU), collects their
progress and any hits, and serves a live dashboard.

    python3 server.py --pattern aistorys --port 8080

Endpoints:
    GET  /api/work?client=NAME&kind=gpu|cpu&batch=N   -> {pattern,start,count,exp}
    POST /api/report  {client,kind,tested,rate,chunks}
    POST /api/found   {client,key,pattern,counter}
    GET  /api/status                                  -> JSON snapshot
    GET  /                                            -> HTML dashboard

No third-party dependencies (stdlib only). Ed25519 .onion rendering uses PyNaCl
if it is installed; otherwise hits are still stored, just without the onion.
"""
import argparse
import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

try:
    import nacl.bindings  # optional
except Exception:
    nacl = None

ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
DEFAULT_CHUNK = {"gpu": 1 << 26, "cpu": 1 << 16}
STALE_SECONDS = 90


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


class DB:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS client(
                name TEXT PRIMARY KEY, kind TEXT, first_seen REAL, last_seen REAL,
                tested INTEGER DEFAULT 0, rate REAL DEFAULT 0, chunks INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS found(
                id INTEGER PRIMARY KEY AUTOINCREMENT, key_hex TEXT, onion TEXT,
                pattern TEXT, client TEXT, counter INTEGER, ts REAL, valid INTEGER);
            """
        )
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

    def get_cursor(self):
        return int(self.get_meta("cursor", "0"))

    def take_chunk(self, size):
        with self.lock:
            start = self.get_cursor()
            self.set_meta("cursor", start + size)
            self.conn.commit()
            return start


class Handler(BaseHTTPRequestHandler):
    server_version = "oniondist/0.1"
    protocol_version = "HTTP/1.1"

    # ---- helpers ----
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
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

    # ---- routes ----
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/work":
            return self.api_work(parse_qs(u.query))
        if u.path == "/api/status":
            return self._json(self.status_obj())
        if u.path in ("/", "/index.html"):
            return self._send(200, DASHBOARD, "text/html; charset=utf-8")
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        data = self._read_json()
        if u.path == "/api/report":
            return self.api_report(data)
        if u.path == "/api/found":
            return self.api_found(data)
        return self._json({"error": "not found"}, 404)

    def api_work(self, q):
        name = (q.get("client", ["anon"])[0]) or "anon"
        kind = q.get("kind", ["cpu"])[0]
        if kind not in DEFAULT_CHUNK:
            kind = "cpu"
        size = self.server.chunk_for(kind)
        db = self.server.db
        now = time.time()
        with db.lock:
            db.conn.execute(
                "INSERT INTO client(name,kind,first_seen,last_seen) VALUES(?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen, kind=excluded.kind",
                (name, kind, now, now),
            )
            db.conn.commit()
        start = db.take_chunk(size)
        self._json({
            "pattern": self.server.pattern,
            "start": start,
            "count": size,
            "exp": self.server.expand,
        })

    def api_report(self, d):
        name = d.get("client", "anon")
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
        pattern = d.get("pattern", self.server.pattern)
        onion = onion_from_key(key) if len(key) == 64 else None
        pref = pattern.replace("?", "").lower()
        valid = 1 if (onion and onion.startswith(pref)) else 0
        if valid:
            saved = save_hs(self.server.keys_root, key, pattern)
            if saved:
                onion = saved
        db = self.server.db
        with db.lock:
            db.conn.execute(
                "INSERT INTO found(key_hex,onion,pattern,client,counter,ts,valid) VALUES(?,?,?,?,?,?,?)",
                (key, onion, pattern, d.get("client", "anon"),
                 int(d.get("counter", 0)), time.time(), valid),
            )
            db.conn.commit()
        self._json({"ok": True, "onion": onion, "valid": bool(valid)})

    def status_obj(self):
        db = self.server.db
        now = time.time()
        with db.lock:
            clients = [dict(r) for r in db.conn.execute("SELECT * FROM client ORDER BY name")]
            found = [dict(r) for r in db.conn.execute("SELECT * FROM found ORDER BY id DESC LIMIT 100")]
            cursor = db.get_cursor()
        total_rate = sum(c["rate"] for c in clients if now - (c["last_seen"] or 0) < STALE_SECONDS)
        plen = len(self.server.pattern.replace("?", ""))
        targets = (32 ** plen) / max(1, self.server.expand)
        eta = targets / total_rate if total_rate > 0 else None
        return {
            "pattern": self.server.pattern,
            "cursor": cursor,
            "expand": self.server.expand,
            "total_rate": total_rate,          # keys/s
            "addresses_per_sec": total_rate * self.server.expand,
            "clients": clients,
            "found": found,
            "targets": targets,
            "eta_seconds": eta,
            "server_time": now,
        }


DASHBOARD = """<!doctype html><html><head><meta charset="utf-8">
<title>oniondist</title>
<style>
 body{background:#0d1117;color:#c9d1d9;font:14px/1.5 monospace;margin:0;padding:20px}
 h1{color:#58a6ff;font-size:20px} h2{color:#3fb950;font-size:15px;margin-top:24px}
 table{border-collapse:collapse;width:100%;margin-top:8px}
 th,td{border:1px solid #30363d;padding:6px 10px;text-align:left}
 th{background:#161b22;color:#8b949e} tr:nth-child(even){background:#161b22}
 .big{font-size:22px;color:#f0f6fc} .mut{color:#8b949e}
 .key{color:#d2a8ff;word-break:break-all} .onion{color:#3fb950}
</style></head><body>
<h1>&#128273; oniondist &mdash; distributed .onion search</h1>
<div>target: <span class="big" id="pat"></span></div>
<div>pool rate: <span class="big" id="rate"></span></div>
<div>ETA (mean): <span class="big" id="eta"></span></div>
<div class="mut" id="eta2"></div>
<h2>Agents</h2><div id="clients"></div>
<h2>Found keys</h2><div id="found"></div>
<script>
function fmtEta(s){if(s==null)return "\\u221e";s=Math.round(s);
 var d=Math.floor(s/86400);s-=d*86400;var h=Math.floor(s/3600);s-=h*3600;
 var m=Math.floor(s/60);s-=m*60;
 var p=[];if(d)p.push(d+"d");if(h||d)p.push(h+"h");p.push(m+"m");p.push(s+"s");return p.join(" ");}
function load(){fetch("/api/status").then(r=>r.json()).then(s=>{
 document.getElementById("pat").textContent=s.pattern.replace(/\\?+$/,"");
 document.getElementById("rate").textContent=(s.total_rate/1e6).toFixed(3)+" M keys/s ("+
   (s.addresses_per_sec/1e6).toFixed(1)+" M addr/s)";
 document.getElementById("eta").textContent=fmtEta(s.eta_seconds);
 document.getElementById("eta2").textContent="expected "+Math.round(s.targets).toLocaleString()+" keys to try";
 var c="<table><tr><th>name</th><th>kind</th><th>tested</th><th>rate (M/s)</th><th>chunks</th><th>last seen</th></tr>";
 s.clients.forEach(x=>{c+="<tr><td>"+x.name+"</td><td>"+x.kind+"</td><td>"+
   x.tested.toLocaleString()+"</td><td>"+(x.rate/1e6).toFixed(3)+"</td><td>"+x.chunks+
   "</td><td>"+Math.round(Date.now()/1000-x.last_seen)+"s ago</td></tr>";});
 document.getElementById("clients").innerHTML=c+"</table>";
 var f="<table><tr><th>ok</th><th>onion</th><th>secret key</th><th>client</th><th>time</th></tr>";
 s.found.forEach(x=>{f+="<tr><td>"+(x.valid?"\\u2705":"\\u26a0\\ufe0f")+"</td><td class=onion>"+(x.onion||"?")+".onion</td><td class=key>"+
   x.key_hex+"</td><td>"+x.client+"</td><td>"+new Date(x.ts*1000).toLocaleTimeString()+"</td></tr>";});
 document.getElementById("found").innerHTML=f+"</table>";
}).catch(e=>{});}
load();setInterval(load,2000);
</script></body></html>
"""


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, db, pattern, expand, chunk, keys_root="keys"):
        super().__init__(addr, Handler)
        self.db = db
        self.pattern = pattern
        self.expand = expand
        self.keys_root = keys_root
        self.chunk = dict(DEFAULT_CHUNK)
        self.chunk.update(chunk)

    def chunk_for(self, kind):
        return self.chunk.get(kind, DEFAULT_CHUNK["cpu"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pattern", required=True, help="target prefix, e.g. aistorys")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--db", default="oniondist.db")
    ap.add_argument("--keys", default="keys", help="root dir for generated hidden-service folders")
    ap.add_argument("--expand", type=int, default=10)
    ap.add_argument("--gpu-chunk", type=int, default=DEFAULT_CHUNK["gpu"])
    ap.add_argument("--cpu-chunk", type=int, default=DEFAULT_CHUNK["cpu"])
    args = ap.parse_args()

    pattern = normalise_pattern(args.pattern)
    bad = [c for c in pattern.replace("?", "") if c not in ALPHABET]
    if bad:
        print("Invalid pattern chars:", bad)
        return 1

    db = DB(args.db)
    db.conn.execute("INSERT INTO meta(k,v) VALUES('pattern',?) "
                    "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (pattern,))
    db.conn.commit()

    srv = Server((args.host, args.port), db, pattern, args.expand,
                 {"gpu": args.gpu_chunk, "cpu": args.cpu_chunk}, keys_root=args.keys)
    print(f"oniondist coordinator on http://{args.host}:{args.port}  pattern={pattern}  expand={args.expand}")
    print(f"  gpu chunk={args.gpu_chunk}  cpu chunk={args.cpu_chunk}  db={args.db}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
