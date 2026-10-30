#!/usr/bin/env bash
#
# smoke.sh - basic end-to-end tests for canyon (TCP, UDP, SOCKS5)
#
set -euo pipefail

cd "$(dirname "$0")/.."

make >/dev/null

TMP="$(mktemp -d)"
SERVER_PIDS=""
cleanup() {
    [ -n "$SERVER_PIDS" ] && kill $SERVER_PIDS 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT

PORT_TCP=19191
PORT_UDP=19192
PORT_SOCKS=19193
PORT_WS=19194
PORT_TLS=19196
PORT_WSS=19197
PORT_HTTP=19198

# --- TCP echo server -------------------------------------------------------
python3 - "$PORT_TCP" "$TMP" <<'PYEOF' &
import os, socket, sys
port, out = int(sys.argv[1]), sys.argv[2]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(5)
open(os.path.join(out, "tcp.ready"), "w").close()
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    with c:
        while True:
            d = c.recv(65536)
            if not d:
                break
            c.sendall(b"echo:" + d)
PYEOF
SERVER_PIDS="$SERVER_PIDS $!"

# --- UDP echo server -------------------------------------------------------
python3 - "$PORT_UDP" "$TMP" <<'PYEOF' &
import os, socket, sys
port, out = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
open(os.path.join(out, "udp.ready"), "w").close()
while True:
    d, a = s.recvfrom(65536)
    s.sendto(b"echo:" + d, a)
PYEOF
SERVER_PIDS="$SERVER_PIDS $!"

# --- SOCKS5 (no-auth) proxy -------------------------------------------------
python3 - "$PORT_SOCKS" <<'PYEOF' &
import socket, struct, sys, threading

def pump(src, dst):
    try:
        while True:
            d = src.recv(65536)
            if not d:
                dst.shutdown(socket.SHUT_WR)
                break
            dst.sendall(d)
    except OSError:
        pass

port = int(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(5)
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    try:
        hdr = c.recv(2)
        if len(hdr) < 2:
            c.close(); continue
        n = hdr[1]
        if n:
            c.recv(n)
        c.sendall(b"\x05\x00")
        hdr = c.recv(4)
        if len(hdr) < 4:
            c.close(); continue
        _ver, _cmd, _rsv, atyp = hdr
        if atyp == 1:
            addr = socket.inet_ntoa(c.recv(4))
        elif atyp == 3:
            ln = c.recv(1)[0]
            addr = c.recv(ln).decode()
        else:
            addr = socket.inet_ntop(socket.AF_INET6, c.recv(16))
        port2 = struct.unpack("!H", c.recv(2))[0]
        up = socket.create_connection((addr, port2))
        c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
        threading.Thread(target=pump, args=(c, up), daemon=True).start()
        threading.Thread(target=pump, args=(up, c), daemon=True).start()
    except Exception:
        c.close()
PYEOF
SERVER_PIDS="$SERVER_PIDS $!"

# --- WebSocket echo server (stdlib only) -----------------------------------
python3 - "$PORT_WS" "$TMP" <<'PYEOF' &
import base64, hashlib, os, socket, struct, sys, threading

def read_exact(c, n):
    buf = b""
    while len(buf) < n:
        d = c.recv(n - len(buf))
        if not d:
            return None
        buf += d
    return buf

def client(c):
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = c.recv(4096)
            if not chunk:
                c.close()
                return
            data += chunk
        headers = {}
        for line in data.decode(errors="replace").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        key = headers.get("sec-websocket-key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        c.sendall(("HTTP/1.1 101 Switching Protocols\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode())
        while True:
            h = read_exact(c, 2)
            if not h:
                break
            op = h[0] & 0x0f
            masked = bool(h[1] & 0x80)
            ln = h[1] & 0x7f
            if ln == 126:
                ln = struct.unpack("!H", read_exact(c, 2))[0]
            elif ln == 127:
                ln = struct.unpack("!Q", read_exact(c, 8))[0]
            mask = read_exact(c, 4) if masked else None
            payload = read_exact(c, ln)
            if payload is None:
                break
            if mask:
                payload = bytes(x ^ mask[i & 3] for i, x in enumerate(payload))
            if op == 0x9:                       # ping -> pong
                frame = bytes([0x8A]) + bytes([0x80 | len(payload)]) + b"\x00\x00\x00\x00" + payload
                c.sendall(frame)
                continue
            if op == 0x8:                       # close -> close
                c.sendall(bytes([0x88, 0x02]) + struct.pack("!H", 1000))
                break
            if op == 0x1 or op == 0x2:          # echo data frame
                if len(payload) <= 125:
                    frame = bytes([0x82, len(payload)])
                elif len(payload) <= 0xffff:
                    frame = bytes([0x82, 126]) + struct.pack("!H", len(payload))
                else:
                    frame = bytes([0x82, 127]) + struct.pack("!Q", len(payload))
                frame += payload
                c.sendall(frame)
    except Exception:
        pass
    c.close()

port, out = int(sys.argv[1]), sys.argv[2]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(5)
open(os.path.join(out, "ws.ready"), "w").close()
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    threading.Thread(target=client, args=(c,), daemon=True).start()
PYEOF
SERVER_PIDS="$SERVER_PIDS $!"

for _ in $(seq 1 50); do
    [ -f "$TMP/tcp.ready" ] && [ -f "$TMP/udp.ready" ] && [ -f "$TMP/ws.ready" ] && break
    sleep 0.1
done
./canyon -H 127.0.0.1 -p "$PORT_TCP" -c 64-256 -n 10 -t 5 -d 50000 -o "$TMP/logs_tcp" -v >/dev/null 2>&1
test -s "$TMP"/logs_tcp/stream-*.log
grep -q '"type":"connect"' "$TMP"/logs_tcp/events-*.log
echo "OK: TCP direct"

# --- TCP via SOCKS5 ---------------------------------------------------------
./canyon -H 127.0.0.1 -p "$PORT_TCP" -x 127.0.0.1:$PORT_SOCKS -c 64-256 -n 5 -t 5 -d 50000 -o "$TMP/logs_socks" -v >/dev/null 2>&1
test -s "$TMP"/logs_socks/stream-*.log
echo "OK: TCP via SOCKS5"

# --- UDP --------------------------------------------------------------------
./canyon -u -H 127.0.0.1 -p "$PORT_UDP" -c 64-256 -n 10 -t 5 -d 50000 -o "$TMP/logs_udp" -v >/dev/null 2>&1
test -n "$(ls "$TMP"/logs_udp/datagrams-*/d_*.bin 2>/dev/null || true)"
echo "OK: UDP"

# --- UDP + SOCKS5 must be rejected ------------------------------------------
if ./canyon -u -p 1 -x 127.0.0.1:$PORT_SOCKS -o "$TMP/logs_bad" >/dev/null 2>&1; then
    echo "FAIL: UDP over SOCKS5 should be rejected"
    exit 1
fi
echo "OK: UDP+SOCKS5 rejected"

# --- WebSocket echo ----------------------------------------------------------
./canyon -H 127.0.0.1 -p "$PORT_WS" -w --ws-path /echo -c 64-256 -n 5 -t 5 -d 50000 -o "$TMP/logs_ws" -v >/dev/null 2>&1
test -s "$TMP"/logs_ws/stream-*.log
grep -q '"type":"ws_frame"' "$TMP"/logs_ws/events-*.log
grep -q '"type":"connect".*websocket' "$TMP"/logs_ws/events-*.log
echo "OK: WebSocket echo"

# --- WebSocket + UDP must be rejected ----------------------------------------
if ./canyon -u -w -p 1 -o "$TMP/logs_bad2" >/dev/null 2>&1; then
    echo "FAIL: WebSocket over UDP should be rejected"
    exit 1
fi
echo "OK: WebSocket+UDP rejected"

# --- Continuous streaming (no -t / no -n, stopped by signal) ------------------
./canyon -H 127.0.0.1 -p "$PORT_TCP" -c 64 -d 100000 -o "$TMP/logs_cont" -q &
CPID=$!
sleep 2.5
kill -TERM "$CPID" 2>/dev/null
wait "$CPID" 2>/dev/null || true
test -s "$TMP"/logs_cont/events-*.log
grep -q '"end"' "$TMP"/logs_cont/events-*.log
echo "OK: continuous stream until signal"

# --- Reconnect on dropped connection -----------------------------------------
python3 - "$TMP" <<'PYEOF' &
import os, socket, sys
out = sys.argv[1]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 19195))
s.listen(5)
open(os.path.join(out, "drop.ready"), "w").close()
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    with c:
        d = c.recv(65536)
        if d:
            c.sendall(b"drop:" + d)
PYEOF
DROP_PID=$!
for _ in $(seq 1 50); do
    [ -f "$TMP/drop.ready" ] && break
    sleep 0.1
done
./canyon -H 127.0.0.1 -p 19195 -c 64 -d 50000 -t 6 -D 200000 -o "$TMP/logs_recon" -q
grep -c '"type":"connect"' "$TMP"/logs_recon/events-*.log | grep -qE '[2-9]'
kill $DROP_PID 2>/dev/null || true
echo "OK: reconnect after connection drop"

# --- TLS servers (self-signed cert) ------------------------------------------
openssl req -x509 -newkey rsa:2048 -keyout "$TMP/key.pem" -out "$TMP/cert.pem" \
    -days 2 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1

# HTTPS echo server (TLS-wrapped TCP echo)
python3 - "$PORT_TLS" "$TMP" <<'PYEOF' &
import os, socket, ssl, sys
port, out = int(sys.argv[1]), sys.argv[2]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.path.join(out, "cert.pem"), os.path.join(out, "key.pem"))
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(5)
open(os.path.join(out, "tls.ready"), "w").close()
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    try:
        c = ctx.wrap_socket(c, server_side=True)
        with c:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                c.sendall(b"echo:" + d)
    except (ssl.SSLError, OSError):
        pass
PYEOF
SERVER_PIDS="$SERVER_PIDS $!"

# WSS echo server (WebSocket echo over TLS)
python3 - "$PORT_WSS" "$TMP" <<'PYEOF' &
import base64, hashlib, os, socket, ssl, struct, sys, threading

def read_exact(c, n):
    buf = b""
    while len(buf) < n:
        d = c.recv(n - len(buf))
        if not d:
            return None
        buf += d
    return buf

def client(c):
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = c.recv(4096)
            if not chunk:
                c.close()
                return
            data += chunk
        headers = {}
        for line in data.decode(errors="replace").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        key = headers.get("sec-websocket-key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        c.sendall(("HTTP/1.1 101 Switching Protocols\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode())
        while True:
            h = read_exact(c, 2)
            if not h:
                break
            op = h[0] & 0x0f
            masked = bool(h[1] & 0x80)
            ln = h[1] & 0x7f
            if ln == 126:
                ln = struct.unpack("!H", read_exact(c, 2))[0]
            elif ln == 127:
                ln = struct.unpack("!Q", read_exact(c, 8))[0]
            mask = read_exact(c, 4) if masked else None
            payload = read_exact(c, ln)
            if payload is None:
                break
            if mask:
                payload = bytes(x ^ mask[i & 3] for i, x in enumerate(payload))
            if op == 0x8:
                c.sendall(bytes([0x88, 0x02]) + struct.pack("!H", 1000))
                break
            if op == 0x1 or op == 0x2:
                if len(payload) <= 125:
                    frame = bytes([0x82, len(payload)])
                elif len(payload) <= 0xffff:
                    frame = bytes([0x82, 126]) + struct.pack("!H", len(payload))
                else:
                    frame = bytes([0x82, 127]) + struct.pack("!Q", len(payload))
                frame += payload
                c.sendall(frame)
    except Exception:
        pass
    c.close()

port, out = int(sys.argv[1]), sys.argv[2]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.path.join(out, "cert.pem"), os.path.join(out, "key.pem"))
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(5)
open(os.path.join(out, "wss.ready"), "w").close()
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    try:
        c = ctx.wrap_socket(c, server_side=True)
    except ssl.SSLError:
        c.close()
        continue
    threading.Thread(target=client, args=(c,), daemon=True).start()
PYEOF
SERVER_PIDS="$SERVER_PIDS $!"

# HTTP server that echoes back the Host header and request path
python3 - "$PORT_HTTP" <<'PYEOF' &
import http.server, socket, sys

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("host:%s path:%s" % (self.headers.get("Host", "?"), self.path)).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

port = int(sys.argv[1])
srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
srv.serve_forever()
PYEOF
SERVER_PIDS="$SERVER_PIDS $!"

for _ in $(seq 1 50); do
    [ -f "$TMP/tls.ready" ] && [ -f "$TMP/wss.ready" ] && break
    sleep 0.1
done

# --- HTTPS echo (TLS, no verify) ---------------------------------------------
./canyon -H 127.0.0.1 -p "$PORT_TLS" -s --http --path /api --sni localhost \
    -c 64-256 -n 5 -t 5 -d 50000 -o "$TMP/logs_https" -v >/dev/null 2>&1
test -s "$TMP"/logs_https/stream-*.log
grep -q '"type":"tls_error"' "$TMP"/logs_https/events-*.log && exit 1
grep -q '"type":"connect".*tls' "$TMP"/logs_https/events-*.log
echo "OK: HTTPS echo (--ssl --http --path --sni)"

# --- HTTPS with verification against our CA -----------------------------------
./canyon -H 127.0.0.1 -p "$PORT_TLS" -s --ssl-ca "$TMP/cert.pem" \
    --sni localhost --http --path /api -c 64-256 -n 5 -t 5 -d 50000 \
    -o "$TMP/logs_https_v" -v >/dev/null 2>&1
test -s "$TMP"/logs_https_v/stream-*.log
grep -q '"type":"tls_error"' "$TMP"/logs_https_v/events-*.log && exit 1
echo "OK: HTTPS with --ssl-ca verification"

# --- HTTPS verification must fail against an untrusted cert -------------------
./canyon -H 127.0.0.1 -p "$PORT_TLS" -s --ssl-verify --sni localhost \
    -c 64-256 -n 2 -t 3 -d 50000 -o "$TMP/logs_https_bad" -q &
BPID=$!
sleep 1.5
kill -TERM "$BPID" 2>/dev/null
wait "$BPID" 2>/dev/null || true
grep -q '"type":"tls_error"' "$TMP"/logs_https_bad/events-*.log
test ! -s "$TMP"/logs_https_bad/stream-*.log
echo "OK: untrusted TLS rejected"

# --- WSS echo ------------------------------------------------------------------
./canyon -H 127.0.0.1 -p "$PORT_WSS" -s -w --path /ws --sni localhost \
    -c 64-256 -n 5 -t 5 -d 50000 -o "$TMP/logs_wss" -v >/dev/null 2>&1
test -s "$TMP"/logs_wss/stream-*.log
grep -q '"type":"ws_frame"' "$TMP"/logs_wss/events-*.log
grep -q '"type":"connect".*wss' "$TMP"/logs_wss/events-*.log
echo "OK: WSS echo"

# --- HTTP hostname + path (Host header from --sni) -----------------------------
./canyon -H 127.0.0.1 -p "$PORT_HTTP" --http --path /api --sni localhost \
    -c 64-256 -n 5 -t 5 -d 50000 -o "$TMP/logs_host" -v >/dev/null 2>&1
test -s "$TMP"/logs_host/stream-*.log
grep -q "host:localhost:$PORT_HTTP path:/api" "$TMP"/logs_host/stream-*.log
echo "OK: HTTP path endpoint + hostname in Host header"

# --- TUI: falls back to log mode when not attached to a terminal --------------
./canyon -T -H 127.0.0.1 -p "$PORT_TCP" -c 64-256 -n 5 -t 5 -d 50000 \
    -o "$TMP/logs_tui_pipe" >/dev/null 2>"$TMP/tui_pipe.err"
grep -qi "tui" "$TMP/tui_pipe.err"
test -s "$TMP"/logs_tui_pipe/stream-*.log
echo "OK: TUI falls back to log mode without a terminal"

# --- TUI: pty run shows received data, honours keys and quits on 'q' ----------
export TERM="${TERM:-xterm}"
if command -v script >/dev/null 2>&1 &&
   script --version 2>/dev/null | grep -qi util-linux &&
   infocmp "$TERM" >/dev/null 2>&1; then
    t0=$SECONDS
    ( sleep 1.5; printf 'x'; sleep 0.5; printf 'p'; sleep 0.5; printf 'q' ) |
        script -qec "./canyon -T -H 127.0.0.1 -p $PORT_TCP -c 64-256 -d 50000 -t 20 -o $TMP/logs_tui_pty" \
        "$TMP/tty.out" >/dev/null 2>&1
    t1=$SECONDS
    [ $((t1 - t0)) -lt 12 ]            # 'q' must stop it well before -t 20
    grep -q "target 127.0.0.1:$PORT_TCP" "$TMP/tty.out"   # title bar
    grep -q "received |" "$TMP/tty.out"                   # data pane
    grep -q "echo:" "$TMP/tty.out"                        # received data on screen
    grep -q "events" "$TMP/tty.out"                       # events pane
    grep -q "PAUSED" "$TMP/tty.out"                       # 'p' key
    grep -q '"type":"end"' "$TMP"/logs_tui_pty/events-*.log
    echo "OK: TUI shows received data on a pty, honours keys and quits on 'q'"
else
    echo "SKIP: TUI pty test (needs util-linux 'script' and terminfo for TERM=$TERM)"
fi

kill $SERVER_PIDS 2>/dev/null || true
SERVER_PIDS=""

echo "All smoke tests passed."