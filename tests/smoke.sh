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

for _ in $(seq 1 50); do
    [ -f "$TMP/tcp.ready" ] && [ -f "$TMP/udp.ready" ] && break
    sleep 0.1
done

# --- TCP direct -------------------------------------------------------------
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

kill $SERVER_PIDS 2>/dev/null || true
SERVER_PIDS=""

echo "All smoke tests passed."