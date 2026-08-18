# canyon

`canyon` is a lightweight TCP/UDP socket flooding and fuzzing tool written in C.
It plugs a random byte stream directly into a socket and logs everything that
comes back. It is designed for penetration testing and service hardening:
feeding a target with unpredictable data (`/dev/random` or any file) and
recording the responses, so you can spot crashes, leaks, protocol aborts or
unexpected behaviour.

It supports both **TCP** and **UDP**, can route TCP traffic through a
**SOCKS5 proxy** (with optional username/password authentication), and persists
**every byte received** on the socket to disk.

> **Disclaimer:** Use canyon only against systems you own or have explicit
> written authorization to test. You are responsible for what you do with it.

## Features

- TCP and UDP flooding from `/dev/urandom` (default), `/dev/random`, or any file
  (`-r /path/to/file`).
- Randomised chunk sizes and inter-chunk delays (`-c MIN-MAX`, `-d MIN-MAX`).
- SOCKS5 proxy support with RFC 1929 user/pass authentication (`-x`, `-U`, `-P`).
- Automatic TCP reconnect on dropped connections (`-R`).
- Full logging of received data:
  - **TCP**: raw byte stream written to `stream-<tag>.log` (auto-rollover with `-m`).
  - **UDP**: every datagram saved as its own `.bin` file under `datagrams-<tag>/`.
  - Both protocols write a machine-readable **JSONL** `events-<tag>.log`.
- Configurable runtime limit (`-t`) and chunk budget (`-n`).
- `--recv-only` / `--no-recv` modes to listen or to flood without listening.
- No external dependencies beyond POSIX, pthreads and libc.

## Build

```sh
make            # builds ./canyon
make test       # runs the smoke tests (TCP, UDP, SOCKS5)
sudo make install   # installs to /usr/local/bin
```

Requires a C11 compiler and `pthreads` (glibc/musl). The project is plain
C with no third-party libraries.

## Usage

```
canyon [options]
```

The only required option is the target port. A target host defaults to
`127.0.0.1`.

### Options

| Option | Description |
| --- | --- |
| `-H, --host <host>` | Target host (default `127.0.0.1`). |
| `-p, --port <port>` | Target port **(required)**. |
| `-u, --udp` | Use UDP instead of TCP. |
| `-x, --socks5 <host:port>` | Route TCP traffic through a SOCKS5 proxy. |
| `-U, --socks5-user <user>` | SOCKS5 username (RFC 1929 auth). |
| `-P, --socks5-pass <pass>` | SOCKS5 password. |
| `-r, --random-source <file>` | File to read random bytes from (default `/dev/urandom`; `/dev/random` works too). |
| `-c, --chunk <MIN[-MAX]>` | Bytes per chunk sent (default `4096`; a range picks a random size per chunk). |
| `-d, --delay <MIN[-MAX]>` | Delay between chunks in microseconds. |
| `-t, --timeout <secs>` | Stop after N seconds (`0` = unlimited). |
| `-n, --count <N>` | Send at most N chunks (`0` = unlimited). |
| `-R, --reconnect` | Reconnect when a TCP connection drops. |
| `-D, --reconnect-delay <us>` | Delay before reconnecting (default `1000000` µs). |
| `-o, --outdir <dir>` | Output directory (default `canyon-logs`). |
| `-m, --max-log <bytes>` | Max size per received-data log file (TCP stream rollover). |
| `-N, --no-recv` | Do not read anything from the socket. |
| `-E, --recv-only` | Only read from the socket, do not send. |
| `-v, --verbose` | Verbose output. |
| `-q, --quiet` | Suppress informational output. |
| `-V, --version` | Print version and exit. |
| `-h, --help` | Show help and exit. |

## Examples

```sh
# Flood a local HTTP port over TCP with 4 KiB random chunks
canyon -p 8080

# Flood 8.8.8.8:53 with 512-byte UDP datagrams
canyon -u -p 53 -H 8.8.8.8 -c 512

# Send random chunks between 1 KiB and 8 KiB, 100-1000 µs apart
canyon -p 3306 -c 1024-8192 -d 100-1000

# Route the traffic through a local SOCKS5 proxy
canyon -p 8080 -x 127.0.0.1:1080

# ...with username/password authentication
canyon -p 8080 -x proxy.example.com:1080 -U bob -P s3cret

# Stay connected, reconnecting whenever the connection drops
canyon -p 22 -R -D 500000

# Listen only for 10 seconds (no data is sent)
canyon -p 12345 -E -t 10

# Use /dev/random as the byte source and stop after 1000 chunks
canyon -p 8080 -r /dev/random -n 1000 -o /var/log/canyon
```

## Logging

All received data and events are stored under the output directory
(`canyon-logs` by default). Files are tagged with a timestamp and the canyon PID,
so concurrent runs never collide.

```
canyon-logs/
├── events-20260818-164117-53161.log     # JSONL event log (all runs)
├── stream-20260818-164117-53161.log     # TCP: raw received byte stream
└── datagrams-20260818-164117-53161/     # UDP: one .bin file per datagram
    └── d_0.bin
```

- **TCP** received bytes are appended raw to `stream-<tag>.log`. Use `-m` to cap
  the size of each file; when the limit is reached canyon rolls over to
  `stream-<tag>-1.log`, `stream-<tag>-2.log`, ...
- **UDP** received datagrams are stored individually as `d_<seq>.bin` files.
- The **events** log is newline-delimited JSON and records start/connect/
  disconnect/end plus send and datagram metadata:

```json
{"ts":1787071528361,"type":"start","msg":"canyon 1.0.0 target=127.0.0.1:19191 proto=tcp via socks5"}
{"ts":1787071528365,"type":"connect","msg":"connected to 127.0.0.1:19191 (via socks5)"}
{"ts":1787071528966,"type":"disconnect","msg":"connection closed"}
{"ts":1787071528966,"type":"end","msg":"shutting down (sent=3 rc=0)"}
```

## SOCKS5 support

`canyon` implements the SOCKS5 CONNECT command (RFC 1928) and the username/
password authentication sub-negotiation (RFC 1929). Both IP addresses and
hostnames are supported as destinations, over IPv4 or IPv6.

**Note:** SOCKS5 is only supported for TCP. SOCKS5 UDP ASSOCIATE is not
implemented; passing `-x` together with `-u` is rejected with an error.

## Random source

By default canyon reads from `/dev/urandom`, which never blocks and is the
recommended source. On Linux kernels >= 5.6 `/dev/random` behaves the same way;
on older kernels it may block when the entropy pool is low. You can point
`-r` at any readable file (for example a replay corpus or a fixed pattern) and
canyon will read from it until EOF.

## Tests

```sh
make test
```

`tests/smoke.sh` spins up throwaway Python services and verifies that canyon:

1. floods a TCP echo server and logs the responses;
2. tunnels the same traffic through a SOCKS5 proxy;
3. floods a UDP echo server and stores every datagram;
4. rejects UDP-over-SOCKS5 with a clear error.

## Project layout

```
src/canyon.c     main entry point, CLI parsing, session orchestration
src/net.c        socket helpers (connect with timeout, UDP connect, send-all)
src/socks5.c     SOCKS5 handshake (RFC 1928 / RFC 1929)
src/rand.c       random byte source + PRNG for sizes/delays
src/logbook.c    received-data and event logging
tests/smoke.sh   end-to-end smoke tests
```

## License

MIT. See [LICENSE](LICENSE).

Homepage: <https://github.com/manalejandro/canyon>
