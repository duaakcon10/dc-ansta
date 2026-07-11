#include "bot.h"

int json_int(const char *msg, const char *key)
{
    char k[128];
    snprintf(k, sizeof(k), "\"%s\":", key);
    const char *p = strstr(msg, k);
    if (!p) return 0;
    return atoi(p + strlen(k));
}

void json_str(const char *msg, const char *key, char *out, int cap)
{
    char k[128];
    snprintf(k, sizeof(k), "\"%s\":\"", key);
    const char *p = strstr(msg, k);
    if (!p) { out[0] = 0; return; }
    p += strlen(k);
    const char *e = strchr(p, '"');
    if (!e) { out[0] = 0; return; }
    int len = (int)(e - p);
    if (len >= cap) len = cap - 1;
    memcpy(out, p, len);
    out[len] = 0;
}
