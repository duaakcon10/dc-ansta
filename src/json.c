#include "bot.h"

static const char *find_key(const char *msg, const char *key)
{
    char k[128];
    snprintf(k, sizeof(k), "\"%s\"", key);
    const char *pos = msg;
    while ((pos = strstr(pos, k)) != NULL) {
        /* Must be preceded by {, , or whitespace, and followed by : */
        const char *before = pos;
        while (before > msg) {
            before--;
            if (*before == '{' || *before == ',') break;
            if (*before != ' ' && *before != '\t' && *before != '\n' && *before != '\r')
                { pos++; break; }
        }
        if (before == msg) { pos++; continue; }
        const char *after = pos + strlen(k);
        while (*after == ' ' || *after == '\t') after++;
        if (*after == ':') return after;
        pos++;
    }
    return NULL;
}

int json_int(const char *msg, const char *key)
{
    const char *p = find_key(msg, key);
    if (!p) return 0;
    return atoi(p + 1); /* skip ':' */
}

void json_str(const char *msg, const char *key, char *out, int cap)
{
    const char *p = find_key(msg, key);
    if (!p) { out[0] = 0; return; }
    p++; /* skip ':' */
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') { out[0] = 0; return; }
    p++;
    const char *e = strchr(p, '"');
    if (!e) { out[0] = 0; return; }
    int len = (int)(e - p);
    if (len >= cap) len = cap - 1;
    memcpy(out, p, len);
    out[len] = 0;
}
