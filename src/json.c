#include "bot.h"

/* Find "key": only at current JSON object depth (skip nested objects/arrays).
 * Fixes: nested "type":"handshake" inside expect{} was returned instead of root "type":"connected".
 */
static const char *find_key(const char *msg, const char *key)
{
    if (!msg || !key) return NULL;
    char k[128];
    snprintf(k, sizeof(k), "\"%s\"", key);
    size_t klen = strlen(k);
    int depth = 0;
    int in_str = 0;
    int esc = 0;

    for (const char *p = msg; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (in_str) {
            if (esc) { esc = 0; continue; }
            if (c == '\\') { esc = 1; continue; }
            if (c == '"') in_str = 0;
            continue;
        }
        if (c == '"') {
            /* candidate key only at depth 1 (inside root object) */
            if (depth == 1 && strncmp(p, k, klen) == 0) {
                const char *after = p + klen;
                while (*after == ' ' || *after == '\t' || *after == '\n' || *after == '\r')
                    after++;
                if (*after == ':')
                    return after;
            }
            in_str = 1;
            continue;
        }
        if (c == '{' || c == '[') depth++;
        else if (c == '}' || c == ']') {
            if (depth > 0) depth--;
        }
    }
    return NULL;
}

int json_int(const char *msg, const char *key)
{
    const char *p = find_key(msg, key);
    if (!p) return 0;
    p++; /* skip ':' */
    while (*p == ' ' || *p == '\t') p++;
    return atoi(p);
}

void json_str(const char *msg, const char *key, char *out, int cap)
{
    const char *p = find_key(msg, key);
    if (!p) { out[0] = 0; return; }
    p++; /* skip ':' */
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') { out[0] = 0; return; }
    p++;
    int len = 0;
    while (p[len] && p[len] != '"' && len < cap - 1) {
        if (p[len] == '\\' && p[len + 1]) {
            /* skip escape pair simply: keep next char */
            if (len + 1 < cap - 1) {
                out[len] = p[len + 1];
                /* store unescaped single char — advance source by 2 later via manual */
            }
            break; /* keep simple: no complex escape in protocol fields */
        }
        len++;
    }
    /* simple unescaped string until " */
    len = 0;
    while (*p && *p != '"' && len < cap - 1) {
        if (*p == '\\' && p[1]) {
            p++;
            out[len++] = *p++;
            continue;
        }
        out[len++] = *p++;
    }
    out[len] = 0;
}

/* Parse a JSON array of integers: "[1,2,3,80,443]" → fills out[] up to cap.
 * Returns count parsed. Skips non-integer tokens. */
int json_int_array(const char *msg, const char *key, int *out, int cap)
{
    const char *p = find_key(msg, key);
    if (!p) return 0;
    p++; /* skip ':' */
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '[') return 0;
    p++; /* skip '[' */
    int n = 0;
    while (*p && *p != ']' && n < cap) {
        while (*p == ' ' || *p == ',' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p == ']' || !*p) break;
        /* parse integer */
        if (*p < '0' || *p > '9') { p++; continue; } /* skip non-digit */
        int v = 0;
        while (*p >= '0' && *p <= '9') {
            v = v * 10 + (*p - '0');
            p++;
        }
        if (v > 0 && v < 65536) out[n++] = v;
    }
    return n;
}
