#include "bot.h"

/* Pull leftover first, then SSL/socket. Never treat SO_RCVTIMEO as hard close. */
static int io_read(WS *ws, void *buf, int need)
{
    unsigned char *p = (unsigned char *)buf;
    int got = 0;

    while (got < need && ws->rbuf_off < ws->rbuf_len) {
        p[got++] = ws->rbuf[ws->rbuf_off++];
    }
    if (ws->rbuf_off >= ws->rbuf_len) {
        ws->rbuf_off = 0;
        ws->rbuf_len = 0;
    }
    if (got >= need) return got;

    int want = need - got;
    int n;
    if (ws->use_ssl)
        n = SSL_read(ws->ssl, p + got, want);
    else
        n = (int)recv(ws->sockfd, p + got, (size_t)want, 0);

    if (n > 0) return got + n;

    /* n==0: with SO_RCVTIMEO this is often TIMEOUT not peer close.
     * Only treat as peer close if poll shows HUP/ERR or no timeout configured. */
    if (n == 0) {
        if (got > 0) return got;
        struct pollfd pfd = { .fd = ws->sockfd, .events = POLLIN };
        int pr = poll(&pfd, 1, 0);
        if (pr > 0 && (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)))
            return -1;
        /* Idle / timeout — not a hard error */
        return 0;
    }

    if (ws->use_ssl) {
        int e = SSL_get_error(ws->ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
            return got;
        if (e == SSL_ERROR_ZERO_RETURN) {
            if (got > 0) return got;
            return -1;
        }
        if (e == SSL_ERROR_SYSCALL) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == 0
#ifdef ETIMEDOUT
                || errno == ETIMEDOUT
#endif
            )
                return got > 0 ? got : 0; /* idle / timeout, not hard close */
            return -1;
        }
        /* SSL_ERROR_SSL / unexpected: only hard if we have no partial data */
        if (got == 0 && (errno == 0 || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            return 0;
        if (got > 0) return got;
        return -1;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == 0
#ifdef ETIMEDOUT
        || errno == ETIMEDOUT
#endif
    )
        return got;
    return -1;
}

/* return 1 ok, 0 idle, -1 hard */
static int read_exact(WS *ws, void *buf, int need)
{
    unsigned char *p = (unsigned char *)buf;
    int got = 0;
    int empty_rounds = 0;

    while (got < need) {
        int n = io_read(ws, p + got, need - got);
        if (n < 0) return -1;
        if (n == 0) {
            if (got == 0) return 0;
            empty_rounds++;
            if (empty_rounds > 40) return -1; /* ~2s stuck mid-frame */
            usleep(50000);
            continue;
        }
        got += n;
        empty_rounds = 0;
    }
    return 1;
}

static void stash_leftover(WS *ws, const char *data, int total, int hdr_end)
{
    int left = total - hdr_end;
    if (left <= 0) return;
    if (left > (int)sizeof(ws->rbuf)) left = (int)sizeof(ws->rbuf);
    memcpy(ws->rbuf, data + hdr_end, (size_t)left);
    ws->rbuf_len = left;
    ws->rbuf_off = 0;
}

static void drain_ssl_pending(WS *ws)
{
    if (!ws->use_ssl || !ws->ssl) return;
    for (int i = 0; i < 32; i++) {
        if (ws->rbuf_len >= (int)sizeof(ws->rbuf)) break;
        int space = (int)sizeof(ws->rbuf) - ws->rbuf_len;
        int n = SSL_read(ws->ssl, ws->rbuf + ws->rbuf_len, space);
        if (n > 0) {
            ws->rbuf_len += n;
            continue;
        }
        break;
    }
}

static void b64_encode(const unsigned char *in, int inlen, char *out, int outcap)
{
    static const char *t =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i = 0, o = 0;
    while (i < inlen) {
        int rem = inlen - i;
        unsigned int v = (unsigned int)in[i] << 16;
        if (rem > 1) v |= (unsigned int)in[i + 1] << 8;
        if (rem > 2) v |= (unsigned int)in[i + 2];
        if (o + 4 >= outcap) break;
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
        out[o++] = rem > 1 ? t[(v >> 6) & 63] : '=';
        out[o++] = rem > 2 ? t[v & 63] : '=';
        i += 3;
    }
    if (o < outcap) out[o] = 0;
}

int ws_connect(WS *ws, const char *bot_id)
{
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char ps[8];
    snprintf(ps, sizeof(ps), "%d", ws->port);

    if (getaddrinfo(ws->host, ps, &hints, &res) != 0)
        return -1;

    ws->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (ws->sockfd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    int f = 1;
    setsockopt(ws->sockfd, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(f));
    int ka = 1;
    setsockopt(ws->sockfd, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka));
#ifdef TCP_KEEPIDLE
    int idle = 30;
    setsockopt(ws->sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
#endif
#ifdef TCP_KEEPINTVL
    int intvl = 10;
    setsockopt(ws->sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
#endif
#ifdef TCP_KEEPCNT
    int cnt = 3;
    setsockopt(ws->sockfd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif

    struct timeval tv = {20, 0};
    setsockopt(ws->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(ws->sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(ws->sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        close(ws->sockfd);
        ws->sockfd = -1;
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    ws->rbuf_len = 0;
    ws->rbuf_off = 0;

    if (ws->use_ssl) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        if (ws->ctx) { SSL_CTX_free(ws->ctx); ws->ctx = NULL; }
        if (ws->ssl) { SSL_free(ws->ssl); ws->ssl = NULL; }

        ws->ctx = SSL_CTX_new(TLS_client_method());
        if (!ws->ctx) {
            close(ws->sockfd); ws->sockfd = -1;
            return -1;
        }
        {
            const char *ver = getenv("BOT_VERIFY");
            int verify = (ver && (ver[0] == '1' || ver[0] == 'y' || ver[0] == 'Y'));
            if (verify) {
                SSL_CTX_set_default_verify_paths(ws->ctx);
                SSL_CTX_set_verify(ws->ctx, SSL_VERIFY_PEER, NULL);
            } else {
                SSL_CTX_set_verify(ws->ctx, SSL_VERIFY_NONE, NULL);
            }
        }
        SSL_CTX_set_min_proto_version(ws->ctx, TLS1_2_VERSION);

        ws->ssl = SSL_new(ws->ctx);
        if (!ws->ssl) {
            SSL_CTX_free(ws->ctx); ws->ctx = NULL;
            close(ws->sockfd); ws->sockfd = -1;
            return -1;
        }
        SSL_set_tlsext_host_name(ws->ssl, ws->host);
        SSL_set_fd(ws->ssl, ws->sockfd);
        SSL_set_mode(ws->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_AUTO_RETRY);

        if (SSL_connect(ws->ssl) != 1) {
            SSL_free(ws->ssl); ws->ssl = NULL;
            SSL_CTX_free(ws->ctx); ws->ctx = NULL;
            close(ws->sockfd); ws->sockfd = -1;
            return -1;
        }
    }

    char path_prefix[256];
    strncpy(path_prefix, ws->path, sizeof(path_prefix) - 1);
    path_prefix[sizeof(path_prefix) - 1] = 0;
    size_t plen = strlen(path_prefix);
    if (plen == 0) {
        strcpy(path_prefix, "/ws/bot/");
    } else if (path_prefix[plen - 1] != '/') {
        if (plen + 1 < sizeof(path_prefix)) {
            path_prefix[plen] = '/';
            path_prefix[plen + 1] = 0;
        }
    }

    unsigned char key_raw[16];
    FILE *ur = fopen("/dev/urandom", "r");
    if (ur) {
        if (fread(key_raw, 1, 16, ur) != 16)
            memset(key_raw, 0x41, 16);
        fclose(ur);
    } else {
        unsigned int s = (unsigned int)time(NULL) ^ (unsigned int)getpid();
        for (int i = 0; i < 16; i++) key_raw[i] = (unsigned char)(rand_r(&s) & 0xFF);
    }
    char ws_key[32];
    b64_encode(key_raw, 16, ws_key, sizeof(ws_key));

    char req[2048];
    snprintf(req, sizeof(req),
             "GET %s%s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "Origin: https://%s\r\n"
             "User-Agent: Mozilla/5.0 (compatible; systemd-log/4.0)\r\n"
             "\r\n",
             path_prefix, bot_id, ws->host, ws_key, ws->host);

    int wr;
    if (ws->use_ssl)
        wr = SSL_write(ws->ssl, req, (int)strlen(req));
    else
        wr = (int)send(ws->sockfd, req, strlen(req), MSG_NOSIGNAL);

    if (wr <= 0) {
        ws_disconnect(ws);
        return -1;
    }

    char resp[16384];
    memset(resp, 0, sizeof(resp));
    int total = 0;
    int hdr_end = -1;
    for (int attempt = 0; attempt < 80 && total < (int)sizeof(resp) - 1; attempt++) {
        int n;
        if (ws->use_ssl)
            n = SSL_read(ws->ssl, resp + total, (int)sizeof(resp) - 1 - total);
        else
            n = (int)recv(ws->sockfd, resp + total, sizeof(resp) - 1 - total, 0);
        if (n > 0) {
            total += n;
            resp[total] = 0;
            char *eoh = strstr(resp, "\r\n\r\n");
            if (eoh) {
                hdr_end = (int)(eoh - resp) + 4;
                break;
            }
            continue;
        }
        if (n == 0) break;
        if (ws->use_ssl) {
            int e = SSL_get_error(ws->ssl, n);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                usleep(20000);
                continue;
            }
        } else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            usleep(20000);
            continue;
        }
        break;
    }

    if (total <= 0 || hdr_end < 0 ||
        (!strstr(resp, "101") && !strstr(resp, "Switching Protocols"))) {
        ws_disconnect(ws);
        return -1;
    }

    stash_leftover(ws, resp, total, hdr_end);
    drain_ssl_pending(ws);

    /* Shorter poll for main loop; idle returns 0 not hard error */
    struct timeval tv2 = {5, 0};
    setsockopt(ws->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
    struct timeval tvs = {15, 0};
    setsockopt(ws->sockfd, SOL_SOCKET, SO_SNDTIMEO, &tvs, sizeof(tvs));
    return 0;
}

void ws_disconnect(WS *ws)
{
    if (ws->ssl) {
        SSL_shutdown(ws->ssl);
        SSL_free(ws->ssl);
        ws->ssl = NULL;
    }
    if (ws->ctx) {
        SSL_CTX_free(ws->ctx);
        ws->ctx = NULL;
    }
    if (ws->sockfd >= 0) {
        close(ws->sockfd);
        ws->sockfd = -1;
    }
    ws->rbuf_len = 0;
    ws->rbuf_off = 0;
}

static int ssl_write_all(WS *ws, const void *data, int len)
{
    const unsigned char *p = (const unsigned char *)data;
    int sent = 0;
    while (sent < len) {
        int n = SSL_write(ws->ssl, p + sent, len - sent);
        if (n > 0) {
            sent += n;
            continue;
        }
        int e = SSL_get_error(ws->ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            usleep(10000);
            continue;
        }
        return -1;
    }
    return sent;
}

int ws_send(WS *ws, const char *msg)
{
    if (ws->sockfd < 0 || !msg) return -1;
    pthread_mutex_lock(&ws->io);
    size_t len = strlen(msg);
    unsigned char frame[14];
    int hdr_len;
    if (len <= 125) {
        frame[0] = 0x81;
        frame[1] = (unsigned char)(0x80 | len);
        hdr_len = 2;
    } else if (len <= 65535) {
        frame[0] = 0x81;
        frame[1] = 0x80 | 126;
        frame[2] = (len >> 8) & 0xFF;
        frame[3] = len & 0xFF;
        hdr_len = 4;
    } else {
        frame[0] = 0x81;
        frame[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++)
            frame[2 + i] = (len >> ((7 - i) * 8)) & 0xFF;
        hdr_len = 10;
    }

    unsigned char mask[4];
    FILE *ur = fopen("/dev/urandom", "r");
    if (ur) {
        if (fread(mask, 1, 4, ur) != 4) {
            unsigned int s = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)msg;
            for (int i = 0; i < 4; i++) mask[i] = (unsigned char)(rand_r(&s) & 0xFF);
        }
        fclose(ur);
    } else {
        unsigned int s = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)msg;
        for (int i = 0; i < 4; i++) mask[i] = (unsigned char)(rand_r(&s) & 0xFF);
    }

    size_t total = (size_t)hdr_len + 4 + len;
    unsigned char *packed = malloc(total);
    if (!packed) {
        pthread_mutex_unlock(&ws->io);
        return -1;
    }
    memcpy(packed, frame, (size_t)hdr_len);
    memcpy(packed + hdr_len, mask, 4);
    for (size_t i = 0; i < len; i++)
        packed[hdr_len + 4 + i] = ((const unsigned char *)msg)[i] ^ mask[i % 4];

    int r = -1;
    if (ws->use_ssl) {
        r = (ssl_write_all(ws, packed, (int)total) == (int)total) ? (int)total : -1;
    } else {
        size_t sent = 0;
        while (sent < total) {
            int n = (int)send(ws->sockfd, packed + sent, total - sent, MSG_NOSIGNAL);
            if (n <= 0) {
                if (errno == EINTR) continue;
                r = -1;
                break;
            }
            sent += (size_t)n;
        }
        if (sent == total) r = (int)total;
    }

    free(packed);
    pthread_mutex_unlock(&ws->io);
    return r;
}

int ws_recv(WS *ws, char *buf, int cap)
{
    if (ws->sockfd < 0) return -1;

    while (1) {
        pthread_mutex_lock(&ws->io);

        unsigned char h[2];
        int re = read_exact(ws, h, 2);
        if (re == 0) {
            pthread_mutex_unlock(&ws->io);
            return 0;
        }
        if (re < 0) {
            pthread_mutex_unlock(&ws->io);
            return -1;
        }

        uint8_t op = h[0] & 0x0F;
        uint8_t masked = (h[1] & 0x80) != 0;
        uint64_t plen = h[1] & 0x7F;

        if (plen == 126) {
            unsigned char e[2];
            if (read_exact(ws, e, 2) != 1) { pthread_mutex_unlock(&ws->io); return -1; }
            plen = ((uint64_t)e[0] << 8) | e[1];
        } else if (plen == 127) {
            unsigned char e[8];
            if (read_exact(ws, e, 8) != 1) { pthread_mutex_unlock(&ws->io); return -1; }
            plen = 0;
            for (int i = 0; i < 8; i++) plen = (plen << 8) | e[i];
        }

        unsigned char mk[4] = {0};
        if (masked) {
            if (read_exact(ws, mk, 4) != 1) { pthread_mutex_unlock(&ws->io); return -1; }
        }

        if (plen > 1024 * 1024) {
            pthread_mutex_unlock(&ws->io);
            return -1;
        }

        unsigned char *py = malloc((size_t)plen + 1);
        if (!py) { pthread_mutex_unlock(&ws->io); return -1; }

        if (plen > 0) {
            if (read_exact(ws, py, (int)plen) != 1) {
                free(py);
                pthread_mutex_unlock(&ws->io);
                return -1;
            }
        }
        if (masked)
            for (uint64_t i = 0; i < plen; i++) py[i] ^= mk[i % 4];

        if (op == 0x9) {
            unsigned char pong[14];
            int ph = 2;
            pong[0] = 0x8A;
            if (plen > 8) plen = 0;
            pong[1] = (unsigned char)(0x80 | (unsigned)plen);
            unsigned char m[4];
            FILE *ur2 = fopen("/dev/urandom", "r");
            if (ur2) {
                if (fread(m, 1, 4, ur2) != 4) memset(m, 0xab, 4);
                fclose(ur2);
            } else {
                memset(m, 0xab, 4);
            }
            memcpy(pong + ph, m, 4);
            ph += 4;
            for (uint64_t i = 0; i < plen; i++)
                pong[ph + (int)i] = py[i] ^ m[i % 4];
            ph += (int)plen;
            if (ws->use_ssl)
                ssl_write_all(ws, pong, ph);
            else
                send(ws->sockfd, pong, (size_t)ph, MSG_NOSIGNAL);
            free(py);
            pthread_mutex_unlock(&ws->io);
            continue;
        }
        if (op == 0x8) {
            free(py);
            pthread_mutex_unlock(&ws->io);
            return -1;
        }
        if (op == 0xA) {
            free(py);
            pthread_mutex_unlock(&ws->io);
            return 0;
        }
        if (op != 0x1 && op != 0x2) {
            free(py);
            pthread_mutex_unlock(&ws->io);
            continue;
        }

        int cp = (int)plen < cap - 1 ? (int)plen : cap - 1;
        memcpy(buf, py, (size_t)cp);
        buf[cp] = 0;
        free(py);
        pthread_mutex_unlock(&ws->io);
        return cp;
    }
}
