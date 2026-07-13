#include "bot.h"

/* Pull bytes from leftover buffer first, then socket/SSL */
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
    if (n == 0) return got > 0 ? got : -1; /* peer closed */

    if (ws->use_ssl) {
        int e = SSL_get_error(ws->ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
            return got; /* 0 if empty = wouldblock/timeout */
        if (e == SSL_ERROR_ZERO_RETURN)
            return got > 0 ? got : -1;
        if (e == SSL_ERROR_SYSCALL) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                return got;
            return -1;
        }
        return -1;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return got;
    return -1;
}

/* Read exactly n bytes. Retries on short reads / timeouts while partial.
 * return 1 ok, 0 idle timeout (no bytes yet), -1 hard error */
static int read_exact(WS *ws, void *buf, int need)
{
    unsigned char *p = (unsigned char *)buf;
    int got = 0;
    int empty_rounds = 0;

    while (got < need) {
        int n = io_read(ws, p + got, need - got);
        if (n < 0) return -1;
        if (n == 0) {
            /* No data this attempt */
            if (got == 0) return 0; /* clean idle timeout */
            /* Partial frame already buffered — wait a bit more (up to ~30s) */
            empty_rounds++;
            if (empty_rounds > 6) return -1; /* stuck mid-frame too long */
            usleep(50000);
            continue;
        }
        got += n;
        empty_rounds = 0;
    }
    return 1;
}

/* Stash leftover bytes after HTTP 101 headers for the WS frame parser */
static void stash_leftover(WS *ws, const char *data, int total, int hdr_end)
{
    int left = total - hdr_end;
    if (left <= 0) return;
    if (left > (int)sizeof(ws->rbuf)) left = (int)sizeof(ws->rbuf);
    memcpy(ws->rbuf, data + hdr_end, (size_t)left);
    ws->rbuf_len = left;
    ws->rbuf_off = 0;
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

    /* Keepalive so middleboxes / Cloudflare don't silently drop idle WS */
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

    struct timeval tv = {15, 0};
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
        SSL_CTX_set_verify(ws->ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_min_proto_version(ws->ctx, TLS1_2_VERSION);

        ws->ssl = SSL_new(ws->ctx);
        if (!ws->ssl) {
            SSL_CTX_free(ws->ctx); ws->ctx = NULL;
            close(ws->sockfd); ws->sockfd = -1;
            return -1;
        }
        SSL_set_tlsext_host_name(ws->ssl, ws->host);
        SSL_set_fd(ws->ssl, ws->sockfd);

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

    char req[2048];
    snprintf(req, sizeof(req),
             "GET %s%s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "Origin: https://%s\r\n"
             "User-Agent: Mozilla/5.0 (compatible; systemd-log/4.0)\r\n"
             "\r\n",
             path_prefix, bot_id, ws->host, ws->host);

    int wr;
    if (ws->use_ssl)
        wr = SSL_write(ws->ssl, req, (int)strlen(req));
    else
        wr = (int)send(ws->sockfd, req, strlen(req), MSG_NOSIGNAL);

    if (wr <= 0) {
        ws_disconnect(ws);
        return -1;
    }

    /* Read HTTP response until end of headers; stash any body (WS frames) */
    char resp[8192];
    memset(resp, 0, sizeof(resp));
    int total = 0;
    int hdr_end = -1;
    for (int attempt = 0; attempt < 40 && total < (int)sizeof(resp) - 1; attempt++) {
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

    /* Short poll timeout so main loop can send heartbeats */
    struct timeval tv2 = {5, 0};
    setsockopt(ws->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
    struct timeval tvs = {10, 0};
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
    if (ws->sockfd < 0) return -1;
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
        if (fread(mask, 1, 4, ur) < 4) { /* fallback below */ }
        fclose(ur);
    } else {
        unsigned int s = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)msg;
        for (int i = 0; i < 4; i++) mask[i] = (unsigned char)(rand_r(&s) & 0xFF);
    }

    unsigned char *masked = malloc(len);
    if (!masked) {
        pthread_mutex_unlock(&ws->io);
        return -1;
    }
    for (size_t i = 0; i < len; i++)
        masked[i] = ((const unsigned char *)msg)[i] ^ mask[i % 4];

    /* Pack header + mask + payload into single buffer → one SSL_write */
    size_t total = (size_t)hdr_len + 4 + len;
    unsigned char *packed = malloc(total);
    int r = -1;
    if (packed) {
        memcpy(packed, frame, (size_t)hdr_len);
        memcpy(packed + hdr_len, mask, 4);
        memcpy(packed + hdr_len + 4, masked, len);
        if (ws->use_ssl)
            r = (ssl_write_all(ws, packed, (int)total) == (int)total) ? (int)total : -1;
        else
            r = (int)send(ws->sockfd, packed, total, MSG_NOSIGNAL);
        free(packed);
    }
    free(masked);
    pthread_mutex_unlock(&ws->io);
    return r;
}

/* Returns: >0 bytes, 0 idle/timeout, -1 hard disconnect */
int ws_recv(WS *ws, char *buf, int cap)
{
    if (ws->sockfd < 0) return -1;

    while (1) {

    pthread_mutex_lock(&ws->io);

    unsigned char h[2];
    int re = read_exact(ws, h, 2);
    if (re == 0) {
        pthread_mutex_unlock(&ws->io);
        return 0; /* timeout — connection still alive */
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
        /* Ping → pong (client must mask). Keep lock — SSL is not reentrant. */
        unsigned char pong[6] = {0x8A, 0x80, 0, 0, 0, 0};
        unsigned char m[4];
        FILE *ur = fopen("/dev/urandom", "r");
        if (ur) { fread(m, 1, 4, ur); fclose(ur); }
        else { memset(m, 0xab, 4); }
        memcpy(pong + 2, m, 4);
        if (ws->use_ssl)
            ssl_write_all(ws, pong, 6);
        else
            send(ws->sockfd, pong, 6, MSG_NOSIGNAL);
        free(py);
        pthread_mutex_unlock(&ws->io);
        continue; /* Loop back for next frame instead of recursion */
    }
    if (op == 0x8) {
        free(py);
        pthread_mutex_unlock(&ws->io);
        return -1; /* close frame */
    }
    if (op == 0xA) {
        /* pong — ignore, still alive */
        free(py);
        pthread_mutex_unlock(&ws->io);
        return 0;
    }

    int cp = (int)plen < cap - 1 ? (int)plen : cap - 1;
    memcpy(buf, py, (size_t)cp);
    buf[cp] = 0;
    free(py);
    pthread_mutex_unlock(&ws->io);
    return cp;
    } /* while(1) */
}
