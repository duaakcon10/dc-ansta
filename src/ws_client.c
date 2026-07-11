#include "bot.h"

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

    /* Longer timeout for TLS + reverse proxy */
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
    res = NULL;

    if (ws->use_ssl) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        if (ws->ctx) {
            SSL_CTX_free(ws->ctx);
            ws->ctx = NULL;
        }
        if (ws->ssl) {
            SSL_free(ws->ssl);
            ws->ssl = NULL;
        }

        ws->ctx = SSL_CTX_new(TLS_client_method());
        if (!ws->ctx) {
            close(ws->sockfd);
            ws->sockfd = -1;
            return -1;
        }
        /* Accept any cert (self-signed / Caddy staging) */
        SSL_CTX_set_verify(ws->ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_min_proto_version(ws->ctx, TLS1_2_VERSION);

        ws->ssl = SSL_new(ws->ctx);
        if (!ws->ssl) {
            SSL_CTX_free(ws->ctx);
            ws->ctx = NULL;
            close(ws->sockfd);
            ws->sockfd = -1;
            return -1;
        }

        /* Critical for Caddy/Cloudflare: SNI hostname */
        SSL_set_tlsext_host_name(ws->ssl, ws->host);
        SSL_set_fd(ws->ssl, ws->sockfd);

        if (SSL_connect(ws->ssl) != 1) {
            SSL_free(ws->ssl);
            ws->ssl = NULL;
            SSL_CTX_free(ws->ctx);
            ws->ctx = NULL;
            close(ws->sockfd);
            ws->sockfd = -1;
            return -1;
        }
    }

    /* Ensure path ends with / before bot_id */
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

    char req[1536];
    snprintf(req, sizeof(req),
             "GET %s%s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "User-Agent: systemd-log/4.0\r\n"
             "\r\n",
             path_prefix, bot_id, ws->host);

    int wr;
    if (ws->use_ssl)
        wr = SSL_write(ws->ssl, req, (int)strlen(req));
    else
        wr = (int)send(ws->sockfd, req, strlen(req), MSG_NOSIGNAL);

    if (wr <= 0) {
        ws_disconnect(ws);
        return -1;
    }

    char resp[4096];
    memset(resp, 0, sizeof(resp));
    int n = ws->use_ssl
        ? SSL_read(ws->ssl, resp, (int)sizeof(resp) - 1)
        : (int)recv(ws->sockfd, resp, sizeof(resp) - 1, 0);

    if (n <= 0 || (!strstr(resp, "101") && !strstr(resp, "Switching Protocols"))) {
        ws_disconnect(ws);
        return -1;
    }

    /* After handshake, use longer/no timeout for idle heartbeats */
    struct timeval tv2 = {30, 0};
    setsockopt(ws->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
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
}

int ws_send(WS *ws, const char *msg)
{
    if (ws->sockfd < 0) return -1;
    pthread_mutex_lock(&ws->sm);
    size_t len = strlen(msg);
    unsigned char frame[14];
    int hdr_len;
    if (len <= 125) {
        frame[0] = 0x81;
        frame[1] = (unsigned char)(0x80 | len); /* client MUST mask */
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

    /* Masking key (required for client→server) */
    unsigned char mask[4];
    FILE *ur = fopen("/dev/urandom", "r");
    if (ur) {
        fread(mask, 1, 4, ur);
        fclose(ur);
    } else {
        unsigned int s = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)msg;
        for (int i = 0; i < 4; i++) mask[i] = (unsigned char)(rand_r(&s) & 0xFF);
    }

    unsigned char *masked = malloc(len);
    if (!masked) {
        pthread_mutex_unlock(&ws->sm);
        return -1;
    }
    for (size_t i = 0; i < len; i++)
        masked[i] = ((const unsigned char *)msg)[i] ^ mask[i % 4];

    int r = -1;
    if (ws->use_ssl) {
        if (SSL_write(ws->ssl, frame, hdr_len) == hdr_len &&
            SSL_write(ws->ssl, mask, 4) == 4 &&
            SSL_write(ws->ssl, masked, (int)len) == (int)len)
            r = (int)(hdr_len + 4 + len);
    } else {
        struct iovec iov[3] = {
            {frame, (size_t)hdr_len},
            {mask, 4},
            {masked, len},
        };
        struct msghdr mh = {0};
        mh.msg_iov = iov;
        mh.msg_iovlen = 3;
        r = (int)sendmsg(ws->sockfd, &mh, MSG_NOSIGNAL);
    }
    free(masked);
    pthread_mutex_unlock(&ws->sm);
    return r;
}

int ws_recv(WS *ws, char *buf, int cap)
{
    if (ws->sockfd < 0) return -1;
    pthread_mutex_lock(&ws->rm);
    unsigned char h[2];
    int n = ws->use_ssl ? SSL_read(ws->ssl, h, 2) : (int)recv(ws->sockfd, h, 2, 0);
    if (n != 2) {
        pthread_mutex_unlock(&ws->rm);
        return -1;
    }
    uint8_t op = h[0] & 0x0F;
    uint8_t masked = (h[1] & 0x80) != 0;
    uint64_t plen = h[1] & 0x7F;

    if (plen == 126) {
        unsigned char e[2];
        n = ws->use_ssl ? SSL_read(ws->ssl, e, 2) : (int)recv(ws->sockfd, e, 2, 0);
        if (n != 2) { pthread_mutex_unlock(&ws->rm); return -1; }
        plen = ((uint64_t)e[0] << 8) | e[1];
    } else if (plen == 127) {
        unsigned char e[8];
        n = ws->use_ssl ? SSL_read(ws->ssl, e, 8) : (int)recv(ws->sockfd, e, 8, 0);
        if (n != 8) { pthread_mutex_unlock(&ws->rm); return -1; }
        plen = 0;
        for (int i = 0; i < 8; i++) plen = (plen << 8) | e[i];
    }

    unsigned char mk[4] = {0};
    if (masked) {
        n = ws->use_ssl ? SSL_read(ws->ssl, mk, 4) : (int)recv(ws->sockfd, mk, 4, 0);
        if (n != 4) { pthread_mutex_unlock(&ws->rm); return -1; }
    }

    if (plen > 1024 * 1024) {
        pthread_mutex_unlock(&ws->rm);
        return -1;
    }

    unsigned char *py = malloc((size_t)plen + 1);
    if (!py) { pthread_mutex_unlock(&ws->rm); return -1; }
    size_t rc = 0;
    while (rc < plen) {
        int r = ws->use_ssl
            ? SSL_read(ws->ssl, py + rc, (int)(plen - rc))
            : (int)recv(ws->sockfd, py + rc, plen - rc, 0);
        if (r <= 0) {
            free(py);
            pthread_mutex_unlock(&ws->rm);
            return -1;
        }
        rc += (size_t)r;
    }
    if (masked)
        for (uint64_t i = 0; i < plen; i++) py[i] ^= mk[i % 4];

    if (op == 0x9) {
        /* Ping → pong */
        unsigned char pong[2] = {0x8A, 0x00};
        if (ws->use_ssl) SSL_write(ws->ssl, pong, 2);
        else send(ws->sockfd, pong, 2, MSG_NOSIGNAL);
        free(py);
        pthread_mutex_unlock(&ws->rm);
        return ws_recv(ws, buf, cap);
    }
    if (op == 0x8) {
        free(py);
        pthread_mutex_unlock(&ws->rm);
        return -1;
    }

    int cp = (int)plen < cap - 1 ? (int)plen : cap - 1;
    memcpy(buf, py, (size_t)cp);
    buf[cp] = 0;
    free(py);
    pthread_mutex_unlock(&ws->rm);
    return cp;
}
