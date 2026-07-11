#include "bot.h"

int ws_connect(WS *ws, const char *bot_id)
{
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char ps[8];
    snprintf(ps, sizeof(ps), "%d", ws->port);
    if (getaddrinfo(ws->host, ps, &hints, &res) != 0) return -1;
    ws->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (ws->sockfd < 0) { freeaddrinfo(res); return -1; }
    int f = 1;
    setsockopt(ws->sockfd, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(f));
    struct timeval tv = {5, 0};
    setsockopt(ws->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(ws->sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        close(ws->sockfd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    if (ws->use_ssl) {
        SSL_library_init();
        SSL_load_error_strings();
        ws->ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(ws->ctx, SSL_VERIFY_NONE, NULL);
        ws->ssl = SSL_new(ws->ctx);
        SSL_set_fd(ws->ssl, ws->sockfd);
        if (SSL_connect(ws->ssl) != 1) { ws->sockfd = -1; return -1; }
    }
    char req[1024];
    snprintf(req, sizeof(req),
             "GET %s%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
             ws->path, bot_id, ws->host);
    if (ws->use_ssl) SSL_write(ws->ssl, req, strlen(req));
    else send(ws->sockfd, req, strlen(req), MSG_NOSIGNAL);
    char resp[4096];
    int n = ws->use_ssl ? SSL_read(ws->ssl, resp, sizeof(resp) - 1) : recv(ws->sockfd, resp, sizeof(resp) - 1, 0);
    if (n <= 0 || !strstr(resp, "101")) { ws->sockfd = -1; return -1; }
    return 0;
}

void ws_disconnect(WS *ws)
{
    if (ws->ssl) { SSL_shutdown(ws->ssl); SSL_free(ws->ssl); ws->ssl = NULL; }
    if (ws->ctx) { SSL_CTX_free(ws->ctx); ws->ctx = NULL; }
    if (ws->sockfd >= 0) { close(ws->sockfd); ws->sockfd = -1; }
}

int ws_send(WS *ws, const char *msg)
{
    pthread_mutex_lock(&ws->sm);
    size_t len = strlen(msg);
    unsigned char frame[14];
    int hdr_len;
    if (len <= 125) { frame[0] = 0x81; frame[1] = len; hdr_len = 2; }
    else if (len <= 65535) { frame[0] = 0x81; frame[1] = 126; frame[2] = (len >> 8) & 0xFF; frame[3] = len & 0xFF; hdr_len = 4; }
    else {
        frame[0] = 0x81; frame[1] = 127;
        for (int i = 7; i >= 0; i--) frame[2 + 7 - i] = (len >> (i * 8)) & 0xFF;
        hdr_len = 10;
    }
    int r;
    if (ws->use_ssl) {
        r = SSL_write(ws->ssl, frame, hdr_len);
        if (r == hdr_len) r = SSL_write(ws->ssl, msg, len);
    } else {
        struct iovec iov[2] = {{frame, hdr_len}, {(void *)msg, len}};
        struct msghdr mh = {0, 0, iov, 2, 0, 0, 0};
        r = sendmsg(ws->sockfd, &mh, MSG_NOSIGNAL);
    }
    pthread_mutex_unlock(&ws->sm);
    return r;
}

int ws_recv(WS *ws, char *buf, int cap)
{
    pthread_mutex_lock(&ws->rm);
    unsigned char h[2];
    int n = ws->use_ssl ? SSL_read(ws->ssl, h, 2) : recv(ws->sockfd, h, 2, 0);
    if (n != 2) { pthread_mutex_unlock(&ws->rm); return -1; }
    uint8_t op = h[0] & 0x0F, masked = (h[1] & 0x80) != 0;
    uint64_t plen = h[1] & 0x7F;
    if (plen == 126) {
        unsigned char e[2];
        ws->use_ssl ? SSL_read(ws->ssl, e, 2) : recv(ws->sockfd, e, 2, 0);
        plen = (e[0] << 8) | e[1];
    } else if (plen == 127) {
        unsigned char e[8];
        ws->use_ssl ? SSL_read(ws->ssl, e, 8) : recv(ws->sockfd, e, 8, 0);
        plen = 0;
        for (int i = 0; i < 8; i++) plen = (plen << 8) | e[i];
    }
    unsigned char mk[4] = {0};
    if (masked) ws->use_ssl ? SSL_read(ws->ssl, mk, 4) : recv(ws->sockfd, mk, 4, 0);
    unsigned char *py = malloc(plen);
    size_t rc = 0;
    while (rc < plen) {
        int r = ws->use_ssl ? SSL_read(ws->ssl, py + rc, plen - rc) : recv(ws->sockfd, py + rc, plen - rc, 0);
        if (r <= 0) { free(py); pthread_mutex_unlock(&ws->rm); return -1; }
        rc += r;
    }
    if (masked) for (uint64_t i = 0; i < plen; i++) py[i] ^= mk[i % 4];
    if (op == 0x9) { free(py); pthread_mutex_unlock(&ws->rm); return ws_recv(ws, buf, cap); }
    if (op == 0x8) { free(py); pthread_mutex_unlock(&ws->rm); return -1; }
    int cp = (int)plen < cap ? (int)plen : cap - 1;
    memcpy(buf, py, cp);
    buf[cp] = 0;
    free(py);
    pthread_mutex_unlock(&ws->rm);
    return cp;
}
