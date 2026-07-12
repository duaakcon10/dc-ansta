#include "bot.h"

/* ── CPU Load Governor (ported from src-base-example) ── */
static volatile int current_cpu_load = 0;
static pthread_mutex_t cpu_load_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int cpu_running = 0;
static pthread_t cpu_tid;

int get_cpu_usage(void)
{
    static unsigned long long lastTotalUser = 0, lastTotalUserLow = 0, lastTotalSys = 0, lastTotalIdle = 0;
    unsigned long long totalUser, totalUserLow, totalSys, totalIdle, total;
    FILE *file = fopen("/proc/stat", "r");
    if (!file) return 0;
    int n = fscanf(file, "cpu %llu %llu %llu %llu", &totalUser, &totalUserLow, &totalSys, &totalIdle);
    (void)n;
    fclose(file);
    if (lastTotalUser == 0) {
        lastTotalUser = totalUser; lastTotalUserLow = totalUserLow;
        lastTotalSys = totalSys; lastTotalIdle = totalIdle;
        return 0;
    }
    unsigned long long dU = totalUser - lastTotalUser;
    unsigned long long dUL = totalUserLow - lastTotalUserLow;
    unsigned long long dS = totalSys - lastTotalSys;
    unsigned long long dI = totalIdle - lastTotalIdle;
    lastTotalUser = totalUser; lastTotalUserLow = totalUserLow;
    lastTotalSys = totalSys; lastTotalIdle = totalIdle;
    total = dU + dUL + dS + dI;
    if (total == 0) return 0;
    return (int)((dU + dUL + dS) * 100 / total);
}

void update_cpu_load(void)
{
    int load = get_cpu_usage();
    pthread_mutex_lock(&cpu_load_mutex);
    current_cpu_load = load;
    pthread_mutex_unlock(&cpu_load_mutex);
}

int should_pause(void)
{
    pthread_mutex_lock(&cpu_load_mutex);
    int load = current_cpu_load;
    pthread_mutex_unlock(&cpu_load_mutex);
    return load > CPU_LOAD_THRESHOLD;
}

static void *cpu_monitor_loop(void *arg)
{
    (void)arg;
    while (cpu_running && !g_shutdown) {
        update_cpu_load();
        usleep(100000);
    }
    return NULL;
}

void cpu_monitor_start(void)
{
    if (cpu_running) return;
    cpu_running = 1;
    pthread_create(&cpu_tid, NULL, cpu_monitor_loop, NULL);
    pthread_detach(cpu_tid);
}
