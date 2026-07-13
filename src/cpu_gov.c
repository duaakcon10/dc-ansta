#include "bot.h"

static volatile int current_cpu_load = 0;
static pthread_mutex_t cpu_load_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int cpu_running = 0;
static pthread_t cpu_tid;
static int cpu_limit = CPU_LOAD_THRESHOLD;

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

/* Returns nonzero if CPU is over limit; caller should back off proportionally.
 * The return value is how many ms to sleep (0 = no pause needed). */
int should_throttle(void)
{
    pthread_mutex_lock(&cpu_load_mutex);
    int load = current_cpu_load;
    pthread_mutex_unlock(&cpu_load_mutex);
    if (load <= cpu_limit) return 0;
    /* Sleep proportional: 1ms for every 1% over limit, capped at 100ms */
    int over = load - cpu_limit;
    if (over > 100) over = 100;
    return over * 1000; /* microseconds */
}

int should_pause(void)
{
    return should_throttle() > 0;
}

static void *cpu_monitor_loop(void *arg)
{
    (void)arg;
    while (cpu_running && !g_shutdown) {
        update_cpu_load();
        usleep(50000); /* 50ms sampling for faster reaction */
    }
    return NULL;
}

void cpu_monitor_start(void)
{
    /* Respect BOT_CPU_LIMIT env var for per-machine tuning */
    const char *env = getenv("BOT_CPU_LIMIT");
    if (env) {
        int v = atoi(env);
        if (v >= 10 && v <= 95) cpu_limit = v;
    }
    /* GitHub Runner detection: force very conservative CPU limit */
    if (getenv("GITHUB_ACTIONS") || getenv("RUNNER_NAME")) {
        cpu_limit = (cpu_limit > 40) ? 40 : cpu_limit;
        fprintf(stderr, "[cpu] GitHub Runner detected: CPU capped at %d%%\n", cpu_limit);
    }
    if (cpu_running) return;
    cpu_running = 1;
    pthread_create(&cpu_tid, NULL, cpu_monitor_loop, NULL);
    pthread_detach(cpu_tid);
}
