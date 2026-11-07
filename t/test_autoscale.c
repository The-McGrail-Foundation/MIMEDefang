/*
 * Unit tests for the autoscaling decision logic (autoscale.c).
 * Prints TAP; run through t/c_unit.t.
 */
#include <stdio.h>
#include <string.h>
#include "../autoscale.h"

static char err_buf[128];
static int test_num = 0;
static int failures = 0;

static void
ok(int cond, const char *label)
{
    test_num++;
    if (cond) {
        printf("ok %d - %s\n", test_num, label);
    } else {
        failures++;
        printf("not ok %d - %s\n", test_num, label);
    }
}

/* A pool of "running" live workers, "busy" of which are busy */
static AutoscaleInput
make_input(time_t now, int running, int busy, int min, int max)
{
    AutoscaleInput in;
    memset(&in, 0, sizeof(in));
    in.now = now;
    in.running = running;
    in.live = running;
    in.busy = busy;
    in.busy_peak = busy;
    in.min_workers = min;
    in.max_workers = max;
    in.have_stopped = (running < max);
    in.have_idle = (running > busy);
    return in;
}

/* One tick: the decision for a pool of "running" workers, "demand" of
   them wanted (busy peak), at time t */
static AutoscaleDecision
tick(AutoscaleParams const *p, AutoscaleState *st, time_t t,
     int running, int demand, int min, int max)
{
    AutoscaleInput in = make_input(t, running, demand > running ? running : demand,
                                   min, max);
    if (demand > running) {
        in.queued_peak = demand - running;
    }
    return autoscale_decide(p, st, &in);
}

int
main(void)
{
    AutoscaleParams p;
    AutoscaleState st;
    AutoscaleInput in;
    AutoscaleDecision d;
    int i;
    time_t now = 1000;

    autoscale_params_default(&p);
    ok(p.interval == 15, "default interval");
    ok(p.window == 600, "default window");
    ok(p.spare == 0, "default spare");

    /* An idle pool at minWorkers stays there */
    autoscale_state_init(&st);
    d = tick(&p, &st, now, 2, 0, 2, 20);
    ok(d.action == AUTOSCALE_HOLD && d.desired == 2, "idle pool at -m holds");

    /* The pool grows to the demand, in one decision */
    d = tick(&p, &st, now += 15, 2, 8, 2, 20);
    ok(d.action == AUTOSCALE_OUT && d.count == 6 && d.desired == 8,
       "grows to the demand (busy + queued) at once");
    ok(st.demand == 8 && st.peak == 8, "demand and window peak recorded");

    /* ... and keeps that size while the peak is in the window */
    for (i = 0; i < 39; i++) {
        d = tick(&p, &st, now += 15, 8, 1, 2, 20);
        if (d.action != AUTOSCALE_HOLD) break;
    }
    ok(i == 39, "workers needed in the window are kept");
    d = tick(&p, &st, now += 15, 8, 1, 2, 20);
    ok(d.action == AUTOSCALE_IN && d.count == 6 && d.desired == 2,
       "once the peak has left the window, shrinks to what is used");

    /* Requests that had to wait or were refused count as demand */
    autoscale_state_init(&st);
    in = make_input(now, 4, 4, 2, 20);
    in.queued_peak = 3;
    in.rejected = 2;
    d = autoscale_decide(&p, &st, &in);
    ok(d.action == AUTOSCALE_OUT && d.desired == 9, "queued and refused requests count");

    /* The peak between ticks is used, not the snapshot */
    autoscale_state_init(&st);
    in = make_input(now, 4, 0, 2, 20);
    in.busy_peak = 4;
    d = autoscale_decide(&p, &st, &in);
    ok(d.action == AUTOSCALE_HOLD && d.desired == 4, "a burst between ticks is seen");

    /* spare idle workers */
    autoscale_state_init(&st);
    p.spare = 2;
    d = tick(&p, &st, now, 4, 4, 2, 20);
    ok(d.action == AUTOSCALE_OUT && d.count == 2 && d.desired == 6, "spare adds headroom");
    p.spare = 0;

    /* Limits */
    autoscale_state_init(&st);
    d = tick(&p, &st, now, 18, 40, 2, 20);
    ok(d.desired == 20 && d.count == 2, "never above maxWorkers");
    ok(!d.saturated, "not saturated while workers can still be added");
    autoscale_state_init(&st);
    d = tick(&p, &st, now, 20, 25, 2, 20);
    ok(d.saturated && d.action == AUTOSCALE_HOLD,
       "saturated at maxWorkers with requests waiting");
    autoscale_state_init(&st);
    in = make_input(now, 18, 18, 2, 20);
    in.queued_peak = 5;
    in.running = 20;        /* two slots still held by killed workers */
    d = autoscale_decide(&p, &st, &in);
    ok(d.action == AUTOSCALE_HOLD, "no scale-out without a free process slot");
    autoscale_state_init(&st);
    in = make_input(now, 4, 4, 2, 4);
    in.have_stopped = 0;
    in.queued_peak = 2;
    d = autoscale_decide(&p, &st, &in);
    ok(d.action == AUTOSCALE_HOLD, "no scale-out without a stopped worker");
    autoscale_state_init(&st);
    d = tick(&p, &st, now, 6, 0, 5, 20);
    ok(d.action == AUTOSCALE_IN && d.count == 1 && d.desired == 5, "never below minWorkers");
    autoscale_state_init(&st);
    in = make_input(now, 6, 0, 2, 20);
    in.have_idle = 0;
    d = autoscale_decide(&p, &st, &in);
    ok(d.action == AUTOSCALE_HOLD, "no scale-in without an eligible idle worker");

    /* window=0: only the last tick counts */
    autoscale_state_init(&st);
    p.window = 0;
    (void) tick(&p, &st, now, 10, 10, 2, 20);
    d = tick(&p, &st, now += 15, 10, 3, 2, 20);
    ok(d.action == AUTOSCALE_IN && d.desired == 3, "window=0 follows the last tick");
    p.window = 600;

    /* A window longer than the history kept */
    autoscale_state_init(&st);
    p.interval = 1;
    p.window = AUTOSCALE_HIST;
    (void) tick(&p, &st, now, 10, 10, 2, 20);
    for (i = 0; i < AUTOSCALE_HIST - 1; i++) {
        d = tick(&p, &st, ++now, 10, 0, 2, 20);
    }
    ok(d.action == AUTOSCALE_HOLD && d.desired == 10, "peak kept for the whole window");
    d = tick(&p, &st, ++now, 10, 0, 2, 20);
    ok(d.action == AUTOSCALE_IN && d.desired == 2, "ring buffer wraps around");
    autoscale_params_default(&p);

    /* Scale events are recorded */
    autoscale_state_init(&st);
    autoscale_note_out(&st, 1234);
    autoscale_note_in(&st, 1240);
    ok(st.last_out == 1234 && st.last_in == 1240, "scale events recorded");

    /* Choosing the worker to stop */
    {
        AutoscaleCandidate c[4];

        c[0].age = 500; c[0].requests = 10;  c[0].activated = 3;
        c[1].age = 500; c[1].requests = 300; c[1].activated = 5;
        c[2].age = 500; c[2].requests = 300; c[2].activated = 1;
        c[3].age = 10;  c[3].requests = 450; c[3].activated = 9;

        ok(autoscale_pick_victim(c, 4, 60) == 2,
           "victim: most requests, oldest on a tie, skipping young workers");
        ok(autoscale_pick_victim(c, 4, 0) == 3,
           "victim: min_age=0 allows any worker");
        ok(autoscale_pick_victim(c, 0, 60) == -1, "victim: no candidates");
        c[0].age = 5; c[1].age = 5; c[2].age = 5;
        ok(autoscale_pick_victim(c, 4, 60) == -1, "victim: all workers too young");
        c[0].age = -1;
        ok(autoscale_pick_victim(c, 4, 60) == 0, "victim: unknown age is eligible");
        autoscale_params_default(&p);
        ok(p.min_age == 60, "default min_age");
    }

    /* Resource guard */
    {
        autoscale_params_default(&p);
        ok(autoscale_guard(&p, 50.0, 1) == AUTOSCALE_BLOCK_NONE,
           "guard: off by default");
        p.max_load = 4.0;
        ok(autoscale_guard(&p, 4.5, 100000) == AUTOSCALE_BLOCK_LOAD,
           "guard: blocks above max_load");
        ok(autoscale_guard(&p, 3.9, 100000) == AUTOSCALE_BLOCK_NONE,
           "guard: allows below max_load");
        ok(autoscale_guard(&p, -1.0, 100000) == AUTOSCALE_BLOCK_NONE,
           "guard: unknown load never blocks");
        p.min_mem = 512;
        ok(autoscale_guard(&p, 1.0, 300) == AUTOSCALE_BLOCK_MEM,
           "guard: blocks below min_mem");
        ok(autoscale_guard(&p, 1.0, 2000) == AUTOSCALE_BLOCK_NONE,
           "guard: allows above min_mem");
        ok(autoscale_guard(&p, 1.0, -1) == AUTOSCALE_BLOCK_NONE,
           "guard: unknown memory never blocks");

        /* The guard stops a scale-out but not a scale-in */
        autoscale_state_init(&st);
        in = make_input(now + 5000, 4, 4, 0, 8);
        in.queued_peak = 2;
        in.load1 = 9.0;
        d = autoscale_decide(&p, &st, &in);
        ok(d.action == AUTOSCALE_HOLD && d.blocked == AUTOSCALE_BLOCK_LOAD,
           "decide: scale-out blocked by load");
        in.load1 = 1.0;
        in.mem_avail_mb = 100;
        d = autoscale_decide(&p, &st, &in);
        ok(d.action == AUTOSCALE_HOLD && d.blocked == AUTOSCALE_BLOCK_MEM,
           "decide: scale-out blocked by memory");
        in.mem_avail_mb = 4000;
        d = autoscale_decide(&p, &st, &in);
        ok(d.action == AUTOSCALE_OUT && d.blocked == AUTOSCALE_BLOCK_NONE,
           "decide: scale-out allowed when resources are fine");
        autoscale_state_init(&st);
        in = make_input(now + 9000, 4, 0, 0, 8);
        in.load1 = 99.0;
        d = autoscale_decide(&p, &st, &in);
        ok(d.action == AUTOSCALE_IN, "decide: scale-in is never blocked");

        ok(autoscale_parse_loadavg("0.52 0.58 0.59 1/467 12345\n") > 0.51 &&
           autoscale_parse_loadavg("0.52 0.58 0.59 1/467 12345\n") < 0.53,
           "loadavg: parsed");
        ok(autoscale_parse_loadavg("garbage") < 0.0, "loadavg: garbage rejected");
        ok(autoscale_parse_loadavg(NULL) < 0.0, "loadavg: NULL rejected");
        ok(autoscale_parse_meminfo("MemTotal:       16384000 kB\n"
                                   "MemFree:         1000000 kB\n"
                                   "MemAvailable:    8388608 kB\n"
                                   "Buffers:          100000 kB\n") == 8192,
           "meminfo: MemAvailable in MiB");
        ok(autoscale_parse_meminfo("MemTotal: 1 kB\nMemFree: 1 kB\n") == -1,
           "meminfo: missing MemAvailable");
        ok(autoscale_parse_meminfo("MemAvailable: x kB\n") == -1,
           "meminfo: garbage rejected");
        autoscale_params_default(&p);
        ok(autoscale_params_parse(&p, "max_load=6.5,min_mem=1024", err_buf, sizeof(err_buf)) == 0 &&
           p.max_load > 6.4 && p.max_load < 6.6 && p.min_mem == 1024,
           "parse: max_load and min_mem");
    }

    /* Counters for the autoscale command */
    {
        autoscale_params_default(&p);
        autoscale_state_init(&st);
        ok(st.out_events == 0 && st.in_events == 0 && st.blocked_ticks == 0 &&
           st.saturated_ticks == 0, "counters: start at zero");
        autoscale_note_out(&st, 100);
        autoscale_note_out(&st, 101);
        autoscale_note_in(&st, 102);
        ok(st.out_events == 2 && st.in_events == 1, "counters: one event per worker");
        ok(st.last_out == 101 && st.last_in == 102, "counters: times recorded");

        autoscale_state_init(&st);
        in = make_input(now + 20000, 4, 4, 0, 4);
        in.queued_peak = 1;
        d = autoscale_decide(&p, &st, &in);
        d = autoscale_decide(&p, &st, &in);
        ok(st.saturated_ticks == 2, "counters: saturated ticks");

        p.max_load = 1.0;
        autoscale_state_init(&st);
        in = make_input(now + 30000, 4, 4, 0, 8);
        in.queued_peak = 1;
        in.load1 = 5.0;
        d = autoscale_decide(&p, &st, &in);
        ok(st.blocked_ticks == 1 && st.last_desired == 5,
           "counters: blocked ticks and last desired size");
        p.max_load = 0.0;
    }

    /* Parsing the settings of -k */
    {
        char err[128];

        autoscale_params_default(&p);
        ok(autoscale_params_parse(&p, "interval=5,window=900,spare=2", err, sizeof(err)) == 0,
           "parse: valid specification");
        ok(p.interval == 5 && p.window == 900 && p.spare == 2, "parse: values stored");
        autoscale_params_default(&p);
        ok(autoscale_params_parse(&p, "window=0", err, sizeof(err)) == 0 &&
           p.window == 0 && p.interval == 15 && p.spare == 0,
           "parse: other keys keep their defaults");

        ok(autoscale_params_parse(&p, "bogus=1", err, sizeof(err)) < 0 &&
           strstr(err, "bogus") != NULL, "parse: unknown key rejected");
        ok(autoscale_params_parse(&p, "interval", err, sizeof(err)) < 0,
           "parse: missing value rejected");
        ok(autoscale_params_parse(&p, "interval=abc", err, sizeof(err)) < 0,
           "parse: non-numeric value rejected");
        ok(autoscale_params_parse(&p, "interval=2.5", err, sizeof(err)) < 0,
           "parse: fractional integer rejected");
        ok(autoscale_params_parse(&p, "interval=0", err, sizeof(err)) < 0,
           "parse: out of range rejected");
        ok(autoscale_params_parse(&p, "spare=2000", err, sizeof(err)) < 0,
           "parse: spare out of range rejected");
        ok(autoscale_params_parse(&p, "window=nan", err, sizeof(err)) < 0,
           "parse: NaN rejected");
        ok(autoscale_params_parse(&p, "window=inf", err, sizeof(err)) < 0,
           "parse: infinity rejected");
        ok(autoscale_params_parse(&p, "interval=1e30", err, sizeof(err)) < 0,
           "parse: huge integer rejected");
        ok(autoscale_params_parse(&p, "interval=1e1", err, sizeof(err)) == 0 &&
           p.interval == 10, "parse: exponent notation for an integer");
        autoscale_params_default(&p);
        ok(autoscale_params_parse(&p, "interval=1,window=86400", err, sizeof(err)) < 0,
           "parse: window longer than the history for the interval rejected");
        ok(autoscale_params_parse(&p, "interval=15,window=86400", err, sizeof(err)) == 0,
           "parse: a day of window at the default interval");
        autoscale_params_default(&p);
        ok(autoscale_params_parse(&p, "", err, sizeof(err)) < 0,
           "parse: empty specification rejected");
        ok(p.interval == 15 && p.window == 600,
           "parse: failed parse leaves parameters unchanged");
        ok(autoscale_params_parse(&p, "interval=10,,spare=1,", err, sizeof(err)) == 0 &&
           p.interval == 10 && p.spare == 1, "parse: empty items are skipped");
        ok(autoscale_params_parse(&p, "min_age=0", err, sizeof(err)) < 0,
           "parse: min_age is not a key");
    }

    printf("1..%d\n", test_num);
    return failures ? 1 : 0;
}
