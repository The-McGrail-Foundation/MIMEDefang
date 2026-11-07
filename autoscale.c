/***********************************************************************
*
* autoscale.c
*
* Decision logic for the adaptive autoscaling of the worker pool of
* mimedefang-multiplexor (-k flag).  See autoscale.h.
*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2.
*
***********************************************************************/

#include "config.h"
#include "autoscale.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/**********************************************************************
* %FUNCTION: autoscale_params_default
* %ARGUMENTS:
*  p -- parameters to initialize
* %RETURNS:
*  Nothing
***********************************************************************/
void
autoscale_params_default(AutoscaleParams *p)
{
    memset(p, 0, sizeof(*p));
    p->interval     = 15;
    p->window       = 600;
    p->spare        = 0;
    p->min_age      = 60;
    p->max_load     = 0.0;
    p->min_mem      = 0;
}

/* Table of the keys understood by autoscale_params_parse() */
#define AS_INT 0
#define AS_DBL 1

typedef struct AutoscaleKey_t {
    char const *name;
    int type;
    size_t off;
    double min;
    double max;
} AutoscaleKey;

static AutoscaleKey const Keys[] = {
    { "interval",     AS_INT, offsetof(AutoscaleParams, interval),     1,    3600 },
    { "window",       AS_INT, offsetof(AutoscaleParams, window),       0,    86400 },
    { "spare",        AS_INT, offsetof(AutoscaleParams, spare),        0,    1024 },
    { "max_load",     AS_DBL, offsetof(AutoscaleParams, max_load),     0.0,  10000.0 },
    { "min_mem",      AS_INT, offsetof(AutoscaleParams, min_mem),      0,    4194304 },
    { NULL, 0, 0, 0, 0 }
};

static void
set_err(char *err, size_t errlen, char const *fmt, char const *a)
{
    if (err && errlen) {
        snprintf(err, errlen, fmt, a ? a : "");
    }
}

/**********************************************************************
* %FUNCTION: autoscale_params_parse
* %ARGUMENTS:
*  p -- parameters to modify
*  spec -- comma-separated list of key=value pairs
*  err, errlen -- buffer for an error message
* %RETURNS:
*  0 on success, -1 on error.  On error, *p is left unchanged.
***********************************************************************/
int
autoscale_params_parse(AutoscaleParams *p, char const *spec,
                       char *err, size_t errlen)
{
    AutoscaleParams tmp = *p;
    char buf[512];
    char *tok;
    char *save;
    char *eq;
    char *end;
    int i;
    int found;
    double v;

    if (!spec || !*spec) {
        set_err(err, errlen, "empty specification%s", NULL);
        return -1;
    }
    if (strlen(spec) >= sizeof(buf)) {
        set_err(err, errlen, "specification too long%s", NULL);
        return -1;
    }
    strcpy(buf, spec);

    for (tok = buf; tok; tok = save) {
        save = strchr(tok, ',');
        if (save) {
            *save++ = 0;
        }
        if (!*tok) {
            continue;
        }
        eq = strchr(tok, '=');
        if (!eq || eq == tok || !eq[1]) {
            set_err(err, errlen, "expected key=value, got '%s'", tok);
            return -1;
        }
        *eq++ = 0;

        found = 0;
        for (i = 0; Keys[i].name; i++) {
            if (strcmp(Keys[i].name, tok)) {
                continue;
            }
            found = 1;
            errno = 0;
            v = strtod(eq, &end);
            if (end == eq || *end || errno) {
                set_err(err, errlen, "invalid value for '%s'", tok);
                return -1;
            }
            /* Written so that NaN fails it too, and checked before the
               value is converted to an integer below. */
            if (!(v >= Keys[i].min && v <= Keys[i].max)) {
                set_err(err, errlen, "value out of range for '%s'", tok);
                return -1;
            }
            if (Keys[i].type == AS_INT && v != (double) (int) v) {
                set_err(err, errlen, "invalid value for '%s'", tok);
                return -1;
            }
            if (Keys[i].type == AS_INT) {
                *(int *) ((char *) &tmp + Keys[i].off) = (int) v;
            } else {
                *(double *) ((char *) &tmp + Keys[i].off) = v;
            }
            break;
        }
        if (!found) {
            set_err(err, errlen, "unknown key '%s'", tok);
            return -1;
        }
    }

    if (tmp.window / tmp.interval > AUTOSCALE_HIST) {
        set_err(err, errlen, "'window' is too long for 'interval'%s", NULL);
        return -1;
    }

    *p = tmp;
    return 0;
}

/**********************************************************************
* %FUNCTION: autoscale_state_init
* %ARGUMENTS:
*  st -- state to initialize
* %RETURNS:
*  Nothing
***********************************************************************/
void
autoscale_state_init(AutoscaleState *st)
{
    memset(st, 0, sizeof(*st));
}

void
autoscale_note_out(AutoscaleState *st, time_t now)
{
    st->last_out = now;
    st->out_events++;
}

void
autoscale_note_in(AutoscaleState *st, time_t now)
{
    st->last_in = now;
    st->in_events++;
}

int
autoscale_guard(AutoscaleParams const *p, double load1, int mem_avail_mb)
{
    if (p->max_load > 0.0 && load1 >= 0.0 && load1 > p->max_load) {
        return AUTOSCALE_BLOCK_LOAD;
    }
    if (p->min_mem > 0 && mem_avail_mb >= 0 && mem_avail_mb < p->min_mem) {
        return AUTOSCALE_BLOCK_MEM;
    }
    return AUTOSCALE_BLOCK_NONE;
}

double
autoscale_parse_loadavg(char const *text)
{
    double v;
    char *end;

    if (!text) {
        return -1.0;
    }
    v = strtod(text, &end);
    if (end == text || v < 0.0) {
        return -1.0;
    }
    return v;
}

int
autoscale_parse_meminfo(char const *text)
{
    char const *line;
    long kb;
    char *end;

    if (!text) {
        return -1;
    }
    line = text;
    while (line && *line) {
        if (!strncmp(line, "MemAvailable:", 13)) {
            kb = strtol(line + 13, &end, 10);
            if (end == line + 13 || kb < 0) {
                return -1;
            }
            return (int) (kb / 1024);
        }
        line = strchr(line, '\n');
        if (line) {
            line++;
        }
    }
    return -1;
}

int
autoscale_victim_better(AutoscaleCandidate const *c,
                        AutoscaleCandidate const *best, int min_age)
{
    if (c->age >= 0 && c->age < min_age) {
        return 0;
    }
    return (!best
            || c->requests > best->requests
            || (c->requests == best->requests
                && c->activated < best->activated));
}

int
autoscale_pick_victim(AutoscaleCandidate const *c, int n, int min_age)
{
    int i, best = -1;

    for (i = 0; i < n; i++) {
        if (autoscale_victim_better(&c[i], best < 0 ? NULL : &c[best], min_age)) {
            best = i;
        }
    }
    return best;
}

static int
clamp_int(int v, int lo, int hi)
{
    if (v > hi) v = hi;
    if (v < lo) v = lo;
    return v;
}

/**********************************************************************
* %FUNCTION: autoscale_decide
* %ARGUMENTS:
*  p -- parameters
*  st -- state (the demand history is updated)
*  in -- what the multiplexor observed
* %RETURNS:
*  What to do.
* %DESCRIPTION:
*  The demand at each tick is the highest number of busy workers seen
*  since the previous tick, plus the requests that had to wait in the
*  queue or were refused.  Peaks are used rather than a snapshot so that
*  a burst between two ticks is not missed.
*
*  The pool is sized for the highest demand of the last p->window
*  seconds, plus p->spare idle workers, within [min_workers,
*  max_workers].  Below that size workers are started; above it the
*  surplus idle workers are stopped.
*
*  A request that finds no free worker starts one anyway, so the pool
*  always follows a rise in demand.  What the window adds is memory:
*  workers that the load has needed recently are kept instead of being
*  reaped by the idle timeout and started again at the next burst, while
*  the pool still shrinks to what is used once the window has passed.
*  The pool kept is bounded by the demand actually seen, never by
*  max_workers alone.  With window=0 only the demand of the last tick
*  counts.
***********************************************************************/
AutoscaleDecision
autoscale_decide(AutoscaleParams const *p,
                 AutoscaleState *st,
                 AutoscaleInput const *in)
{
    AutoscaleDecision d;
    int demand, target, ticks, i, k, n, room;

    d.action = AUTOSCALE_HOLD;
    d.count = 0;
    d.desired = in->live;
    d.saturated = 0;
    d.blocked = AUTOSCALE_BLOCK_NONE;

    demand = in->busy_peak + in->queued_peak + in->rejected;
    if (demand < 0) {
        demand = 0;
    }
    st->demand = demand;

    /* Highest demand over the window, this tick included */
    st->hist[st->hist_pos] = demand;
    st->hist_pos = (st->hist_pos + 1) % AUTOSCALE_HIST;
    if (st->hist_n < AUTOSCALE_HIST) {
        st->hist_n++;
    }
    ticks = (p->interval > 0) ? p->window / p->interval : 0;
    if (ticks < 1) ticks = 1;
    if (ticks > st->hist_n) ticks = st->hist_n;
    st->peak = 0;
    for (i = 0; i < ticks; i++) {
        k = (st->hist_pos - 1 - i + AUTOSCALE_HIST) % AUTOSCALE_HIST;
        if (st->hist[k] > st->peak) {
            st->peak = st->hist[k];
        }
    }

    /* Both terms are bounded (pool sizes and spare <= 1024), so the sum
       cannot overflow */
    target = clamp_int(clamp_int(st->peak, 0, in->max_workers) + p->spare,
                       in->min_workers, in->max_workers);
    d.desired = target;

    d.saturated = (in->max_workers > 0
                   && in->busy_peak >= in->max_workers
                   && (in->queued_peak + in->rejected) > 0);
    st->last_desired = d.desired;
    if (d.saturated) {
        st->saturated_ticks++;
    }

    if (in->live < target
        && in->running < in->max_workers
        && in->have_stopped) {
        /* Do not make an overloaded machine worse */
        d.blocked = autoscale_guard(p, in->load1, in->mem_avail_mb);
        if (d.blocked != AUTOSCALE_BLOCK_NONE) {
            st->blocked_ticks++;
        } else {
            n = target - in->live;
            room = in->max_workers - in->running;
            if (n > room) n = room;
            d.action = AUTOSCALE_OUT;
            d.count = n;
        }
    } else if (in->live > target && in->have_idle) {
        d.action = AUTOSCALE_IN;
        d.count = in->live - target;
    }
    return d;
}
