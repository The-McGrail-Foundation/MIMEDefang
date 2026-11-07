/***********************************************************************
*
* autoscale.h
*
* Decision logic for the adaptive autoscaling of the worker pool of
* mimedefang-multiplexor (-k flag).  This code is deliberately free of
* any I/O, signal or event-loop dependency so that it can be unit
* tested (see t/test_autoscale.c).
*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2.
*
***********************************************************************/

#ifndef MD_AUTOSCALE_H
#define MD_AUTOSCALE_H 1

#include <stddef.h>
#include <time.h>

/* Tunable parameters */
typedef struct AutoscaleParams_t {
    int    interval;       /* Seconds between autoscale checks          */
    int    window;         /* Keep as many workers as the highest demand
                              seen in the last window seconds           */
    int    spare;          /* Idle workers to keep as headroom          */
    int    min_age;        /* Never stop a worker younger than this (s) */
    double max_load;       /* No scale-out above this 1-min load (0=off)*/
    int    min_mem;        /* No scale-out below this many MiB of available
                              memory (0 = off)                          */
} AutoscaleParams;

/* Ticks of demand kept: window / interval may not exceed this */
#define AUTOSCALE_HIST 8192

/* Runtime state */
typedef struct AutoscaleState_t {
    time_t last_out;       /* Time of last scale-out (0 = never)        */
    time_t last_in;        /* Time of last scale-in (0 = never)         */
    int demand;            /* Demand at the last tick, in workers       */
    int peak;              /* Highest demand in the window              */
    int hist[AUTOSCALE_HIST]; /* Demand at each tick (ring buffer)      */
    int hist_n;            /* Entries used in hist                      */
    int hist_pos;          /* Next entry to write                       */
    unsigned long out_events;   /* Workers started while autoscaling    */
    unsigned long in_events;    /* Workers stopped by the autoscaler    */
    unsigned long blocked_ticks;   /* Ticks where the guard stopped a
                                      scale-out                         */
    unsigned long saturated_ticks; /* Ticks where demand hit maxWorkers */
    int last_desired;      /* Pool size the last tick called for        */
} AutoscaleState;

/* What the multiplexor observed at this tick */
typedef struct AutoscaleInput_t {
    time_t now;
    int running;           /* Idle + busy + killed workers (process slots) */
    int live;              /* Idle + busy workers (able to take work)   */
    int busy;              /* Busy workers right now                    */
    int busy_peak;         /* Highest number of busy workers since the
                              previous tick (>= busy)                   */
    int queued_peak;       /* Highest number of queued requests since the
                              previous tick                             */
    int rejected;          /* Requests refused for lack of a worker since
                              the previous tick                         */
    int min_workers;       /* -m                                        */
    int max_workers;       /* -x                                        */
    int have_stopped;      /* Is a stopped worker available?            */
    int have_idle;         /* Is an idle worker available?              */
    double load1;          /* 1-minute load average, or < 0 if unknown  */
    int mem_avail_mb;      /* Available memory in MiB, or < 0 if unknown*/
} AutoscaleInput;

#define AUTOSCALE_HOLD 0
#define AUTOSCALE_OUT  1
#define AUTOSCALE_IN   2

typedef struct AutoscaleDecision_t {
    int action;            /* AUTOSCALE_HOLD, _OUT or _IN               */
    int count;             /* Number of workers to start or stop        */
    int desired;           /* Pool size the window calls for            */
    int saturated;         /* Demand exceeds maxWorkers                 */
    int blocked;           /* AUTOSCALE_BLOCK_*: why a scale-out was not
                              done                                      */
} AutoscaleDecision;

#define AUTOSCALE_BLOCK_NONE 0
#define AUTOSCALE_BLOCK_LOAD 1
#define AUTOSCALE_BLOCK_MEM  2

/* Would starting a worker now overload the machine?  Returns
   AUTOSCALE_BLOCK_NONE, _LOAD or _MEM.  Unknown values never block. */
int autoscale_guard(AutoscaleParams const *p, double load1, int mem_avail_mb);

/* Parse the text of /proc/loadavg: returns the 1-minute load, or -1.0. */
double autoscale_parse_loadavg(char const *text);

/* Parse the text of /proc/meminfo: returns MemAvailable in MiB, or -1. */
int autoscale_parse_meminfo(char const *text);

void autoscale_params_default(AutoscaleParams *p);

/* Parse the settings of "-k":  comma-separated key=value pairs, for example
   "window=900,spare=1".  Only the keys named are changed.
   Returns 0 on success; on error returns -1 and writes a message to err. */
int  autoscale_params_parse(AutoscaleParams *p, char const *spec,
                            char *err, size_t errlen);
void autoscale_state_init(AutoscaleState *st);

/* Update the state with the new observation and decide what to do. */
AutoscaleDecision autoscale_decide(AutoscaleParams const *p,
                                   AutoscaleState *st,
                                   AutoscaleInput const *in);

/* An idle worker that could be stopped by a scale-in */
typedef struct AutoscaleCandidate_t {
    int age;               /* Seconds since activation (-1 = unknown)   */
    int requests;          /* Requests handled so far                   */
    unsigned int activated;/* Activation order (lower = older)          */
} AutoscaleCandidate;

/* Pick the worker to stop: among those at least min_age seconds old, the one
   that has handled the most requests (it is the closest to being recycled
   anyway and has had the most time to grow), the oldest on a tie.  Returns
   its index, or -1 if none is eligible. */
int autoscale_pick_victim(AutoscaleCandidate const *c, int n, int min_age);

/* The rule used by autoscale_pick_victim(): is c eligible and a better
   victim than best (NULL if there is none yet)? */
int autoscale_victim_better(AutoscaleCandidate const *c,
                            AutoscaleCandidate const *best, int min_age);

/* The caller reports scale events it actually carried out: one call per
   worker started or stopped. */
void autoscale_note_out(AutoscaleState *st, time_t now);
void autoscale_note_in(AutoscaleState *st, time_t now);

#endif
