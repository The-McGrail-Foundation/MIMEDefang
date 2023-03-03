/*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2.
*/

#include "mimedefang.h"
#include <pthread.h>

/* Our identifiers are in base-60 */
#define BASE 60

/* Our time-based identifier is 5 base-60 characters.
   TIMESPAN below is 60^5 */
#define TIMESPAN (BASE*BASE*BASE*BASE*BASE)

#define COUNTER_MOD (BASE*BASE)

/* Counter incremented each time gen_id is called */
static unsigned int id_counter = 0;

/* Mutex to protect id_counter */
static pthread_mutex_t id_counter_mutex = PTHREAD_MUTEX_INITIALIZER;

/* This had better be 60 characters long! */
static char const char_map[BASE] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX";

char *
gen_mx_id(char *out)
{
    unsigned int counter, time_part;
    int i;

    pthread_mutex_lock(&id_counter_mutex);
    counter = id_counter++;
    pthread_mutex_unlock(&id_counter_mutex);

    time_part = ((unsigned int) time(NULL)) % TIMESPAN;

    for (i=4; i>=0; i--) {
	out[i] = char_map[time_part % BASE];
	time_part /= BASE;
    }

    for (i=6; i>=5; i--) {
	out[i] = char_map[counter % BASE];
	counter /= BASE;
    }
    out[MX_ID_LEN] = 0;
    return out;
}
