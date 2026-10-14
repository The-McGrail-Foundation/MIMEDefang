/***********************************************************************
*
*  JSON_OUT.H
*
*  Minimal streaming JSON writer on top of dynamic buffers.
*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2.
*
***********************************************************************/

#ifndef JSON_OUT_H
#define JSON_OUT_H

#include "dynbuf.h"

#define JSON_MAX_DEPTH 16

typedef struct {
    dynamic_buffer buf;
    int err;                          /* Sticky: set on OOM or misuse */
    int depth;                        /* Current nesting depth        */
    int need_comma[JSON_MAX_DEPTH];   /* Per-level "element written"  */
} json_writer;

/* A json_writer embeds a dynamic_buffer and must not be copied. */
void json_init(json_writer *jw);
void json_free(json_writer *jw);

/* "key" is NULL for array elements and for the top-level value. */
void json_obj_begin(json_writer *jw, char const *key);
void json_obj_end(json_writer *jw);
void json_arr_begin(json_writer *jw, char const *key);
void json_arr_end(json_writer *jw);

void json_str(json_writer *jw, char const *key, char const *val);
void json_int(json_writer *jw, char const *key, long val);
void json_dbl(json_writer *jw, char const *key, double val, int prec);
void json_bool(json_writer *jw, char const *key, int val);

/* Append a final newline and return the text, or NULL on error. */
char const *json_finish(json_writer *jw);

#endif /* JSON_OUT_H */
