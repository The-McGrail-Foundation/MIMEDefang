/***********************************************************************
*
*  JSON_OUT.C
*
*  Minimal streaming JSON writer on top of dynamic buffers.  Used by
*  the multiplexor to answer the json* control commands.
*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2.
*
***********************************************************************/

#include "json_out.h"
#include <stdio.h>
#include <string.h>

static void
put(json_writer *jw, char const *s)
{
    if (!jw->err && dbuf_puts(&jw->buf, s) < 0) {
	    jw->err = 1;
    }
}

static void
putc_(json_writer *jw, char c)
{
    if (!jw->err && dbuf_putc(&jw->buf, c) < 0) {
	    jw->err = 1;
    }
}

/**********************************************************************
* %FUNCTION: put_escaped
* %ARGUMENTS:
*  jw -- writer
*  s -- string to emit as a quoted JSON string
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Escapes quotes, backslashes and control characters.  Bytes >= 0x80
*  are passed through unchanged (UTF-8).  '%' is written as % so
*  that clients which percent-decode multiplexor answers (md-mx-ctrl)
*  cannot alter the JSON text.
***********************************************************************/
static void
put_escaped(json_writer *jw, char const *s)
{
    char tmp[8];
    unsigned char c;

    putc_(jw, '"');
    if (s) {
        while ((c = (unsigned char) *s++) != 0) {
            switch (c) {
                case '"':  put(jw, "\\\""); break;
                case '\\': put(jw, "\\\\"); break;
                case '\n': put(jw, "\\n");  break;
                case '\r': put(jw, "\\r");  break;
                case '\t': put(jw, "\\t");  break;
                default:
                if (c < 0x20 || c == 0x7f || c == '%') {
                    sprintf(tmp, "\\u%04x", (unsigned int) c);
                    put(jw, tmp);
                } else {
                    putc_(jw, (char) c);
                }
            }
        }
    }
    putc_(jw, '"');
}

/* Emit separator and optional key before a value */
static void
prefix(json_writer *jw, char const *key)
{
    if (jw->need_comma[jw->depth]) {
	    putc_(jw, ',');
    }
    jw->need_comma[jw->depth] = 1;
    if (key) {
	    put_escaped(jw, key);
	    putc_(jw, ':');
    }
}

void
json_init(json_writer *jw)
{
    dbuf_init(&jw->buf);
    jw->err = 0;
    jw->depth = 0;
    memset(jw->need_comma, 0, sizeof(jw->need_comma));
}

void
json_free(json_writer *jw)
{
    dbuf_free(&jw->buf);
}

static void
open_(json_writer *jw, char const *key, char c)
{
    prefix(jw, key);
    putc_(jw, c);
    if (jw->depth >= JSON_MAX_DEPTH - 1) {
	    jw->err = 1;
	    return;
    }
    jw->depth++;
    jw->need_comma[jw->depth] = 0;
}

static void
close_(json_writer *jw, char c)
{
    if (jw->depth <= 0) {
	    jw->err = 1;
	    return;
    }
    jw->depth--;
    putc_(jw, c);
}

void json_obj_begin(json_writer *jw, char const *key) { open_(jw, key, '{'); }
void json_obj_end(json_writer *jw)                    { close_(jw, '}'); }
void json_arr_begin(json_writer *jw, char const *key) { open_(jw, key, '['); }
void json_arr_end(json_writer *jw)                    { close_(jw, ']'); }

void
json_str(json_writer *jw, char const *key, char const *val)
{
    prefix(jw, key);
    if (val) {
	    put_escaped(jw, val);
    } else {
	    put(jw, "null");
    }
}

void
json_int(json_writer *jw, char const *key, long val)
{
    char tmp[32];
    prefix(jw, key);
    sprintf(tmp, "%ld", val);
    put(jw, tmp);
}

void
json_dbl(json_writer *jw, char const *key, double val, int prec)
{
    char tmp[64];
    prefix(jw, key);
    /* NaN and +/-Inf are not valid JSON; NaN != NaN */
    if (val != val || val > 1e300 || val < -1e300) {
	    val = 0.0;
    }
    if (prec < 0) prec = 0;
    if (prec > 6) prec = 6;
    sprintf(tmp, "%.*f", prec, val);
    put(jw, tmp);
}

void
json_bool(json_writer *jw, char const *key, int val)
{
    prefix(jw, key);
    put(jw, val ? "true" : "false");
}

char const *
json_finish(json_writer *jw)
{
    if (jw->depth != 0) {
	    jw->err = 1;
    }
    putc_(jw, '\n');
    if (jw->err) {
	    return NULL;
    }
    return DBUF_VAL(&jw->buf);
}
