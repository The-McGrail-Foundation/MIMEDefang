/***************************************************************/
/*                                                             */
/*  DYNBUF.C                                                   */
/*                                                             */
/*  Implementation of functions for manipulating dynamic       */
/*  buffers.                                                   */
/*                                                             */
/*  This file was part of REMIND.                              */
/*  Copyright (C) 1992-1998 by Dianne Skoll                    */
/*  Copyright (C) 1999-2007 by Roaring Penguin Software Inc.   */
/*                                                             */
/***************************************************************/

#include "dynbuf.h"
#include <stdlib.h>
#include <string.h>

/**********************************************************************
%FUNCTION: dbuf_makeroom
%ARGUMENTS:
 dbuf -- pointer to a dynamic buffer
 n -- size to expand to
%RETURNS:
 0 if all went well, -1 otherwise.
%DESCRIPTION:
 Doubles the size of dynamic buffer until it has room for at least
 'n' characters, not including trailing '\0'
**********************************************************************/
static int
dbuf_makeroom(dynamic_buffer *dbuf, int n)
{
    /* Double size until it's greater than n (strictly > to leave room
       for trailing '\0' */
    int size = dbuf->allocated_len;
    char *buf;

    if (size > n) return 0;

    while (size <= n) {
	size *= 2;
    }

    /* Allocate memory */
    buf = (char *) malloc(size);
    if (!buf) return -1;

    /* Copy contents */
    strcpy(buf, dbuf->buffer);

    /* Free old contents if necessary */
    if (dbuf->buffer != dbuf->static_buf) free(dbuf->buffer);
    dbuf->buffer = buf;
    dbuf->allocated_len = size;
    return 0;
}

/**********************************************************************
%FUNCTION: dbuf_init
%ARGUMENTS:
 dbuf -- pointer to a dynamic buffer
%RETURNS:
 Nothing
%DESCRIPTION:
 Initializes a dynamic buffer
**********************************************************************/
void
dbuf_init(dynamic_buffer *dbuf)
{
    dbuf->buffer = dbuf->static_buf;
    dbuf->len = 0;
    dbuf->allocated_len = DBUF_STATIC_SIZE;
    dbuf->buffer[0] = 0;
}

/**********************************************************************
%FUNCTION: dbuf_putc
%ARGUMENTS:
 dbuf -- pointer to a dynamic buffer
 c -- character to append to buffer
%RETURNS:
 0 if all went well; -1 if out of memory
%DESCRIPTION:
 Appends a character to the buffer.
**********************************************************************/
int
dbuf_putc(dynamic_buffer *dbuf, char const c)
{
    if (dbuf->allocated_len <= dbuf->len+1) {
	if (dbuf_makeroom(dbuf, dbuf->len+1) != 0) return -1;
    }
    dbuf->buffer[dbuf->len++] = c;
    dbuf->buffer[dbuf->len] = 0;
    return 0;
}

/**********************************************************************
%FUNCTION: dbuf_puts
%ARGUMENTS:
 dbuf -- pointer to a dynamic buffer
 str -- string to append to buffer
%RETURNS:
 OK if all went well; E_NO_MEM if out of memory
%DESCRIPTION:
 Appends a string to the buffer.
**********************************************************************/
int
dbuf_puts(dynamic_buffer *dbuf, char const *str)
{
    int l = strlen(str);
    if (!l) return 0;

    if (dbuf->allocated_len <= dbuf->len + l) {
	if (dbuf_makeroom(dbuf, dbuf->len+l) != 0) return -1;
    }
    strcpy((dbuf->buffer+dbuf->len), str);
    dbuf->len += l;
    return 0;
}

/**********************************************************************
%FUNCTION: dbuf_free
%ARGUMENTS:
 dbuf -- pointer to a dynamic buffer
%RETURNS:
 Nothing
%DESCRIPTION:
 Frees and reinitializes a dynamic buffer
**********************************************************************/
void
dbuf_free(dynamic_buffer *dbuf)
{
    if (dbuf->buffer != dbuf->static_buf) free(dbuf->buffer);
    dbuf_init(dbuf);
}
