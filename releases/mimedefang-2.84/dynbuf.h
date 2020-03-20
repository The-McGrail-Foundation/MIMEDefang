/***************************************************************/
/*                                                             */
/*  DYNBUF.H                                                   */
/*                                                             */
/*  Declaration of functions for manipulating dynamic buffers  */
/*                                                             */
/*  This file was part of REMIND.                              */
/*  Copyright (C) 1992-1998 by Dianne Skoll                    */
/*  Copyright (C) 1999-2007 by Roaring Penguin Software Inc.   */
/*                                                             */
/***************************************************************/

#ifndef DYNBUF_H
#define DYNBUF_H

#define DBUF_STATIC_SIZE 4096
typedef struct {
    char *buffer;
    int len;
    int allocated_len;
    char static_buf[DBUF_STATIC_SIZE];
} dynamic_buffer;

void dbuf_init(dynamic_buffer *dbuf);
int dbuf_putc(dynamic_buffer *dbuf, char const c);
int dbuf_puts(dynamic_buffer *dbuf, char const *str);
void dbuf_free(dynamic_buffer *dbuf);

#define DBUF_VAL(buf_ptr) ((buf_ptr)->buffer)
#define DBUF_LEN(buf_ptr) ((buf_ptr)->len)

#endif /* DYNBUF_H */
