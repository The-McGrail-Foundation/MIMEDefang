/***********************************************************************
*
* notifier.c
*
* Notification routines for multiplexor
*
* Copyright (C) 2002-2005 Roaring Penguin Software Inc.
* http://www.roaringpenguin.com
*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2.
*
***********************************************************************/

#include "config.h"
#include "event_tcp.h"
#include "mimedefang.h"
#include <syslog.h>
#include <string.h>
#include <stdio.h>

#define MAX_LISTENERS 5
#define MAX_MSGLEN 256
#define NUM_MSG_TYPES 26  /* Message types range from 'A' to 'Z' */
typedef struct Listener_t {
    int fd;
    char msg[MAX_MSGLEN+1];
    char msg_types[NUM_MSG_TYPES];
    EventTcpState *read_ev;
    EventTcpState *write_ev;
} Listener;

static int ListenersInitialized = 0;

static void handle_notifier_accept(EventSelector *es, int fd);

extern EventTcpState *reply_to_mimedefang(EventSelector *es,
					  int fd,
					  char const *msg);
static void notify(EventSelector *es, Listener *l, char const *msg);
static void notify_complete(EventSelector *es, int fd, char *buf,
			    int len, int flag, void *data);
static void handle_notify_input(EventSelector *es, int fd, char *buf,
				int len, int flag, void *data);
static void close_listener(Listener *l);
static EventTcpState *setup_read_event(Listener *l, EventSelector *es);

void notify_listeners(EventSelector *es, char const *msg);

Listener listeners[MAX_LISTENERS];

/**********************************************************************
* %FUNCTION: make_notifier_socket
* %ARGUMENTS:
*  es -- an EventSelector
*  name -- name of socket to create
* %DESCRIPTION:
*  Makes a listening socket for programs that want notifications to connect to
* %RETURNS:
*  0 on success; -1 on failure.
***********************************************************************/
int
make_notifier_socket(EventSelector *es, char const *name)
{
    int sock;
    int i;

    sock = make_listening_socket(name, 5, 0);
    if (sock < 0) {
	return -1;
    }
    set_cloexec(sock);
    if (!EventTcp_CreateAcceptor(es, sock, handle_notifier_accept)) {
	syslog(LOG_ERR, "Could not listen for notifier requests: EventTcp_CreateAcceptor: %m");
	close(sock);
	return -1;
    }

    /* Initialize listeners */
    for (i=0; i<MAX_LISTENERS; i++) {
	listeners[i].fd = -1;
	listeners[i].msg[0] = 0;
	memset(listeners[i].msg_types, 0, NUM_MSG_TYPES);
	listeners[i].read_ev = NULL;
	listeners[i].write_ev = NULL;
    }
    ListenersInitialized = 1;

    return 0;
}

/**********************************************************************
* %FUNCTION: handle_notifier_accept
* %ARGUMENTS:
*  es -- an EventSelector
*  fd -- file descriptor
* %DESCRIPTION:
*  Called when someone connects to the notifier socket.  Sends a banner
*  and adds descriptor to list of listeners.
* %RETURNS:
*  Nothing
***********************************************************************/
void
handle_notifier_accept(EventSelector *es, int fd) {
    int i;
    Listener *l = NULL;

    /* Find a free listener slot */
    for (i=0; i<MAX_LISTENERS; i++) {
	if (listeners[i].fd == -1) {
	    l = &listeners[i];
	    break;
	}
    }

    /* No free slot -- send error message back */
    if (!l) {
	reply_to_mimedefang(es, fd, "*ERR No free listening slots\n");
	return;
    }
    l->fd = fd;
    memset(l->msg_types, 0, NUM_MSG_TYPES);
    l->msg[0] = 0;
    l->write_ev = NULL;

    /* Try making a read event */
    if (!setup_read_event(l, es)) {
	return;
    }

    /* Issue banner */
    notify(es, l, "*OK\n");
}

/**********************************************************************
* %FUNCTION: close_listener
* %ARGUMENTS:
*  l -- listener who needs closing
* %DESCRIPTION:
*  Closes a listener
* %RETURNS:
*  Nothing
***********************************************************************/
static void
close_listener(Listener *l)
{
    if (l->read_ev) {
	EventTcp_CancelPending(l->read_ev);
	l->read_ev = NULL;
    }
    if (l->write_ev) {
	EventTcp_CancelPending(l->write_ev);
	l->write_ev = NULL;
    }
    l->msg[0] = 0;
    if (l->fd >= 0) {
	close(l->fd);
	l->fd = -1;
    }
}

/**********************************************************************
* %FUNCTION: notify
* %ARGUMENTS:
*  es -- an EventSelector
*  l -- listener who needs notification
*  msg -- message to send to listener
* %DESCRIPTION:
*  Sends a message to listener.
* %RETURNS:
*  Nothing
***********************************************************************/
static void
notify(EventSelector *es, Listener *l, char const *msg)
{
    EventTcpState *e;
    size_t len = strlen(msg);

    if (l->fd < 0) {
	return;
    }

    /* Are we interested in this message type? */
    if (*msg >= 'A' && *msg <= 'Z' && !l->msg_types[(*msg)-'A']) {
	return;
    }

    /* If busy: Save message for later! */
    if (l->write_ev) {
	/* If room to append, append it; otherwise replace all messages */
	if (strlen(l->msg) + len <= MAX_MSGLEN) {
	    strcat(l->msg, msg);
	    return;
	}

	if (strlen(msg) > MAX_MSGLEN) {
	    return;
	}
	strcpy(l->msg, msg);
	return;
    }
    e = EventTcp_WriteBuf(es, l->fd, msg, strlen(msg), notify_complete,
			  10, l);
    if (!e) {
	syslog(LOG_ERR, "notify failed: EventTcp_WriteBuf: %m");
	close_listener(l);
	return;
    }
    l->write_ev = e;
}

/**********************************************************************
* %FUNCTION: notify_complete
* %ARGUMENTS:
*  es -- an EventSelector
*  fd -- file descriptor
*  buf -- buffer that was written to listener
*  len -- amount of data writeen to listener
*  flag -- flag indicating what happened
*  data -- the listener
* %DESCRIPTION:
*  Called when a message has been sent to the listener
* %RETURNS:
*  Nothing
***********************************************************************/
static void
notify_complete(EventSelector *es, int fd, char *buf,
		int len, int flag, void *data)
{
    Listener *l = (Listener *) data;
    l->write_ev = NULL;

    if (flag == EVENT_TCP_FLAG_TIMEOUT || flag == EVENT_TCP_FLAG_IOERROR) {
	close_listener(l);
	return;
    }
    if (l->msg[0]) {
	/* Queued message -- send it now */
	notify(es, l, l->msg);
	l->msg[0] = 0;
    }
}

static EventTcpState *
setup_read_event(Listener *l, EventSelector *es)
{
    l->read_ev = EventTcp_ReadBuf(es, l->fd, MAX_MSGLEN, '\n',
				  handle_notify_input, 0, 1, l);
    if (!l->read_ev) {
	reply_to_mimedefang(es, l->fd, "*ERR Unable to make reader event\n");
	l->fd = -1;
	close_listener(l);
    }
    return l->read_ev;
}

/**********************************************************************
* %FUNCTION: handle_notify_input
* %ARGUMENTS:
*  es -- an EventSelector
*  fd -- file descriptor
*  buf -- buffer that was written to listener
*  len -- amount of data writeen to listener
*  flag -- flag indicating what happened
*  data -- the listener
* %DESCRIPTION:
*  Called when a message has been sent *from* the listener
* %RETURNS:
*  Nothing
***********************************************************************/
static void
handle_notify_input(EventSelector *es, int fd, char *buf,
		    int len, int flag, void *data)
{
    Listener *l = (Listener *) data;
    char *s;

    l->read_ev = NULL;
    if (flag == EVENT_TCP_FLAG_TIMEOUT || flag == EVENT_TCP_FLAG_IOERROR) {
	close_listener(l);
	return;
    }

    /* EOF? */
    if (!len) {
	close_listener(l);
	return;
    }

    /* Null-terminate buffer */
    buf[len-1] = 0;
    len--;

    /* Only accept "?" command */
    if (buf[0] != '?') {
	setup_read_event(l, es);
	return;
    }

    memset(l->msg_types, 0, NUM_MSG_TYPES);

    s = buf+1;
    while(*s) {
	if (*s >= 'A' && *s <= 'Z') {
	    l->msg_types[(*s) - 'A'] = 1;
	}
	if (*s == '*') {
	    memset(l->msg_types, 1, NUM_MSG_TYPES);
	}
	s++;
    }
    setup_read_event(l, es);
}

/**********************************************************************
* %FUNCTION: notify_listeners
* %ARGUMENTS:
*  es -- event selector
*  msg -- message to send to all listeners
* %DESCRIPTION:
*  Notifies all listeners of a message
* %RETURNS:
*  Nothing
***********************************************************************/
void
notify_listeners(EventSelector *es, char const *msg)
{
    int i;
    if (!ListenersInitialized) return;

    for (i=0; i<MAX_LISTENERS; i++) {
	if (listeners[i].fd >= 0) {
	    notify(es, &listeners[i], msg);
	}
    }
}

/**********************************************************************
* %FUNCTION: notify_worker_status
* %ARGUMENTS:
*  es -- event selector
*  workerno -- worker number
*  msg -- worker's new status
* %DESCRIPTION:
*  Notifies all listeners of a message
* %RETURNS:
*  Nothing
***********************************************************************/
void
notify_worker_status(EventSelector *es, int workerno, char const *msg)
{
    char buf[256];

    if (!ListenersInitialized) return;
    if (!msg || !*msg) {
	return;
    }
    snprintf(buf, sizeof(buf), "S %d %.200s\n", workerno, msg);
    notify_listeners(es, buf);
}

void
notify_worker_state_change(EventSelector *es, int workerno,
			  char const *old_state, char const *new_state)
{
    char buf[256];
    if (!ListenersInitialized) return;
    snprintf(buf, sizeof(buf), "S %d StateChange %s -> %s\n",
	     workerno, old_state, new_state);
    notify_listeners(es, buf);
}
