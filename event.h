/***********************************************************************
*
* event.h
*
* Abstraction of select call into "event-handling" to make programming
* easier.
*
* Copyright (C) 2001-2003 Roaring Penguin Software Inc.
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
***********************************************************************/

#define DEBUG_EVENT

#ifndef INCLUDE_EVENT_H
#define INCLUDE_EVENT_H 1

struct EventSelector_t;

/* Callback function */
typedef void (*EventCallbackFunc)(struct EventSelector_t *es, 
				 int fd, unsigned int flags,
				 void *data);

#include "eventpriv.h"

/* Create an event selector */
extern EventSelector *Event_CreateSelector(void);

/* Destroy the event selector */
extern void Event_DestroySelector(EventSelector *es);

/* Handle one event */
#ifdef EVENT_USE_POLL
extern int Event_HandleEventUsingPoll(EventSelector *es);
#define Event_HandleEvent Event_HandleEventUsingPoll
#else
extern int Event_HandleEventUsingSelect(EventSelector *es);
#define Event_HandleEvent Event_HandleEventUsingSelect
#endif

/* Add a handler for a ready file descriptor */
extern EventHandler *Event_AddHandler(EventSelector *es,
				      int fd,
				      unsigned int flags,
				      EventCallbackFunc fn, void *data);

/* Add a handler for a ready file descriptor with associated timeout*/
extern EventHandler *Event_AddHandlerWithTimeout(EventSelector *es,
						 int fd,
						 unsigned int flags,
						 struct timeval t,
						 EventCallbackFunc fn,
						 void *data);


/* Add a timer handler */
extern EventHandler *Event_AddTimerHandler(EventSelector *es,
					   struct timeval t,
					   EventCallbackFunc fn,
					   void *data);

/* Delete a handler */
extern int Event_DelHandler(EventSelector *es,
			    EventHandler *eh);

/* Retrieve callback function from a handler */
extern EventCallbackFunc Event_GetCallback(EventHandler *eh);

/* Retrieve data field from a handler */
extern void *Event_GetData(EventHandler *eh);

/* Set callback and data to new values */
extern void Event_SetCallbackAndData(EventHandler *eh,
				     EventCallbackFunc fn,
				     void *data);

extern int Event_EnableDebugging(char const *fname);

extern int set_cloexec(int fd);
extern int set_nonblocking(int fd);

#ifdef DEBUG_EVENT
extern void Event_DebugMsg(char const *fmt, ...);
#define EVENT_DEBUG(x) Event_DebugMsg x
#else
#define EVENT_DEBUG(x) ((void) 0)
#endif

/* Flags */
#define EVENT_FLAG_READABLE 1
#define EVENT_FLAG_WRITEABLE 2
#define EVENT_FLAG_WRITABLE EVENT_FLAG_WRITEABLE

/* This is strictly a timer event */
#define EVENT_FLAG_TIMER 4

/* This is a read or write event with an associated timeout */
#define EVENT_FLAG_TIMEOUT 8

#define EVENT_TIMER_BITS (EVENT_FLAG_TIMER | EVENT_FLAG_TIMEOUT)
#endif
