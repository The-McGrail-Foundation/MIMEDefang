/***********************************************************************
*
* milter_cap.h
*
* Determine capabilities of libmilter we're building against.
*
* Copyright (C) 2006 by Roaring Penguin Software Inc.
*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2.
*
***********************************************************************/

#ifndef MILTER_CAP_H
#define MILTER_CAP_H 1

#ifndef SMFI_VERSION
#error "You must include libmilter/mfapi.h before milter_cap.h"
#endif

#ifndef SM_LM_VRS_MAJOR
#define SM_LM_VRS_MAJOR(v) (((v) & 0x7f000000) >> 24)
#endif

#ifndef SM_LM_VRS_MINOR
#define SM_LM_VRS_MINOR(v) (((v) & 0x007fff00) >> 8)
#endif

#ifndef SM_LM_VRS_PLVL
#define SM_LM_VRS_PLVL(v)  ((v) & 0x0000007f)
#endif

#ifdef SMFIF_QUARANTINE
#define MILTER_BUILDLIB_HAS_QUARANTINE 1
#endif

/* UGLY hack... it's almost impossible to distinguish between the Sendmail
   8.12 and 8.13 mfapi.h header.  The only way to know for sure is as
   follows... */
#ifdef SMFIF_QUARANTINE
#ifndef _FFR_QUARANTINE
/* We have SMFIR_QUARANTINE without _FFR_QUARANTINE.  Must be Sendmail 8.13
   or higher */
#define SM813 1
#endif
#endif

#ifdef SM813
#define MILTER_BUILDLIB_HAS_OPENSOCKET 1
#define MILTER_BUILDLIB_HAS_SETMLREPLY 1
#define MILTER_BUILDLIB_HAS_PROGRESS   1
#define MILTER_BUILDLIB_HAS_INSHEADER  1
#else

#ifdef _FFR_SMFI_OPENSOCKET
#define MILTER_BUILDLIB_HAS_OPENSOCKET 1
#endif

#ifdef  _FFR_MULTILINE
#define MILTER_BUILDLIB_HAS_SETMLREPLY 1
#endif

#ifdef _FFR_SMFI_PROGRESS
#define MILTER_BUILDLIB_HAS_PROGRESS   1
#endif
#endif /* SM813 */

#if SMFI_VERSION > 2
#define MILTER_BUILDLIB_HAS_VERSION    1
#define MILTER_BUILDLIB_HAS_NEGOTIATE  1
#define MILTER_BUILDLIB_HAS_UNKNOWN    1
#define MILTER_BUILDLIB_HAS_DATA       1
#define MILTER_BUILDLIB_HAS_CHGFROM    1
#endif

#if SMFI_VERSION > 1
#define MILTER_BUILDLIB_HAS_CHGHDRS    1
#endif

#ifdef SMFIF_CHGFROM
#define MILTER_BUILDLIB_HAS_CHGFROM    1
#endif

#ifdef SMFIF_ADDRCPT_PAR
#define MILTER_BUILDLIB_HAS_ADDRCPT_PAR 1
#endif

#ifdef SMFIF_SETSYMLIST
#define MILTER_BUILDLIB_HAS_SETSYMLIST 1
#endif

extern int milter_version_ok(void);
extern void dump_milter_buildlib_info(void);

#endif

