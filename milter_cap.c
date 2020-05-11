/***********************************************************************
*
* milter_cap.c
*
* Utility functions for checking libmilter capabilities
*
* Copyright (C) 2006 Roaring Penguin Software Inc.
* http://www.roaringpenguin.com
*
* This program may be distributed under the terms of the GNU General
* Public License, Version 2, or (at your option) any later version.
*
***********************************************************************/
#include <stdio.h>
#include "libmilter/mfapi.h"
#include "milter_cap.h"

/**********************************************************************
* %FUNCTION: milter_version_ok
* %ARGUMENTS:
*  None
* %RETURNS:
*  1 if the libmilter version we're linked against matches that which we
*  were compiled against; 0 otherwise.
* %DESCRIPTION:
*  This makes a stab at ensuring we're linking to the right library, but
*  it's not foolproof.
***********************************************************************/
int
milter_version_ok(void)
{
#ifndef MILTER_BUILDLIB_HAS_VERSION
    /* We can't determine it -- build version is too old */
    return 1;
#else
    unsigned int major, minor, plevel;
    smfi_version(&major, &minor, &plevel);
    if (major == SM_LM_VRS_MAJOR(SMFI_VERSION) &&
	minor == SM_LM_VRS_MINOR(SMFI_VERSION)) {
	/* Ignore patchlevel differences */
	return 1;
    }
    return 0;
#endif
}

/**********************************************************************
* %FUNCTION: dump_milter_buildlib_info
* %ARGUMENTS:
*  None
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Debugging output -- dumps what we found out about libmilter.
***********************************************************************/
void
dump_milter_buildlib_info(void)
{
#if SMFI_VERSION > 2
    printf("%-30s %d.%d.%d (New-Style)\n",
	   "SMFI_VERSION",
	   SM_LM_VRS_MAJOR(SMFI_VERSION),
	   SM_LM_VRS_MINOR(SMFI_VERSION),
	   SM_LM_VRS_PLVL(SMFI_VERSION));
#else
    printf("%-30s %d (Old-Style)\n",
	   "SMFI_VERSION",
	   SMFI_VERSION);
#endif

#ifdef MILTER_BUILDLIB_HAS_CHGFROM
    printf("%-30s 1\n", "MILTER_BUILDLIB_HAS_CHGFROM");
#else
    printf("%-30s 0\n", "MILTER_BUILDLIB_HAS_CHGFROM");
#endif

#ifdef MILTER_BUILDLIB_HAS_CHGHDRS
    printf("%-30s 1\n", "MILTER_BUILDLIB_HAS_CHGHDRS");
#else
    printf("%-30s 0\n", "MILTER_BUILDLIB_HAS_CHGHDRS");
#endif

#ifdef MILTER_BUILDLIB_HAS_DATA
    printf("%-30s 1\n", "MILTER_BUILDLIB_HAS_DATA");
#else
    printf("%-30s 0\n", "MILTER_BUILDLIB_HAS_DATA");
#endif

#ifdef MILTER_BUILDLIB_HAS_INSHEADER
    printf("%-30s 1\n", "MILTER_BUILDLIB_HAS_INSHEADER");
#else
    printf("%-30s 0\n", "MILTER_BUILDLIB_HAS_INSHEADER");
#endif

#ifdef MILTER_BUILDLIB_HAS_NEGOTIATE
    printf("%-30s 1\n", "MILTER_BUILDLIB_HAS_NEGOTIATE");
#else
    printf("%-30s 0\n", "MILTER_BUILDLIB_HAS_NEGOTIATE");
#endif

#ifdef MILTER_BUILDLIB_HAS_OPENSOCKET
    printf("%-30s 1\n", "MILTER_BUILDLIB_HAS_OPENSOCKET");
#else
    printf("%-30s 0\n", "MILTER_BUILDLIB_HAS_OPENSOCKET");
#endif

#ifdef MILTER_BUILDLIB_HAS_PROGRESS
    printf("%-30s 1\n", "MILTER_BUILDLIB_HAS_PROGRESS");
#else
    printf("%-30s 0\n", "MILTER_BUILDLIB_HAS_PROGRESS");
#endif

#ifdef MILTER_BUILDLIB_HAS_QUARANTINE
    printf("%-30s 1\n", "MILTER_BUILDLIB_HAS_QUARANTINE");
#else
    printf("%-30s 0\n", "MILTER_BUILDLIB_HAS_QUARANTINE");
#endif

#ifdef MILTER_BUILDLIB_HAS_SETMLREPLY
    printf("%-30s 1\n", "MILTER_BUILDLIB_HAS_SETMLREPLY");
#else
    printf("%-30s 0\n", "MILTER_BUILDLIB_HAS_SETMLREPLY");
#endif

#ifdef MILTER_BUILDLIB_HAS_SETSYMLIST
    printf("%-30s 1\n", "MILTER_BUILDLIB_HAS_SETSYMLIST");
#else
    printf("%-30s 0\n", "MILTER_BUILDLIB_HAS_SETSYMLIST");
#endif

#ifdef MILTER_BUILDLIB_HAS_UNKNOWN
    printf("%-30s 1\n", "MILTER_BUILDLIB_HAS_UNKNOWN");
#else
    printf("%-30s 0\n", "MILTER_BUILDLIB_HAS_UNKNOWN");
#endif

#ifdef MILTER_BUILDLIB_HAS_VERSION
    printf("%-30s 1\n", "MILTER_BUILDLIB_HAS_VERSION");
#else
    printf("%-30s 0\n", "MILTER_BUILDLIB_HAS_VERSION");
#endif
}
