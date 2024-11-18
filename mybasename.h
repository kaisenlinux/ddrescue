/* mybasename.h */
/*
 * The reason for not just using the library function is that
 * the POSIX standard does not give us reasonable guarantees.
 * It allows for the argument to be changed, and it allows
 * to return a pointer to some statically allocated buffer.
 * glibc does not do such nonsense, but portable programming
 * requires us to use strdup(basename(strdupa(nm))) to be
 * safe to have a string that is not overwritten.
 * Two pointless memory allocations ...
 *
 * So it's easiest to have our own version that
 * does the easy thing and always returns a pointer
 * into the original string.
 *
 * License: GNU GPL v2 or later.
 * (c) Kurt Garloff <kurt@garloff.de>, 8/2024
 */

#ifndef _MYBASENAME_H
#define _MYBASENAME_H

#include <string.h>
static inline const char* mybasename(const char* nm)
{
	const char* ptr = strrchr(nm, '/');
#ifdef _WIN32
	if (!ptr)
		ptr = strrchr(nm, '\\');
#endif
	if (ptr)
		return ptr+1;
	else
		return nm;
}

#endif
