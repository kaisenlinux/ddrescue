/** Helper to find length of block with zero bytes
 * (c) Kurt Garloff <kurt@garloff.de>, 2013
 * License: GNU GPL v2 or v3
 */

#ifndef _FIND_NONZERO_H
#define _FIND_NONZERO_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "ffs.h"
#include "archdep.h"

/* This has been inspired by http://developer.amd.com/community/blog/faster-string-operations/ */
extern size_t find_nonzero_sse2 (const unsigned char* blk, const size_t ln);
extern size_t find_nonzero_avx2 (const unsigned char* blk, const size_t ln);
extern size_t find_nonzero_arm6 (const unsigned char* blk, const size_t ln);
extern size_t find_nonzero_arm8 (const unsigned char* blk, const size_t ln);
#ifdef TEST
extern size_t find_nonzero_sse2o(const unsigned char* blk, const size_t ln);
#endif

#if defined(TEST) || !(defined(__arm__) || defined(__aarch64__)) //1 //defined(TEST) || !(defined(__x86_64__) || defined(__arm__))
/** return number of bytes at beginning of blk that are all zero, assumes __WORDSIZE bit alignment */
static size_t find_nonzero_c(const unsigned char* blk, const size_t ln)
{
	const unsigned long* ptr = (const unsigned long*)blk;
	const unsigned long* const bptr = ptr;
	for (; (size_t)(ptr-bptr) < ln/sizeof(*ptr); ++ptr)
		if (*ptr)
#if __BYTE_ORDER == __BIG_ENDIAN
			return sizeof(long)*(ptr-bptr) + sizeof(long)-((myflsl(*ptr)+7)>>3);
#else
			return sizeof(long)*(ptr-bptr) + ((myffsl(*ptr)-1)>>3);
#endif
	return ln;
}
#endif /* TEST */

/** return number of bytes at beginning of blk that are all zero 
  * Generic version, does not require an aligned buffer blk or even ln ... */
inline static size_t find_nonzero(const unsigned char* blk, const size_t ln)
{
	if (!ln || *blk)
		return 0;
	/* 1st pass: Bytes before 32B aligned block */
	const unsigned off = (-(unsigned char)(unsigned long)blk) & 0x1f;
	size_t i;
	for (i = 0; i < off; ++i)
		if (blk[i])
			return i;
	/* Rest without 1st pass */
	const size_t remain = ln - off;
	/* Calc size of third pass -- this avoids reading beyond the end of blk */
	const int r2 = remain & 0x1f;
	/* 2nd pass: Process 32B aligned block */
	const size_t res = FIND_NONZERO_OPT(blk+off, remain-r2);
	/* Return if we found non-null in 2nd pass */
	if (!r2 || res != remain-r2)
		return off+res;
	/* 3rd pass: Trailing bytes */
	for (i = off+remain; i < ln; ++i)
		if (blk[i])
			return i;
	return ln;
}

#define ZEROCHUNK 512
/* blk is a pointer just behind the buffer, we count the zero bytes starting from the end */
inline static size_t find_nonzero_bkw(const unsigned char* blk, const size_t ln)
{
	if (!ln || blk[-1])
		return 0;
	int off = 0;
	while (-off < ln) {
		const int seglen = (ln+off > ZEROCHUNK? ZEROCHUNK: ln+off);
		if (find_nonzero(blk+off-seglen, seglen) != seglen)
			return -off;
		off -= seglen;
	}
	return ln;
}

char probe_procedure(void (*probefn)(void));

#endif /* _FIND_NONZERO_H */
