/* iohavoc.h
 *
 * wrapper around read() and write() calls,
 * deliberately injecting behavior like
 * interrupted system calls returning with EINTR
 * or EAGAIN and short reads/writes.
 *
 * These are things that can happen in real life
 * according to glibc documentation, yet do happen
 * only rarely and only under certain circumstances,
 * which make robustness against these things hard
 * to test.
 * This collection of wrappers allow to inject such
 * things, so we can test robustness.
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 3/2025
 * SPDX-License-Identifier: LGPL-v2.1
 */

#ifndef _IOHAVOC_H
#define _IOHAVOC_H

//#define _FILE_OFFSET_BITS 64
#include <random.h>
#include <unistd.h>
#include <errno.h>

/* From GNU libc info pages
 * 
 * read() can return -1 with errno EAGAIN or EINTR, indicating that
 *  it needs to be called again.
 * read() can return only a subset of the requested bytes,
 *  which means it needs to be called again for the rest.
 * read() returning 0 (with a non-zero size param) means EOF.
 * pread() and pread64() behave the same way.
 *
 * write() has the same behavior w.r.t. EAGAIN/EINTR and short
 *  writes as read().
 * write() returning 0 should be treated as short writes, not EOF.
 * pwrite, pwrite64() behaves as write() does.
 */

#ifdef IO_HAVOC

static int limit1, limit2;
static long cnt_sh, cnt_in, cnt_reg;

/* configure limits */
static inline
void iohavoc_init(int seed, char shortpct, char intrpct)
{
	if (!seed)
		seed = time(0);
	srand(seed);
	assert(intrpct+shortpct <= 100);
	/* We generate random numbers
	 * - If they are below limit1, we do short reads/writes
	 * - If they are below limit2 (but above limit1), we do EINTR/EAGAIN
	 * - Else (above limit2), we do normal reads/writes
	 */
	limit1 = shortpct*(RAND_MAX/100);
	limit2 = (shortpct+intrpct)*(RAND_MAX/100);
	cnt_sh = 0; cnt_in = 0; cnt_reg = 0;
}


/* Call rand and determine action */
static inline
ssize_t io_determine(ssize_t sz)
{
	int rd = rand();
	/* Full read/write */
	if (rd >= limit2)
		return sz;
	/* EINTR/EAGAIN */
	if (rd >= limit1)
		return rd&1? -EINTR: -EAGAIN;
	/* Short read/write */
	ssize_t shortln = sz*rd/limit1;
	return shortln - shortln%512;
}


#define IOWRAP3(fn, wr, fd, bf, sz)	\
	ssize_t nsz = io_determine(sz);	\
	if (nsz < 0) {			\
		++cnt_in;		\
		errno = -nsz;		\
		return -1;		\
	}				\
	/* Avoid 0-sized read (EOF) */	\
	if (!wr && !nsz)		\
		nsz = sz;		\
	if (nsz != sz)			\
		++cnt_sh;		\
	else				\
		++cnt_reg;		\
	/*errno = 0;*/			\
	return fn(fd, bf, nsz);

#define IOWRAP4(fn, wr, fd, bf, sz, off)\
	ssize_t nsz = io_determine(sz);	\
	if (nsz < 0) {			\
		++cnt_in;		\
		errno = -nsz;		\
		return -1;		\
	}				\
	/* Avoid 0-sized read (EOF) */	\
	if (!wr && !nsz)		\
		nsz = sz;		\
	if (nsz != sz)			\
		++cnt_sh;		\
	else				\
		++cnt_reg;		\
	/*errno = 0;*/			\
	return fn(fd, bf, nsz, off);


#define IOHAVOC_INIT(s, sh, in)	\
	iohavoc_init(s, sh, in)

static char _iohavoc_report[80];
static inline char* IOHAVOC_REPORT()
{
	if (cnt_sh || cnt_in) {
		snprintf(_iohavoc_report, 79, "iohavoc stats: %li regular calls, %li short, %li intr\n",
			 cnt_reg, cnt_sh, cnt_in);
		return _iohavoc_report;
	}
	return NULL;
}

/*
static inline ssize_t READ(int fd, void *bf, size_t sz)
{
	IOWRAP3(read, 0, fd, bf, sz)
}

static inline ssize_t WRITE(int fd, void *bf, size_t sz)
{
	IOWRAP3(write, 1, fd, bf, sz)
}
*/

static inline ssize_t PREAD64(int fd, void *bf, size_t sz, loff_t off)
{
	IOWRAP4(pread64, 0, fd, bf, sz, off)
}

static inline ssize_t PWRITE64(int fd, void *bf, size_t sz, loff_t off)
{
	IOWRAP4(pwrite64, 1, fd, bf, sz, off)
}

#else	/* IO_HAVOC */

#define IOHAVOC_INIT(s, sh, in) \
	do {} while(0)
#define IOHAVOC_REPORT() NULL


/*
static inline ssize_t READ(int fd, void *bf, size_t sz)
{
	return read(fd, bf, sz);
}

static inline ssize_t WRITE(int fd, void *bf, size_t sz)
{
	return write(fd, bf, sz);
}
*/

static inline ssize_t PREAD64(int fd, void *bf, size_t sz, loff_t off)
{
	return pread64(fd, bf, sz, off);
}

static inline ssize_t PWRITE64(int fd, void *bf, size_t sz, loff_t off)
{
	return pwrite64(fd, bf, sz, off);
}

#endif	/* IO_HAVOC */

#endif	/* _IOHAVOC_H */
