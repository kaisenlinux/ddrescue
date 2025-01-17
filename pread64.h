/** pread64.h 
 *
 * Implements pread64() for platforms where the libc misses it
 * - implementing a syscall wrapper for linux
 * - using lseek64 and read
 * - or using plain pread in the worst case ...
 * Likewise for pwrite64()
 */

#ifndef _PREAD64_H
#define _PREAD64_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_REG_H
# include <sys/reg.h>
#endif

#if !defined(HAVE_PREAD64) && __WORDSIZE == 64 && !defined(TEST_SYSCALL) && defined(HAVE_PREAD)
# define pread64 pread
# define HAVE_PREAD64 1
#endif
#if !defined(HAVE_PWRITE64) && __WORDSIZE == 64 && !defined(TEST_SYSCALL) && defined(HAVE_PWRITE)
# define pwrite64 pwrite
# define HAVE_PWRITE64 1
#endif

/* pread64 */
#if !defined(HAVE_PREAD64) || defined(TEST_SYSCALL)

# ifdef __linux__
#  include <sys/syscall.h>
#  include <sys/types.h>
#  ifdef HAVE_ENDIAN_H
#   include <endian.h>
#  endif
#  define __KERNEL__
#  include <asm/unistd.h>
#  undef __KERNEL__
#  ifdef __NR_pread64
static inline ssize_t pread64(int fd, void *buf, size_t sz, loff_t off)
{
#   if __WORDSIZE == 64
	return syscall(__NR_pread64, fd, buf, sz, off);
#   elif __BYTE_ORDER == __LITTLE_ENDIAN 
#    ifdef __arm__
	return syscall(__NR_pread64, fd, buf, sz, 0, (unsigned int)off, (int)(off >> 32));
#    else
	return syscall(__NR_pread64, fd, buf, sz, (unsigned int)off, (int)(off >> 32));
#    endif
#   else
#    warning 32bit wrapper big endian pread64 untested
#    if 0
	return syscall(__NR_pread64, fd, buf, 0, sz, (int)(off >> 32), (unsigned int)off);
#    else
	return syscall(__NR_pread64, fd, buf, sz, (int)(off >> 32), (unsigned int)off);
#    endif
#   endif
}
#   define HAVE_PREAD64 1
#  endif	/* __NR_PREAD64 */
# endif		/* __linux__ */	
#endif		/* !HAVE_PREAD64 */

#ifndef HAVE_PREAD64
# ifdef HAVE_LSEEK64
static inline ssize_t pread64(int fd, void *buf, size_t sz, loff_t off)
{
	if (lseek64(fd, off, SEEK_SET))
		return -1;
	return read(fd, buf, sz);
}
# elif defined(HAVE_PREAD)
#  warning Using plain pread will likely limit file size to 2GB
static inline ssize_t pread64(int fd, void *buf, size_t sz, loff_t off)
{
	return pread(fd, buf, sz, off);
}
# else
#  warning Using plain lseek will likely limit file size to 2GB
static inline ssize_t pread64(int fd, void *buf, size_t sz, loff_t off)
{
	if (lseek(fd, off, SEEK_SET))
		return -1;
	return read(fd, buf, sz);
}
# endif
#endif	/* !HAVE_PREAD64 -- after syscall wrapper */


#if !defined(HAVE_PWRITE64) || defined(TEST_SYSCALL)
# ifdef __linux__
#  include <sys/syscall.h>
#  include <sys/types.h>
#  ifdef HAVE_ENDIAN_H
#   include <endian.h>
#  endif
#  define __KERNEL__
#  include <asm/unistd.h>
#  undef __KERNEL__
#  ifdef __NR_pwrite64
static inline ssize_t pwrite64(int fd, const void *buf, size_t sz, loff_t off)
{
#   if __WORDSIZE == 64
	return syscall(__NR_pwrite64, fd, buf, sz, off);
#   elif __BYTE_ORDER == __LITTLE_ENDIAN
#    ifdef __arm__
	return syscall(__NR_pwrite64, fd, buf, sz, 0, (unsigned int)off, (int)(off >> 32));
#    else
	return syscall(__NR_pwrite64, fd, buf, sz, (unsigned int)off, (int)(off >> 32));
#    endif
#   else
#    if 0
	return syscall(__NR_pwrite64, fd, buf, 0, sz, (int)(off >> 32), (unsigned int)off);
#    else
	return syscall(__NR_pwrite64, fd, buf, sz, (int)(off >> 32), (unsigned int)off);
#    endif
#   endif
}
#   define HAVE_PWRITE64 1
#  endif	/* __NR_pwrite64 */
# endif		/* __linux__ */
#endif		/* !HAVE_PRWTIE64 */

#ifndef HAVE_PWRITE64
# ifdef HAVE_LSEEK64
static inline ssize_t pwrite64(int fd, const void *buf, size_t sz, loff_t off)
{
	if (lseek64(fd, off, SEEK_SET))
		return -1;
	return write(fd, buf, sz);
}
# elif defined(HAVE_PWRITE)
#  warning Using plain pwrite will likely limit file size to 2GB
static inline ssize_t pwrite(int fd, const void *buf, size_t sz, loff_t off)
{
	return pwrite(fd, buf, sz, off);
}
# else
#  warning Using plain lseek will likely limit file size to 2GB
static inline ssize_t pwrite64(int fd, const void *buf, size_t sz, loff_t off)
{
	if (lseek(fd, off, SEEK_SET))
		return -1;
	return write(fd, buf, sz);
}
# endif
#endif /* !HAVE_PWRITE64 -- after syscall wrapper */

#endif /* _PREAD64_H */
