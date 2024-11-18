AC_INIT([dd_rescue],[1.99],[kurt@garloff.de])
AC_CONFIG_HEADERS(config.h)
AC_PROG_CC
AC_C_CONST
AC_C_INLINE
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
#AC_CHECK_INCLUDES_DEFAULT
#AC_PROG_EGREP
#AC_CHECK_HEADERS([inttypes.h locale.h stddef.h stdint.h])

#AC_PROG_INSTALL
#CFLAGS="$CFLAGS -DHAVE_CONFIG_H"
#CFLAGS="$CFLAGS -D_LARGEFILE64_SOURCE=1"
AC_CHECK_HEADERS([fallocate.h dlfcn.h unistd.h libgen.h sys/xattr.h attr/xattr.h sys/acl.h sys/ioctl.h endian.h linux/fs.h linux/fiemap.h stdint.h lzo/lzo1x.h lzma.h openssl/evp.h linux/random.h sys/random.h malloc.h sched.h sys/statvfs.h sys/resource.h sys/endian.h linux/swab.h sys/user.h fcntl.h sys/reg.h arm_acle.h])
AC_CHECK_FUNCS([ffs ffsl basename splice getopt_long pread posix_fadvise htonl htobe64 feof_unlocked getline getentropy getrandom posix_memalign valloc sched_yield fstatvfs getrlimit aligned_alloc])
AC_CHECK_LIB(dl,dlsym)
AC_CHECK_LIB(lzma,lzma_easy_encoder)
#AC_CHECK_LIB(lzma,init_lzma_stream)
AC_CHECK_LIB(fallocate,linux_fallocate64)
AC_CHECK_LIB(lzo2,lzo1x_1_compress)
AC_CHECK_LIB(crypto,EVP_aes_192_ctr)

dnl @synopsis CC_FLAGS_CHECK [compiler flags] 
dnl @summary check whether compiler supports given C flags or not 
AC_DEFUN([CC_FLAGS_CHECK],
[dnl 
  AC_MSG_CHECKING([if $CC supports $1]) 
  dnl AC_LANG_PUSH([C]) 
  ac_saved_cflags="$CFLAGS" 
  CFLAGS="-Werror $1" 
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])], 
    [AC_MSG_RESULT([yes])
     AC_DEFINE_UNQUOTED([CC_FLAGS_$2], $1,
	[Check whether compiler supports $1])
    ],
    [AC_MSG_RESULT([no])
     dnl AC_MSG_ERROR([no])
     dnl AC_DEFINE_UNQUOTED([CC_FLAGS_$2], , [No compiler support for $1])
    ] )
  CFLAGS="$ac_saved_cflags" 
  dnl AC_LANG_POP([C]) 
])

CC_FLAGS_CHECK(-msse4.2,SSE42)
CC_FLAGS_CHECK(-mavx,AVX)
CC_FLAGS_CHECK(-mavx2,AVX2)
CC_FLAGS_CHECK(-mrdrnd,RDRND)
CC_FLAGS_CHECK(-maes,AES)

#CFLAGS="$CFLAGS -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fPIE -pie -rdynamic"
CFLAGS="$CFLAGS -fPIE"
dnl ***************************************************************************
dnl Check for support of rep nop
AC_MSG_CHECKING(whether asm rep nop is supported)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
	int main() {
	int err = 0;
	asm volatile ("rep nop":::"memory");
	return err;
	}
]])],[
	AC_MSG_RESULT(yes)
	AC_DEFINE_UNQUOTED([HAVE_REP_NOP], 1,
		[check whether asm rep nop works])
],[
	AC_MSG_RESULT(no)
],[
	AC_MSG_RESULT(no -- cross compiling)
	])

dnl ***************************************************************************
dnl Check for support of rep nop
AC_MSG_CHECKING(whether asm lfence is supported)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
	int main() {
	int err = 0;
	asm volatile ("lfence":::"memory");
	return err;
	}
]])],[
	AC_MSG_RESULT(yes)
	AC_DEFINE_UNQUOTED([HAVE_LFENCE], 1,
		[check whether asm lfence works])
],[
	AC_MSG_RESULT(no)
],[
	AC_MSG_RESULT(no -- cross compiling)
])

dnl Check for __attribute__((aligned(N))) support
AC_MSG_CHECKING(whether we support __attribute__((aligned)))
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
	typedef unsigned long aligned_ulong __attribute__((aligned(64)));
]])],[
	AC_MSG_RESULT(yes)
	AC_DEFINE_UNQUOTED([HAVE_ALIGNED_ATTR], 1,
		[whether we support __attribute__((aligned(N)))])
],[
	AC_MSG_RESULT(no)
])

dnl Check for Android min SDK
AC_MSG_CHECKING(the need for android min SDK setting)
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
	#include <stdlib.h>
	#include <stdio.h>
	#if defined(__ANDROID_MIN_SDK_VERSION__) && __ANDROID_MIN_SDK_VERSION__ < 28
	#ifdef __aarch64__
	#error need -target linux-aarch64-android28
	#else
	#error need -target linux-arm-android28
	#endif
	#endif
]])],[
	AC_MSG_RESULT(no)
],[
	AC_DEFINE_UNQUOTED([NEED_ANDROID_TARGET], 1,
		[check whether we need to pass -target])
	AC_MSG_RESULT(yes)
])

dnl Check for bionic aligned_alloc failure
AC_MSG_CHECKING(whether aligned_alloc works)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
	#if defined(__ANDROID_MIN_SDK_VERSION__) && __ANDROID_MIN_SDK_VERSION__ < 28
	#warning Compile with -target linux-aarch64-android28
	#endif
	#include <stdlib.h>
	#include <stdio.h>
	int main() {
	    char *ptr1 = aligned_alloc(64,448);
	    char *ptr2 = aligned_alloc(64,320);
	    volatile unsigned long p1 = (unsigned long)ptr1; 
	    volatile unsigned long p2 = (unsigned long)ptr2; 
	    if (ptr1 && ptr2 && !((unsigned long)ptr1%64) && !((unsigned long)ptr2%64)) {
		free(ptr2);
		free(ptr1);
		return 0;
	    } else {
		if (ptr2)
			free(ptr2);
		if (ptr1)
			free(ptr1);
		return 1;
	    }
	}
]])],[
	AC_DEFINE_UNQUOTED([ALIGNED_ALLOC_WORKS], 1,
		[check whether aligned_alloc works])
	AC_MSG_RESULT(yes)
],[
	AC_MSG_RESULT(no)
],[
	AC_MSG_RESULT(no -- cross-compiling)
])

dnl ***************************************************************************
dnl Check for valloc decl
CFLAGS="$CFLAGS -Werror"
AC_MSG_CHECKING(whether valloc has been declared)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
	#include <stdlib.h>
	int main() {
	 void *ptr = valloc(1024);
	 free(ptr);
	 return (ptr != (void*)0);;
	}
]])],[
	AC_MSG_RESULT(yes)
	AC_DEFINE_UNQUOTED([HAVE_VALLOC_DECL], 1,
		[check whether valloc has been declared])
],[
	AC_MSG_RESULT(no)
],[
	AC_MSG_RESULT(no -- cross-compiling)
])

dnl ***************************************************************************
dnl Check for alignement needs
AC_MSG_CHECKING(whether unaligned int reads are handled)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	char bytes[19], b2[16];
	union intu {
	 char bytes[8];
	 int  intvals[2];
	};
	void copy(int *dst, const int *src, size_t sz)
	{
	 union intu *iptr;
	 for (size_t i = 0; i < sz; i+=2) {
		*dst = ((union intu*)src)->intvals[0];
		*(dst+1) = ((union intu*)src)->intvals[1];
		src += 2; dst += 2;
	 }
	}
	int main(int argc, char* argv[])
	{
	 int off = 1;
	 memset(bytes, 0, 19);
	 if (argc > 1)
		off = atol(argv[1])%4;
	 char* ptr = bytes+off;
	 fprintf(stderr, "Debug: Off %i, Ptr %08lx\n", off, (unsigned long)ptr);
	 copy((int*)b2, (const int*)ptr, 4);
	 fprintf(stderr, "Ints: %08x %08x %08x %08x\n", *(int*)b2, *(int*)(b2+4), *(int*)(b2+8), *(int*)(b2+12));
	 /* HACK: Somehow this test does no longer trigger with gcc-12 on armhf, but it should */
	 #ifdef __arm__
	 return 1;
	 #endif
	 return 0;
	}
]])],[
	AC_MSG_RESULT(yes)
	AC_DEFINE_UNQUOTED([HAVE_UNALIGNED_HANDLING], 1,
		[check whether unaligned int reads are handled])
],[
	AC_MSG_RESULT(no)
],[
	AC_MSG_RESULT(no -- cross-compiling)
])

dnl @synopsis CC_COMPILE64_CHECK [compiler flags] 
dnl @summary check whether compiler links ..64 function
AC_DEFUN([CC_COMPILE64_CHECK],
[dnl 
  AC_MSG_CHECKING([if we can link $1]) 
  dnl AC_LANG_PUSH([C]) 
  ac_saved_cflags="$CFLAGS"
  CFLAGS="$CFLAGS -D_LARGEFILE64_SOURCE=1 -D_GNU_SOURCE=1"
  AC_COMPILE_IFELSE([AC_LANG_SOURCE([
	#include <unistd.h>
	#include <fcntl.h>
	#include <sys/stat.h>
	int main() {
	long res = $1$2;
	return res;
	}
	])], 
    [AC_MSG_RESULT([yes])
     AC_DEFINE_UNQUOTED([HAVE_$3], 1,
	[Check whether we can link $1])
    ],
    [AC_MSG_RESULT([no])
     dnl AC_MSG_ERROR([no])
     dnl AC_DEFINE_UNQUOTED([HAVE_$3], , [No library support for $1])
    ] )
  CFLAGS="$ac_saved_cflags" 
  dnl AC_LANG_POP([C]) 
])

#AC_CHECK_FUNCS([fallocate64 open64 pread64 lseek64 stat64 posix_fadvise64 __builtin_prefetch __builtin_cpu_supports])
CC_COMPILE64_CHECK(fallocate64, (1, 0, (off64_t)0, (off64_t)0), FALLOCATE64)
CC_COMPILE64_CHECK(open64, ("", 0), OPEN64)
CC_COMPILE64_CHECK(pread64, (1, (void*)1, (size_t)0, (off64_t)0), PREAD64)
CC_COMPILE64_CHECK(pwrite64, (1, (void*)1, (size_t)0, (off64_t)0), PWRITE64)
CC_COMPILE64_CHECK(lseek64, (1, (off64_t)0, 0), LSEEK64)
CC_COMPILE64_CHECK(stat64, ("", (struct stat64*)1), STAT64)
CC_COMPILE64_CHECK(posix_fadvise64, (0, (off64_t)0, (off64_t)0, 0), POSIX_FADVISE64)
CC_COMPILE64_CHECK(0; __builtin_prefetch, ((void*)1, 0), __BUILTIN_PREFETCH)
CC_COMPILE64_CHECK(__builtin_cpu_supports, ("aes"), __BUILTIN_CPU_SUPPORTS)

AC_OUTPUT
dnl link (if needed) Makefile configure.ac test_crypt.sh test_lzo_fuzz.sh
