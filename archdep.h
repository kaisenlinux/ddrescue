/** archdep.h */
/**
 * Abstract away the dependencies on specific features
 */

#ifndef _ARCHDEP_H
#define _ARCHDEP_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define mem_clobber	asm("":::"memory")
extern char cap_str[64];
extern char FNZ_OPT[64];
extern void detect_cpu_cap();

#if defined(__x86_64__) || defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)
#define HAVE_OPT
#define have_arm8sha 0
#define have_arm8crypto 0

#ifdef __i386__
extern char have_sse2;
void probe_sse2();
#define ARCH_DECL_386 char have_sse2;
#define ARCH_DETECT_386 ; have_sse2 = detect("sse2", probe_sse2)
#else /* x86_64 */
#define have_sse2 1
#define ARCH_DECL_386
#define ARCH_DETECT_386
#endif

#ifdef NO_SSE42		/* compiler does not support -msse4.2 (nor -mavx2) */
#define have_avx2 0
#define have_sse42 0
#define have_rdrand 0
#define have_sha256 0
#define have_aesni 0
#define have_vaes 0
#define ARCH_DETECT do {} while (0)
#define ARCH_DECLS ARCH_DECL_386

#else 	/* We have SSE4.2 */
extern char have_sse42;
void probe_sse42();

#ifdef NO_AESNI		/* compiler does not support -maes */
#define have_avx2 0
#define have_rdrand 0
#define have_sha256 0
#define have_aesni 0
#define have_vaes 0
#define ARCH_DECLS char have_sse42; ARCH_DECL_386
#define ARCH_DETECT have_sse42 = detect("sse4.2", probe_sse42) ARCH_DETECT_386

#else	/* We have AESNI, yeah! */
extern char have_aesni;
void probe_aesni();

#ifdef NO_AVX2	/* compiler does not support -mavx2 */
#define have_avx2 0
#define have_rdrand 0
#define have_sha256 0
#define have_vaes 0
#define ARCH_DECLS char have_sse42, have_aesni; ARCH_DECL_386
#define ARCH_DETECT have_aesni = detect2("aes", probe_aesni); have_sse42 = detect("sse4.2", probe_sse42) \
		    ARCH_DETECT_386

#else	/* We have avx2 compiler support */
extern char have_avx2;
void probe_avx2();

#ifdef NO_RDRND	/* SSE42 and AESNI and AVX2 but no rdrand */
#define have_rdrand 0
#define have_sha256 0
#define have_vaes 0
#define ARCH_DECLS char have_avx2, have_aesni, have_sse42; ARCH_DECL_386
#define ARCH_DETECT have_avx2 = detect("avx2", probe_avx2); have_aesni = detect2("aes", probe_aesni); \
		    have_sse42 = detect("sse4.2", probe_sse42) ARCH_DETECT_386

#else /* We have rdrand compiler support */
extern char have_rdrand;
void probe_rdrand();
#ifdef NO_SHA	/* RDRAND but not SHA */
#define have_sha256 0
#define have_vaes 0
#define ARCH_DECLS char have_rdrand, have_avx2, have_aesni, have_sse42; ARCH_DECL_386
#define ARCH_DETECT have_rdrand = detect2("rdrand", probe_rdrand); have_avx2 = detect("avx2", probe_avx2); \
		    have_aesni = detect2("aes", probe_aesni); have_sse42 = detect("sse4.2", probe_sse42) \
		    ARCH_DETECT_386
#else	/* We have sha compiler support */
extern char have_sha256;
void probe_sha256();
#ifdef NO_VAES	/* Disabled VAES */
#define have_vaes 0
#define ARCH_DECLS char have_sha256, have_rdrand, have_avx2, have_aesni, have_sse42; ARCH_DECL_386
#define ARCH_DETECT have_sha256 = detect2("sha", probe_sha256); have_rdrand = detect2("rdrand", probe_rdrand); \
		    have_avx2 = detect("avx2", probe_avx2); have_aesni = detect2("aes", probe_aesni); \
		    have_sse42 = detect("sse4.2", probe_sse42) \
		    ARCH_DETECT_386
#else /* Probe everything */
extern char have_vaes;
void probe_vaes();
#define ARCH_DECLS char have_vaes, have_sha256, have_rdrand, have_avx2, have_aesni, have_sse42; \
		   ARCH_DECL_386
#define ARCH_DETECT have_vaes = detect2("vaes", probe_vaes); have_sha256 = detect2("sha", probe_sha256); \
		    have_rdrand = detect2("rdrand", probe_rdrand); have_avx2 = detect("avx2", probe_avx2); \
		    have_aesni = detect2("aes", probe_aesni); have_sse42 = detect("sse4.2", probe_sse42) \
		    ARCH_DETECT_386
#endif	/* VAES */
#endif	/* SHA */
#endif	/* RDRND */
#endif	/* AVX2 */
#endif	/* AESNI */
#endif	/* SSE42 */

#define FIND_NONZERO_OPT(x,y) (have_avx2? find_nonzero_avx2(x,y): (have_sse2? find_nonzero_sse2(x,y): find_nonzero_c(x,y)))
#define OPT_STR (have_avx2? "avx2": (have_sse42? "sse4.2": (have_sse2? "sse2": "c")))
#define OPT_STR2 (have_avx2? "avx2": (have_sse2? "sse2": "c"))

#elif defined(__arm__)
#define HAVE_OPT
#define have_arm  1
#define have_avx2 0
#define have_sse2 0
#define have_sse42 0
#define have_aesni 0
#define have_rdrand 0
#define have_sha256 0
#define have_vaes 0
extern char have_arm8sha;
void probe_arm8sha_32();
extern char have_arm8crypto;
void probe_arm8crypto_32();
#define ARCH_DECLS char have_arm8crypto, have_arm8sha;
#define ARCH_DETECT have_arm8crypto = detect2("aes", probe_arm8crypto_32); have_arm8sha = detect2("sha", probe_arm8sha_32)
#define FIND_NONZERO_OPT(x,y) find_nonzero_arm6(x,y)
#define OPT_STR "arm6"
#define OPT_STR2 "arm6"

#elif defined(__aarch64__)
#define HAVE_OPT
#define have_arm  1
#define have_avx2 0
#define have_sse2 0
#define have_sse42 0
#define have_aesni 0
#define have_rdrand 0
#define have_sha256 0
#define have_vaes 0
extern char have_arm8sha;
void probe_arm8sha();
extern char have_arm8crypto;
void probe_arm8crypto();
#define ARCH_DECLS char have_arm8crypto, have_arm8sha;
#define ARCH_DETECT have_arm8crypto = detect2("aes", probe_arm8crypto); have_arm8sha = detect2("sha", probe_arm8sha)
#define FIND_NONZERO_OPT(x,y) find_nonzero_arm8(x,y)
#define OPT_STR "arm8"
#define OPT_STR2 "arm8"

#else	/* other CPU arch */
#define have_arm 0
#define have_avx2 0
#define have_sse2 0
#define have_sse42 0
#define have_aesni 0
#define have_rdrand 0
#define have_sha256 0
#define have_vaes 0
#define have_arm8sha 0
#define have_arm8crypto 0
#define FIND_NONZERO_OPT(x,y) find_nonzero_c(x,y)
#define ARCH_DECLS
#define ARCH_DETECT do {} while (0)
#define OPT_STR "c"
#define OPT_STR2 "c"
#endif

#endif /* _ARCHDEP_H */
