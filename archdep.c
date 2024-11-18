/* archdep.c
 *
 * The probe functions, constants, ...
 * to detect CPU specific extensions
 */

#include "archdep.h"
#include <string.h>
#include <stdio.h>

char cap_str[64];
char FNZ_OPT[64];

ARCH_DECLS

#if defined( __GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8)) && !defined(DO_OWN_DETECT)
# define PROBE(FEAT, PROBEFN)	!!__builtin_cpu_supports(FEAT)
#else
# define PROBE(FEAT, PROBEFN)	probe_procedure(PROBEFN)
#endif

#define detect(feature, probefn)		\
({						\
	char cap = PROBE(feature, probefn);	\
	if (cap) {				\
		strcat(cap_str, feature);	\
		strcat(cap_str, " ");		\
	}					\
 	cap;					\
})

#define detect2(feature, probefn)		\
({						\
	char cap = probe_procedure(probefn);	\
	if (cap) {				\
		strcat(cap_str, feature);	\
		strcat(cap_str, " ");		\
	}					\
 	cap;					\
})


#include <signal.h>
#include <setjmp.h>
static jmp_buf sigill_jmp;
static void ill_handler(int sig)
{
	/* As we can't return from handler (as it would result in 
	 * reexecuting the illegal instruction again - we jump back
	 * using longjmp) -- we have to restore signal delivery, so the
	 * program context is back to normal. Otherwise a second
	 * probe_procedure would not handle SIGILL. */
	sigset_t sigmask;
	sigemptyset(&sigmask); sigaddset(&sigmask, sig);
	sigprocmask(SIG_UNBLOCK, &sigmask, NULL);
	longjmp(sigill_jmp, 1);
}

char probe_procedure(void (*probefn)(void))
{
	/*static*/ sig_atomic_t have_feature;
	signal(SIGILL, ill_handler);
	if (setjmp(sigill_jmp) == 0) {
		probefn();
		mem_clobber;
		have_feature = 1;
	} else {
		have_feature = 0;
	}
	signal(SIGILL, SIG_DFL);
	return have_feature;
}

void detect_cpu_cap()
{
	*cap_str = 0;
	ARCH_DETECT;
	sprintf(FNZ_OPT, "find_nonzero_%s", OPT_STR2);
}

#if defined(__x86_64__) || defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)

#if defined(__SSE2__)
#include <emmintrin.h>
/** Issue an SSE2 insn for runtime detection of SSE2 capability (x86) */
volatile __m128d _probe_xmm;
void probe_sse2()
{
	double val = 3.14159265358979323844;
	_probe_xmm = _mm_set_sd(val);
}

#else
# warning pointless exercise compiling find_nonzero_sse2 with -msse2 ...
#endif	/* __SSE2__ */

#if defined(__SSE4_2__)
# include <smmintrin.h>
# include <unistd.h>
volatile unsigned _probe_sse42_res;
void probe_sse42()
{
	unsigned int val = getpid();
	_probe_sse42_res = _mm_popcnt_u32(val);
}

#endif /* SSE4.2 */

#ifdef __AVX2__
#include <immintrin.h>
volatile unsigned _cmp_mask_probe_avx;
void probe_avx2()
{
	__m256i register _probe_ymm = _mm256_setzero_si256();
	__m256i register ymm2 = _mm256_setzero_si256();
	__m256i register ymm3 = _mm256_cmpeq_epi8(_probe_ymm, ymm2);
	_cmp_mask_probe_avx = _mm256_movemask_epi8(ymm3);
}
#endif


#ifdef __RDRND__
#include <immintrin.h>
//#include <unistd.h>
volatile unsigned int _rdrand_res;
void probe_rdrand()
{
	unsigned int val = 0;
	_rdrand32_step(&val);
	_rdrand_res = val;
}
#endif	/* RDRND */

#ifndef NO_SHA
#include <immintrin.h>
volatile char _sha_probe_res[16];
void probe_sha256()
{
	__m128i x = _mm_setzero_si128();
	__m128i y = _mm_setzero_si128();
	x = _mm_sha256msg1_epu32(x, y);
	_mm_storeu_si128((__m128i*)_sha_probe_res, x);
}
#else
# ifndef NO_SHA
#  warning please compile archdep.c with -msha
# endif
#endif	/* SHA */

#ifdef __AES__
#include <wmmintrin.h>
volatile char _aes_probe_res[32];
void probe_aesni()
{
	__m128i x = _mm_setzero_si128();
	x = _mm_aeskeygenassist_si128(x, 0x01);
	_mm_storeu_si128((__m128i*)_aes_probe_res, x);
}
#ifdef __VAES__
#include <immintrin.h>
#include <vaesintrin.h>
void probe_vaes()
{
	__m256i x = _mm256_setzero_si256();
	__m256i k = _mm256_setzero_si256();
	x = _mm256_aesenc_epi128(x, k);
	_mm256_storeu_si256((__m256i*)_aes_probe_res, x);
}
#else
# ifndef NO_VAES
#  warning please compile rdrand with -mvaes
# endif
#endif
#else
# warning please compile rdrand with -maes
#endif

#endif	/* x86 */

#ifdef __arm__
void probe_arm8crypto_32()
{
	asm volatile(
#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 5)
	"	.arch armv8-a			\n"
#endif
	"	.fpu crypto-neon-fp-armv8	\n"
	"	veor	q0, q0, q0		\n"
	"	veor 	q1, q1, q1		\n"
#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 5)
	"	aese.8	q1, q0			\n"
#else
	"	//.word 0xffb02300		\n"
#endif
	"	//.word 0xf3b02300		\n"
	:
	:
	: "q0", "q1");
}

void probe_arm8sha_32()
{
	asm volatile(
#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 5)
	"	.arch armv8-a			\n"
#endif
	"	.fpu crypto-neon-fp-armv8	\n"
	"	veor	q0, q0, q0		\n"
	"	veor 	q1, q1, q1		\n"
	"	veor 	q12, q12, q12		\n"
#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 5)
	"	sha256h.32	q0, q1, q12	\n"
#else
	"	//.word 0xff020c68		\n"
#endif
	"	//.word 0xf3020c68		\n"
	:
	:
	: "q0", "q1", "q12");
}
#endif

#ifdef __aarch64__
void probe_arm8crypto()
{
	asm volatile(
	"	movi	v0.16b, #0		\n"
	"	movi	v1.16b, #0		\n"
	"	aese v1.16b, v0.16b		\n"
	:
	:
	: "v0", "v1");
}

void probe_arm8sha()
{
	asm volatile(
	"	movi 	v0.16b, #0		\n"
	"	movi 	v1.16b, #0		\n"
	"	movi	v12.16b, #0		\n"
	"	sha256h	q0, q1, v12.4s		\n"
	:
	:
	: "v0", "v1", "v12");
}
#endif

