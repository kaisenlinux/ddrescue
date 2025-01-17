/** find_nonzero_sse2.c
 *
 * SSE2 optimized version to find first non-zero byte in a block
 * (c) Kurt Garloff <kurt@garloff.de>, GNU GPL v2 or v3
 */

#include "find_nonzero.h"

#if defined(__x86_64__) || defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)

#if defined(__SSE2__)
#include <emmintrin.h>
//#ifdef TEST
/** SSE2 version for measuring the initial zero bytes of aligned blk */
size_t find_nonzero_sse2o(const unsigned char* blk, const size_t ln)
{
	__m128i register xmm;
	const __m128i register zero = _mm_setzero_si128();
#ifdef SIMD_XOR
	const __m128i register mask = _mm_set_epi16(-1, -1, -1, -1, -1, -1, -1, -1);
#endif
	unsigned register eax;
	size_t i = 0;
	//asm(".align 32");
	for (; i < ln; i+= 16) {
		xmm = _mm_load_si128((__m128i*)(blk+i));
#ifdef BUGGY_136
		_mm_cmpeq_epi8(xmm, zero);
		eax = _mm_movemask_epi8(xmm);
#else
		xmm = _mm_cmpeq_epi8(xmm, zero);
#ifdef SIMD_XOR
		xmm = _mm_xor_si128(xmm, mask);
#endif
		eax = _mm_movemask_epi8(xmm);
#endif	/* BUGGY **/
#if defined(SIMD_XOR) || defined(BUGGY_136)
		if (eax) {
			i += myffs(eax)-1;
			return i>ln? ln: i;
		}
#else
		if (eax != 0xffff) {
			i += myffs(eax^0xffff)-1;
			return i>ln? ln: i;
		}
#endif
	}
	return ln;
}
//#endif

/** SSE2 version for measuring the initial zero bytes of 16b aligned blk */
size_t find_nonzero_sse2(const unsigned char* blk, const size_t ln)
{
	/*
	if (!ln || *blk)
		return 0;
	 */
	register const __m128i zero = _mm_setzero_si128();
	register __m128i xmm0, xmm1;
	register unsigned int eax, ebx;
	size_t i = 0;
	//asm(".p2align 5");
	for (; i < ln; i+= 32) {
#if 1
		xmm0 = _mm_load_si128((__m128i*)(blk+i));
		xmm1 = _mm_load_si128((__m128i*)(blk+i+16));
		xmm0 = _mm_cmpeq_epi8(xmm0, zero);
		xmm1 = _mm_cmpeq_epi8(xmm1, zero);
#else
		//xmm0 = _mm_cmpeq_epi8(*(__m128i*)(blk+i), zero);
		//xmm1 = _mm_cmpeq_epi8(*(__m128i*)(blk+i+16), zero);
#endif
		eax = _mm_movemask_epi8(xmm0);
		ebx = _mm_movemask_epi8(xmm1);
		eax = ~(eax | (ebx << 16));
		if (eax) {
			i += myffs(eax)-1;
			return i>ln? ln: i;
		}
	}
	return ln;
}

#endif	/* SSE2 */
#endif /* x86 */
