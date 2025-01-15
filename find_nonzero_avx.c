/** find_nonzero_avx.c
  * AVX2 optimized search for non-zero bytes
  * taken straight from SSE2 and adapted to use AVX registers
  * Needs recent (2.23+) binutils to compile ...
  * Has only seen testing in bochs ...
  * (c) Kurt Garloff <kurt@garloff.de>, 2013
  * License: GNU GPL v2 or v3
  */

#define _GNU_SOURCE 1
#include "find_nonzero.h"

#ifdef __AVX2__
#include <assert.h>

#include <immintrin.h>
/** AVX2 version for measuring the initial zero bytes of 32B aligned blk
 *  ln does not need to be dividable by 32, however, we do read beyond
 *  blk+ln by 32-ln%32 bytes then, which we must be sure to be safe. */
size_t find_nonzero_avx2(const unsigned char* blk, const size_t ln)
{
	const __m256i register zero = _mm256_setzero_si256();
	__m256i register ymm;
	unsigned register eax;
	size_t i = 0;
	//asm(".p2align 5");
	//assert(!((unsigned long)blk%32));
	//assert(!(ln%32));
	for (; i < ln; i+= 32) {
		//ymm = _mm256_load_si256((__m256i*)(blk+i));
		ymm = _mm256_cmpeq_epi8(*(__m256i*)(blk+i), zero);
		eax = ~(_mm256_movemask_epi8(ymm));
		if (eax) {
			i += myffs(eax)-1;
			/* Support ln%32 != 0, however we read beyond blk+ln
			 * by 32-ln%32 then.*/
			return i>ln? ln: i;
		}
	}
	return ln;
}
#endif


