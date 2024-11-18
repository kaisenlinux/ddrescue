/** rdrand.c
 * x86-64 implementation for rdrand (and aesni probing)
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 8/2014
 * License: GNU GPL v2 or v3
 *
 * Can also be compiled as selfstanding program to just retrive one random number
 * using the rdrand CPU instruction unconditionally (will SIGILL is not supported)
 * gcc -O2 -Wall -mrdrnd -DRDRAND_MAIN -o rdrand rdrand.c
 */

#ifdef HAVE_CONFIG_H
# include "archdep.h"
#else
# define have_rdrand 1
#endif

#if defined(__x86_64__) || defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)

#ifdef __RDRND__
#include <immintrin.h>
#define BSWAP32(x) ((x<<24) | ((x<<8)&0x00ff0000) | ((x>>8)&0x0000ff00) | (x>>24))

unsigned int rdrand32()
{
	unsigned int val = (unsigned long)&rdrand32;
	val = BSWAP32(val);
	if (have_rdrand)
		_rdrand32_step(&val);
	return val;
}

#ifdef __x86_64__
unsigned long rdrand64()
{
	unsigned long long val = (unsigned long long)&rdrand64;
	val = (unsigned long)BSWAP32((unsigned int)val&0xffffffff)<<32 | BSWAP32((unsigned int)(val>>32));
	if (have_rdrand)
		_rdrand64_step(&val);
	return val;
}
#else
#warning no rdrand64 on 32bit system
#endif

#if 0
unsigned int rdrand32()
{
	unsigned int val = (unsigned long)&rdrand32;
	val = BSWAP32(val);
	return val;
}
#endif
#endif /* __x86_64__ */

#endif	/* x86 */

#ifdef RDRAND_MAIN
#include <stdio.h>
int main(int argc, char* argv[])
{
#ifdef __x86_64__
	unsigned long rnd = rdrand64();
	printf("%lu\n", rnd);
#else
	unsigned int rnd = rdrand32();
	printf("%u\n", rnd);
#endif
	return 0;
}
#endif
