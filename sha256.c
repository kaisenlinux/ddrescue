/** sha256.c
 *
 * Algorithm translated to C from pseudocode at Wikipedia
 * by Kurt Garloff <kurt@garloff.de>
 * License: GNU GPL v2 or v3, at your option.
 * Source:
 * http://en.wikipedia.org/wiki/SHA-2
 * Copyright: CC-BY-SA 3.0/GFDL
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "sha256.h"
#include "archdep.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <assert.h>
#include <unistd.h>

/*
Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 2^32 
Note 2: For each round; there is one round constant k[i] and one entry in the message schedule array w[i]; 0 ≤ i ≤ 63 
Note 3: The compression function uses 8 working variables, a through h 
Note 4: Big-endian convention is used when expressing the constants in this pseudocode, and when parsing message block data i
	from bytes to words, for example, the first word of the input message "abc" after padding is 0x61626380 
*/

/*
 * Initialize array of round constants: (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
 */
static const
uint32_t k[] ALIGNED(64) = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


/*
 * Initialize hash values: (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19): 
 */
void sha256_init(hash_t *ctx)
{
#ifdef HAVE____BUILTIN_PREFETCH
	/* Prefetch k */
	int koff;
	for (koff = 0; koff < sizeof(k)/sizeof(*k); koff += 64/sizeof(*k))
		__builtin_prefetch(k+koff, 0, 3);
#endif
	memset((uint8_t*)ctx+32, 0, sizeof(hash_t)-32);
	ctx->sha256_h[0] = 0x6a09e667;
	ctx->sha256_h[1] = 0xbb67ae85;
	ctx->sha256_h[2] = 0x3c6ef372;
	ctx->sha256_h[3] = 0xa54ff53a;
	ctx->sha256_h[4] = 0x510e527f;
	ctx->sha256_h[5] = 0x9b05688c;
	ctx->sha256_h[6] = 0x1f83d9ab;
	ctx->sha256_h[7] = 0x5be0cd19;
}

void sha224_init(hash_t *ctx)
{
#ifdef HAVE____BUILTIN_PREFETCH
	/* Prefetch k */
	int koff;
	for (koff = 0; koff < sizeof(k)/sizeof(*k); koff += 64/sizeof(*k))
		__builtin_prefetch(k+koff, 0, 3);
#endif
	memset((uint8_t*)ctx+32, 0, sizeof(hash_t)-32);
	ctx->sha256_h[0] = 0xc1059ed8;
	ctx->sha256_h[1] = 0x367cd507;
	ctx->sha256_h[2] = 0x3070dd17;
	ctx->sha256_h[3] = 0xf70e5939;
	ctx->sha256_h[4] = 0xffc00b31;
	ctx->sha256_h[5] = 0x68581511;
	ctx->sha256_h[6] = 0x64f98fa7;
	ctx->sha256_h[7] = 0xbefa4fa4;
}

#if !defined(HAVE_UNALIGNED_HANDLING)
/* Read val from little-endian array */
static inline uint32_t to_int32_be(const uint8_t *bytes)
{
	return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
	       ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}
#endif

#define  LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
#define RIGHTROTATE(x, c) (((x) >> (c)) | ((x) << (32 - (c))))
/* 
 * Process the message in successive 512-bit chunks: 
 * break message into 512-bit chunks 
 * (The initial values in w[0..63] don't matter, so many implementations zero them here) 
 */
static inline void __sha256_64(const uint8_t* msg, hash_t* ctx, const char clear)
{
 	/* for each chunk create a 64-entry message schedule array w[0..63] of 32-bit words */
	uint32_t w[64] ALIGNED(64);
	int i;
#ifdef __ANALYZER__
	/* -fanalyzer is not clever enough to see that initializing the first 16 ints is enough */
	memset(w+16, 0, sizeof(w)-16*sizeof(*w));
#endif
 	/* copy chunk into first 16 words w[0..15] of the message schedule array */
#if 0
	memcpy(w, msg, 64);
#else
#if defined(HAVE_UNALIGNED_HANDLING)
	for (i = 0; i < 16; ++i)
		w[i] = htonl(*(uint32_t*)(msg+4*i));
#else
	for (i = 0; i < 16; ++i)
		w[i] = to_int32_be(msg+4*i);
#endif
#endif
	/* Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array: */
	for (i = 16; i < 64;  ++i) {
		const uint32_t s0 = RIGHTROTATE(w[i-15], 7) ^ RIGHTROTATE(w[i-15], 18) ^ (w[i-15] >> 3);
		const uint32_t s1 = RIGHTROTATE(w[i-2], 17) ^ RIGHTROTATE(w[i-2] , 19) ^ (w[i-2] >> 10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	/* Initialize working variables to current hash value:*/
	uint32_t a = ctx->sha256_h[0], b = ctx->sha256_h[1], c = ctx->sha256_h[2], d = ctx->sha256_h[3];
	uint32_t e = ctx->sha256_h[4], f = ctx->sha256_h[5], g = ctx->sha256_h[6], h = ctx->sha256_h[7];
	/* Compression function main loop: */
	for (i = 0; i < 64; ++i) {
		const uint32_t S1 = RIGHTROTATE(e, 6) ^ RIGHTROTATE(e, 11) ^ RIGHTROTATE(e, 25);
		//const uint32_t ch = (e & f) ^ ((~e) & g);
		const uint32_t ch = g ^ (e & (f ^ g));
		const uint32_t temp1 = h + S1 + ch + k[i] + w[i];
		const uint32_t S0 = RIGHTROTATE(a, 2) ^ RIGHTROTATE(a, 13) ^ RIGHTROTATE(a, 22);
		//const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		const uint32_t maj = (a & b) | (c & (a | b));
		const uint32_t temp2 = S0 + maj;
		++i;

		h = g; g = f; f = e;
		e = d + temp1;
		d = c; c = b; b = a;
		a = temp1 + temp2;

		const uint32_t S1_ = RIGHTROTATE(e, 6) ^ RIGHTROTATE(e, 11) ^ RIGHTROTATE(e, 25);
		const uint32_t ch_ = g ^ (e & (f ^ g));
		const uint32_t temp1_ = h + S1_ + ch_ + k[i] + w[i];
		const uint32_t S0_ = RIGHTROTATE(a, 2) ^ RIGHTROTATE(a, 13) ^ RIGHTROTATE(a, 22);
		const uint32_t maj_ = (a & b) | (c & (a | b));
		const uint32_t temp2_ = S0_ + maj_;

		h = g; g = f; f = e;
		e = d + temp1_;
		d = c; c = b; b = a;
		a = temp1_ + temp2_;
	}
	/* Clear w */
	if (clear) {
		memset(w, 0, sizeof(w));
		asm(""::"r"(w):"0");
	}
	/* Add the compressed chunk to the current hash value: */
	ctx->sha256_h[0] += a; ctx->sha256_h[1] += b; ctx->sha256_h[2] += c; ctx->sha256_h[3] += d;
	ctx->sha256_h[4] += e; ctx->sha256_h[5] += f; ctx->sha256_h[6] += g; ctx->sha256_h[7] += h;
}

#if !defined(NO_SHA) && (defined(__x86_64__) || defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__))
#define have_sha have_sha256
/* x86 version moved to own .c file sha256_x86.c */
void __sha256_64_sha(const uint8_t* data, hash_t* ctx);
#endif

#if defined(__arm__) || defined(__aarch64__)
//#ifdef __ARM_FEATURE_CRYPTO
#if defined(HAVE_AES_ARM64) && (defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 5))
#ifdef GEN_DEP
// Avoid preprocessor errors when generating dependencies
#define __ARM_FP __ARM_SOFTFP
#define __ARM_NEON 1
#define __ARM_NEON__ 1
#endif
#include <arm_neon.h>
#ifdef HAVE_ARM_ACLE_H
#include <arm_acle.h>
#endif

/* Code copied and slightly adapted from https://github.com/noloader/SHA-Intrinsics */
static inline void __sha256_64_sha(const uint8_t* data, hash_t* ctx)
{
	uint32x4_t STATE0, STATE1, ABEF_SAVE, CDGH_SAVE;
	uint32x4_t MSG0, MSG1, MSG2, MSG3;
	uint32x4_t TMP0, TMP1, TMP2;

	/* Load state */
	STATE0 = vld1q_u32(&ctx->sha256_h[0]);
	STATE1 = vld1q_u32(&ctx->sha256_h[4]);

	/* Begin loop */

	/* Save state */
	ABEF_SAVE = STATE0;
	CDGH_SAVE = STATE1;

	/* Load message */
	MSG0 = vld1q_u32((const uint32_t *)(data +  0));
	MSG1 = vld1q_u32((const uint32_t *)(data + 16));
	MSG2 = vld1q_u32((const uint32_t *)(data + 32));
	MSG3 = vld1q_u32((const uint32_t *)(data + 48));

	/* Reverse for little endian */
	MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG0)));
	MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG1)));
	MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG2)));
	MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG3)));

	TMP0 = vaddq_u32(MSG0, vld1q_u32(&k[0x00]));

	/* Rounds 0-3 */
	MSG0 = vsha256su0q_u32(MSG0, MSG1);
	TMP2 = STATE0;
	TMP1 = vaddq_u32(MSG1, vld1q_u32(&k[0x04]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
	MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

	/* Rounds 4-7 */
	MSG1 = vsha256su0q_u32(MSG1, MSG2);
	TMP2 = STATE0;
	TMP0 = vaddq_u32(MSG2, vld1q_u32(&k[0x08]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
	MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

	/* Rounds 8-11 */
	MSG2 = vsha256su0q_u32(MSG2, MSG3);
	TMP2 = STATE0;
	TMP1 = vaddq_u32(MSG3, vld1q_u32(&k[0x0c]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
	MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

	/* Rounds 12-15 */
	MSG3 = vsha256su0q_u32(MSG3, MSG0);
	TMP2 = STATE0;
	TMP0 = vaddq_u32(MSG0, vld1q_u32(&k[0x10]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
	MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

	/* Rounds 16-19 */
	MSG0 = vsha256su0q_u32(MSG0, MSG1);
	TMP2 = STATE0;
	TMP1 = vaddq_u32(MSG1, vld1q_u32(&k[0x14]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
	MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

	/* Rounds 20-23 */
	MSG1 = vsha256su0q_u32(MSG1, MSG2);
	TMP2 = STATE0;
	TMP0 = vaddq_u32(MSG2, vld1q_u32(&k[0x18]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
	MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

	/* Rounds 24-27 */
	MSG2 = vsha256su0q_u32(MSG2, MSG3);
	TMP2 = STATE0;
	TMP1 = vaddq_u32(MSG3, vld1q_u32(&k[0x1c]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
	MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

	/* Rounds 28-31 */
	MSG3 = vsha256su0q_u32(MSG3, MSG0);
	TMP2 = STATE0;
	TMP0 = vaddq_u32(MSG0, vld1q_u32(&k[0x20]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
	MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

	/* Rounds 32-35 */
	MSG0 = vsha256su0q_u32(MSG0, MSG1);
	TMP2 = STATE0;
	TMP1 = vaddq_u32(MSG1, vld1q_u32(&k[0x24]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
	MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

	/* Rounds 36-39 */
	MSG1 = vsha256su0q_u32(MSG1, MSG2);
	TMP2 = STATE0;
	TMP0 = vaddq_u32(MSG2, vld1q_u32(&k[0x28]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
	MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

	/* Rounds 40-43 */
	MSG2 = vsha256su0q_u32(MSG2, MSG3);
	TMP2 = STATE0;
	TMP1 = vaddq_u32(MSG3, vld1q_u32(&k[0x2c]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
	MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

	/* Rounds 44-47 */
	MSG3 = vsha256su0q_u32(MSG3, MSG0);
	TMP2 = STATE0;
	TMP0 = vaddq_u32(MSG0, vld1q_u32(&k[0x30]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
	MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

	/* Rounds 48-51 */
	TMP2 = STATE0;
	TMP1 = vaddq_u32(MSG1, vld1q_u32(&k[0x34]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

	/* Rounds 52-55 */
	TMP2 = STATE0;
	TMP0 = vaddq_u32(MSG2, vld1q_u32(&k[0x38]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

	/* Rounds 56-59 */
	TMP2 = STATE0;
	TMP1 = vaddq_u32(MSG3, vld1q_u32(&k[0x3c]));
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

	/* Rounds 60-63 */
	TMP2 = STATE0;
	STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
	STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

	/* Combine state */
	STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
	STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

	/* End loop */

	/* Save state */
	vst1q_u32(&ctx->sha256_h[0], STATE0);
	vst1q_u32(&ctx->sha256_h[4], STATE1);
}
#define have_sha have_arm8sha
#else
#warning Compiling ARM without sha support
#endif
#endif

#ifdef have_sha
void sha256_64(const uint8_t* msg, hash_t* ctx)
{
	if (have_sha)
		__sha256_64_sha(msg, ctx);
	else
		__sha256_64(msg, ctx, 0);
}
void sha256_64_clear(const uint8_t* msg, hash_t* ctx)
{
	if (have_sha)
		__sha256_64_sha(msg, ctx);
	else
		__sha256_64(msg, ctx, 1);
}

#else
void sha256_64(const uint8_t* msg, hash_t* ctx)
{
	__sha256_64(msg, ctx, 0);
}
void sha256_64_clear(const uint8_t* msg, hash_t* ctx)
{
	__sha256_64(msg, ctx, 1);
}
#endif

static char _sha256_res[65];
static inline 
char* sha2xx_hexout(char *buf, const hash_t* ctx, int wd)
{
	int i;
	/* Produce the final hash value (big-endian): */ 
	//digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
	if (!buf)
		buf = _sha256_res;
	*buf = 0;
	for (i = 0; i < wd; ++i) {
		char res[9];
		sprintf(res, "%08x", ctx->sha256_h[i]);
		strcat(buf, res);
	}
	return buf;
}

char* sha256_hexout(char *buf, const hash_t* ctx)
{
	return sha2xx_hexout(buf, ctx, 8);
}
char* sha224_hexout(char *buf, const hash_t* ctx)
{
	return sha2xx_hexout(buf, ctx, 7);
}

/* Big endian byte output */
static inline
unsigned char* sha2xx_beout(unsigned char* buf, const hash_t* ctx, int wd)
{
	int i;
	assert(buf);
	for (i = 0; i < wd; ++i)
		*((uint32_t*)buf+i) = htonl(ctx->sha256_h[i]);
	return buf;
}

unsigned char* sha256_beout(unsigned char *buf, const hash_t *ctx)
{
	return sha2xx_beout(buf, ctx, 8);
}

unsigned char* sha224_beout(unsigned char *buf, const hash_t *ctx)
{
	return sha2xx_beout(buf, ctx, 7);
}


#ifdef DEBUG
static void output(unsigned char* ptr, int ln)
{
	int i;
	for (i = 0; i < ln; ++i) {
		printf("%02x ", ptr[i]);
		if (!((i+1)%16))
			printf("\n");
	}
	if (i%16)
		printf("\n");
}
#endif

/*
 * Pre-processing: 
 * append the bit '1' to the message 
 * append k bits '0', where k is the minimum number >= 0 such that the resulting message length (modulo 512 in bits) is 448. 
 * append length of message (without the '1' bit or padding), in bits, as 64-bit big-endian integer 
 * (this will make the entire post-processed length a multiple of 512 bits)
 */
void sha256_calc(const uint8_t *ptr, size_t chunk_ln, size_t final_len, hash_t *ctx)
{
	/*
	static int first = 0;
	if (!first++)
		fprintf(stderr, "SHA256: %i, ARM8SHA: %i\n", have_sha256, have_arm8sha);
	 */

	/* ctx and k should be cache-hot already */
	//__builtin_prefetch(ctx->sha256_h, 0, 3);
	size_t offset;
	for (offset = 0; offset+64 <= chunk_ln; offset += 64)
		sha256_64(ptr + offset, ctx);
	if (offset == chunk_ln && final_len == (size_t)-1)
		return;
	const int remain = chunk_ln - offset;
	static uint8_t sha256_buf[64];
	if (remain)
		memcpy(sha256_buf, ptr+offset, remain);
	memset(sha256_buf+remain, 0, 64-remain);
	if (final_len == (size_t)-1) {
		sha256_64(sha256_buf, ctx);
		fprintf(stderr, "sha256: WARN: Incomplete block without EOF!\n");
		return;
	}
	/* EOF */
	sha256_buf[remain] = 0x80;
	if (remain >= 56) {
		sha256_64(sha256_buf, ctx);
		memset(sha256_buf, 0, 56);
	}
	*(uint32_t*)(sha256_buf+56) = htonl(final_len >> 29);
	*(uint32_t*)(sha256_buf+60) = htonl(final_len <<  3);
	sha256_64_clear(sha256_buf, ctx);
}

#ifdef SHA256_MAIN
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include "mybasename.h"
#include "find_nonzero.h"
#define BUFSIZE 65536
//ARCH_DECLS;

int main(int argc, char **argv)
{
	hash_t ctx;

	char is_sha224 = 0;
	if (!strcmp(mybasename(argv[0]), "sha224"))
	       is_sha224 = 1;

	if (argc < 2) {
		printf("usage: %s file [file [..]]\n", argv[0]);
		return 1;
	}

	detect_cpu_cap();
	//printf("Using sha asm: %i\n", have_sha);

	uint8_t *obf = (uint8_t *)malloc(BUFSIZE + 128);
	uint8_t *bf = obf;
#if defined(HAVE___BUILTIN_PREFETCH) && !defined(NO_ALIGN)
	bf += 63;
	bf -= ((unsigned long)bf % 64);
#endif

	if (!bf) {
		fprintf(stderr, "sha256: Failed to allocate buffer of size %i\n",
			BUFSIZE);
		exit(2);
	}

	int arg;
	for (arg = 1; arg < argc; ++arg) {
		//uint8_t result[16];
		struct stat stbf;
		if (strcmp(argv[arg], "-") && stat(argv[arg], &stbf)) {
			fprintf(stderr, "sha256: Can't stat %s: %s\n", argv[arg],
				strerror(errno));
			free(obf);
			exit(1);
		}
		//size_t len = stbf.st_size;

		int fd;
		if (strcmp(argv[arg], "-"))
			fd = open(argv[arg], O_RDONLY);
		else {
			fd = 0;
			//len = 0;
		}

		if (fd < 0) {
			fprintf(stderr, "sha256: Failed to open %s for reading: %s\n",
				argv[arg], strerror(errno));
			free(obf);
			exit(3);
		}

#ifdef BENCH
		int i;
		for (i = 0; i < 10000; ++i) {
#endif
		size_t clen = 0;
		if (is_sha224)
			sha224_init(&ctx);
		else
			sha256_init(&ctx);
		while (1) {
			ssize_t rd = read(fd, bf, BUFSIZE);
			if (rd == 0) {
				sha256_calc(bf, 0, clen, &ctx);
				break;
			}
			if (rd < 0) {
				fprintf(stderr, "sha256: Error reading %s: %s\n",
					argv[arg], strerror(errno));
				free(bf);
				exit(4);
			}
			clen += rd;
			if (rd < BUFSIZE) {
				sha256_calc(bf, rd, clen, &ctx);
				break;
			} else
				sha256_calc(bf, BUFSIZE, -1, &ctx);
		}

#ifdef BENCH
		lseek(fd, 0, SEEK_SET);
		}
#endif
		if (fd)
			close(fd);

		// display result
		printf("%s *%s\n", is_sha224? sha224_hexout(NULL, &ctx): sha256_hexout(NULL, &ctx), 
				argv[arg]);
	}
	free(obf);

	return 0;
}
#endif
