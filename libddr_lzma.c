/* libddr_lzma.c
 *
 * plugin for dd_rescue, doing compression and decompression for xz archives.
 *
 * (c) Dmitrii Ivanov <dsivanov_9@edu.hse.ru>, 2023
 * 
 * Changed buffer handling, added support for sparse files and fixed
 * plugin flags, Kurt Garloff <kurt@garloff.de>, 12/2024.
 * 
 * SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
 */
#include "ddr_plugin.h"
#include "ddr_ctrl.h"
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#ifdef HAVE_LZMA_H	// Avoid breaking on dependency generation
#include <lzma.h>
#endif

#define CHUNK_SIZE 32768

/* fwd decl */
extern ddr_plugin_t ddr_plug;

enum compmode {
	AUTO=0,
	TEST,
	COMPRESS,
	DECOMPRESS
};

typedef struct _lzma_state {
	enum compmode mode;
	lzma_check type;
	uint32_t preset;
	int seq;
	uint64_t memlimit;
	uint64_t max_memlimit;
	unsigned char *output;
	size_t buf_len;
	lzma_stream strm;
	uint32_t mt;
	bool do_bench;
	clock_t cpu;
	loff_t next_ipos;
	unsigned char* zero_buf;
	size_t zero_size;
	loff_t hole;
	/* DEBUG */
	size_t read, write;
} lzma_state;

#define FPLOG_(seq, lvl, fmt, args...) \
	plug_log(ddr_plug.logger, seq, stderr, lvl, fmt, ##args)
#define FPLOG(lvl, fmt, args...) \
	FPLOG_(state->seq, lvl, fmt, ##args)

const char* lzma_help = "LZMA plugin which is doing compression/decompression for xz archives.\n"
			" Parameters:\n"
			" z|compr[ess] - compress input file;\n"
			" d|decom[press] - decompress input file;\n"
			" test - check archive integrity;\n"
			" check=CRC32/CRC64/SHA256/NONE - select checksum to calculate on compression, CRC32 by default;\n"
			" preset=0...9 - compression preset, default is 3;\n"
			" memlimit=N - memory limit for decompression (integer, suffices supported);\n"
			" bench - measure and output CPU time spent on (de)compression.\n";

static loff_t readint(const char* const ptr)
{
	char *es; double res;

	res = strtod(ptr, &es);
	switch (*es) {
		case 's':
		case 'b': res *= 512; break;
		case 'k': res *= 1024; break;
		case 'M': res *= 1024*1024; break;
		case 'G': res *= 1024*1024*1024; break;
		case 'T': res *= 1024*1024*1024*1024ULL; break;
		case ' ':
		case '\0': break;
		default: FPLOG_(-1, WARN, "suffix %c ignored!\n", *es);
	}
	return (loff_t)res;
}

lzma_ret init_lzma_stream(lzma_state* state)
{
	if (!lzma_check_is_supported(state->type)) {
		FPLOG(FATAL, "This type of integrity check is not supported by liblzma yet!\n");
		return LZMA_UNSUPPORTED_CHECK;
	}
#if LZMA_VERSION_MAJOR > 5 || (LZMA_VERSION == 5 && LZMA_VERSION_MAJOR >= 2)
	if (state->mt == -1)
	state->mt = lzma_cputhreads();
#else
	state->mt = 0;
#endif

	if (state->mode == COMPRESS) {
#if LZMA_VERSION_MAJOR > 5 || (LZMA_VERSION == 5 && LZMA_VERSION_MAJOR >= 2)
		if (state->mt) {
			lzma_mt options = {
				.threads=state->mt,
				.block_size=0,
				.timeout=0,
				.preset=state->preset,
				.filters=NULL,
				.check=state->type
			};
			return lzma_stream_encoder_mt(&(state->strm), &options);
		}
#endif
		return lzma_easy_encoder(&(state->strm), state->preset, state->type);
	}

	uint32_t flags = LZMA_CONCATENATED | LZMA_TELL_UNSUPPORTED_CHECK;
	// Multithreaded decompression starts with 5.4.0 (ignore 5.3.3 here)
#if LZMA_VERSION_MAJOR > 5 || (LZMA_VERSION == 5 && LZMA_VERSION_MAJOR >= 4)
	if (state->mt) {
		lzma_mt options = {
			.flags=flags,
			.threads=state->mt,
			.timeout=0,
			.filters=NULL,
			.memlimit_threading=state->max_memlimit / 8
		};
		return lzma_stream_decoder_mt(&(state->strm), &options);
	}
#endif
	return lzma_auto_decoder(&(state->strm), state->max_memlimit / 8, flags);
}

#ifndef MIN
# define MIN(a,b) ((a)<(b)? (a): (b))
#endif
#ifndef MAX
# define MAX(a,b) ((a)>(b)? (a): (b))
#endif

int lzma_plug_init(void **stat, char* param, int seq, const opt_t *opt)
{
	lzma_state *state = (lzma_state *)malloc(sizeof(lzma_state));
	if (!state) {
		FPLOG_(-1, FATAL, "allocation of %zd bytes failed: %s\n", sizeof(lzma_state), strerror(errno));
		return -1;
	}
	*stat = (void *)state;
	memset(state, 0, sizeof(lzma_state));

	lzma_stream strm = LZMA_STREAM_INIT;
	state->type = LZMA_CHECK_CRC32;
	state->preset = 3;
	state->seq = seq;
	state->strm = strm;
	//state->mt = 0;
	state->hole = -1;
	state->max_memlimit = lzma_physmem()*15/16;
	state->max_memlimit -= state->max_memlimit%65536;

	while (param) {
		char* next = strchr(param, ':');
		if (next)
			*next++ = 0;

		size_t length = strlen(param);
		if (!strcmp(param, "help")) {
			FPLOG(INFO, "%s", lzma_help);
		} else if (!strcmp(param, "z") || (length >= 5 && !memcmp(param, "compr", 5))) {
			state->mode = COMPRESS;
		} else if (!strcmp(param, "d") || (length >= 5 && !memcmp(param, "decom", 5))) {
			state->mode = DECOMPRESS;
		} else if (!strcmp(param, "mt")) {
			state->mt = -1;
		} else if (length > 3 && !memcmp(param, "mt=", 3)) {
			char *eptr; state->mt = strtol(param+3, &eptr, 10);
		} else if (!strcmp(param, "bench")) {
			state->do_bench = true;
		} else if (!strcmp(param, "test") || !strcmp(param, "t")) {
			state->mode = TEST;
		} else if (length >= 9 && !memcmp(param, "memlimit=", 9)) {
			state->memlimit = readint(param+9);

		if (state->memlimit < 1024*1024 || state->memlimit > state->max_memlimit) {
			FPLOG(FATAL, "Unreasonable memlimit param value: %zd MiB (use value b/w 1 and %zd MiB)\n",
			      state->memlimit/(1024*1024), state->max_memlimit/(1024*1024));
			return -1;
		}

		} else if ((length == 8 || length == 9) && !memcmp(param, "preset=", 7)){
			state->preset = param[7] - '0';
			if (state->preset < 0 || state->preset > 9 || (length > 8 && param[8] != 'e')) {
				FPLOG(FATAL, "plugin doesn't understand encoding preset %s\n", param+7);
				return -1;
			}
			if (length == 9 && param[8] == 'e')
				state->preset |= LZMA_PRESET_EXTREME;

		} else if (length > 6 && !memcmp(param, "check=", 6)) {
			if (!strcmp(param + 6, "CRC32")) {
				state->type = LZMA_CHECK_CRC32;
			} else if (!strcmp(param + 6, "CRC64")) {
				state->type = LZMA_CHECK_CRC64;
			} else if (!strcmp(param + 6, "SHA256")) {
				state->type = LZMA_CHECK_SHA256;
			} else if (!strcmp(param + 6, "NONE")) {
				state->type = LZMA_CHECK_NONE;
			} else {
				FPLOG(FATAL, "plugin doesn't understand integrity check type!\n");
				return -1;
			}
		} else {
			FPLOG(FATAL, "plugin doesn't understand param %s\n", param);
			return -1;
		}
		param = next;
	}
	state->zero_size = MAX(65536, opt->softbs);
	return 0;
}

int lzma_plug_release(void **stat)
{
	if (!stat || !*stat)
		return -1;

	lzma_state *state = (lzma_state *)*stat;
	if (state->zero_buf)
		free(state->zero_buf);
	if (state->output)
		free(state->output);

	free(*stat);
	return 0;
}

int lzma_open(const opt_t *opt, int ilnchg, int olnchg, int ichg, int ochg,
	      unsigned int totslack_pre, unsigned int totslack_post,
	      const fstate_t *fst, void **stat, int islast)
{
	lzma_state *state = (lzma_state*)*stat;

	if (state->mode == TEST && strcmp(opt->iname + strlen(opt->iname) - 2, "xz") != 0) {
	// Don't overinterpret filename, the user might do this on purpose
		FPLOG(WARN, "integrity check can be provided only for xz archives!\n");
		//return -1;
	}

	if (state->mode == AUTO) {
		if (!strcmp(opt->iname + strlen(opt->iname) - 2, "xz"))
			state->mode = DECOMPRESS;
	else if (!strcmp(opt->iname + strlen(opt->iname) - 4, "lzma"))
			state->mode = DECOMPRESS;
		else if (!strcmp(opt->oname + strlen(opt->oname) - 2, "xz"))
			state->mode = COMPRESS;
		else if (!strcmp(opt->oname + strlen(opt->oname) - 4, "lzma"))
			state->mode = COMPRESS;
		else {
			FPLOG(FATAL, "can't determine compression/decompression from filenames (and not set)!\n");
			return -1;
		}
	}

	if (init_lzma_stream(state) != LZMA_OK) {
		FPLOG(FATAL, "failed to initialize lzma library!");
		return -1;
	}

	lzma_memlimit_set(&(state->strm),
		state->memlimit ? state->memlimit : state->max_memlimit / 8);
	state->buf_len = 2 * opt->softbs + 16384;

	state->next_ipos = opt->init_ipos;
	return 0;
}


unsigned char* lzma_algo(unsigned char *bf, lzma_state *state, int eof, fstate_t *fst, int *towr)
{
	if (state->output == NULL)
		state->output = (unsigned char *)malloc(state->buf_len);

	if (!state->output) {
		FPLOG(FATAL, "failed to alloc %zd bytes for output buffer!\n", state->buf_len);
		//*towr = 0;
		raise(SIGQUIT);
	}

	size_t curr_pos = 0;
	int ret_xz = 0;

	lzma_action action = eof ? LZMA_FINISH : LZMA_RUN;

	state->strm.next_in = bf;
	state->strm.avail_in = *towr;
	state->read += *towr;
	size_t maxlen;
	do {
		maxlen = state->buf_len-1 - curr_pos;
		state->strm.avail_out = maxlen;
		state->strm.next_out = state->output + curr_pos;

		ret_xz = lzma_code(&(state->strm), action);

		if (ret_xz != LZMA_OK && ret_xz != LZMA_STREAM_END &&
		    ret_xz != LZMA_MEMLIMIT_ERROR && ret_xz != LZMA_BUF_ERROR) {
			FPLOG(FATAL, "(de)compression failed with code %d at ipos %zd\n", ret_xz, fst->ipos);
			raise(SIGQUIT);
			break;
		} else if (ret_xz == LZMA_MEMLIMIT_ERROR) {
			uint64_t curr_memlimit = lzma_memlimit_get(&(state->strm));

			if (!state->memlimit && curr_memlimit < state->max_memlimit) {
				lzma_memlimit_set(&(state->strm), MIN(state->max_memlimit, curr_memlimit+curr_memlimit/2+131072));
				//curr_pos += maxlen - state->strm.avail_out;
				FPLOG(DEBUG, "increased lzma_memlimit from %zi to %zi\n", curr_memlimit,
					MIN(state->max_memlimit, curr_memlimit+curr_memlimit/2+131072));
			} else {
				FPLOG(FATAL, "lzma plugin exceeded memory limit!\n");
				raise(SIGQUIT);
				break;
			}
		} else if (ret_xz == LZMA_BUF_ERROR) {
			FPLOG(WARN, "lzma buf error at %zd\n", fst->ipos);
#if 0
		FPLOG(DEBUG, "Debug next_ipos %zd, avail_in %i, avail_out %d\n",
		      state->next_ipos, state->strm.avail_in, state->strm.avail_out);
#endif
		} else {
		/* Increase output buffer if it has left less than 4k of space */
			if (state->strm.avail_out < 4096) {
				const size_t old_blen = state->buf_len;
				state->buf_len += state->buf_len/2 + 65536;
				state->output = (unsigned char *)realloc(state->output, state->buf_len);
				FPLOG(DEBUG, "increased output buffer from %zi to %zi\n", old_blen, state->buf_len);

				if (!state->output) {
					FPLOG(FATAL, "failed to realloc %zd bytes for output buffer!\n", state->buf_len);
					raise(SIGQUIT);
					break;
				}
			}
			curr_pos += maxlen - state->strm.avail_out;
		}
	} while (state->strm.avail_out != maxlen && ret_xz != LZMA_STREAM_END);

	if (eof)
		FPLOG(DEBUG, "Final bytes: %i (@%zd) -> %i (@%zd)\n",
			*towr, fst->ipos, curr_pos, fst->opos);

	//state->next_ipos = fst->ipos + *towr;
	state->next_ipos += *towr;

	if (state->mode == TEST)
		*towr = 0;
	else
		*towr = curr_pos;
	state->write += *towr;
	return state->output;
}

unsigned char* lzma_blk_cb(fstate_t *fst, unsigned char* bf,
			   int *towr, int eof, int *recall, void **stat)
{
	lzma_state *state = (lzma_state*)*stat;

	unsigned char* ptr = 0;	/* Silence gcc */
	clock_t t1 = 0;
	if (state->do_bench)
		t1 = clock();

	const loff_t hsz = fst->ipos - state->next_ipos;
	const int origtowr = *towr;
	if (hsz > 0) {
		/* FIXME: bf should be zero-filled as well, do we really need our own? */
		if (!state->zero_buf) {
			state->zero_buf = malloc(state->zero_size);
			if (!state->zero_buf) {
				FPLOG(FATAL, "failed to allocate zeroed buffer of size %zd to handle holes", state->zero_size);
				raise(SIGQUIT);
				return 0;
			}
			memset(state->zero_buf, 0, state->zero_size);
		}
		//const int backup_towr = *towr;
		if (state->hole == -1) {
			state->hole = *towr;
			FPLOG(DEBUG, "Need to do sparse magic here ipos %zd > %zd (%d) opos %zd hole %zd \n",
				fst->ipos, state->next_ipos, *towr, fst->opos, hsz);
			state->read -= hsz;
		}
		/* TODO: We could loop here as long as we're below ipos
		 * and as long as no bytes get output */
		int bytes = MIN(state->zero_size, hsz);
		int bcpy = bytes;
		ptr = lzma_algo(state->zero_buf, state, 0, fst, &bytes);
		if (state->hole)
			FPLOG(DEBUG, "Hole continued %zd >= %zd (%d/%d) (orig %d)\n",
				fst->ipos, state->next_ipos, bcpy, bytes, origtowr);
		if (eof && fst->ipos <= state->next_ipos) {
			if (!bytes)
				ptr = lzma_algo(state->zero_buf, state, eof, fst, &bytes);
		}
		*towr = bytes;
		*recall = RECALL_MARK;
	} else {
		if (state->hole != -1) {
			FPLOG(DEBUG, "After hole: Pos is %zd / %zd, opos %zd\n",
				state->next_ipos, fst->ipos, fst->opos);
		}
		state->hole = -1;
		ptr = lzma_algo(bf, state, eof, fst, towr);
	}

	if (state->do_bench)
		state->cpu += clock() - t1;

	return ptr;
}

int lzma_close(loff_t ooff, void **stat)
{
	lzma_state *state = (lzma_state *)*stat;
	FPLOG(INFO, "%zd bytes read, %zd bytes written (%.1f%)\n",
		state->read, state->write, state->read? 100.0*state->write/state->read: 100.0);
	if (state->do_bench && state->cpu / (CLOCKS_PER_SEC / 100) > 0)
		FPLOG(INFO, "%.2fs CPU time\n", (double)state->cpu / CLOCKS_PER_SEC);

	lzma_end(&(state->strm));
	return 0;
}

ddr_plugin_t ddr_plug = {
	.name = "lzma",
	//.slack_post = -18,
	.handles_sparse = 1,
	.makes_unsparse = 1,
	.changes_output = 1,
	.changes_output_len = 1,
	.supports_seek = 0,
	.init_callback  = lzma_plug_init,
	.open_callback  = lzma_open,
	.block_callback = lzma_blk_cb,
	.close_callback = lzma_close,
	.release_callback = lzma_plug_release,
};
