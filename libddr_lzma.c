/* libddr_lzma.c
 *
 * plugin for dd_rescue, doing compression and decompression for xz archives.
 *
 * (c) Dmitrii Ivanov <dsivanov_9@edu.hse.ru>, 2023
 * License: GNU GPLv2 or v3
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
    uint64_t memlimit;
    uint64_t max_memlimit;
    unsigned char *output;
    size_t buf_len;
    lzma_stream strm;
    uint32_t mt;
    bool do_bench;
    clock_t cpu;
} lzma_state;

#define FPLOG(lvl, fmt, args...) \
	plug_log(ddr_plug.logger, stderr, lvl, fmt, ##args)

const char* lzma_help = "LZMA plugin which is doing compression/decompression for xz archives.\n"
                        " Parameters:\n"
                        " z|compr[ess] - compress input file;\n"
                        " d|decom[press] - decompress input file;\n"
                        " test - check archive integrity;\n"
                        " check=CRC32/CRC64/SHA256/NONE - select checksum to calculate on compression, CRC32 by default;\n"
                        " preset=0...9 - compression preset, default is 5;\n"
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
		default:
			FPLOG(WARN, "suffix %c ignored!\n", *es);
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
            .memlimit_threading=state->max_memlimit / 4
        };
        return lzma_stream_decoder_mt(&(state->strm), &options);
    }
#endif
    return lzma_auto_decoder(&(state->strm), state->max_memlimit / 4, flags);
}

int lzma_plug_init(void **stat, char* param, int seq, const opt_t *opt)
{
    lzma_state *state = (lzma_state *)malloc(sizeof(lzma_state));
    if (!state) {
        FPLOG(FATAL, "allocation of %zd bytes failed: %s\n", sizeof(lzma_state), strerror(errno));
        return -1;
    }
    *stat = (void *)state;
    memset(state, 0, sizeof(lzma_state));

    lzma_stream strm = LZMA_STREAM_INIT;
    state->type = LZMA_CHECK_CRC32;
    state->preset = 5;
    state->strm = strm;
    //state->mt = 0;
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
    return 0;
}

int lzma_plug_release(void **stat)
{
    if (!stat || !*stat)
        return -1;

    lzma_state *state = (lzma_state *)*stat;
    if (state->output)
        free(state->output);

    free(*stat);
    return 0;
}

int lzma_open(const opt_t *opt, int ilnchg, int olnchg, int ichg, int ochg,
          unsigned int totslack_pre, unsigned int totslack_post,
	      const fstate_t *fst, void **stat)
{
    lzma_state *state = (lzma_state*)*stat;

    if (state->mode == TEST && strcmp(opt->iname + strlen(opt->iname) - 2, "xz") != 0) {
        FPLOG(FATAL, "integrity check can be provided only for xz archives!\n");
        return -1;
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
        !state->memlimit ? state->max_memlimit / 4 : state->memlimit);

    return 0;
}

#ifndef MIN
# define MIN(a,b) ((a)<(b)? (a): (b))
#endif

unsigned char* lzma_algo(unsigned char *bf, lzma_state *state, int eof, fstate_t *fst, int *towr)
{
    uint8_t output_bf[CHUNK_SIZE + 1];
    state->buf_len = state->buf_len ? state->buf_len : CHUNK_SIZE * 2;
    if (state->output == NULL)
        state->output = (unsigned char *)malloc(state->buf_len);

    size_t curr_pos = 0;
    if (state->output) {
        state->strm.next_in = bf;
        state->strm.avail_in = *towr;

        lzma_action action = eof ? LZMA_FINISH : LZMA_RUN;

        int ret_xz = 0;
        do {
            state->strm.next_out = output_bf;
            state->strm.avail_out = CHUNK_SIZE;

            ret_xz = lzma_code(&(state->strm), action);

            if (ret_xz != LZMA_OK && ret_xz != LZMA_STREAM_END && ret_xz != LZMA_MEMLIMIT_ERROR) {
                FPLOG(FATAL, "(de)compression failed with code: %d\n", ret_xz);
                raise(SIGQUIT);
                break;
            } else if (ret_xz == LZMA_MEMLIMIT_ERROR) {
                uint64_t curr_memlimit = lzma_memlimit_get(&(state->strm));

                if (!state->memlimit && curr_memlimit < state->max_memlimit) {
                    lzma_memlimit_set(&(state->strm), MIN(state->max_memlimit, 2*curr_memlimit));
                } else {
                    FPLOG(FATAL, "lzma plugin exceeded memory limit!\n");
                    raise(SIGQUIT);
                    break;
                }
            } else {
                if (state->buf_len - CHUNK_SIZE - 1 < curr_pos) {
                    state->buf_len *= 2;
                    state->output = (unsigned char *)realloc(state->output, state->buf_len);

                    if (!state->output) {
                        FPLOG(FATAL, "failed to realloc %zd bytes for output buffer!\n", state->buf_len);
                        raise(SIGQUIT);
                        break;
                    }
                }

                memcpy(state->output + curr_pos, output_bf, CHUNK_SIZE);
                curr_pos += CHUNK_SIZE - state->strm.avail_out;
            }
        } while (state->strm.avail_out != CHUNK_SIZE && ret_xz != LZMA_STREAM_END);
    } else {
        FPLOG(FATAL, "failed to alloc %zd bytes for output buffer!\n", state->buf_len);
        //*towr = 0;
        raise(SIGQUIT);
    }

    if (state->mode == TEST)
        *towr = 0;
    else
        *towr = curr_pos;
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

    ptr = lzma_algo(bf, state, eof, fst, towr);

    if (state->do_bench)
        state->cpu += clock() - t1;

    return ptr;
}

int lzma_close(loff_t ooff, void **stat)
{
    lzma_state *state = (lzma_state *)*stat;
    if (state->do_bench && state->cpu / (CLOCKS_PER_SEC / 100) > 0)
        FPLOG(INFO, "%.2fs CPU time\n", (double)state->cpu / CLOCKS_PER_SEC);

    lzma_end(&(state->strm));
    return 0;
}

ddr_plugin_t ddr_plug = {
    .name = "lzma",
    .handles_sparse = 0,
    .init_callback  = lzma_plug_init,
    .open_callback  = lzma_open,
    .block_callback = lzma_blk_cb,
    .close_callback = lzma_close,
    .release_callback = lzma_plug_release,
};
