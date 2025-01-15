/** ddr_plugin.h
 *
 * Data structure to register dd_rescue plugins
 */

#ifndef _DDR_PLUGIN_H
#define _DDR_PLUGIN_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#define _LARGEFILE_SOURCE 1
#define _LARGEFILE64_SOURCE 1
#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE 1

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#if 0
typedef struct _opt_t opt_t;
typedef struct _fstate_t fstate_t;
typedef struct _progress_t progress_t;
#else
#include "ddr_ctrl.h"
#endif

/* Pull in __WORDSIZE on musl */
#ifdef HAVE_SYS_REG_H
#include <sys/reg.h>
#endif

#ifdef __BIONIC__
#define strdupa(str)				\
({						\
	char* _mem = alloca(strlen(str)+1);	\
	strcpy(_mem, str);			\
	_mem;					\
 })
#endif

#define RECALL_NONE -1
#define RECALL_NA 0
#define RECALL_MARK 1

/** init callback parameters:
 * opaque handle, parameters from commandline, sequence in filter chain,
 * pointer to options.
 * Return value: 0 = OK, -x = ERROR
 */
typedef int (_init_callback)(void **stat, char* param, int seq, const opt_t *opt);

/** open_callback parameters: pointer to options, four flags telling the
 * 	plugin whether length, and/or contents of the stream are changed
 * 	by other plugins before (i) or after (o) this one,
 * 	required extra buffer memory before and after the main buffer
 * 	and the opaque handle
 * 	Return value: 0 = OK, -x = ERROR, +x = Bytes consumed from input file.
 */
typedef int (_open_callback)(const opt_t *opt, int ilnchange, int olnchange, 
			     int ichange, int ochange,
			     unsigned int totslack_pre, unsigned int totslack_post,
			     const fstate_t *fst, void **stat, int islast);

/** block_callback parameters: file state (contains file descriptors, positions,
 * 	...), buffer to be written (can be modified),
 *  	number of bytes to be written (can be null and can be modified), 
 *  	eof flag, recall request(output!), handle.
 *  Will be called with eof=1 exactly once at the end.
 *  *recall can be set to RECALL_MARK to indicate we should
 *  be called again without new data.
 *  Return value: buffer to be really written.
 */
typedef unsigned char* (_block_callback)(fstate_t *fst, unsigned char* bf, 
					 int *towr, int eof, int *recall, 
					 void **stat);

/** close_callback parameters: final output position and handle.
 * Return value: 0 = OK, -x = ERROR
 * close_callback is called before files are fsynced and closed
 */
typedef int (_close_callback)(loff_t ooff, void **stat);

/** release_callback: Called before the plugin is unloaded
 * (New in 1.47! Previously, deallocation was supposed to happen
 * in the close_callback
 */
typedef int (_release_callback)(void **stat);


enum ddrlog_t { NOHDR=0, DEBUG, INFO, WARN, GOOD, FATAL, INPUT };
typedef int (_fplog_upcall)(FILE* const f, enum ddrlog_t logpre, 
			    const char* const prefix, const char* const fmt, 
			    va_list va);

typedef struct _plug_logger {
	_fplog_upcall *vfplog;
	char prefix[24];
} plug_logger_t;

extern int ddr_loglevel;

static inline 
int plug_log(plug_logger_t *logger, int seq, FILE* const f,
		enum ddrlog_t logpre, const char* const fmt, ...)
{
	int ret = 0;
	if (logpre >= ddr_loglevel) {
		char prefix[32];
		strcpy(prefix, logger->prefix);
		int ln = strlen(prefix);
		snprintf(prefix+ln, 8, " (%2i): ", seq);
		va_list vag;
		va_start(vag, fmt);
		ret = logger->vfplog(f, logpre, prefix, fmt, vag);
		va_end(vag);
	}
	return ret;
}

/* 64bit abs */
static inline
loff_t off_labs(const loff_t diff)
{
	if (diff < 0)
		return -diff;
	else
		return  diff;
}



typedef struct _ddr_plugin {
	/* Will be filled by loader */
	const char* name;
	/* Amount of extra bytes required in buffer, negative => softbs*slackspace/16 */
	int slack_pre;
	int slack_post;
	/* Alignment need */
	unsigned int needs_align;
	/* Handles sparse */
	unsigned char handles_sparse:1;
	/* Transforms to unsparse */
	unsigned char makes_unsparse:1;
	/* Transforms output */
	unsigned char changes_output:1;
	/* Output transformation changes length -- breaks sparse detection on subsequent plugins */
	unsigned char changes_output_len:1;
	/* Support random access / reverse */
	unsigned char supports_seek:1;
	/* Don't use first non-option arg as input */
	unsigned char replaces_input:1;
	/* Don't use second non-option arg as output */
	unsigned char replaces_output:1;
	/* Internal individual state of plugin */
	void* state;
	/* Will be called after loading the plugin */
	 _init_callback * init_callback;
	/* Will be called after opening the input and output files */
	 _open_callback * open_callback;
	/* Will be called before a block is written */
	_block_callback *block_callback;
	/* Will be called before fsyncing and closing the output file */
	_close_callback *close_callback;
	/* Will be called before unloading */
	_release_callback *release_callback;
	/* Callback filled by the loader: Logging */
	//_fplog_upcall *fplog;
	plug_logger_t *logger;
	/* Filled by loader: Parameters */
	char* param;
} ddr_plugin_t;
#endif	/* _DDR_PLUGIN_H */
