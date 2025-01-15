/* libddr_null.c
 *
 * plugin for dd_rescue, doing nothing (except optionally setting changes_length)
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 2014
 * License: GNU GPLv2 or v3
 */

#include "ddr_plugin.h"
#include "ddr_ctrl.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>

/* fwd decl */
extern ddr_plugin_t ddr_plug;

typedef struct _null_state {
	int seq;
	char debug;
	char rev;
	loff_t next_ipos;
	unsigned char *nullbuf;
} null_state;

#define FPLOG(lvl, fmt, args...) \
	plug_log(ddr_plug.logger, state->seq, stderr, lvl, fmt, ##args)

const char* null_help = "The null plugin does nothing ...\n"
			"Options: debug:[no]lnchange:[no]change:unsparse:nosparse:noseek.\n"
		        " [no]lnchange indicates that the length may [not] be changed by ddr_null;\n"
		        " [no]change indicates that the contents may [not] be changed by ddr_null.\n"
			" unsparse indicates that the plugin may make sparse content non-sparse\n"
			" while nosparse indicates the plugin can't handle sparse files\n"
			" and noseek indicates the plguin can't freely choose the file position.\n"
			"None of thses are true, of course, but can be used for testing or for\n"
			" changing the behavior of other plugins in a chain.\n";

int null_plug_init(void **stat, char* param, int seq, const opt_t *opt)
{
	null_state *state = (null_state*)malloc(sizeof(null_state));
	*stat = (void*)state;
	memset(state, 0, sizeof(null_state));
	state->seq = seq;
	while (param) {
		char* next = strchr(param, ':');
		if (next)
			*next++ = 0;
		if (!strcmp(param, "help"))
			FPLOG(INFO, "%s", null_help);
		else if (!strcmp(param, "lnchange"))
			ddr_plug.changes_output_len = 1;
		else if (!strcmp(param, "lnchg"))
			ddr_plug.changes_output_len = 1;
		else if (!strcmp(param, "unsparse"))
			ddr_plug.makes_unsparse = 1;
		else if (!strcmp(param, "nosparse"))
			ddr_plug.handles_sparse = 0;
		else if (!strcmp(param, "noseek"))
			ddr_plug.supports_seek = 0;
		/* Do we need this if loaded multiple times? */
		else if (!strcmp(param, "nolnchange"))
			ddr_plug.changes_output_len = 0;
		else if (!strcmp(param, "nolnchg"))
			ddr_plug.changes_output_len = 0;
		else if (!strcmp(param, "change"))
			ddr_plug.changes_output = 1;
		else if (!strcmp(param, "chg"))
			ddr_plug.changes_output = 1;
		/* Do we need this if loaded multiple times? */
		else if (!strcmp(param, "nochange"))
			ddr_plug.changes_output = 0;
		else if (!strcmp(param, "nochg"))
			ddr_plug.changes_output = 0;
		else if (!strcmp(param, "debug"))
			state->debug = 1;
		else {
			FPLOG(FATAL, "plugin doesn't understand param %s\n",
				param);
			return 1;

		}
		param = next;
	}
	/* If the length changes, so does the contents ... */
	if (ddr_plug.changes_output_len && !ddr_plug.changes_output)
		FPLOG(WARN, "Change indication for length without contents change?\n");
	return 0;
}

int null_plug_release(void **stat)
{
	if (!stat || !*stat)
		return -1;
	null_state *state = (null_state*)*stat;
	if (state->nullbuf)
		free(state->nullbuf);
	free(*stat);
	return 0;
}

int null_open(const opt_t *opt, int ilnchg, int olnchg, int ichg, int ochg,
	      unsigned int totslack_pre, unsigned int totslack_post,
	      const fstate_t *fst, void **stat, int islast)
{
	null_state *state = (null_state*)*stat;
	state->next_ipos = opt->init_ipos;
	if (opt->reverse)
		state->rev = 1;
	return 0;
}

#if __WORDSIZE == 64
#define LL "l"
#elif __WORDSIZE == 32
#define LL "ll"
#else
#error __WORDSIZE unknown
#endif

#define NULLSZ 65536

#define MIN(a,b) (a<b? a: b)

unsigned char* null_blk_cb(fstate_t *fst, unsigned char* bf, 
			   int *towr, int eof, int *recall, void **stat)
{
	/* TODO: Could actually add debugging output here if wanted ... */
	null_state *state = (null_state*)*stat;
	if (state->debug) 
		FPLOG(DEBUG, "Block ipos %" LL "i opos %" LL "i with %i bytes %s\n",
			fst->ipos, fst->opos, *towr, (eof? "EOF": ""));
	/* Hack: Do only detect holes on forward jumps wjen fwd copying and bkw jump on rev copy */
	if ((fst->ipos > state->next_ipos && !state->rev) ||
	    (fst->ipos < state->next_ipos &&  state->rev)) {
		const loff_t hsz = off_labs(fst->ipos - state->next_ipos);
		FPLOG(DEBUG, "Jump of ipos detected: %lli vs %lli (%lli)\n",
			fst->ipos, state->next_ipos, hsz);
		/* Prevent infinite loop */
		//assert((fst->ipos > state->next_ipos && !state->rev) || (fst->ipos < state->next_ipos && state->rev));
		if (ddr_plug.makes_unsparse) {
#if 0
			/* We could just jump if we're the only plugin ... */
			fst->opos += hsz;
			fst->next_ipos += hsz;
#else
			/* Now we would need to feed back null blocks ... */
			if (!state->nullbuf) {
				state->nullbuf = malloc(NULLSZ);
				assert(state->nullbuf);
				memset(state->nullbuf, 0, NULLSZ);
			}
			*towr = MIN(NULLSZ, hsz);
			/* We expect to be called repeatedly with same ipos,
			 * while we're catching up with next_ipos
			 */
			*recall = RECALL_MARK;
			state->next_ipos += *towr * (state->rev? -1LL: 1);
			return state->nullbuf;
#endif
		} else {
			/* Someone else may have set unsparse, we don't need to care then
			 * nor do we need to is noone has ...
			 */
		}

	}
	//state->next_ipos += *towr * (state->rev? -1LL : 1);
	state->next_ipos = fst->ipos + *towr * (state->rev? -1LL : 1);
	return bf;
}

int null_close(loff_t ooff, void **stat)
{
	return 0;
}

ddr_plugin_t ddr_plug = {
	.name = "null",
	.needs_align = 0,
	.handles_sparse = 1,
	.supports_seek = 1,
	.init_callback  = null_plug_init,
	.open_callback  = null_open,
	.block_callback = null_blk_cb,
	.close_callback = null_close,
	.release_callback = null_plug_release,
};


