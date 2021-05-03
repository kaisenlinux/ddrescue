/** secmem.c
 * Get a block of memory and prevent it from being swapped
 * out or core dumped to ensure it's contents remains private
 */

#include "secmem.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif

static unsigned char *optr;
static unsigned int pagesize;

sec_fields* secmem_init()
{
#ifdef _SC_PAGESIZE
	pagesize = sysconf(_SC_PAGESIZE);
#else
#warning Cant determine pagesize, setting to 4kiB
	pagesize = 4096;
#endif  
	unsigned char *ptr = 0;
#ifdef HAVE_VALLOC
//#if defined (__DragonFly__) || defined(__NetBSD__) || defined(__BIONIC__)
	ptr = (unsigned char*)valloc(pagesize);
#elif defined(HAVE_POSIX_MEMALIGN)
	void *mp;
	if (posix_memalign(&mp, pagesize, pagesize))
		ptr = 0;
	else
		ptr = (unsigned char*)mp;
#endif /* NetBSD */
	if (!ptr) {
		//fplog(stderr, WARN, "allocation of aligned buffer failed -- use malloc\n");
		ptr = (unsigned char*)malloc(2*pagesize);
		if (!ptr) {
			fprintf(stderr, "Allocation of size %i failed!\n", 2*pagesize);
			/*
			fplog(stderr, FATAL, "allocation of buffer of size %li failed!\n", 
				bs+pagesize+plug_max_slack_pre+plug_max_slack_post);
			cleanup(); exit(18);
			 */
			abort();
		}
		ptr += pagesize-1;
		ptr -= (unsigned long)ptr % pagesize;
	}
	optr = ptr;
	memset(ptr, 0, pagesize);
	if (mlock(ptr, pagesize)) {
		fprintf(stderr, "Can't lock page in memory: %s\n", strerror(errno));
		abort();
	}
#ifdef MADV_DONTDUMP
	if (madvise(ptr, pagesize, MADV_DONTDUMP)) {
		fprintf(stderr, "Can't set to exclude from core: %s\n", strerror(errno));
		abort();
	}
#elif defined(HAVE_GETRLIMIT)
	struct rlimit rlim;
	if (getrlimit(RLIMIT_CORE, &rlim)) {
		fprintf(stderr, "Can't get core limit: %s\n", strerror(errno));
		abort();
	}
	rlim.rlim_cur = 0;
	if (setrlimit(RLIMIT_CORE, &rlim)) {
		fprintf(stderr, "Can't set core limit: %s\n", strerror(errno));
		abort();
	}
#else
#warning Cannot exclude memory from being included in core dump
#endif
	sec_fields *sf = (sec_fields*)ptr;
	sf->canary = 0xbeefdead;
	//fprintf(stderr, "secmem_init: Length=%zi\n", offsetof(sec_fields, canary));
	return (sec_fields*)ptr;
}

void secmem_release(sec_fields* sf)
{
	unsigned char* ptr = (unsigned char*)sf;
	if (sf->canary != 0xbeefdead) {
		fprintf(stderr, "Corruption: Canary overwritten! %llx\n", sf->canary);
		memset(sf, 0, offsetof(sec_fields, hashbuf1));
		abort();
	}
	memset(ptr, 0, pagesize);
	LFENCE;
	munlock(ptr, pagesize);
	if ((unsigned long)ptr - (unsigned long)optr < pagesize)
		free(optr);
	else
		free(ptr);
}

