#ifndef IPSVD_CHECK_H
#define IPSVD_CHECK_H

#include "stralloc.h"

extern unsigned long phccmax;
extern stralloc phccmsg;

#define IPSVD_ERR 0
#define IPSVD_DENY 1
#define IPSVD_DEFAULT 2
#define IPSVD_INSTRUCT 3
#define IPSVD_EXEC 4

extern int ipsvd_check(int, stralloc *, stralloc *, char *, char *, char *,
		       unsigned long);

#endif
