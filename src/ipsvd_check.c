#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include "ipsvd_check.h"
#include "ipsvd_log.h"
#include "error.h"
#include "stralloc.h"
#include "strerr.h"
#include "byte.h"
#include "scan.h"
#include "str.h"
#include "openreadclose.h"
#include "open.h"
#include "cdb.h"
#include "pathexec.h"

extern const char *progname;
unsigned long phccmax;

int ipsvd_instruct(stralloc *inst, stralloc *match) {
  char *insts;
  unsigned int instslen;
  int delim;
  int i;
  unsigned long ccmax =0;

  if (inst->s && inst->len) {
    insts =inst->s; instslen =inst->len;
    while ((i =byte_chr(insts, instslen, 0)) < instslen) {
      switch(*insts) {
      case '+':
	if ((delim =str_chr(insts, '=')) <= 1) break; /* empty inst */
	if (insts[delim] == '=') {
	  insts[delim] =0;
	  if (! pathexec_env(insts +1, insts +delim +1)) return(-1);
	  insts[delim] ='=';
	}
	else if (! pathexec_env(insts +1, 0)) return(-1);
	break;
      case 'C':
	if (! ccmax) scan_ulong(insts +1, &ccmax);
	break;
      case 0: /* skip empty line */
	break;
      default:
	strerr_warn6(progname, ": warning: ",
		     "bad instruction: ", match->s, ": ", insts, 0);
      }
      insts +=i +1;
      instslen -=i +1;
    }
    if (ccmax) phccmax =ccmax;
  }
  return(IPSVD_INSTRUCT);
}

int ipsvd_check_direntry(stralloc *d, stralloc *m, time_t now,
			 unsigned long t, int *rc) {
  int i;
  struct stat s;

  if (stat(m->s, &s) != -1) {
    if (t && (s.st_mode & S_IWUSR) && (now >= s.st_atime))
      if ((now -s.st_atime) >= t) {
	if (unlink(m->s) == -1)
	  strerr_warn4(progname, ": unable to unlink ", m->s, ": ",
		       &strerr_sys);
	return(0);
      }
    if (! (s.st_mode & S_IXUSR) && ! (s.st_mode & S_IRUSR)) {
      *rc =IPSVD_DENY; return(1);
    }
    if (s.st_mode & S_IXUSR) {
      if (! openreadclose(m->s, d, 256)) return(-1);
      if (d->len && (d->s[d->len -1] == '\n')) d->len--;
      if (! stralloc_0(d)) return(-1);
      *rc =IPSVD_EXEC;
      return(1);
    }
    if (s.st_mode & S_IRUSR) {
      if (! openreadclose(m->s, d, 256)) return(-1);
      if (d->len && (d->s[d->len -1] == '\n')) d->len--;
      for (i =0; i < d->len; i++) if (d->s[i] == '\n') d->s[i] =0;
      if (! stralloc_0(d)) return(-1);
      if ((*rc =ipsvd_instruct(d, m)) == -1) return(-1);
      return(1);
    }
    if (! stralloc_copys(m, "")) return(-1);
    if (! stralloc_0(m)) return(-1);
    *rc =IPSVD_DEFAULT;
    return(1);
  }
  else if (errno != error_noent) return(-1);
  return(0);
}

int ipsvd_check_dir(stralloc *data, stralloc *match, char *dir,
		    char *ip, char *name, unsigned long timeout) {
  struct stat s;
  int i;
  int rc;
  int ok;
  int base;
  time_t now =0;

  if (stat(dir, &s) == -1) return(IPSVD_ERR);
  if (timeout) now =time((time_t*)0);
  if (! stralloc_copys(match, dir)) return(-1);
  if (! stralloc_cats(match, "/")) return(-1);
  base =match->len;
  if (! stralloc_cats(match, ip)) return(-1);
  if (! stralloc_0(match)) return(-1);
  /* ip */
  for (;;) {
    printf("%s\n", match->s);
    ok =ipsvd_check_direntry(data, match, now, timeout, &rc);
    if (ok == -1) return(-1);
    if (ok) return(rc);

    if ((i =byte_rchr(match->s, match->len, '.')) == match->len) break;
    if (i <= base) break;
    match->s[i] =0; match->len =i;
  }
  /* host */
  if (name) {
    for (;;) {
      if (! *name) break;
      match->len =base;
      if (! stralloc_cats(match, name)) return(-1);
      if (! stralloc_0(match)) return(-1);

      ok =ipsvd_check_direntry(data, match, now, timeout, &rc);
      if (ok == -1) return(-1);
      if (ok) return(rc);

      if ((i =byte_chr(name, str_len(name), '.')) == str_len(name)) break;
      name +=i +1;
    }
  }
  /* default */
  match->len =base;
  if (! stralloc_cats(match, "0")) return(-1);
  if (! stralloc_0(match)) return(-1);

  ok =ipsvd_check_direntry(data, match, now, timeout, &rc);
  if (ok == -1) return(-1);
  if (ok) return(rc);

  if (! stralloc_copys(match, "")) return(-1);
  if (! stralloc_0(match)) return(-1);
  return(IPSVD_DEFAULT);
}

int ipsvd_check_cdb(stralloc *data, stralloc *match, char *cdb,
		    char *ip, char *name, unsigned long unused) {
  struct cdb c;
  uint32 dlen;
  int fd;
  int i;

  if ((fd =open_read(cdb)) == -1) return(IPSVD_ERR);
  cdb_init(&c, fd);
  if (! stralloc_copys(match, ip)) return(-1);
  if (! stralloc_0(match)) return(-1);
  /* ip */
  for (;;) {
    switch(cdb_find(&c, match->s, match->len -1)) {
    case -1: return(-1);
    case 1:
      dlen =cdb_datalen(&c);
      if (! stralloc_ready(data, dlen)) return(-1);
      if (cdb_read(&c, data->s, dlen, cdb_datapos(&c)) == -1) return(-1);
      if (! dlen) return(-1);
      switch(data->s[dlen -1]) {
      case 'D':
	close(fd);
	return(IPSVD_DENY);
      case 'X':
	close(fd);
	data->s[dlen -1] =0; data->len =dlen;
	return(IPSVD_EXEC);
      case 'I':
	close(fd);
	data->s[dlen -1] =0; data->len =dlen;
	return(ipsvd_instruct(data, match));
      }
    }
    if ((i =byte_rchr(match->s, match->len, '.')) == match->len) break;
    match->s[i] =0; match->len =i +1;
  }
  /* host */
  if (name) {
    for (;;) {
      if (! *name) break;
      if (! stralloc_copys(match, name)) return(-1);
      if (! stralloc_0(match)) return(-1);
      switch(cdb_find(&c, match->s, match->len -1)) {
      case -1: return(-1);
      case 1:
	dlen =cdb_datalen(&c);
	if (! stralloc_ready(data, dlen)) return(-1);
	if (cdb_read(&c, data->s, dlen, cdb_datapos(&c)) == -1) return(-1);
	if (! dlen) return(-1);
	switch(data->s[dlen -1]) {
	case 'D':
	  close(fd);
	  return(IPSVD_DENY);
	case 'X':
	  close(fd);
	  data->s[dlen -1] =0; data->len =dlen;
	  return(IPSVD_EXEC);
	case 'I':
	  close(fd);
	  data->s[dlen -1] =0; data->len =dlen;
	  return(ipsvd_instruct(data, match));
	}
      }
      if ((i =byte_chr(name, str_len(name), '.')) == str_len(name)) break;
      name +=i +1;
    }
  }
  /* default */
  if (! stralloc_copys(match, "0")) return(-1);
  if (! stralloc_0(match)) return(-1);
  switch(cdb_find(&c, match->s, 1)) {
  case -1: return(-1);
  case 1:
    dlen =cdb_datalen(&c);
    if (! stralloc_ready(data, dlen)) return(-1);
    if (cdb_read(&c, data->s, dlen, cdb_datapos(&c)) == -1) return(-1);
    if (! dlen) return(-1);
    switch(data->s[dlen -1]) {
    case 'D':
      close(fd);
      return(IPSVD_DENY);
    case 'X':
      close(fd);
      data->s[dlen -1] =0; data->len =dlen;
      return(IPSVD_EXEC);
    case 'I':
      close(fd);
      data->s[dlen -1] =0; data->len =dlen;
      return(ipsvd_instruct(data, match));
    }
  }

  if (! stralloc_copys(match, "")) return(-1);
  if (! stralloc_0(match)) return(-1);
  close(fd);
  return(IPSVD_DEFAULT);
}

int ipsvd_check(int c, stralloc *data, stralloc *match, char *db,
		char *ip, char *name, unsigned long timeout) {
  if (c)
    return(ipsvd_check_cdb(data, match, db, ip, name, 0));
  else
    return(ipsvd_check_dir(data, match, db, ip, name, timeout));
}
