#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "ipsvd_check.h"
#include "ipsvd_log.h"
#include "error.h"
#include "stralloc.h"
#include "strerr.h"
#include "byte.h"
#include "str.h"
#include "openreadclose.h"
#include "open.h"
#include "cdb.h"
#include "pathexec.h"

extern const char *progname;

int ipsvd_instruct(stralloc *inst, stralloc *match) {
  char *envs;
  unsigned int envlen;
  int delim;
  int i;

  if (inst->s && inst->len) {
    envs =inst->s; envlen =inst->len;
    while ((i =byte_chr(envs, envlen, 0)) < envlen) {
      switch(*envs) {
      case '+':
	delim =str_chr(envs, '=');
	if (envs[delim] == '=') {
	  envs[delim] =0;
	  if (! pathexec_env(envs +1, envs +delim +1)) return(-1);
	  envs[delim] ='=';
	}
	break;
      case 0: /* skip empty line */
	break;
      default:
	strerr_warn6(progname, ": warning: ",
		     "bad instruction: ", match->s, ": ", envs, 0);
      }
      envs +=i +1;
      envlen -=i +1;
    }
  }
  return(IPSVD_INSTRUCT);
}

int ipsvd_check_dir(stralloc *data, stralloc *match, char *dir, char *ip) {
  struct stat s;
  int i;

  if (stat(dir, &s) == -1) return(IPSVD_ERR);
  if (! stralloc_copys(match, dir)) return(-1);
  if (! stralloc_cats(match, "/")) return(-1);
  if (! stralloc_cats(match, ip)) return(-1);
  if (! stralloc_0(match)) return(-1);
  for (;;) {
    if (stat(match->s, &s) != -1) {
      if ((s.st_mode & S_IRWXU) == 0) return(IPSVD_DENY);
      if (s.st_mode & S_IXUSR) {
	if (! openreadclose(match->s, data, 256)) return(-1);
	if (data->len && (data->s[data->len -1] == '\n')) data->len--;
	if (! stralloc_0(data)) return(-1);
	return(IPSVD_EXEC);
      }
      if (s.st_mode & S_IRUSR) {
	if (! openreadclose(match->s, data, 256)) return(-1);
	if (data->len && (data->s[data->len -1] == '\n')) data->len--;
	for (i =0; i < data->len; i++) if (data->s[i] == '\n') data->s[i] =0;
	if (! stralloc_0(data)) return(-1);
	return(ipsvd_instruct(data, match));
      }
      if (! stralloc_copys(match, "")) return(-1);
      if (! stralloc_0(match)) return(-1);
      return(IPSVD_DEFAULT);
    }
    else if (errno != error_noent) return(-1);
    if ((i =byte_rchr(match->s, match->len, '.')) == match->len) break;
    match->s[i] =0; match->len =i;
  }
  if (! stralloc_copys(match, "")) return(-1);
  if (! stralloc_0(match)) return(-1);
  return(IPSVD_DEFAULT);
}

int ipsvd_check_cdb(stralloc *data, stralloc *match, char *cdb, char *ip) {
  struct cdb c;
  uint32 dlen;
  int fd;
  int i;

  if ((fd =open_read(cdb)) == -1) return(IPSVD_ERR);
  cdb_init(&c, fd);
  if (! stralloc_copys(match, ip)) return(-1);
  if (! stralloc_0(match)) return(-1);
  for (;;) {
    switch(cdb_find(&c, match->s, match->len)) {
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
    match->s[i] =0; match->len =i;
  }
  if (! stralloc_copys(match, "")) return(-1);
  if (! stralloc_0(match)) return(-1);
  close(fd);
  return(IPSVD_DEFAULT);
}

int ipsvd_check(int c, stralloc *data, stralloc *match, char *db, char *ip) {
  if (c)
    return(ipsvd_check_cdb(data, match, db, ip));
  else
    return(ipsvd_check_dir(data, match, db, ip));
}
