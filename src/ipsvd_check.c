#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "error.h"
#include "stralloc.h"
#include "byte.h"
#include "openreadclose.h"
#include "cdb.h"

int ipsv_check_dirip(stralloc *data, stralloc *match, char *dir, char *ip) {
  stralloc tmp ={0};
  struct stat s;
  int i;

  if (! stralloc_copys(&tmp, dir)) return(-1);
  if (! stralloc_cats(&tmp, "/")) return(-1);
  if (! stralloc_cats(&tmp, ip)) return(-1);
  if (! stralloc_0(&tmp)) return(-1);
  for (;;) {
    if (stat(tmp.s, &s) != -1) {
      if ((s.st_mode & S_IRWXU) == 0) {
	if (! stralloc_copyb(match, tmp.s, tmp.len)) return(-1);
	return(0);
      }
      if (s.st_mode & S_IXUSR) { /* exec */
	if (! openreadclose(tmp.s, data, 256)) return(-1);
	if (data->s[data->len -1] != '\n') if (! stralloc_0(data)) return(-1);
	if (! stralloc_copyb(match, tmp.s, tmp.len)) return(-1);
	return(3);
      }
      if (s.st_mode & S_IRUSR) { /* env */
	if (! openreadclose(tmp.s, data, 256)) return(-1);
	for (i =0; i < data->len; i++) if (data->s[i] == '\n') data->s[i] =0;
	if (! data->len || (data->s[data->len -1] != 0))
	  if (! stralloc_0(data)) return(-1);
	if (! stralloc_copyb(match, tmp.s, tmp.len)) return(-1);
	return(2);
      }
      if (! stralloc_copys(match, "")) return(-1);
      return(0);
    }
    else if (errno != error_noent) return(-1);
    if ((i =byte_rchr(tmp.s, tmp.len, '.')) == tmp.len) break;
    tmp.s[i] =0; tmp.len =i;
  }
  if (! stralloc_copys(match, "")) return(-1);
  return(1);
}

int ipsv_check_cdbip(stralloc *data, stralloc *match, int fd, char *ip) {
  stralloc tmp ={0};
  struct cdb c;
  uint32 dlen;
  int i;

  cdb_init(&c, fd);
  if (! stralloc_copys(&tmp, ip)) return(-1);
  for (;;) {
    switch(cdb_find(&c, tmp.s, tmp.len)) {
    case -1: return(-1);
    case 1:
      dlen =cdb_datalen(&c);
      if (! stralloc_ready(data, dlen)) return(-1);
      if (cdb_read(&c, data->s, dlen, cdb_datapos(&c)) == -1) return(-1);

      if (data->s[dlen -1] == 'D') { /* deny */
	if (! stralloc_copyb(match, tmp.s, tmp.len)) return(-1);
	return(0);
      }
      if (data->s[dlen -1] == 'X') { /* exec */
	data->s[dlen -1] =0;
	data->len =dlen;
	if (! stralloc_copyb(match, tmp.s, tmp.len)) return(-1);
	return(3);
      }
      if (data->s[dlen -1] == 'A') { /* env */
	data->s[dlen -1] =0;
	data->len =dlen;
	if (! stralloc_copyb(match, tmp.s, tmp.len)) return(-1);
	return(2);
      }
      break;
    }
    if ((i =byte_rchr(tmp.s, tmp.len, '.')) == tmp.len) break;
    tmp.s[i] =0; tmp.len =i;
  }
  if (! stralloc_copys(match, "")) return(-1);
  return(1);
}

