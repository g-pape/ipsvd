#include <netdb.h>
#include "scan.h"

unsigned int ipsvd_scan_port(const char *s, const char *proto,
			     unsigned long *port) {
  struct servent *se;
  unsigned char *p;

  if ((se =getservbyname(s, proto))) {
    p =&se->s_port;
    *port =p[0]; *port <<=8; *port +=p[1];
    printf("port: %d\n", *port);
    return(1);
  }
  if (s[scan_ulong(s, port)]) return(0);
  return(1);
}
