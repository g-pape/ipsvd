#include <dns.h>
#include "byte.h"

static stralloc sa;

int ipsvd_hostname(stralloc *host, char *ip, unsigned int paranoid) {
  int i;

  host->len =0;
  if (dns_name4(host, ip) == -1) return(-1);
  if (paranoid) {
    if (dns_ip4(&sa, host) == -1) {
      host->len =0;
      return(-1);
    }
    for (i =0; i +4 <= sa.len; i +=4)
      if (byte_equal(ip, 4, sa.s +i)) {
	paranoid =0;
	break;
      }
    if (paranoid) host->len =0;
  }
  return(0);
}
