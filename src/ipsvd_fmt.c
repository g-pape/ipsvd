#include "fmt.h"

unsigned int ipsvd_fmt_ip(char *s, char ip[4]) {
  char *p =s;
  int i;

  i =fmt_ulong(p, (unsigned long)(unsigned char)ip[0]);
  if (p) p +=i; if (p) *p++ ='.';
  i =fmt_ulong(p, (unsigned long)(unsigned char)ip[1]);
  if (p) p +=i; if (p) *p++ ='.';
  i =fmt_ulong(p, (unsigned long)(unsigned char)ip[2]);
  if (p) p +=i; if (p) *p++ ='.';
  i =fmt_ulong(p, (unsigned long)(unsigned char)ip[3]);
  if (p) p +=i;
  return(p -s);
}
unsigned int ipsvd_fmt_port(char *s, char port[2]) {
  unsigned short u;

  u =(unsigned char)port[0];
  u <<=8;
  u +=(unsigned char)port[1];
  return(fmt_ulong(s, (unsigned long)u));
}
