#ifndef IPSVD_LOG_H
#define IPSVD_LOG_H

#include "buffer.h"

void out(char *m) { buffer_puts(buffer_1, m); }
void outfix(char *m) { 
  char ch;
  int i;
  
  for (i = 0;i < 100;++i) {
    ch = m[i];
    if (!ch) return;
    if (ch < 33) ch = '?';
    if (ch > 126) ch = '?';
    if (ch == '%') ch = '?'; /* logger stupidity */
    if (ch == ':') ch = '?';
    buffer_put(buffer_1, &ch, 1);
  }
  out("...(truncate)");
}
void flush(char *m) { buffer_putsflush(buffer_1, m); }

#endif
