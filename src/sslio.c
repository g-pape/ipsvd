#include <unistd.h>
#include <matrixSsl.h>
#include "uidgid.h"
#include "prot.h"
#include "error.h"
#include "strerr.h"
#include "fd.h"
#include "pathexec.h"
#include "stralloc.h"
#include "byte.h"
#include "taia.h"
#include "iopause.h"
#include "ndelay.h"
#include "fmt.h"
#include "scan.h"
#include "sgetopt.h"
#include "env.h"

#define USAGEROOT " -u user [-U user] [-/ root] [-C cert] [-K key] [-v] prog"
#define USAGE " [-C cert] [-K key] [-v] prog"
#define VERSION "$Id$"
#define NAME "sslio["
#define FATAL "]: fatal: "
#define WARNING "]: warning: "
#define INFO "]: info: "

const char *progname;
char id[FMT_ULONG];
char ul[FMT_ULONG];

void usage() {
  if (getuid() == 0) strerr_die4x(111, "usage: ", progname, USAGEROOT, "\n");
  strerr_die4x(111, "usage: ", progname, USAGE, "\n");
}
void die_nomem() { strerr_die4x(111, NAME, id, FATAL, "out of memory."); }
void fatal(char *m0) { strerr_die5sys(111, NAME, id, FATAL, m0, ": "); }
void warn(char *m0) { strerr_warn4(NAME, id, WARNING, m0, &strerr_sys); }
void warnx(char *m0) { strerr_warn4(NAME, id, WARNING, m0, 0); }
void info(char *m0) { strerr_warn4(NAME, id, INFO, m0, 0); }
void infou(char *m0, unsigned long u) {
  ul[fmt_ulong(ul, u)] =0;
  strerr_warn5(NAME, id, INFO, m0, ul, 0);
}

char *cert ="./cert.pem";
char *key =0;
char *user =0;
char *svuser =0;
char *root =0;
unsigned int verbose =0;

struct uidgid ugid, svugid;
unsigned long bufsizein =8192;
unsigned long bufsizeou =12288;

sslKeys_t *keys;
ssl_t *ssl;
int pid;
int encpipe[2];
int decpipe[2];
int len;
int rc;
int handshake =1;
int getdec =1;
char *s;

sslBuf_t encin, encou;
stralloc encinbuf ={0};
stralloc encoubuf ={0};
sslBuf_t decin, decou;
stralloc decinbuf ={0};
stralloc decoubuf ={0};

int fdstdin =0;
int fdstdou =1;
unsigned long bytesin =0;
unsigned long bytesou =0;

unsigned char error, alvl, adesc;

unsigned int blowup(sslBuf_t *buf, stralloc *sa, unsigned int len) {
  sa->len =buf->end -buf->buf;
  buf->size +=len;
  if (! stralloc_ready(sa, buf->size)) return(0);
  buf->end =sa->s +(buf->end -buf->buf);
  buf->start =sa->s +(buf->start -buf->buf);
  buf->buf =sa->s;
  return(1);
}
void finish(void) {
  for (;;) {
    decou.start =decou.end =decou.buf;
    rc =matrixSslEncodeClosureAlert(ssl, &decou);
    if (rc == SSL_ERROR)
      if (verbose) info("matrixSslEncodeClosureAlert returns ssl error");
    if (rc == SSL_FULL) {
      if (! blowup(&decou, &decoubuf, bufsizeou)) die_nomem();
      if (verbose > 1) infou("decode output buffer size: ", decou.size);
      continue;
    }
    if (rc == 0) {
      if (write(fdstdou, decou.start, decou.end -decou.start)
	  != (decou.end -decou.start)) {
	warn("unable to send ssl closure alert");
	return;
      }
      if (verbose > 2) info("sending ssl closure alert");
      bytesou +=decou.end -decou.start;
    }
    /* bummer */
    matrixSslDeleteSession(ssl);
    close(fdstdou); close(decpipe[1]); close(encpipe[0]);
    if (fdstdin != -1) close(fdstdin);
    fdstdou = fdstdin = decpipe[1] =encpipe[0] =-1;
    return;
  }
}
void encode(void) {
  if ((len =read(encpipe[0], encinbuf.s, encin.size)) < 0)
    fatal("unable to read from prog");
  if (len == 0) {
    if (verbose > 2) info("prog: eof");
    finish();
    return;
  }
  for (;;) {
    rc =matrixSslEncode(ssl, encin.buf, len, &encou);
    if (rc == SSL_ERROR) fatal("matrixSslEncode returns ssl error");
    if (rc == SSL_FULL) {
      if (! blowup(&encou, &encoubuf, bufsizeou)) die_nomem();
      if (verbose > 1) infou("encode output buffer size: ", encou.size);
      continue;
    }
    if (write(fdstdou, encou.start, encou.end -encou.start)
	!= encou.end -encou.start) fatal("unable to write to stdout");
    if (verbose > 2) infou("write bytes: ", encou.end -encou.start);
    bytesou +=encou.end -encou.start;
    encou.start =encou.end =encou.buf =encoubuf.s;
    return;
  }
}

void decode(void) {
  do {
    if (getdec) {
      len =decin.size -(decin.end -decin.buf);
      if ((len =read(fdstdin, decin.end, len)) < 0)
	fatal("unable to read from stdin");
      if (len == 0) {
	if (verbose > 2) info("stdin: eof");
	close(fdstdin); close(decpipe[1]);
	fdstdin =-1;
	return;
      }
      if (verbose > 2) infou("read bytes: ", len);
      bytesin +=len;
      decin.end +=len;
      getdec =0;
    }
    for (;;) {
      rc =matrixSslDecode(ssl, &decin, &decou, &error, &alvl, &adesc);
      if (rc == SSL_SUCCESS) { handshake =0; break; }
      if (rc == SSL_ERROR) fatal("ssl dec error");
      if (rc == SSL_PROCESS_DATA) {
	if (write(decpipe[1], decou.start, decou.end -decou.start)
	    != decou.end -decou.start) fatal("unable to write to prog");
	decou.start =decou.end =decou.buf;
	if (decin.start > decin.buf) { /* align */
	  byte_copy(decin.buf, decin.end -decin.start, decin.start);
	  decin.end -=decin.start -decin.buf;
	  decin.start =decin.buf;
	}
	break;
      }
      if (rc == SSL_SEND_RESPONSE) {
	if (write(fdstdou, decou.start, decou.end -decou.start)
	    != (decou.end -decou.start))
	  fatal("unable to send ssl response");
	bytesou +=decou.end -decou.start;
	if (verbose > 2) info("ssl handshake response");
	decou.start =decou.end =decou.buf;
	break;
      }
      if (rc == SSL_ALERT) {
	if (adesc != SSL_ALERT_CLOSE_NOTIFY) fatal("ssl alert from peer");
	if (verbose > 1) info("ssl alert from peer");
	finish();
	return;
      }
      if (rc == SSL_PARTIAL) {
	getdec =1;
	if (decin.size -(decin.end -decin.buf) < bufsizein) {
	  if (! blowup(&decin, &decinbuf, bufsizein)) die_nomem();
	  if (verbose > 1) infou("decode input buffer size: ", decin.size);
	}
	break;
      }
      if (rc == SSL_FULL) {
	if (! blowup(&decou, &decoubuf, bufsizeou)) die_nomem();
	if (verbose > 1) infou("decode output buffer size: ", decou.size);
	continue;
      }
    }
    if (decin.start == decin.end) {
      decin.start =decin.end =decin.buf;
      getdec =1;
    }
  } while (getdec == 0);
}

void doio(void) {
  iopause_fd x[2];
  struct taia deadline;
  struct taia now;

  if (! stralloc_ready(&encinbuf, bufsizein)) die_nomem();
  encin.buf =encin.start =encin.end =encinbuf.s; encin.size =bufsizein;
  if (! stralloc_ready(&decinbuf, bufsizein)) die_nomem();
  decin.buf =decin.start =decin.end =decinbuf.s; decin.size =bufsizein;
  if (! stralloc_ready(&encoubuf, bufsizeou)) die_nomem();
  encou.buf =encou.start =encou.end =encoubuf.s; encou.size =bufsizeou;
  if (! stralloc_ready(&decoubuf, bufsizeou)) die_nomem();
  decou.buf =decou.start =decou.end =decoubuf.s; decou.size =bufsizeou;

  for (;;) {
    iopause_fd *xx =x;
    int l =2;

    x[0].fd =encpipe[0];
    x[0].events =IOPAUSE_READ;
    x[0].revents =0;
    x[1].fd =fdstdin;
    x[1].events =IOPAUSE_READ;
    x[1].revents =0;

    if ((x[0].fd == -1) || handshake) { --l; ++xx; }
    if (x[1].fd == -1) --l;
    if (! l) return;

    taia_now(&now);
    taia_uint(&deadline, 30);
    taia_add(&deadline, &now, &deadline);
    iopause(xx, l, &deadline, &now);
    
    if (x[0].revents) encode();
    if (x[1].revents) decode();
  }
}

int main(int argc, const char **argv) {
  int opt;

  progname =*argv;
  pid =getpid();
  id[fmt_ulong(id, pid)] =0;

  while ((opt =getopt(argc, argv, "u:U:/:C:K:vV")) != opteof) {
    switch(opt) {
    case 'u': user =(char*)optarg; break;
    case 'U': svuser =(char*)optarg; break;
    case '/': root =(char*)optarg; break;
    case 'C': cert =(char*)optarg; break;
    case 'K': key =(char*)optarg; break;
    case 'v': ++verbose; break;
    case 'V': strerr_warn1(VERSION, 0);
    case '?': usage();
    }
  }
  argv +=optind;
  if (! argv || ! *argv) usage();

  if (getuid() == 0) { if (! user) usage(); }
  else { if (root || user || svuser) usage(); }

  if (user) if (! uidgid_get(&ugid, user, 1))
    strerr_die3x(100, FATAL, "unknown user/group: ", user);
  if (svuser) if (! uidgid_get(&svugid, svuser, 1))
    strerr_die3x(100, FATAL, "unknown user/group for prog: ", svuser);

  if ((s =env_get("SSLIO_BUFIN"))) scan_ulong(s, &bufsizein);
  if ((s =env_get("SSLIO_BUFOU"))) scan_ulong(s, &bufsizeou);
  if (bufsizein < 64) bufsizein =64;
  if (bufsizeou < 64) bufsizeou =64;

  if (pipe(encpipe) == -1) fatal("unable to create pipe for encoding");
  if (pipe(decpipe) == -1) fatal("unable to create pipe for decoding");
  if ((pid =fork()) == -1) fatal("unable to fork");
  if (pid == 0) {
    if (close(encpipe[1]) == -1)
      fatal("unable to close encoding pipe output");
    if (close(decpipe[0]) == -1)
      fatal("unable to close decoding pipe input");
    matrixSslOpen();
    if (root) {
      if (chdir(root) == -1) fatal("unable to change to new root directory");
      if (chroot(".") == -1) fatal("unable to chroot");
    }
    if (user) {
      /* drop permissions */
      if (prot_gid(ugid.gid) == -1) fatal("unable to set gid");
      if (prot_uid(ugid.uid) == -1) fatal("unable to set uid");
    }
    if (! key) key =cert;
    if (matrixSslReadKeys(&keys, cert, key, 0, 0) < 0)
      fatal("unable to read certfile or keyfile");
    if (matrixSslNewSession(&ssl, keys, 0, SSL_FLAGS_SERVER) < 0)
      fatal("unable to create ssl session");
    doio();
    matrixSslDeleteSession(ssl);
    if (verbose) {
      infou("bytes in: ", bytesin); infou("bytes ou: ", bytesou);
    }
    _exit(0);
  }
  if (close(encpipe[0]) == -1) fatal("unable to close encoding pipe input");
  if (close(decpipe[1]) == -1) fatal("unable to close decoding pipe output");
  if (fd_move(fdstdin, decpipe[0]) == -1)
    fatal("unable to setup filedescriptor for decoding");
  if (fd_move(fdstdou, encpipe[1]) == -1)
    fatal("unable to setup filedescriptor for encoding");
  if (svuser) {
    if (prot_gid(svugid.gid) == -1) fatal("unable to set gid for prog");
    if (prot_uid(svugid.uid) == -1) fatal("unable to set uid for prog");
  }
  pathexec(argv);
  fatal("unable to run child");
  return(111);
}
