#include <unistd.h>
#include <dns.h>
#include <socket.h>
#include "ipsvd_log.h"
#include "ipsvd_fmt.h"
#include "sgetopt.h"
#include "stralloc.h"
#include "str.h"
#include "fmt.h"
#include "error.h"
#include "strerr.h"
#include "scan.h"
#include "iopause.h"
#include "taia.h"
#include "fd.h"
#include "wait.h"
#include "pathexec.h"

#define USAGE " [-v] host port prog"
#define VERSION "$Id$"

#define FATAL "udpsvd: fatal: "
#define WARNING "udpsvd: warning: "
#define INFO "udpsvd: info: "

const char *progname;

unsigned long verbose =0;

void usage() { strerr_die4x(111, "usage: ", progname, USAGE, "\n"); }
void die_nomem() { strerr_die2x(111, FATAL, "out of memory."); }
void fatal(char *m0) { strerr_die3sys(111, FATAL, m0, ": "); };
void fatal2(char *m0, char *m1) {
  strerr_die5sys(111, FATAL, m0, ": ", m1, ": ");
}
void warn(char *m0) { strerr_warn3(WARNING, m0, ": ", &strerr_sys); }

int main(int argc, const char **argv, const char *const *envp) {
  int opt;
  char *host;
  char *portstr;
  unsigned long port;
  const char **prog;
  const char **tmp;
  stralloc sa ={0};
  stralloc ips ={0};
  stralloc fqdn ={0};
  char bufnum[FMT_ULONG];
  int s;
  int pid;
  int wstat;
  iopause_fd io[1];
  struct taia now;
  struct taia deadline;

  progname =*argv;

  while ((opt =getopt(argc, argv, "vV")) != opteof) {
    switch(opt) {
    case 'v':
      verbose =1;
      break;
    case 'V':
      strerr_warn1(VERSION, 0);
    case '?':
      usage();
    }
  }
  argv +=optind;


  if (! argv || ! *argv) usage();
  host =(char*)*argv++;
  if (! argv || ! *argv) usage();
  portstr =(char*)*argv++;
  if (! argv || ! *argv) usage();
  prog =argv;

  if (str_equal(host, "")) host ="0.0.0.0";
  if (str_equal(host, "0")) host ="0.0.0.0";

  scan_ulong(portstr, &port);
  if (! port) usage();

  if (! stralloc_copys(&sa, host)) die_nomem();
  if ((dns_ip4(&ips, &sa) == -1) || (ips.len < 4))
    if (dns_ip4_qualify(&ips, &fqdn, &sa) == -1)
      fatal2("temporarily unable to look up IP address", host);
  if (ips.len < 4) fatal2("unable to look up IP address", host);
  ips.len =4;
  ips.s[4] =0;

  if ((s =socket_udp()) == -1) fatal("unable to create socket");
  if (socket_bind4_reuse(s, ips.s, port) == -1)
    fatal("unable to bind socket");
  close(0);

  io[0].fd =s;
  io[0].events =IOPAUSE_READ;
  for (;;) {
    taia_now(&now);
    taia_uint(&deadline, 3600);
    taia_add(&deadline, &now, &deadline);

    iopause(io, 1, &deadline, &now);

    if (io[0].revents | IOPAUSE_READ) {
      while ((pid =fork()) == -1) {
	warn("unable to fork, sleeping");
	sleep(5);
      }
      if (pid == 0) {
	/* child */
	if (verbose) {
	  out(INFO); out("start ");
	  bufnum[fmt_ulong(bufnum, getpid())] =0;
	  out(bufnum);
	  tmp =prog;
	  while (tmp && *tmp) {
	    out(" "); outfix((char*)*tmp++);
	  }
	  flush("\n");
	}
	if ((fd_move(0, s) == -1) || (fd_copy(1, 0) == -1))
	  fatal("unable to set filedescriptor");
	pathexec_run(*prog, prog, envp);
	fatal2("unable to run", (char*)*prog);
      }
      while (wait_pid(&wstat, pid) == -1)
	warn("error waiting for child");
      if (verbose) {
	out(INFO); out("end ");
	bufnum[fmt_ulong(bufnum, pid)] =0;
	out(bufnum); flush("\n");
      }
    }
  }
  _exit(0);
}
