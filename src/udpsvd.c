#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pwd.h>
#include <dns.h>
#include <socket.h>
#include <ip4.h>
#include "ipsvd_log.h"
#include "ipsvd_check.h"
#include "ipsvd_fmt.h"
#include "sgetopt.h"
#include "sig.h"
#include "stralloc.h"
#include "str.h"
#include "open.h"
#include "fmt.h"
#include "byte.h"
#include "error.h"
#include "strerr.h"
#include "prot.h"
#include "ndelay.h"
#include "scan.h"
#include "iopause.h"
#include "taia.h"
#include "fd.h"
#include "wait.h"
#include "pathexec.h"

#define USAGE " [-vh] [-u user] host port prog"
#define VERSION "$Id$"

#define FATAL "udpsvd: fatal: "
#define WARNING "udpsvd: warning: "
#define INFO "udpsvd: info: "
#define DROP "udpsvd: drop: "

const char *progname;

const char **prog;
const char *rules =0;
unsigned int cdbrules =0;
unsigned long verbose =0;
unsigned int deny =0;
unsigned int lookuphost =0;

int s;
char local_ip[IP4_FMT];
char local_hostname[] ="";
char *local_port;
stralloc remote_hostname ={0};
char remote_ip[IP4_FMT];
char remote_port[FMT_ULONG];
struct sockaddr_in socka;
int socka_size =sizeof(socka);
char bufnum[FMT_ULONG];
char ch;

void usage() { strerr_die4x(111, "usage: ", progname, USAGE, "\n"); }
void die_nomem() { strerr_die2x(111, FATAL, "out of memory."); }
void fatal(char *m0) { strerr_die3sys(111, FATAL, m0, ": "); };
void fatal2(char *m0, char *m1) {
  strerr_die5sys(111, FATAL, m0, ": ", m1, ": ");
}
void warn(char *m0) { strerr_warn3(WARNING, m0, ": ", &strerr_sys); }
void warn2(char *m0, char *m1) {
  strerr_warn5(WARNING, m0, ": ", m1, ": ", &strerr_sys);
}
void drop_nomem() { strerr_die2x(111, DROP, "out of memory."); }
void drop(char *m0) { strerr_die3sys(111, DROP, m0, ": "); }
void discard(char *m0, char *m1) {
  recv(s, 0, 0, 0);
  strerr_die6sys(111, DROP, "discard data: ", m0, ": ", m1, ": ");
}

void sig_term_handler() {
  if (verbose) {
    out(INFO); flush("sigterm received, exit.\n");
  }
  _exit(0);
}

void connection_accept(int c) {
  stralloc rule ={0};
  stralloc match ={0};
  int ac;
  const char **run;
  const char *args[4];

  remote_ip[ipsvd_fmt_ip(remote_ip, (char*)&socka.sin_addr)] =0;
  remote_port[ipsvd_fmt_port(remote_port, (char*)&socka.sin_port)] =0;
  if (lookuphost) {
    if (dns_name4(&remote_hostname, (char *)&socka.sin_addr) == -1) {
      warn2("temporarily unable to reverse look up IP address", remote_ip);
      if (! stralloc_copys(&remote_hostname, "(unknown)")) drop_nomem();
    }
    if (! stralloc_0(&remote_hostname)) drop_nomem();
  }

  if (rules) {
    ac =ipsvd_check(cdbrules, &rule, &match, (char*)rules, remote_ip);
    if (ac == -1) discard("unable to check rule", remote_ip);
    if (ac == IPSVD_ERR) discard("unable to read", (char*)rules);
  }
  else ac =IPSVD_DEFAULT;
  if (deny && (ac == IPSVD_DEFAULT)) ac =IPSVD_DENY;

  if (verbose) {
    out(INFO);
    switch(ac) {
    case IPSVD_DENY: out("deny "); break;
    case IPSVD_DEFAULT: case IPSVD_INSTRUCT: out("start "); break;
    case IPSVD_EXEC: out("exec "); break;
    }
    bufnum[fmt_ulong(bufnum, getpid())] =0;
    out(bufnum); out(" :"); outfix(remote_hostname.s); out(":");
    outfix(remote_ip); out(":"); outfix(remote_port);
    if (rules) {
      out(" ");
      if (cdbrules) {
	out((char*)rules); out("/");
      }
      outfix(match.s);
      if(rule.s && rule.len) {
	out(": "); outrule(&rule);
      }
    }
    flush("\n");
  }
  
  if (ac == IPSVD_DENY) {
    recv(s, 0, 0, 0);
    _exit(100);
  }
  if (ac == IPSVD_EXEC) {
    args[0] ="/bin/sh"; args[1] ="-c"; args[2] =rule.s; args[3] =0;
    run =args;
  }
  else run =prog;

  if ((fd_move(0, c) == -1) || (fd_copy(1, 0) == -1))
    drop("unable to set filedescriptor");
  sig_uncatch(sig_term);
  sig_uncatch(sig_pipe);
  pathexec(run);

  discard("unable to run", (char*)*prog);
}

int main(int argc, const char **argv, const char *const *envp) {
  int opt;
  char *host;
  unsigned long port;
  stralloc sa ={0};
  stralloc ips ={0};
  stralloc fqdn ={0};
  int pid;
  int wstat;
  iopause_fd io[1];
  struct taia now;
  struct taia deadline;
  struct passwd *pwd =0;

  progname =*argv;

  while ((opt =getopt(argc, argv, "vu:hr:x:V")) != opteof) {
    switch(opt) {
    case 'v':
      verbose =1;
      break;
    case 'u':
      if (! (pwd =getpwnam(optarg)))
	strerr_die3x(100, FATAL, "unknown user: ", (char*)optarg);
      break;
    case 'h':
      lookuphost =1;
      break;
    case 'r':
      if (rules) usage();
      rules =optarg;
      break;
    case 'x':
      if (rules) usage();
      rules =optarg;
      cdbrules =1;
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
  local_port =(char*)*argv++;
  if (! argv || ! *argv) usage();
  prog =argv;
  
  sig_catch(sig_term, sig_term_handler);
  sig_ignore(sig_pipe);
  
  if (str_equal(host, "")) host ="0.0.0.0";
  if (str_equal(host, "0")) host ="0.0.0.0";
  
  scan_ulong(local_port, &port);
  if (! port) usage();

  if (! stralloc_copys(&sa, host)) die_nomem();
  if ((dns_ip4(&ips, &sa) == -1) || (ips.len < 4))
    if (dns_ip4_qualify(&ips, &fqdn, &sa) == -1)
      fatal2("temporarily unable to look up IP address", host);
  if (ips.len < 4)
    strerr_die3x(100, FATAL, "unable to look up IP address: ", host);
  ips.len =4;
  ips.s[4] =0;
  
  local_ip[ipsvd_fmt_ip(local_ip, ips.s)] =0;
  
  if ((s =socket_udp()) == -1) fatal("unable to create socket");
  if (socket_bind4_reuse(s, ips.s, port) == -1)
    fatal("unable to bind socket");
  ndelay_off(s);
  
  if (pwd) { /* drop permissions */
    if (prot_gid(pwd->pw_gid) == -1) fatal("unable to set gid");
    if (prot_uid(pwd->pw_uid) == -1) fatal("unable to set uid");
  }
  close(0);
  
  if (verbose) {
    out(INFO); out("listening on "); outfix(local_ip); out(":");
    outfix(local_port);
    if (pwd) {
      bufnum[fmt_ulong(bufnum, pwd->pw_uid)] =0;
      out(", uid "); out(bufnum);
      bufnum[fmt_ulong(bufnum, pwd->pw_gid)] =0;
      out(", gid "); out(bufnum);
    }
    flush(", starting.\n");
  }
  
  io[0].fd =s;
  io[0].events =IOPAUSE_READ;
  io[0].revents =0;
  for (;;) {
    taia_now(&now);
    taia_uint(&deadline, 3600);
    taia_add(&deadline, &now, &deadline);
    iopause(io, 1, &deadline, &now);
    
    if (io[0].revents | IOPAUSE_READ) {
      io[0].revents =0;
      while ((pid =fork()) == -1) {
	warn("unable to fork, sleeping");
	sleep(5);
      }
      if (pid == 0) { /* child */
	if (recvfrom(s, 0, 0, MSG_PEEK, (struct sockaddr *)&socka,
		     &socka_size) == -1) drop("unable to read from socket");
	connection_accept(s);
      }
      while (wait_pid(&wstat, pid) == -1) warn("error waiting for child");
      if (verbose) {
	out(INFO); out("end ");
	bufnum[fmt_ulong(bufnum, pid)] =0;
	out(bufnum); flush("\n");
      }
    }
  }
  _exit(0);
}
