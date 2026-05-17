% ipsvd - internet protocol service daemons

[G. Pape](https://smarden.org/pape/)

---

# ipsvd - internet protocol service daemons

---

[How to install ipsvd](install.html)\
[Upgrading from previous versions of ipsvd](upgrade.html)

[Benefits](benefits.html)\
[How to use dietlibc](usedietlibc.html)

[Examples](examples.html)

[The `ipsvd` interface](ipsvd.7.html)\
[The `tcpsvd` program](tcpsvd.8.html)\
[The `udpsvd` program](udpsvd.8.html)

[The ipsvd instructions](ipsvd-instruct.5.html)\
[The `ipsvd-cdb` program](ipsvd-cdb.8.html)

---

*ipsvd* is a set of internet protocol service daemons for Unix. It
currently includes a TCP/IP service daemon and an UDP/IP service daemon.

An internet protocol service (*ipsv*) daemon waits for incoming
connections on a local socket; for new connections, it conditionally
runs an arbitrary program with standard input reading from the socket,
and standard output writing to the socket (if connected), to handle the
connection. Standard error is used for logging.

*ipsv* daemons can be told to read and follow pre-defined instructions
on how to handle incoming connections; based on the client\'s IP address
or hostname, they can run different programs, set a different
environment, deny a connection, or set a per host concurrency limit.

Normally the *ipsv* daemons are run by a supervisor process, such as
[runsv](https://smarden.org/runit/runsv.8.html) from the
[runit](https://smarden.org/runit/) package, or
[supervise](https://cr.yp.to/daemontools/supervise.html) from the
[daemontools](https://cr.yp.to/daemontools.html) package.

*ipsvd* can be used to run services normally run by *inetd*, *xinetd*,
or *tcpserver*.

---

Contribute to *ipsvd* through [GitHub
ipsvd](https://github.com/g-pape/ipsvd/).

---

Related links:

-   [ucspi-tcp](https://cr.yp.to/ucspi-tcp.html)
-   [netcat](https://netcat.sourceforge.net)
-   [xinetd](https://en.wikipedia.org/wiki/Xinetd)
-   [inetd](https://en.wikipedia.org/wiki/Inetd)

---

[Gerrit Pape \<pape@smarden.org\>](mailto:pape@smarden.org)
