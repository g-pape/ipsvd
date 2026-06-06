% ipsvd - upgrading from previous versions

[G. Pape](https://smarden.org/pape/)\
[ipsvd](index.html)

---

# ipsvd - upgrading from previous versions

---

### 1.0.0 to 1.1.0 or 1.1.1

The `sslsvd` and `sslio` programs are no longer installed.

### 0.14.0 to 1.0.0

No further action from you is required.

### 0.13.0 to 0.14.0

The command line options to tell the [tcpsvd](tcpsvd.8.html),
[udpsvd](udpsvd.8.html), [sslsvd](sslsvd.8.html), and
[sslio](sslio.8.html) programs to drop permissions have been made more
flexible to allow specifying numerical uids and gids, as well as a list
of multiple groups or gids.

### 0.12.0 or 0.12.1 to 0.13.0

The ssl programs have been improved slightly, and build against the
matrixssl library version 1.8.3.

### 0.11.x to 0.12.0 or 0.12.1

This version introduces the new [sslsvd](sslsvd.8.html) SSLv3 TCP/IP
service daemon. [sslsvd](sslsvd.8.html) integrates the
[sslio](sslio.8.html) program into [tcpsvd](tcpsvd.8.html), so that
initializing the SSL session and reading the SSL key and certificate
doesn\'t need to be done for each incoming connection, but only once on
startup of the service daemon.

### 0.10.1 to 0.11.0 or 0.11.1

The [sslio](sslio.8.html) program also runs on MacOSX, see the
[installation insructions](install.html) on how to enable it in the
build and testing process.

### 0.9.x to 0.10.1

Client support has been added to the [sslio](sslio.8.html) program to
have it run under `tcpclient`. The logging, especially for ssl warnings
and errors, has been improved, and the documentation updated.

Here\'s a sample on how to use [sslio](sslio.8.html) in client mode with
`tcpclient`, a `https@` program derived from ucspi-tcp\'s `http@`
program:

    #!/bin/sh
    echo "GET /${2-} HTTP/1.0
    Host: ${1-0}:${3-443}
    " | tcpclient -RHl0 -- "${1-0}" "${3-443}" sslio -c sh -c '
      addcr >&7
      exec delcr <&6
    ' | awk '/^$/ { body=1; next } { if (body) print }'

### 0.8.0 or 0.8.2 to 0.9.x

This version introduces the new [sslio](sslio.8.html) program (for Linux
only), which can be used to encrypt network connections using SSLv3. A
new web page describing some of *ipsvd*\'s [benefits](benefits.html) has
been added to the documentation.

### 0.7.0 or 0.7.1 to 0.8.0 or 0.8.2

No further action from you is required.

### 0.6.1 to 0.7.0 or 0.7.1

A new type of instruction has been added. *ipsvd* now can be told to
look up IP addresses of (dynamic) hostnames on incoming connections, and
to handle a connection through different instructions if the client\'s
IP address matches one of these addresses. See
[ipsvd-instruct](ipsvd-instruct.5.html) for details. The
[examples](examples.html) have been updated slightly, and additionally
includes an example of the new check host instructions.

---

[Gerrit Pape \<pape@smarden.org\>](mailto:pape@smarden.org)
