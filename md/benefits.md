% ipsvd - benefits

[G. Pape](https://smarden.org/pape/)\
[ipsvd](index.html)

---

# ipsvd - benefits

---

[One daemon for each service](#separation)\
[Powerful client-based instructions](#instruct)\
[Secure DNS client library](#libdjbdns)\
[Reliable service management and logging](#runit)\
[Small code size](#smallcode)

---

[]{#separation}

### One daemon for each service

Unlike other projects also handling IP services through inetd-compatible
server programs that provide one daemon to handle several services on
multiple server addresses (`ipaddress:port`), *ipsvd* provides daemons
that handle one server address only. Setting up one service daemon for
each server address separates the configurations of services, allows to
apply different memory and other resource limits easily, and supports
running in changed root directories. *ipsvd* instructions optionally can
be shared.

---

[]{#instruct}

### Powerful client-based instructions

*ipsvd* allows flexible dynamic instructions and fast static
instructions. Dynamic instructions defined through a directory can be
adjusted on the fly through other programs and the administrator. The
filesystem\'s file and directory permissions can be used to grant and
restrict access to the configuration. For mostly static instructions, an
instructions directory can be compiled into a [constant data
base](https://cr.yp.to/cdb.html) for faster lookup.

Based on *ipsvd*\'s client-based [instructions](ipsvd-instruct.5.html),
the process state of the server program can be altered, the per-client
concurrency can be adjusted, connections can be denied, and even a
completely different server program can be started for special clients,
see some [examples](examples.html#instruct).

Clients are identified by their IP address and through IP address
ranges, by the fully qualified domain name the client\'s IP address
reverse-resolves and parts if it, and by host names currently resolving
to the client\'s IP address (to identify clients through dynamic DNS
names), see [ipsvd instructions](ipsvd-instruct.5.html) for details.

---

[]{#libdjbdns}

### Secure DNS client library

The *ipsvd* programs use the [djbdns client
library](https://smarden.org/pape/djb/) to query the DNS. This DNS
client library is known to be
[secure](https://cr.yp.to/djbdns/res-disaster.html) yet very
[convenient](https://cr.yp.to/djbdns/qualify.html).

---

[]{#runit}

### Reliable service management and logging

The daemons provided by the *ipsvd* package normally are run by a
[runsv](https://smarden.org/runit/runsv.8.html) supervisor process, and
started and managed through its control interface. The
[runit](https://smarden.org/runit/) packages provides [service
supervision](https://smarden.org/runit/benefits.html#supervision) and a
[reliable logging
facility](https://smarden.org/runit/benefits.html#log).

---

[]{#smallcode}

### Small code size

One of the *ipsvd* project\'s principles is to keep the code size small.
This minimizes the possibility of bugs introduced by programmer\'s
fault, and makes it more easy for security related people to proofread
the source code. As of version 0.9.2 of *ipsvd*, the source is about
1400 lines of C code.

The small size and memory footprint of the programs makes the *ipsvd*
package well suited for embedded systems.

---

[Gerrit Pape \<pape@smarden.org\>](mailto:pape@smarden.org)
