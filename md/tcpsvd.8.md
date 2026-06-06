% tcpsvd(8)

# NAME

tcpsvd - TCP/IP service daemon

# SYNOPSIS

**tcpsvd** \[-hpEvv\] \[-c *n*\] \[-C *n*:*msg*\] \[-b *n*\] \[-u
*user*\] \[-l *name*\] \[-i *dir*\|-x *cdb*\] \[ -t *sec*\] *host*
*port* *prog*

# DESCRIPTION

**tcpsvd** creates a TCP/IP socket, binds it to the address
*host*:*port*, and listens on the socket for incoming connections.

On each incoming connection, **tcpsvd** conditionally runs a program,
with standard input reading from the socket, and standard output writing
to the socket, to handle this connection. **tcpsvd** keeps listening on
the socket for new connections, and can handle multiple connections
simultaneously.

**tcpsvd** optionally checks for special instructions depending on the
IP address or hostname of the client that initiated the connection, see
**ipsvd-instruct**(5).

# OPTIONS

*host*
:   *host* either is a hostname, or a dotted-decimal IP address, or 0.
    If *host* is 0, **tcpsvd** accepts connections to any local IP
    address.

*port*
:   **tcpsvd** accepts connections to *host*:*port*. *port* may be a
    name from /etc/services or a number.

*prog*
:   *prog* consists of one or more arguments. For each connection,
    **tcpsvd** normally runs *prog*, with file descriptor 0 reading from
    the network, and file descriptor 1 writing to the network. By
    default it also sets up TCP-related environment variables, see
    **tcp-environ**(5)

**-i** *dir*
:   read instructions for handling new connections from the instructions
    directory *dir*. See **ipsvd-instruct**(5) for details.

**-x** *cdb*
:   read instructions for handling new connections from the constant
    database *cdb*. The constant database normally is created from an
    instructions directory by running **ipsvd-cdb**(8).

**-t** *sec*
:   timeout. This option only takes effect if the -i option is given.
    While checking the instructions directory, check the time of last
    access of the file that matches the clients address or hostname if
    any, discard and remove the file if it wasn\'t accessed within the
    last *sec* seconds; **tcpsvd** does not discard or remove a file if
    the user\'s write permission is not set, for those files the timeout
    is disabled. Default is 0, which means that the timeout is disabled.

**-l** *name*
:   local hostname. Do not look up the local hostname in DNS, but use
    *name* as hostname. This option must be set if **tcpsvd** listens on
    port 53 to avoid loops.

**-u** \[:\]*user*\[:*group*\]
:   drop permissions. Set uid and gid to the *user*\'s uid and gid, as
    found in */etc/passwd*, before running *prog*. If *user* is followed
    by a colon and a *group*, set the gid to *group*\'s gid, as found in
    */etc/group*, instead of *user*\'s gid. If *group* consists of a
    colon-separated list of group names, set the group ids of all listed
    groups. If *user* is prefixed with a colon, the *user* and all
    *group* arguments are interpreted as uid and gids respectively, and
    not looked up in the password or group file. All supplementary
    groups are removed.

**-c** *n*
:   concurrency. Handle up to *n* connections simultaneously. Default
    is 30. If there are *n* connections active, **tcpsvd** defers
    acceptance of a new connection until an active connection is closed.

**-C** *n*\[:*msg*\]
:   per host concurrency. Allow only up to *n* connections from the same
    IP address simultaneously. If there are *n* active connections from
    one IP address, new incoming connections from this IP address are
    closed immediately. If *n* is followed by :*msg,* the message *msg*
    is written to the client if possible, before closing the connection.
    By default *msg* is empty. See **ipsvd-instruct**(5) for supported
    escape sequences in *msg*.

    For each accepted connection, the current per host concurrency is
    available through the environment variable *TCPCONCURRENCY*. *n* and
    *msg* can be overwritten by **ipsvd**(7) instructions, see
    **ipsvd-instruct**(5). By default **tcpsvd** doesn\'t keep track of
    connections.

**-h**
:   Look up the client\'s hostname in DNS.

**-p**
:   paranoid. After looking up the client\'s hostname in DNS, look up
    the IP addresses in DNS for that hostname, and forget about the
    hostname if none of the addresses match the client\'s IP address.
    You should set this option if you use hostname based instructions.
    The -p option implies the -h option.

**-b** *n*
:   backlog. Allow a backlog of approximately *n* TCP SYNs. On some
    systems *n* is silently limited. Default is 20.

**-E**
:   no special environment. Do not set up TCP-related environment
    variables.

**-v**
:   verbose. Print verbose messsages to standard output.

**-vv**
:   more verbose. Print more verbose messages to standard output.

# SEE ALSO

ipsvd(7), udpsvd(8), ipsvd-instruct(5), ipsvd-cdb(8)

https://smarden.org/ipsvd/

# AUTHOR

Gerrit Pape \<pape@smarden.org\>
