% ipsvd(7)

# NAME

ipsvd - Internet protocol service daemon

# SYNOPSIS

*ipsvd* \[-hp\] \[-l *name*\] \[-u *user*\] \[-i *dir*\|-x *cdb*\] \[-t
*sec*\] *host* *port* *prog*

# DESCRIPTION

An implementation of an internet protocol service daemon provides the
command line interface as shown in SYNOPSIS above (additional options
are possible), and supports pre-defined instructions for handling
connections through files in a instructions directory, and through a
constant database, as described in **ipsvd-instruct**(5).

Currently there are two implementations of an internet protocol service
daemon: a TCP/IP service daemon, **tcpsvd**(8), and an UDP/IP service
daemon, **udpsvd**(8). More internet protocol service daemons may appear
in the future.

# OPTIONS

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
    last *sec* seconds; **ipsvd** does not discard or remove a file if
    the user\'s write permission is not set, for those files the timeout
    is disabled. Default is 0, which means that the timeout is disabled.

**-l** *name*
:   local hostname. Do not look up the local hostname in DNS, but use
    *name* as hostname.

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

**-h**
:   Look up the client\'s hostname in DNS.

**-p**
:   paranoid. After looking up the client\'s hostname in DNS, look up
    the IP addresses in DNS for that hostname, and forget about the
    hostname if none of the addresses match the client\'s IP address.
    You should set this option if you use hostname based instructions.
    The -p option implies the -h option.

# SIGNALS

If an **ipsvd** receives a TERM signal, it exists with 0.

# SEE ALSO

tcpsvd(8), udpsvd(8), ipsvd-instruct(5), ipsvd-cdb(8)

https://smarden.org/ipsvd/

# AUTHOR

Gerrit Pape \<pape@smarden.org\>
