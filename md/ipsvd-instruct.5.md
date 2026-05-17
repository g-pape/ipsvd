% ipsvd-instruct(5)

# NAME

ipsvd-instruct - format of the ipsvd(8) instructions directory

# DESCRIPTION

The internet protocol service daemons, **ipsvd**(7), can be told to read
and follow instructions from a directory on incoming connections to the
socket they listen on.

For mostly static instructions or for performance reasons, it is
possible to compile the instructions from a directory into a constant
database (cdb) with **ipsvd-cdb**(8) for faster lookup, and to tell
**ipsvd**(7) to read the instructions from there.

# MATCHING

On each incoming connection, the **ipsvd**(7) matches the client\'s IP
address against files in the instructions directory. For example, the IP
address *a.b.c.d* which reverse resolves to *moa.bit.smarden.org* is
matched against the following files in the instructions directory, in
this order, first match wins:

1. *a.b.c.d*
2. *a.b.c*
3. *a.b*
4. *a*

If the client\'s hostname has been successfully looked up in DNS:

5. *moa.bit.smarden.org*
6. *bit.smarden.org*
7. *smarden.org*
8. *org*

And finally the catchall file "0" (zero):

9. *0*

After successfully matching a client\'s IP address or hostname against
the instructions directory, **ipsvd**(7) examines the file that matched
the IP address or hostname, and acts accordingly:

1. If neither the user\'s read permission, nor the user\'s execute
permission is set for the file, the connection is closed
immediately.
2. If the file has the user\'s execute permission set, **ipsvd**(7)
reads the contents of the file and runs *`/bin/sh -c
'<contents>'`* instead of the default program *prog* given at the
command line for this connection.
3. If the file has the user\'s read permission set, **ipsvd**(7) reads
the contents of the file and interprets each line as an instruction
for this connection (see below).

If the client\'s IP address or hostname doesn\'t match any file in the
instructions directory, the default action is taken (the program *prog*
is run to handle the connection).

# INSTRUCTIONS

If **ipsvd**(7) is given instructions for an incoming connection, it
reads the corresponding file and interprets each line as follows. The
file may be empty, meaning that there is no special instruction.

Empty lines and lines starting with "#" are ignored.

**+***VAR=VALUE*
:   environment. If the line starts with a plus ("+"), and the
    string following the plus contains a "=", **ipsvd**(7) puts
    the string following the plus into the environment before starting
    *prog* to handle the connection. If the string following the plus
    doesn\'t contain a "=", **ipsvd**(7) makes sure that the
    environment variable with the name string is not set.

**C***num*\[:*msg*\]
:   concurrency. If the line starts with a "C", and is followed by
    a number, the per host concurrency limit for the IP address that
    initiated the connection is set to this number. If *num* is zero,
    per host concurrency limit is disabled. If *num* is followed by
    ":*msg",* the message *msg* is written to this client if
    possible, if the per host concurrency limit is reached.

    *msg* may contain backslash-escaped characters as follows:
    "\\\\" is converted to a single backslash, "\\n" is
    converted to a new line character, and "\\r" is converted to a
    carriage return.

    On multiple concurrency instructions the last processed concurrency
    instruction is considered. Not all **ipsvd**(7)\'s support per host
    concurrency.

**=***hostname*\[:*forward*\]
:   check hostname. If the line starts with a "=", and is followed
    by a hostname, **ipsvd**(7) looks up the IP addresses for *hostname*
    in DNS and checks if the client\'s IP address matches one of these
    IP addresses. If so, *ipsvd*(7) stops processing the instructions
    here and runs *prog*. If *hostname* is followed a colon and
    *forward*, **ipsvd**(7) now examines the file *forward* and acts
    accordingly, instead of running *prog*. All check hostname
    instructions in *forward* are ignored. If *forward* does not exist,
    the connection is closed.

    *hostname* may be "0" (zero), matching any IP address.

    Note: Using check hostname instructions can cause significant delay
    while responding to connection attempts, caused by DNS lookups.

If **ipsvd**(7) cannot interpret a line, it prints a warning, discards
the line, and continues with the next instruction if any.

After processing all instructions, **ipsvd**(7) runs *prog*. If the file
contains at least one check hostname instruction, and none was
successful, it closes the connection instead of running *prog*.

# EXAMPLE INSTRUCTIONS

+MEMORY=20000
:   This instruction causes the environment variable "MEMORY" with
    the value "20000" to be available to the program *prog* that
    handles the connection.

+DEBUG=
:   This instruction adds the variable "DEBUG" with an empty value
    to the environment.

+LOGNAME
:   This instructions makes sure that the environment variable
    "LOGNAME" is unset when running *prog*.

C16
:   Set the per host concurrency to 16. A connection will be closed
    silently if there are already 16 active connections from this
    client\'s IP address.

=floyd.dyn.smarden.org:127.0.0.1
:   Check IP address of the dynamic hostname *floyd.dyn.smarden.org*. If
    one of the IP addresses *floyd.dyn.smarden.org* currently resolves
    to matches the client\'s IP address, handle the connection through
    the file *127.0.0.1* in the instructions directory.

# SEE ALSO

ipsvd(7), ipsvd-cdb(8), tcpsvd(8), udpsvd(8),

https://smarden.org/ipsvd/

# AUTHOR

Gerrit Pape \<pape@smarden.org\>
