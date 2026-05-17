% ipsvd-cdb(8)

# NAME

ipsvd-cdb - create constant database from ipsvd instructions directory

# SYNOPSIS

**ipsvd-cdb** *cdb* *cdb.tmp* *dir*

# DESCRIPTION

**ipsvd-cdb** scans the directory *dir*, and compiles all relevant
information for an internet protocol service daemon, **ipsvd**(7), into
the newly created constant database *cdb.tmp*. If *cdb.tmp* exists, it
will be destroyed. **ipsvd-cdb** then renames *cdb.tmp* to *cdb*. If
*cdb* exists, it will be destroyed.

**ipsvd-cdb** skips filenames starting with two dots.

If **ipsvd-cdb** has trouble building the constant database, it exits
with an error message, and leaves *cdb* unchanged.

# SEE ALSO

ipsvd(7), tcpsvd(8), udpsvd(8), ipsvd-instruct(5)

https://smarden.org/ipsvd/

# AUTHOR

Gerrit Pape \<pape@smarden.org\>
