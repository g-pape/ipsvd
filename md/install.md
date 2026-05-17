% ipsvd - installation

[G. Pape](https://smarden.org/pape/)\
[ipsvd](index.html)

---

# ipsvd - installation

---

*ipsvd* by default installs into the [/package
hierarchy](https://cr.yp.to/slashpackage.html). To install as non-root
user and without the [/package](https://cr.yp.to/slashpackage.html)
directory, make the programs and documentation available manually.

---

[Install into /package](#package)\
[Install programs and documentation manually](#manually)

---

[]{#package}

## Install ipsvd into /package

If you don\'t have a `/package` directory, create it now:

    mkdir -p /package
    chmod 1755 /package

Download [ipsvd-1.1.1.tar.gz](ipsvd-1.1.1.tar.gz) into `/package`
([sha256sum](https://smarden.org/ipsvd/sha256sum.asc)) and unpack the
archive

    cd /package
    gunzip ipsvd-1.1.1.tar
    tar -xpf ipsvd-1.1.1.tar
    rm ipsvd-1.1.1.tar
    cd net/ipsvd-1.1.1

Now compile and install the *ipsvd* programs

    package/install

If you want to make the man pages available in the `/usr/local/man/`
hierarchy, do

    package/install-man

To report success:

    mail pape-ipsvd-1.1.1@xxiv.smarden.org <compile/sysdeps

If you use *ipsvd* regularly, please
[contribute](https://smarden.org/pape/#contribution) to the project.

Refer to the [examples](examples.html) to learn how to set up services
with *ipsvd*.

---

[]{#manually}

## Install ipsvd programs and documentation manually

Download [ipsvd-1.1.1.tar.gz](ipsvd-1.1.1.tar.gz) into the current
directory ([sha256sum](https://smarden.org/ipsvd/sha256sum.asc)) and
unpack the archive

    gunzip ipsvd-1.1.1.tar
    tar -xpf ipsvd-1.1.1.tar
    cd net/ipsvd-1.1.1

Compile and check the *ipsvd* programs

    package/compile
    package/check

The *ipsvd* programs are available in the `command/` directory. You
probably want to install them into `/bin`. As non-root user you probably
want to install them into `$HOME/bin`.

The documentation is available in the `doc/` directory, and the man
pages in the `man/` directory.

To report success:

    mail pape-ipsvd-1.1.1@xxiv.smarden.org <compile/sysdeps

If you use *ipsvd* regularly, please
[contribute](https://smarden.org/pape/#contribution) to the project.

Refer to the [examples](examples.html) to learn how to set up services
with *ipsvd*.

---

[Gerrit Pape \<pape@smarden.org\>](mailto:pape@smarden.org)
