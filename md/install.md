% ipsvd - installation

[G. Pape](https://smarden.org/pape/)\
[ipsvd](index.html)

---

# ipsvd - installation

---

*ipsvd* installs into [/package](https://cr.yp.to/slashpackage.html). If
you don\'t have a `/package` directory, create it now:

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

[Gerrit Pape \<pape@smarden.org\>](mailto:pape@smarden.org)
