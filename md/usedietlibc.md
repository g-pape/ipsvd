% ipsvd - use dietlibc

[G. Pape](https://smarden.org/pape/)\
[ipsvd](index.html)

---

# ipsvd - use dietlibc

---

To recompile the *ipsvd* programs with the [diet
libc](http://www.fefe.de/dietlibc/), check that you have the recent
version of [dietlibc](http://www.fefe.de/dietlibc/) installed.

Change to the package directory of *ipsvd*

     # cd /package/net/ipsvd/

Change the `conf-cc` and `conf-ld` to use `diet`

     # echo 'diet -Os gcc -O2 -Wall' >src/conf-cc
     # echo 'diet -Os gcc -s -Os -pipe' >src/conf-ld

Rebuild and install the *ipsvd* programs:

     # package/install

---

[Gerrit Pape \<pape@smarden.org\>](mailto:pape@smarden.org)
