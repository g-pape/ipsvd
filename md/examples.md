% ipsvd - examples

[G. Pape](https://smarden.org/pape/)\
[ipsvd](index.html)

---

# ipsvd - examples

---

[TCP/IP services](#tcp)\
[UDP/IP services](#udp)\
[*ipsvd* instructions](#instruct)

---

### [TCP/IP service examples]{#tcp}

This `run` script provides an *identd* service on `0.0.0.0:113`

     #!/bin/sh
     exec tcpsvd -l0 0 113 identd

This `run` script provides a
[smtpfront-qmail](http://untroubled.org/mailfront/) service on
`192.168.2.1:25`, with per-host instructions through the constant
database `./peers.cdb`.

     #!/bin/sh
     exec 2>&1
     MAXSMTPD="`cat /var/qmail/control/concurrencyincoming`"
     exec chpst -m2000000 \
       env SMTPGREETING=smarden.org \
           MAILRULES=/etc/mailfront/smtp/mailrules \
       tcpsvd -vp -uqmaild -c"$MAXSMTPD" -x./peers.cdb 192.168.2.1 25 \
         smtpfront-qmail

This `run` script provides a [bincimaps](http://www.bincimap.org/)
service on `10.0.0.14:993`, with per-host concurrency limit, and with
per-host instructions through the directory `./peers`.

     #!/bin/sh
     exec 2>&1
     exec tcpsvd -vvp -c40 -C10 -l0 -i./peers 10.0.0.14 993 \
       bincimap-up --logtype=multilog --conf=/etc/bincimap/bincimap.conf --ssl -- \
         /usr/bin/checkpw /usr/sbin/bincimapd

This `run` script provides a [qmail-smtpd](http://www.qmail.org/)
service on `192.168.14.6:25`, with per-host concurrency limit, and with
per-host instructions through the directory `./peers`.

     #!/bin/sh
     exec 2>&1
     exec chpst -m2000000 \
      tcpsvd -vvh -i./peers -uqmaild \
        -c40 -C'10:421 per host concurrency limit reached\r\n' \
          192.168.14.6 25 qmail-smtpd

---

### [UDP/IP service examples]{#udp}

This `run` script provides a *talkd* service on `192.168.1.1:517`

     #!/bin/sh
     exec udpsvd -unobody:tty 192.168.1.1 517 in.talkd

This `run` script provides a *tftpd* service on `0.0.0.0:69` with
per-IP-address instructions through the directory `/etc/tftpd/peers`

     #!/bin/sh
     cd /
     exec 2>&1
     exec udpsvd -v -lbootserver -unobody -i/etc/tftpd/peers 0 69 \
       in.tftpd -s /boot/tftpboot/

---

### [*ipsvd* instruction examples]{#instruct}

This `run` script provides a *telnetd* TCP/IP service, with
per-IP-address [instructions](ipsvd-instruct.5.html) through the
directory `./peers`

     #!/bin/sh
     exec tcpsvd -i./peers 0.0.0.0 23 in.telnetd

Per default any client IP address is allowed to connect to this service.
To allow connections from `192.168.1.17`, and to deny connections from
anywhere else, do

    touch ./peers/192.168.1.17; chmod 644 ./peers/192.168.1.17
    touch ./peers/0; chmod 0 ./peers/0

To allow connections from `192.168.3.0-255`, do

    touch ./peers/192.168.3; chmod 644 ./peers/192.168.3

To deny connections from `10.0.*.*` explicitly, do

    touch ./peers/10.0; chmod 0 ./peers/10.0

To have `TRUST=true` set in the environment when running *in.telnetd*
for a connection from `192.168.14.2`, do

    echo '+TRUST=true' >./peers/192.168.14.2; chmod 644 ./peers/192.168.14.2

To provide a *sshd* login for connections from `10.2.0.14` on port 23,
and the usual *telnetd* service for all others, do

    echo 'sshd -i' >./peers/10.2.0.14; chmod 744 ./peers/10.2.0.14

To allow only connections from IP addresses the (dynamic) hostnames
`floyd.dyn.smarden.org` and `greg.dyn.smarden.org` currently resolve to,
do

    echo '=floyd.dyn.smarden.org' >./peers/0
    echo '=greg.dyn.smarden.org' >>./peers/0
    chmod 644 ./peers/0

See [ipsvd instructions](ipsvd-instruct.5.html) for details.

---

[Gerrit Pape \<pape@smarden.org\>](mailto:pape@smarden.org)
