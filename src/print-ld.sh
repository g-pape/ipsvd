ld="`head -1 conf-ld`"
systype="`cat systype`"
djbdnslib="`head -1 conf-djbdnslib`"

cat warn-auto.sh
echo 'main="$1"; shift'
echo exec "$ld" '-o "$main" "$main".o ${1+"$@"}' -L$djbdnslib
