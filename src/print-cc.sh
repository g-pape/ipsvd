cc="`head -1 conf-cc`"
systype="`cat systype`"
djbdnsinc="`head -1 conf-djbdnsinc`"

cat warn-auto.sh
echo exec "$cc" '-c ${1+"$@"}' "-I$djbdnsinc"
