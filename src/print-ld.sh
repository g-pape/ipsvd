ld="`head -1 conf-ld`"
cat warn-auto.sh
echo 'main="$1"; shift'
echo exec "$ld" '-o "$main" "$main".o ${1+"$@"}'
