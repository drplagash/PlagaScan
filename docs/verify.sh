#!/usr/bin/env bash
# Cross-check PlagaScan against independent commands. Run: sudo bash docs/verify.sh
# Temporarily changes two sysctls and restores them. Everything else is read-only.
cd "$(dirname "$0")/.." || exit 1
ok=0; bad=0
scan() { python3 -m plagascan --all --no-color 2>/dev/null; }
expect() { # name, condition-rc, 
  if [ "$2" = 0 ]; then echo "OK   $1"; ok=$((ok+1)); else echo "FAIL $1"; bad=$((bad+1)); fi; }
has() { grep -q "$1" <<<"$OUT"; }

OUT=$(scan)
echo "== 1. Hallazgos vs. comando independiente"
getent group docker | grep -q ":.*[a-z]$" ; d=$?
has "ACC-006" ; s=$?; [ $d = 0 ] && e=0 || e=1; expect "docker (grupo con miembros <-> ACC-006)" $([ $((s==0?0:1)) = $e ] && echo 0 || echo 1)
ss -tln | grep -qE ":59[0-9][0-9]\b" ; d=$?; has "NET-002"; s=$?
expect "VNC 59xx (ss <-> NET-002)" $([ $d = $s ] && echo 0 || echo 1)
grep -rqE "^[^#]*NOPASSWD:\s*ALL" /etc/sudoers /etc/sudoers.d 2>/dev/null; d=$?; has "PRIV-004"; s=$?
expect "sudo NOPASSWD ALL (grep <-> PRIV-004)" $([ $d = $s ] && echo 0 || echo 1)
n=$(apt list --upgradable 2>/dev/null | grep -c upgradable); has "$n actualizaciones normales"; s=$?
expect "apt upgradable=$n (<-> PKG-002)" $s
for kv in "kernel.kptr_restrict:KER-002:0" "kernel.dmesg_restrict:KER-003:0" "net.ipv4.conf.all.send_redirects:KER-010:1" "net.ipv4.conf.all.rp_filter:KER-012:0"; do
  k=${kv%%:*}; r=${kv#*:}; id=${r%%:*}; bad_v=${r#*:}
  v=$(sysctl -n "$k"); has "$id"; s=$?
  expect "$k=$v (<-> $id)" $([ "$v" = "$bad_v" ] && [ $s = 0 ] || { [ "$v" != "$bad_v" ] && [ $s != 0 ]; } && echo 0 || echo 1)
done

echo "== 2. Cambiar el sistema y ver que el escáner reaccione"
orig_k=$(sysctl -n kernel.kptr_restrict); orig_d=$(sysctl -n kernel.dmesg_restrict)
sysctl -qw kernel.kptr_restrict=1 kernel.dmesg_restrict=1
OUT=$(scan)
has "KER-002"; expect "kptr_restrict=1 -> KER-002 desaparece" $([ $? != 0 ] && echo 0 || echo 1)
has "KER-003"; expect "dmesg_restrict=1 -> KER-003 desaparece" $([ $? != 0 ] && echo 0 || echo 1)
sysctl -qw kernel.kptr_restrict="$orig_k" kernel.dmesg_restrict="$orig_d"
OUT=$(scan)
has "KER-002"; expect "restaurado -> KER-002 vuelve" $?

echo "== 3. SUID plantado en /tmp se detecta y se limpia"
t=$(mktemp -d /tmp/plagaverify.XXXXXX); cp /bin/true "$t/x"; chmod 4755 "$t/x"
OUT=$(scan); has "$t/x"; expect "SUID en $t/x detectado (PRIV-001)" $?
rm -rf "$t"
OUT=$(scan); has "plagaverify"; expect "tras borrarlo ya no aparece" $([ $? != 0 ] && echo 0 || echo 1)

echo "== 4. Casos plantados: secretos, permisos, cron, servicios (todo se borra al terminar)"
W=$(mktemp -d /opt/plagaverify.XXXXXX); PLANTED=(); PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  for f in "${PLANTED[@]}"; do rm -f "$f"; done
  rm -rf "$W" /etc/cron.d/plagaverify
}
trap cleanup EXIT
plant() { # archivo contenido  (solo si no existe: nunca pisa nada real)
  if [ ! -e "$1" ]; then mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; PLANTED+=("$1"); return 0; fi; return 1; }
serve() { # puerto respuesta  (servidor falso en 127.0.0.1; solo si el puerto está libre)
  ss -tln | grep -q ":$1\b" && return 1
  python3 - "$1" "$2" <<'PY' &
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(5); s.settimeout(40)
try:
    while True:
        c, _ = s.accept(); c.settimeout(1)
        try: c.recv(512)
        except Exception: pass
        c.sendall(sys.argv[2].encode().decode("unicode_escape").encode("latin-1")); c.close()
except Exception: pass
PY
  PIDS+=($!); sleep 0.5; }

printf 'DB_%s=%s\n' PASSWORD "v$(date +%s)zz" > "$W/.env";            chmod 644 "$W/.env"
echo 'fake' > "$W/id_ed25519";                             chmod 644 "$W/id_ed25519"
echo '#!/bin/sh' > "$W/world.sh";                          chmod 777 "$W/world.sh"
mkdir "$W/wdir";                                           chmod 777 "$W/wdir"
echo '#!/bin/sh' > "$W/run.sh";                            chmod 777 "$W/run.sh"
echo "* * * * * root $W/run.sh" > /etc/cron.d/plagaverify
sf=0; plant /etc/vsftpd.conf "anonymous_enable=YES" && sf=1
ex=0; plant /etc/exports "/srv *(rw,no_root_squash)" && ex=1
sn=0; plant /etc/snmp/snmpd.conf "rwcommunity private" && sn=1
rs=0; plant /etc/rsyncd.conf "[pub]
path=/srv" && rs=1
he=0; plant /etc/hosts.equiv "+" && he=1
rd=0; serve 6379 '+PONG\r\n' && rd=1
es=0; serve 9200 'HTTP/1.0 200 OK\r\n\r\n{"cluster_name":"x"}' && es=1
bash -c 'exec -a "Xtigervnc :9 -SecurityTypes None" sleep 40' & PIDS+=($!)
sleep 0.5

OUT=$(scan)
has "$W/.env";           expect "SEC-001 .env con secreto en 644" $?
has "$W/id_ed25519";     expect "SEC-001 clave privada en 644" $?
has "$W/world.sh";       expect "SEC-003 archivo 777" $?
has "$W/wdir";           expect "SEC-004 directorio 777 sin sticky" $?
has "SCH-001";           expect "SCH-001 cron de root ejecuta script 777" $?
[ $sf = 1 ] && { has "SVC-003"; expect "SVC-003 FTP anónimo" $?; }
[ $ex = 1 ] && { has "SVC-004"; expect "SVC-004 NFS abierto" $?; }
[ $sn = 1 ] && { has "SVC-012"; expect "SVC-012 SNMP rwcommunity" $?; }
[ $rs = 1 ] && { has "SVC-013"; expect "SVC-013 rsync sin auth" $?; }
[ $he = 1 ] && { has "SVC-011"; expect "SVC-011 hosts.equiv" $?; }
[ $rd = 1 ] && { has "SVC-005"; expect "SVC-005 Redis sin auth (servidor falso)" $?; }
[ $es = 1 ] && { has "SVC-008"; expect "SVC-008 Elasticsearch sin auth (servidor falso)" $?; }
has "SVC-009";           expect "SVC-009 VNC con SecurityTypes None" $?
[ "$sf$ex$sn$rs$he$rd$es" = 0000000 ] && echo "NOTA  ningún caso de servicios se pudo plantar (ya existen los archivos o puertos)"

cleanup; PLANTED=(); PIDS=(); sleep 1
OUT=$(scan)
has "plagaverify";       expect "tras limpiar, nada de lo plantado aparece" $([ $? != 0 ] && echo 0 || echo 1)

echo; echo "Resultado: $ok OK, $bad FAIL"; [ $bad = 0 ]
