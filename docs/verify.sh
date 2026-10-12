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

echo; echo "Resultado: $ok OK, $bad FAIL"; [ $bad = 0 ]
