#!/usr/bin/env bash
# Revierte real_up.sh: apaga los servicios, restaura configuraciones y borra los datos de prueba.
B=/root/plagascan-real-backup
systemctl stop smbd nmbd vsftpd redis-server snmpd rsync 2>&1 | grep -v "^$"
for f in /etc/samba/smb.conf /etc/vsftpd.conf /etc/snmp/snmpd.conf /etc/redis/redis.conf /etc/rsyncd.conf; do
  b="$B/$(echo $f | tr / _)"
  if [ -e "$b" ]; then cp -a "$b" "$f"; echo "restaurado $f"; fi
done
if [ -e $B/absent.txt ]; then while read -r f; do rm -f "$f"; echo "borrado $f (no existía antes)"; done < $B/absent.txt; fi
rm -rf /srv/pub /srv/ftp /srv/rsyncmod
rmdir /srv 2>/dev/null
echo "--- estado final"
systemctl is-active smbd vsftpd redis-server snmpd rsync | tr '\n' ' '; echo
ss -tuln | grep -E ":(21|139|445|161|873|6379)\b" || echo "ningún puerto de prueba escuchando"
diff -q $B/_etc_samba_smb.conf /etc/samba/smb.conf && echo "smb.conf idéntico al original"
