#!/usr/bin/env bash
# Servicios REALES con configuración insegura (anónimo/guest/sin auth) pero atados SOLO a 127.0.0.1.
# Hace backup para revertir. Si algo escuchara fuera de loopback, apaga todo y aborta.
set -u
B=/root/plagascan-real-backup; mkdir -p $B
for f in /etc/samba/smb.conf /etc/vsftpd.conf /etc/snmp/snmpd.conf /etc/redis/redis.conf /etc/rsyncd.conf; do
  if [ -e "$f" ]; then cp -a "$f" "$B/$(echo $f | tr / _)"; else echo "$f" >> $B/absent.txt; fi
done

mkdir -p /srv/pub /srv/ftp/pub /srv/rsyncmod /var/run/vsftpd/empty
echo hola > /srv/pub/a.txt; chmod 777 /srv/pub
echo ftp > /srv/ftp/pub/f.txt; chmod 755 /srv/ftp; chmod 777 /srv/ftp/pub
echo r > /srv/rsyncmod/r.txt

# Samba: solo loopback + share guest con escritura
sed -i '/^\[global\]/a\   interfaces = lo\n   bind interfaces only = yes' /etc/samba/smb.conf
cat >> /etc/samba/smb.conf <<'EOF'

[plagapub]
   path = /srv/pub
   guest ok = yes
   writable = yes
EOF

# vsftpd: solo loopback + anónimo con subida
cat > /etc/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
listen_address=127.0.0.1
anonymous_enable=YES
local_enable=NO
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_root=/srv/ftp
secure_chroot_dir=/var/run/vsftpd/empty
EOF

# rsync daemon: solo loopback + módulo sin auth y escribible
cat > /etc/rsyncd.conf <<'EOF'
address = 127.0.0.1
[plagamod]
   path = /srv/rsyncmod
   read only = no
   uid = nobody
   gid = nogroup
EOF

# SNMP: solo loopback + community de escritura
sed -i '/^agentaddress/d' /etc/snmp/snmpd.conf
echo "agentaddress udp:127.0.0.1:161" >> /etc/snmp/snmpd.conf
echo "rwcommunity private" >> /etc/snmp/snmpd.conf

systemctl restart smbd vsftpd redis-server snmpd rsync 2>&1
sleep 2
echo "--- estado"; systemctl is-active smbd vsftpd redis-server snmpd rsync | tr '\n' ' '; echo
echo "--- sockets"; ss -tuln | grep -E ":(21|139|445|161|873|6379)\b"

# Guardia: nada fuera de loopback
if ss -tuln | grep -E ":(21|139|445|161|873|6379)\b" | grep -vE "127\.0\.0\.1:|\[::1\]:"; then
  echo "ABORTO: hay servicios fuera de loopback; los apago."
  systemctl stop smbd nmbd vsftpd redis-server snmpd rsync
  exit 1
fi
echo "OK: todo en loopback"
