# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
from conftest import FakeContext, ids
from plagascan.checks import services
from plagascan.models import Severity


def ss(*ports, host="0.0.0.0"):
    return "".join("tcp LISTEN 0 128 %s:%d 0.0.0.0:* users:((\"x\",pid=1,fd=3))\n" % (host, p) for p in ports)


def run(**kw):
    kw.setdefault("root", True)
    return services.check_services(FakeContext(**kw))


def by_id(findings, fid):
    return [f for f in findings if f.id == fid]


# --- Samba -------------------------------------------------------------------------

SMB = """
[global]
   map to guest = Bad User
[publico]
   path = /srv/pub
   guest ok = yes
   writable = yes
[solo-lectura]
   path = /srv/ro
   public = yes
   read only = yes
[privado]
   valid users = ana
"""


def test_samba_guest_shares_and_severities():
    out = run(files={"/etc/samba/smb.conf": SMB}, commands={"ss -H -tulnp": ss(445)})
    shares = by_id(out, "SVC-001")
    sev = {f.evidence[0].split("]")[0]: f.severity for f in shares}
    assert sev["[publico"] == Severity.HIGH
    assert sev["[solo-lectura"] == Severity.MEDIUM
    assert not any("privado" in f.evidence[0] for f in shares)
    assert by_id(out, "SVC-002")  # map to guest


def test_samba_inactive_service_lowers_severity():
    out = run(files={"/etc/samba/smb.conf": SMB})
    assert [f for f in by_id(out, "SVC-001") if "publico" in f.evidence[0]][0].severity == Severity.MEDIUM


def test_samba_clean_config():
    out = run(files={"/etc/samba/smb.conf": "[global]\n map to guest = never\n[h]\n valid users = a\n"})
    assert not by_id(out, "SVC-001") and not by_id(out, "SVC-002")


def test_samba_security_share_is_high():
    out = run(files={"/etc/samba/smb.conf": "[global]\n security = share\n"}, commands={"ss -H -tulnp": ss(139)})
    assert by_id(out, "SVC-002")[0].severity == Severity.HIGH


# --- FTP ----------------------------------------------------------------------------

def test_vsftpd_anonymous_with_upload_is_high():
    out = run(files={"/etc/vsftpd.conf": "anonymous_enable=YES\nanon_upload_enable=YES\n"},
              commands={"ss -H -tulnp": ss(21)})
    (f,) = by_id(out, "SVC-003")
    assert f.severity == Severity.HIGH


def test_vsftpd_anonymous_disabled_and_commented():
    out = run(files={"/etc/vsftpd.conf": "anonymous_enable=NO\n#anon_upload_enable=YES\n"})
    assert not by_id(out, "SVC-003")


def test_proftpd_and_pureftpd_anonymous():
    out = run(files={"/etc/proftpd/proftpd.conf": "<Anonymous ~ftp>\nUser ftp\n</Anonymous>\n",
                     "/etc/pure-ftpd/conf/NoAnonymous": "no\n"})
    assert len(by_id(out, "SVC-003")) == 2


# --- NFS ----------------------------------------------------------------------------

def test_nfs_wildcard_rw_and_no_root_squash():
    out = run(files={"/etc/exports": "/srv/a *(rw,sync)\n/srv/b 10.0.0.5(ro,no_root_squash)\n# /x *(rw)\n"},
              commands={"ss -H -tulnp": ss(2049)})
    (f,) = by_id(out, "SVC-004")
    assert f.severity == Severity.HIGH and len(f.evidence) == 2


def test_nfs_specific_hosts_are_ok():
    out = run(files={"/etc/exports": "/srv/a 192.168.1.10(rw,sync,root_squash)\n"})
    assert not by_id(out, "SVC-004")


# --- servicios que responden sin credenciales (prueba local) --------------------------------

def test_redis_open_exposed_is_critical():
    out = run(commands={"ss -H -tulnp": ss(6379)}, probes={6379: b"+PONG\r\n"})
    (f,) = by_id(out, "SVC-005")
    assert f.severity == Severity.CRITICAL


def test_redis_loopback_only_is_medium():
    out = run(commands={"ss -H -tulnp": ss(6379, host="127.0.0.1")}, probes={6379: b"+PONG\r\n"})
    assert by_id(out, "SVC-005")[0].severity == Severity.MEDIUM


def test_redis_with_auth_is_clean():
    out = run(commands={"ss -H -tulnp": ss(6379)}, probes={6379: b"-NOAUTH Authentication required.\r\n"})
    assert not by_id(out, "SVC-005")


def test_elasticsearch_and_rabbit_guest_detected():
    es = b'HTTP/1.0 200 OK\r\n\r\n{"cluster_name":"x"}'
    rb = b'HTTP/1.0 200 OK\r\n\r\n{"rabbitmq_version":"3.12"}'
    out = run(commands={"ss -H -tulnp": ss(9200, 15672)}, probes={9200: es, 15672: rb})
    titles = " ".join(f.title for f in by_id(out, "SVC-008"))
    assert "Elasticsearch" in titles and "guest/guest" in titles


def test_open_service_not_listening_is_ignored():
    out = run(probes={6379: b"+PONG\r\n"})
    assert not by_id(out, "SVC-005")


def test_redis_conf_fallback_when_probe_fails():
    out = run(commands={"ss -H -tulnp": ss(6379)}, files={"/etc/redis/redis.conf": "bind 0.0.0.0\n"})
    assert by_id(out, "SVC-005")[0].severity == Severity.MEDIUM
    out = run(commands={"ss -H -tulnp": ss(6379)}, files={"/etc/redis/redis.conf": "requirepass s3cret\n"})
    assert not by_id(out, "SVC-005")


# --- MongoDB / MySQL -----------------------------------------------------------------------

def test_mongo_without_auth_open_bind():
    cfg = "net:\n  bindIp: 0.0.0.0\n"
    out = run(files={"/etc/mongod.conf": cfg}, commands={"ss -H -tulnp": ss(27017)})
    assert by_id(out, "SVC-006")[0].severity == Severity.HIGH


def test_mongo_with_auth_ok():
    out = run(files={"/etc/mongod.conf": "security:\n  authorization: enabled\n"})
    assert not by_id(out, "SVC-006")


def test_mysql_skip_grant_tables_and_anonymous_users():
    out = run(files={"/etc/mysql/conf.d/x.cnf": "[mysqld]\nskip-grant-tables\n"},
              commands={"ss -H -tulnp": ss(3306),
                        "mysql -N -B -e SELECT user,host FROM mysql.user WHERE user=''": "\tlocalhost\n"})
    assert by_id(out, "SVC-007")[0].severity == Severity.CRITICAL
    assert by_id(out, "SVC-015")


def test_mysql_commented_skip_grant_tables_ignored():
    out = run(files={"/etc/mysql/conf.d/x.cnf": "#skip-grant-tables\n"})
    assert not by_id(out, "SVC-007")


# --- VNC -------------------------------------------------------------------------------------

def test_vnc_security_none_and_missing_password_file():
    ps = ("Xtigervnc :1 -SecurityTypes None -rfbport 5901\n"
          "Xtigervnc :2 -rfbauth /home/a/.vnc/passwd\n"
          "x11vnc -display :0 -nopw\n")
    out = run(commands={"ps -eo args": ps}, stats={})
    (f,) = by_id(out, "SVC-009")
    assert f.severity == Severity.CRITICAL and len(f.evidence) >= 3


def test_vnc_with_password_file_is_clean():
    out = run(commands={"ps -eo args": "Xtigervnc :1 -rfbauth /home/a/.vnc/passwd\n"},
              files={"/home/a/.vnc/passwd": "x"}, stats={"/home/a/.vnc/passwd": (0o600, 1000, 1000)})
    assert not by_id(out, "SVC-009")


# --- guest / autologin / cuentas por defecto ----------------------------------------------------------

def test_lightdm_guest_and_gdm_autologin():
    out = run(files={"/etc/lightdm/lightdm.conf": "[Seat:*]\nallow-guest=true\nautologin-user=kali\n",
                     "/etc/gdm3/custom.conf": "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob\n"})
    (f,) = by_id(out, "SVC-010")
    assert f.severity == Severity.MEDIUM and len(f.evidence) == 3


PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "guest:x:1001:1001::/home/guest:/bin/bash\n"
          "kali:x:1000:1000::/home/kali:/bin/zsh\n"
          "test:x:1002:1002::/home/test:/usr/sbin/nologin\n"
          "pi:x:1003:1003::/home/pi:/bin/bash\n")


def test_default_accounts_flagged_unless_locked_or_nologin():
    shadow = "guest:!:1:0:99999:7:::\nkali:$y$abc:1:0:99999:7:::\npi::1:0:99999:7:::\n"
    out = run(files={"/etc/passwd": PASSWD, "/etc/shadow": shadow})
    (f,) = by_id(out, "SVC-014")
    joined = " ".join(f.evidence)
    assert "kali" in joined and "pi" in joined
    assert "guest" not in joined and "test" not in joined


def test_default_accounts_without_root_report_unknown_state():
    out = run(files={"/etc/passwd": PASSWD}, root=False)
    assert "desconocida" in by_id(out, "SVC-014")[0].evidence[0]


# --- r-services, SNMP, rsync -----------------------------------------------------------------------

def test_rhosts_and_inetd():
    out = run(files={"/etc/hosts.equiv": "+\n", "/home/a/.rhosts": "+ +\n",
                     "/etc/inetd.conf": "telnet stream tcp nowait root /usr/sbin/tcpd in.telnetd\n#ftp x\n"})
    (f,) = by_id(out, "SVC-011")
    assert f.severity == Severity.HIGH and len(f.evidence) == 3


def test_snmp_default_and_rw_communities():
    text = "rocommunity public\nrwcommunity secreto\nrocommunity ok 10.0.0.0/8\n"
    out = run(files={"/etc/snmp/snmpd.conf": text}, commands={"ss -H -tulnp": "udp UNCONN 0 0 0.0.0.0:161 0.0.0.0:*\n"})
    f = by_id(out, "SVC-012")[0]
    assert f.severity == Severity.HIGH and len(f.evidence) == 2


def test_rsyncd_modules_without_auth():
    text = "[backup]\npath=/srv\nread only=no\n[docs]\npath=/d\nauth users=bob\n[pub]\npath=/p\nhosts allow=10.0.0.0/8\n"
    out = run(files={"/etc/rsyncd.conf": text}, commands={"ss -H -tulnp": ss(873)})
    f = by_id(out, "SVC-013")[0]
    assert f.severity == Severity.HIGH
    assert any("backup" in e for e in f.evidence) and not any("docs" in e for e in f.evidence)


def test_everything_clean_on_empty_system():
    assert ids(run()) == []


def test_loopback_only_service_lowers_severity_and_says_so():
    out = run(files={"/etc/vsftpd.conf": "anonymous_enable=YES\nanon_upload_enable=YES\n"},
              commands={"ss -H -tulnp": ss(21, host="127.0.0.1")})
    (f,) = by_id(out, "SVC-003")
    assert f.severity == Severity.MEDIUM and "loopback" in f.detail
    exposed = run(files={"/etc/vsftpd.conf": "anonymous_enable=YES\nanon_upload_enable=YES\n"},
                  commands={"ss -H -tulnp": ss(21)})
    assert by_id(exposed, "SVC-003")[0].severity == Severity.HIGH


def test_samba_map_to_guest_has_its_own_explanation():
    out = run(files={"/etc/samba/smb.conf": "[global]\n map to guest = bad user\n"})
    (f,) = by_id(out, "SVC-002")
    assert "invitado" in f.detail and "leer/escribir" not in f.detail
