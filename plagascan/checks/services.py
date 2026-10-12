# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Servicios con acceso anónimo/guest o sin autenticación, y cuentas por defecto."""
import os
import re
from typing import Dict, List, Optional, Tuple

from . import register
from .accounts import parse_passwd
from .common import (active_lines, adjust, exposed_on, listening, lower, parse_ini,
                     parse_kv, probe_host, truthy)
from ..models import Finding, Severity

CAT = "services"

NOLOGIN = ("nologin", "false", "sync", "shutdown", "halt")


# --- Samba ---------------------------------------------------------------------------

def analyze_samba(text: str) -> List[Tuple[Severity, str, str, List[str]]]:
    """[(severidad, id, título, evidencia)] a partir de un smb.conf."""
    ini = parse_ini(text)
    g = ini.get("global", {})
    out = []
    if g.get("security") == "share":
        out.append((Severity.HIGH, "SVC-002", "Samba con security = share (sin usuarios)",
                    ["security = share"]))
    mtg = g.get("map to guest", "never")
    if mtg in ("bad user", "bad password", "bad uid"):
        out.append((Severity.LOW, "SVC-002", "Samba: usuarios inexistentes entran como guest",
                    ["map to guest = %s" % mtg]))
    for name, sec in ini.items():
        if name in ("global", "printers", "print$"):
            continue
        guest = truthy(sec.get("guest ok")) or truthy(sec.get("public")) or truthy(sec.get("guest only"))
        if not guest:
            continue
        writable = (truthy(sec.get("writable")) or truthy(sec.get("writeable"))
                    or truthy(sec.get("write ok")) or sec.get("read only") == "no")
        ev = "[%s] acceso guest%s%s" % (name, " con escritura" if writable else " (solo lectura)",
                                        "  path=%s" % sec["path"] if "path" in sec else "")
        out.append((Severity.HIGH if writable else Severity.MEDIUM, "SVC-001",
                    "Share de Samba accesible sin usuario (guest)", [ev]))
    return out


def _check_samba(ctx) -> List[Finding]:
    text = ctx.read("/etc/samba/smb.conf")
    if text is None:
        return []
    active = listening(ctx, 445) or listening(ctx, 139)
    out = []
    for sev, fid, title, ev in analyze_samba(text):
        sev, note = adjust(sev, active)
        out.append(Finding(fid, title, sev, CAT,
                           "Cualquiera de la red puede leer/escribir sin credenciales." + note,
                           "Quitar guest ok/public, exigir usuarios (smbpasswd) y poner map to guest = never.",
                           ev))
    return out


# --- FTP -----------------------------------------------------------------------------

def _check_ftp(ctx) -> List[Finding]:
    out: List[Finding] = []
    active = listening(ctx, 21)
    vs = ctx.read("/etc/vsftpd.conf") or ctx.read("/etc/vsftpd/vsftpd.conf")
    if vs is not None:
        cfg = {k: v.lower() for k, v in parse_kv(vs).items()}
        if truthy(cfg.get("anonymous_enable")):
            writes = [k for k in ("anon_upload_enable", "anon_mkdir_write_enable",
                                  "anon_other_write_enable") if truthy(cfg.get(k))]
            sev, note = adjust(Severity.HIGH if writes else Severity.MEDIUM, active)
            out.append(Finding(
                "SVC-003", "FTP anónimo habilitado (vsftpd)", sev, CAT,
                "Cualquiera puede entrar con el usuario 'anonymous'." + note,
                "Poner anonymous_enable=NO.",
                ["anonymous_enable=YES"] + ["%s=YES" % w for w in writes]))
    pro = ctx.read("/etc/proftpd/proftpd.conf") or ctx.read("/etc/proftpd.conf")
    if pro is not None and any(l.lower().startswith("<anonymous") for l in active_lines(pro, ("#",))):
        sev, note = adjust(Severity.MEDIUM, active)
        out.append(Finding("SVC-003", "FTP anónimo habilitado (proftpd)", sev, CAT,
                           "Hay un bloque <Anonymous> activo." + note,
                           "Quitar el bloque <Anonymous>.", ["<Anonymous ...> en proftpd.conf"]))
    pure = ctx.read("/etc/pure-ftpd/conf/NoAnonymous")
    if pure is not None and pure.strip().lower() == "no":
        sev, note = adjust(Severity.MEDIUM, active)
        out.append(Finding("SVC-003", "FTP anónimo habilitado (pure-ftpd)", sev, CAT,
                           "NoAnonymous=no permite entrar como anonymous." + note,
                           "Poner 'yes' en /etc/pure-ftpd/conf/NoAnonymous.", ["NoAnonymous no"]))
    return out


# --- NFS -----------------------------------------------------------------------------

def analyze_exports(text: str) -> List[Tuple[Severity, str]]:
    out = []
    for line in active_lines(text, ("#",)):
        parts = line.split()
        path, clients = parts[0], parts[1:]
        if not clients:
            out.append((Severity.HIGH, "%s sin lista de clientes (abierto a todos)" % path))
            continue
        for c in clients:
            m = re.match(r"^([^(]*)\((.*)\)$", c)
            host, opts = (m.group(1), m.group(2).split(",")) if m else (c, [])
            anyone = host in ("", "*") or host.startswith("0.0.0.0")
            rw = "rw" in opts
            if anyone and (rw or "no_root_squash" in opts):
                out.append((Severity.HIGH, "%s -> %s(%s)" % (path, host or "*", ",".join(opts))))
            elif anyone:
                out.append((Severity.MEDIUM, "%s -> %s(%s) abierto a cualquier cliente" % (
                    path, host or "*", ",".join(opts))))
            elif "no_root_squash" in opts:
                out.append((Severity.MEDIUM, "%s -> %s(%s) con no_root_squash" % (
                    path, host, ",".join(opts))))
    return out


def _check_nfs(ctx) -> List[Finding]:
    text = ctx.read("/etc/exports")
    if text is None:
        return []
    rows = analyze_exports(text)
    if not rows:
        return []
    active = listening(ctx, 2049)
    sev, note = adjust(max(r[0] for r in rows), active)
    return [Finding("SVC-004", "NFS exporta a cualquier cliente o con no_root_squash", sev, CAT,
                    "Cualquier host puede montar el export; no_root_squash entrega root del cliente." + note,
                    "Limitar a hosts concretos, usar ro y root_squash.", [r[1] for r in rows])]


# --- Servicios que responden sin pedir credenciales (prueba local, solo lectura) ----------

def _http(path: str, extra: str = "") -> bytes:
    return ("GET %s HTTP/1.0\r\nHost: localhost\r\n%s\r\n" % (path, extra)).encode()


# puerto -> (nombre, payload, detector, severidad si expuesto, severidad si solo loopback)
OPEN_PROBES = {
    6379: ("Redis", b"PING\r\n", lambda r: r.startswith(b"+PONG"),
           Severity.CRITICAL, Severity.MEDIUM),
    11211: ("Memcached", b"version\r\n", lambda r: r.startswith(b"VERSION"),
            Severity.HIGH, Severity.LOW),
    9200: ("Elasticsearch", _http("/"), lambda r: b" 200 " in r.split(b"\r\n", 1)[0] and b"cluster_name" in r,
           Severity.HIGH, Severity.MEDIUM),
    2375: ("Docker API", _http("/version"), lambda r: b" 200 " in r.split(b"\r\n", 1)[0] and b"ApiVersion" in r,
           Severity.CRITICAL, Severity.HIGH),
    8888: ("Jupyter", _http("/api/contents"), lambda r: b" 200 " in r.split(b"\r\n", 1)[0] and b'"type"' in r,
           Severity.CRITICAL, Severity.HIGH),
    2379: ("etcd", _http("/version"), lambda r: b" 200 " in r.split(b"\r\n", 1)[0] and b"etcdserver" in r,
           Severity.HIGH, Severity.MEDIUM),
    5984: ("CouchDB", _http("/_all_dbs"), lambda r: b" 200 " in r.split(b"\r\n", 1)[0],
           Severity.HIGH, Severity.MEDIUM),
    # Cuenta guest/guest que RabbitMQ trae por defecto (la consola solo la acepta desde loopback).
    15672: ("RabbitMQ (usuario guest/guest por defecto)",
            _http("/api/overview", "Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=\r\n"),
            lambda r: b" 200 " in r.split(b"\r\n", 1)[0] and b"rabbitmq_version" in r,
            Severity.HIGH, Severity.LOW),
}


def _check_open_services(ctx) -> List[Finding]:
    out: List[Finding] = []
    for port, (name, payload, detect, sev_exposed, sev_local) in OPEN_PROBES.items():
        if not listening(ctx, port):
            continue
        resp = ctx.probe(probe_host(ctx, port), port, payload)
        if resp is None:
            continue
        if not detect(resp):
            continue
        exposed = exposed_on(ctx, port)
        out.append(Finding(
            "SVC-005" if port == 6379 else "SVC-008",
            "%s responde sin pedir credenciales (puerto %d)" % (name, port),
            sev_exposed if exposed else sev_local, CAT,
            "Se probó desde este mismo equipo: el servicio contestó sin autenticación%s." % (
                " y escucha fuera de loopback, así que cualquiera de la red puede usarlo" if exposed
                else " (solo accesible localmente)"),
            "Activar autenticación (requirepass/usuarios/token) y escuchar solo en 127.0.0.1.",
            ["%s: respuesta válida sin credenciales en puerto %d" % (name, port)]))
    return out


def _check_redis_config(ctx) -> List[Finding]:
    """Respaldo cuando no se pudo probar: redis.conf sin requirepass."""
    if not listening(ctx, 6379) or ctx.probe(probe_host(ctx, 6379), 6379, b"PING\r\n") is not None:
        return []
    conf = ctx.read("/etc/redis/redis.conf") or ctx.read("/etc/redis.conf")
    if conf is None:
        return []
    keys = [l.split()[0].lower() for l in active_lines(conf, ("#",))]
    if "requirepass" not in keys:
        return [Finding("SVC-005", "Redis sin requirepass", Severity.MEDIUM, CAT,
                        "No se pudo probar el servicio y redis.conf no define requirepass.",
                        "Definir requirepass (o ACLs) y escuchar solo en 127.0.0.1.",
                        ["redis.conf sin requirepass"])]
    return []


# --- MongoDB / MySQL -------------------------------------------------------------------

def _check_mongo(ctx) -> List[Finding]:
    text = ctx.read("/etc/mongod.conf")
    if text is None:
        return []
    if re.search(r"^\s*authorization:\s*[\"']?enabled", text, re.M):
        return []
    m = re.search(r"^\s*bindIp:\s*([^\s#]+)", text, re.M)
    bind = m.group(1) if m else "127.0.0.1"
    wide = any(x not in ("127.0.0.1", "localhost", "::1") for x in bind.strip("\"'").split(","))
    sev, note = adjust(Severity.HIGH if wide else Severity.MEDIUM, listening(ctx, 27017))
    return [Finding("SVC-006", "MongoDB sin autenticación (security.authorization)", sev, CAT,
                    "Sin authorization: enabled cualquiera que llegue al puerto lee y escribe todo." + note,
                    "Activar security.authorization: enabled y crear usuarios.",
                    ["authorization no está 'enabled'", "bindIp: %s" % bind])]


MYSQL_CONFS = ("/etc/my.cnf", "/etc/mysql/my.cnf", "/etc/mysql/*.cnf", "/etc/mysql/*.d/*.cnf",
               "/etc/my.cnf.d/*.cnf")


def _check_mysql(ctx) -> List[Finding]:
    out: List[Finding] = []
    seen = set()
    hits = []
    for pat in MYSQL_CONFS:
        for path in ctx.glob(pat):
            if path in seen:
                continue
            seen.add(path)
            for l in active_lines(ctx.read(path), ("#", ";")):
                if re.match(r"^skip[-_]grant[-_]tables\b", l):
                    hits.append("%s: %s" % (path, l))
    if hits:
        sev, note = adjust(Severity.CRITICAL, listening(ctx, 3306))
        out.append(Finding("SVC-007", "MySQL/MariaDB con skip-grant-tables", sev, CAT,
                           "Con skip-grant-tables NO se valida ningún usuario ni contraseña." + note,
                           "Quitar skip-grant-tables y reiniciar el servicio.", hits))
    if ctx.is_root and listening(ctx, 3306):
        res = ctx.run(["mysql", "-N", "-B", "-e", "SELECT user,host FROM mysql.user WHERE user=''"], timeout=15)
        rows = [r for r in (res or "").splitlines() if r.strip() or "\t" in r]
        if rows:
            out.append(Finding("SVC-015", "MySQL/MariaDB con usuarios anónimos", Severity.MEDIUM, CAT,
                               "Un usuario con nombre vacío acepta a cualquiera desde ese host.",
                               "DROP USER ''@'host'; (o mysql_secure_installation).",
                               ["usuario anónimo @ %s" % (r.split("\t")[-1] or "?") for r in rows[:10]]))
    return out


# --- VNC sin contraseña ---------------------------------------------------------------

def analyze_vnc(ps_text: str, file_ok) -> List[Tuple[Severity, str]]:
    out = []
    for line in (ps_text or "").splitlines():
        low = line.lower()
        if not any(x in low for x in ("xtigervnc", "xvnc", "x11vnc", "vncserver", "tightvnc")):
            continue
        if re.search(r"-securitytypes[= ]+none\b", low):
            out.append((Severity.CRITICAL, "VNC con SecurityTypes None: " + line.strip()[:100]))
        elif "x11vnc" in low and "-nopw" in low:
            out.append((Severity.CRITICAL, "x11vnc con -nopw: " + line.strip()[:100]))
        else:
            m = re.search(r"-rfbauth[= ]+(\S+)", line, re.I)
            if m and not file_ok(m.group(1)):
                out.append((Severity.HIGH, "archivo de contraseña VNC ausente o vacío: " + m.group(1)))
            elif "x11vnc" in low and not re.search(r"-(rfbauth|passwd|usepw)", low):
                out.append((Severity.HIGH, "x11vnc sin contraseña configurada: " + line.strip()[:100]))
    return out


def _check_vnc(ctx) -> List[Finding]:
    ps = ctx.run(["ps", "-eo", "args"])
    if not ps:
        return []

    def file_ok(path: str) -> bool:
        st = ctx.stat(path)
        return bool(st) and ctx.read(path) not in (None, "")

    rows = analyze_vnc(ps, file_ok)
    if not rows:
        return []
    return [Finding("SVC-009", "VNC sin contraseña", max(r[0] for r in rows), CAT,
                    "Quien llegue al puerto VNC controla la sesión gráfica sin autenticarse.",
                    "Usar vncpasswd / -rfbauth y escuchar solo en localhost (túnel SSH).",
                    [r[1] for r in rows])]


# --- Sesión guest, autologin, cuentas por defecto ----------------------------------------------

DEFAULT_ACCOUNTS = {
    "guest": "cuenta de invitado", "test": "cuenta de prueba", "demo": "cuenta de demostración",
    "admin": "nombre por defecto", "user": "nombre por defecto", "student": "cuenta de práctica",
    "kali": "usuario por defecto de Kali (contraseña 'kali')",
    "pi": "usuario por defecto de Raspberry Pi", "ubuntu": "usuario por defecto de imágenes cloud",
    "vagrant": "usuario por defecto de Vagrant (contraseña 'vagrant')",
    "oracle": "usuario por defecto de Oracle",
}


def _check_guest_sessions(ctx) -> List[Finding]:
    out: List[Finding] = []
    ev = []
    for path in ["/etc/lightdm/lightdm.conf"] + ctx.glob("/etc/lightdm/lightdm.conf.d/*.conf"):
        cfg = parse_kv(ctx.read(path))
        if truthy(cfg.get("allow-guest")):
            ev.append("%s: allow-guest=true (sesión de invitado sin contraseña)" % path)
        if cfg.get("autologin-user"):
            ev.append("%s: autologin-user=%s" % (path, cfg["autologin-user"]))
    gdm = parse_kv(ctx.read("/etc/gdm3/custom.conf") or ctx.read("/etc/gdm/custom.conf"))
    if truthy(gdm.get("automaticloginenable")) or truthy(gdm.get("timedloginenable")):
        ev.append("GDM: inicio de sesión automático (%s)" % (gdm.get("automaticlogin") or gdm.get("timedlogin") or "?"))
    for path in ["/etc/sddm.conf"] + ctx.glob("/etc/sddm.conf.d/*.conf"):
        t = ctx.read(path) or ""
        if re.search(r"^\s*User=\S+", t, re.M) and "[Autologin]" in t:
            ev.append("%s: [Autologin] activo" % path)
    if ev:
        guest = any("allow-guest" in e for e in ev)
        out.append(Finding("SVC-010", "Sesión guest o inicio de sesión automático", Severity.MEDIUM if guest else Severity.LOW,
                           CAT, "Cualquiera con acceso físico (o remoto por VNC/RDP) entra sin contraseña.",
                           "Desactivar allow-guest y el autologin.", ev))
    return out


def _check_default_accounts(ctx) -> List[Finding]:
    passwd = ctx.read("/etc/passwd")
    if passwd is None:
        return []
    shadow = {}
    for l in (ctx.read("/etc/shadow") or "").splitlines():
        f = l.split(":")
        if len(f) > 1:
            shadow[f[0]] = f[1]
    ev = []
    for u in parse_passwd(passwd):
        if u["name"] not in DEFAULT_ACCOUNTS or u["shell"].rsplit("/", 1)[-1] in NOLOGIN:
            continue
        pw = shadow.get(u["name"])
        if pw is not None and pw[:1] in ("!", "*"):
            continue
        state = "contraseña activa" if pw else "contraseña desconocida (sin root)"
        ev.append("%s (uid %s, %s): %s, %s" % (u["name"], u["uid"], u["shell"], DEFAULT_ACCOUNTS[u["name"]], state))
    if not ev:
        return []
    return [Finding("SVC-014", "Cuentas por defecto con acceso", Severity.MEDIUM, CAT,
                    "Los nombres de cuenta predecibles se prueban primero en cualquier ataque.",
                    "Eliminar la cuenta, bloquearla (usermod -L) o cambiar su contraseña.", ev)]


# --- r-services, SNMP, rsync -----------------------------------------------------------------

LEGACY = ("telnet", "shell", "login", "exec", "rsh", "rlogin", "rexec", "talk", "ntalk", "tftp", "ftp")


def _check_legacy(ctx) -> List[Finding]:
    ev = []
    sev = Severity.MEDIUM
    if ctx.exists("/etc/hosts.equiv"):
        ev.append("/etc/hosts.equiv existe (confianza por host sin contraseña)")
        sev = Severity.HIGH
    for path in ctx.glob("/home/*/.rhosts") + ctx.glob("/root/.rhosts"):
        ev.append("%s (confianza por host sin contraseña)" % path)
        sev = Severity.HIGH
    for l in active_lines(ctx.read("/etc/inetd.conf"), ("#",)):
        if l.split()[0].split("/")[0] in LEGACY:
            ev.append("inetd.conf: " + l[:80])
    for path in ctx.glob("/etc/xinetd.d/*"):
        t = ctx.read(path) or ""
        if os.path.basename(path) in LEGACY and not re.search(r"^\s*disable\s*=\s*yes", t, re.M):
            ev.append("xinetd: %s activo" % os.path.basename(path))
    if not ev:
        return []
    return [Finding("SVC-011", "Servicios r* / inetd antiguos o confianza por host", sev, CAT,
                    "rsh/rlogin/telnet no cifran ni autentican de forma segura; .rhosts permite entrar sin contraseña.",
                    "Eliminar los servicios y los archivos .rhosts / hosts.equiv; usar SSH.", ev)]


def analyze_snmp(text: str) -> List[Tuple[Severity, str]]:
    out = []
    for l in active_lines(text, ("#",)):
        m = re.match(r"^(ro|rw)community6?\s+(\S+)(?:\s+(\S+))?", l, re.I)
        if not m:
            continue
        kind, comm, src = m.group(1).lower(), m.group(2), m.group(3)
        default = comm.lower() in ("public", "private")
        if kind == "rw" and not src:
            out.append((Severity.HIGH, "%scommunity %s sin restricción de origen (escritura)" % (kind, comm)))
        elif default and not src:
            out.append((Severity.MEDIUM, "%scommunity %s (nombre por defecto, sin restricción de origen)" % (kind, comm)))
    return out


def _check_snmp(ctx) -> List[Finding]:
    text = ctx.read("/etc/snmp/snmpd.conf")
    rows = analyze_snmp(text) if text else []
    if not rows:
        return []
    sev, note = adjust(max(r[0] for r in rows), listening(ctx, 161))
    return [Finding("SVC-012", "SNMP con community por defecto o de escritura abierta", sev, CAT,
                    "Quien conozca la community (public/private) lee la configuración o la modifica." + note,
                    "Usar SNMPv3, community aleatoria y limitar el origen.", [r[1] for r in rows])]


def analyze_rsyncd(text: str) -> List[Tuple[Severity, str]]:
    ini = parse_ini(text)
    glob = ini.get("global", {})
    out = []
    for name, sec in ini.items():
        if name == "global":
            continue
        auth = sec.get("auth users") or glob.get("auth users")
        if auth:
            continue
        ro = sec.get("read only", glob.get("read only", "yes")) == "yes"
        restricted = bool(sec.get("hosts allow") or glob.get("hosts allow"))
        sev = Severity.MEDIUM if ro else Severity.HIGH
        if restricted:
            sev = lower(sev)
        out.append((sev, "[%s] sin 'auth users'%s%s" % (
            name, "" if ro else ", con escritura", ", con hosts allow" if restricted else "")))
    return out


def _check_rsyncd(ctx) -> List[Finding]:
    text = ctx.read("/etc/rsyncd.conf")
    rows = analyze_rsyncd(text) if text else []
    if not rows:
        return []
    sev, note = adjust(max(r[0] for r in rows), listening(ctx, 873))
    return [Finding("SVC-013", "rsync daemon con módulos sin autenticación", sev, CAT,
                    "Cualquiera que llegue al puerto 873 puede leer (o escribir) esos módulos." + note,
                    "Definir 'auth users' y 'secrets file', y limitar con 'hosts allow'.", [r[1] for r in rows])]


@register(CAT, "Servicios con acceso anónimo/guest o sin autenticación")
def check_services(ctx) -> List[Finding]:
    out: List[Finding] = []
    for fn in (_check_samba, _check_ftp, _check_nfs, _check_open_services, _check_redis_config,
               _check_mongo, _check_mysql, _check_vnc, _check_guest_sessions,
               _check_default_accounts, _check_legacy, _check_snmp, _check_rsyncd):
        out.extend(fn(ctx))
    return out
