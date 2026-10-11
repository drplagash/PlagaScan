# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Vías de escalada de privilegios: SUID/SGID, capabilities, sudoers (GTFOBins)."""
import os
import re
from typing import Dict, List, Optional, Tuple

from . import register
from .. import gtfobins
from ..models import Finding, Severity

CAT = "privesc"

UNUSUAL_SUID_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/mnt/", "/media/", "/run/user/")


def parse_find_suid(text: str) -> List[Dict]:
    """Parsea `find -printf '%m %u %p\\n'`."""
    rows = []
    for line in text.splitlines():
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        mode_s, owner, path = parts
        try:
            mode = int(mode_s, 8)
        except ValueError:
            continue
        rows.append({"mode": mode, "owner": owner, "path": path,
                     "suid": bool(mode & 0o4000), "sgid": bool(mode & 0o2000)})
    return rows


def parse_getcap(text: str) -> List[Tuple[str, List[str]]]:
    """Parsea `getcap -r /`: 'ruta cap_a,cap_b=ep' (o 'ruta = cap_a=ep' en libcap viejo)."""
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or " " not in line:
            continue
        path, _, rest = line.partition(" ")
        rest = rest.lstrip("= ").strip()
        caps = set()
        for chunk in re.split(r"[ ,]+", rest):
            name = chunk.split("=")[0].split("+")[0].strip().lower()
            if name.startswith("cap_"):
                caps.add(name)
        if caps:
            rows.append((path, sorted(caps)))
    return rows


@register(CAT, "SUID/SGID, capabilities y sudo (GTFOBins)")
def check_privesc(ctx) -> List[Finding]:
    out: List[Finding] = []
    out.extend(_check_suid(ctx))
    out.extend(_check_caps(ctx))
    out.extend(_check_sudoers(ctx))
    out.extend(_check_docker_sock(ctx))
    return out


def _check_suid(ctx) -> List[Finding]:
    text = ctx.run(["find", "/", "-xdev", "-type", "f", "(", "-perm", "-4000", "-o",
                    "-perm", "-2000", ")", "-not", "-path", "/proc/*",
                    "-printf", "%m %u %p\\n"], timeout=120)
    if text is None:
        ctx.skip(CAT + "/suid", "no se pudo ejecutar find")
        return []
    rows = parse_find_suid(text)
    ctx.shared["suid_paths"] = [r["path"] for r in rows if r["suid"]]
    out: List[Finding] = []
    abusable, unusual = [], []
    for r in rows:
        name = os.path.basename(r["path"])
        if r["suid"] and any(r["path"].startswith(d) for d in UNUSUAL_SUID_DIRS):
            unusual.append(r)
            continue
        if r["suid"] and name not in gtfobins.EXPECTED_SUID and name in gtfobins.SUID:
            abusable.append(r)
    for r in unusual:
        out.append(Finding(
            "PRIV-001", "Binario SUID en una ubicación inusual", Severity.HIGH, CAT,
            "Un SUID en %s es típico de una puerta trasera o de una mala configuración." % r["path"],
            "Verificar el origen del archivo y quitar el bit: chmod u-s %s" % r["path"],
            ["%04o %s %s" % (r["mode"], r["owner"], r["path"])]))
    for r in abusable:
        name = os.path.basename(r["path"])
        root_owned = r["owner"] == "root"
        sev = Severity.HIGH if root_owned else Severity.MEDIUM
        out.append(Finding(
            "PRIV-002", "SUID abusable: %s" % name, sev, CAT,
            "%s tiene el bit SUID%s. Técnica: %s." % (
                r["path"], " y es de root" if root_owned else "", gtfobins.SUID[name]),
            "Quitar el bit SUID si no es imprescindible: chmod u-s %s" % r["path"],
            ["%04o %s %s" % (r["mode"], r["owner"], r["path"])],
            [gtfobins.reference(name)]))
    return out


def _check_caps(ctx) -> List[Finding]:
    # Solo directorios del sistema: `getcap -r /` entra en /proc, /mnt y montajes
    # de red, y puede tardar minutos.
    roots = [d for d in ("/usr", "/opt", "/home", "/tmp", "/var", "/srv", "/root")
             if ctx.exists(d)]
    text = ctx.run(["getcap", "-r"] + roots, timeout=120)
    if text is None:
        ctx.skip(CAT + "/capabilities",
                 "getcap no está instalado (paquete libcap2-bin) o excedió el tiempo")
        return []
    out: List[Finding] = []
    for path, caps in parse_getcap(text):
        dangerous = [c for c in caps if c in gtfobins.DANGEROUS_CAPS]
        if not dangerous:
            continue
        name = os.path.basename(path)
        known = name in gtfobins.CAPS
        sev = Severity.HIGH if known else Severity.MEDIUM
        why = "; ".join("%s: %s" % (c, gtfobins.DANGEROUS_CAPS[c]) for c in dangerous)
        out.append(Finding(
            "PRIV-003", "Capabilities peligrosas en %s" % name, sev, CAT,
            "%s tiene %s (%s)." % (path, ", ".join(dangerous), why),
            "Quitar con: setcap -r %s" % path, ["%s %s" % (path, ",".join(caps))],
            [gtfobins.reference(name)] if known else []))
    return out


# --- sudoers ------------------------------------------------------------------

_SKIP_PREFIXES = ("Defaults", "User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias",
                  "#include", "@include", "#", "@")
_RULE_RE = re.compile(r"^(?P<who>\S+)\s+(?P<host>[^=\s]+)\s*=\s*(?P<rest>.+)$")
_TAG_RE = re.compile(r"^(?P<tag>[A-Z_]+):\s*(?P<cmd>.*)$")


def parse_sudoers(text: str) -> List[Dict]:
    """Extrae reglas (usuario, comando, nopasswd) de un sudoers.

    Reglas con varios comandos separados por coma y tags NOPASSWD:/PASSWD:
    que se mantienen hasta el siguiente tag, como hace sudo.
    """
    rules = []
    logical = text.replace("\\\n", " ")
    for raw in logical.splitlines():
        line = raw.strip()
        if not line or line.startswith(_SKIP_PREFIXES):
            continue
        m = _RULE_RE.match(line)
        if not m:
            continue
        who, rest = m.group("who"), m.group("rest").strip()
        if rest.startswith("("):
            end = rest.find(")")
            rest = rest[end + 1:].strip() if end != -1 else rest
        nopasswd = False
        for cmd in rest.split(","):
            cmd = cmd.strip()
            while True:
                t = _TAG_RE.match(cmd)
                if not t:
                    break
                tag = t.group("tag")
                if tag == "NOPASSWD":
                    nopasswd = True
                elif tag == "PASSWD":
                    nopasswd = False
                cmd = t.group("cmd").strip()
            if cmd:
                rules.append({"who": who, "cmd": cmd, "nopasswd": nopasswd})
    return rules


def _check_sudoers(ctx) -> List[Finding]:
    files = ["/etc/sudoers"] + ctx.glob("/etc/sudoers.d/*")
    texts = [(f, ctx.read(f)) for f in files]
    readable = [(f, t) for f, t in texts if t is not None]
    if not readable:
        ctx.skip(CAT + "/sudoers", "requiere root para leer /etc/sudoers")
        return []
    out: List[Finding] = []
    for fname, text in readable:
        for rule in parse_sudoers(text):
            who, cmd, nopw = rule["who"], rule["cmd"], rule["nopasswd"]
            if who in ("root", "%root"):
                continue
            first = cmd.split()[0] if cmd.split() else cmd
            name = os.path.basename(first.lstrip("!"))
            where = "%s: %s ... %s%s" % (fname, who, "NOPASSWD: " if nopw else "", cmd)
            if first == "ALL":
                if nopw:
                    out.append(Finding(
                        "PRIV-004", "sudo sin contraseña para cualquier comando (%s)" % who,
                        Severity.HIGH, CAT,
                        "Quien comprometa esta cuenta es root sin pasos extra.",
                        "Quitar NOPASSWD o limitar los comandos permitidos.", [where]))
                continue
            if name in gtfobins.SUDO:
                sev = Severity.HIGH if nopw else Severity.MEDIUM
                out.append(Finding(
                    "PRIV-005", "sudo permite un binario abusable: %s" % name, sev, CAT,
                    "La regla da root al usuario %s con %s. Técnica: %s." % (
                        who, name, gtfobins.SUDO[name]),
                    "Quitar el binario de sudoers o usar un wrapper restringido.",
                    [where], [gtfobins.reference(name)]))
            elif "*" in cmd and "/" in first:
                out.append(Finding(
                    "PRIV-006", "Regla de sudo con comodín (*)", Severity.MEDIUM, CAT,
                    "Los comodines en argumentos suelen permitir inyectar opciones o rutas.",
                    "Especificar argumentos exactos.", [where]))
    return out


def _check_docker_sock(ctx) -> List[Finding]:
    st = ctx.stat("/var/run/docker.sock") or ctx.stat("/run/docker.sock")
    if st and st[0] & 0o006:
        return [Finding(
            "PRIV-007", "El socket de Docker es accesible por todos", Severity.CRITICAL, CAT,
            "Cualquier usuario puede hablar con Docker y obtener root en el host.",
            "chmod 660 /var/run/docker.sock y limitar el grupo docker.",
            ["modo %04o" % st[0]], [gtfobins.reference("docker")])]
    return []
