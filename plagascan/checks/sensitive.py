# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Secretos legibles por todos, backups de /etc/shadow y archivos escribibles fuera de /etc."""
import os
import re
from typing import Dict, List, Tuple

from . import register
from .accounts import parse_passwd
from .common import lower
from ..models import Finding, Severity

CAT = "sensitive"

SECRET_ROOTS = ["/home", "/root", "/opt", "/srv", "/var/www", "/etc"]

# patrón de find -> (descripción, severidad si lo puede leer cualquiera)
SECRET_NAMES = {
    "id_rsa": ("Clave privada SSH", Severity.HIGH),
    "id_dsa": ("Clave privada SSH", Severity.HIGH),
    "id_ecdsa": ("Clave privada SSH", Severity.HIGH),
    "id_ed25519": ("Clave privada SSH", Severity.HIGH),
    ".pgpass": ("Contraseñas de PostgreSQL (.pgpass)", Severity.HIGH),
    ".git-credentials": ("Credenciales de git en claro", Severity.HIGH),
    ".netrc": ("Credenciales de .netrc", Severity.HIGH),
    ".my.cnf": ("Contraseña de MySQL (.my.cnf)", Severity.MEDIUM),
    ".htpasswd": ("Hashes de contraseñas web (.htpasswd)", Severity.MEDIUM),
    ".env": ("Archivo .env con credenciales", Severity.MEDIUM),
    ".npmrc": ("Token de npm (.npmrc)", Severity.MEDIUM),
    ".pypirc": ("Token de PyPI (.pypirc)", Severity.MEDIUM),
    ".dockercfg": ("Credenciales de registry Docker", Severity.MEDIUM),
    "*.kdbx": ("Base de contraseñas KeePass", Severity.MEDIUM),
}


# Archivos cuyo nombre no alcanza: solo se reportan si el contenido trae un secreto real.
CONTENT_CHECKED = {".env", ".npmrc", ".pypirc", ".my.cnf", ".dockercfg", ".htpasswd"}
_SECRET_RE = re.compile(
    r"(?im)^\s*(?:export\s+)?[\w./:@-]*(token|secret|passw(?:or)?d|pwd|api[_-]?key|auth|credential|private[_-]?key)"
    r"[\w.-]*\s*[=:]\s*[\"']?([^\s\"'#]{6,})")
_PLACEHOLDER_RE = re.compile(r"(?i)^(\$\{|<|\{\{|your[_-]|change[_-]?me|xxx|example|placeholder|todo|\*+$|none$|null$|true$|false$)")


def has_secret_content(text: str) -> bool:
    """True si hay `clave=valor` con pinta de secreto real (no plantillas ni referencias a variables)."""
    for m in _SECRET_RE.finditer(text or ""):
        if not _PLACEHOLDER_RE.match(m.group(2)):
            return True
    if re.search(r"(?m)^[^#\n]*:\$?apr1\$|^[^#\n]*:\{SHA\}|^[^#\n]*:\$2[aby]\$", text or ""):
        return True
    return False


def _find_secrets_cmd(roots: List[str]) -> List[str]:
    cmd = ["find"] + roots + ["-xdev", "-type", "f", "("]
    first = True
    for name in SECRET_NAMES:
        if not first:
            cmd.append("-o")
        cmd += ["-name", name]
        first = False
    cmd += ["-o", "-path", "*/.aws/credentials", "-o", "-path", "*/ssl/private/*", ")",
            "-perm", "-0004", "-printf", "%m %u %p\\n"]
    return cmd


def parse_find_modes(text: str) -> List[Dict]:
    rows = []
    for line in (text or "").splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit():
            try:
                rows.append({"mode": int(parts[0], 8), "owner": parts[1], "path": parts[2]})
            except ValueError:
                continue
    return rows


def classify_secret(path: str) -> Tuple[str, Severity]:
    base = os.path.basename(path)
    if base in SECRET_NAMES:
        return SECRET_NAMES[base]
    if base.endswith(".kdbx"):
        return SECRET_NAMES["*.kdbx"]
    if path.endswith("/.aws/credentials"):
        return ("Credenciales de AWS", Severity.HIGH)
    if "/ssl/private/" in path:
        return ("Clave privada TLS", Severity.HIGH)
    return ("archivo sensible", Severity.MEDIUM)


def _check_secrets(ctx) -> List[Finding]:
    roots = [r for r in SECRET_ROOTS if ctx.exists(r)]
    text = ctx.run(_find_secrets_cmd(roots), timeout=90)
    if text is None:
        ctx.skip(CAT + "/secretos", "no se pudo ejecutar find")
        return []
    if not ctx.is_root:
        ctx.skip(CAT + "/secretos", "sin root no se ven los directorios de otros usuarios")
    out: List[Finding] = []
    for row in parse_find_modes(text):
        what, sev = classify_secret(row["path"])
        if os.path.basename(row["path"]) in CONTENT_CHECKED and not has_secret_content(ctx.read(row["path"]) or ""):
            continue
        out.append(Finding(
            "SEC-001", "%s legible por cualquier usuario" % what, sev, CAT,
            "%s tiene modo %04o: cualquier cuenta local puede leerlo." % (row["path"], row["mode"]),
            "chmod 600 %s" % row["path"], ["%04o %s %s" % (row["mode"], row["owner"], row["path"])]))
    return out


# --- copias de seguridad de cuentas ---------------------------------------------------------

BACKUPS: Dict[str, Tuple[int, Severity]] = {
    "/etc/shadow-": (0o640, Severity.HIGH), "/etc/gshadow-": (0o640, Severity.HIGH),
    "/etc/shadow~": (0o640, Severity.HIGH), "/etc/shadow.bak": (0o640, Severity.HIGH),
    "/etc/shadow.old": (0o640, Severity.HIGH), "/var/backups/shadow.bak": (0o640, Severity.HIGH),
    "/var/backups/gshadow.bak": (0o640, Severity.HIGH), "/etc/security/opasswd": (0o600, Severity.MEDIUM),
    "/etc/passwd-": (0o644, Severity.LOW), "/etc/group-": (0o644, Severity.LOW),
}


def _check_account_backups(ctx) -> List[Finding]:
    out = []
    for path, (maxmode, sev) in BACKUPS.items():
        st = ctx.stat(path)
        if st is None:
            continue
        mode = st[0]
        if mode & ~maxmode & 0o7777:
            out.append(Finding(
                "SEC-002", "Copia de seguridad de cuentas con permisos excesivos: %s" % os.path.basename(path),
                sev, CAT, "%s es %04o; las copias de shadow exponen los mismos hashes que el original." % (path, mode),
                "chmod %04o %s" % (maxmode, path), ["%04o %s" % (mode, path)]))
    return out


# --- archivos y directorios escribibles por todos fuera de /etc ----------------------------------

WRITABLE_ROOTS = ["/usr/local", "/var/www", "/opt", "/srv", "/home"]
CODE_PREFIXES = ("/usr/local/", "/var/www/")


def _prefix_sev(path: str) -> Severity:
    if path.startswith(CODE_PREFIXES):
        return Severity.HIGH
    if path.startswith(("/opt/", "/srv/")):
        return Severity.MEDIUM
    return Severity.LOW


def _check_world_writable(ctx) -> List[Finding]:
    roots = [r for r in WRITABLE_ROOTS if ctx.exists(r)]
    if not roots:
        return []
    out: List[Finding] = []
    files = ctx.run(["find"] + roots + ["-xdev", "-type", "f", "-perm", "-0002", "-printf", "%m %u %p\\n"], timeout=90)
    if files is None:
        ctx.skip(CAT + "/escribibles", "find expiró (90 s) o no está disponible: archivos escribibles sin revisar")
    by_sev: Dict[Severity, List[str]] = {}
    for row in parse_find_modes(files or ""):
        by_sev.setdefault(_prefix_sev(row["path"]), []).append("%04o %s %s" % (row["mode"], row["owner"], row["path"]))
    for sev, ev in sorted(by_sev.items(), reverse=True):
        out.append(Finding(
            "SEC-003", "Archivos escribibles por cualquier usuario (%d)" % len(ev), sev, CAT,
            "Si root o un servicio los ejecuta o los lee como configuración, cualquiera puede inyectar código.",
            "chmod o-w sobre estos archivos tras verificar que no es intencional.", ev))
    dirs = ctx.run(["find"] + roots + ["-xdev", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000",
                                       "-printf", "%m %u %p\\n"], timeout=90)
    if dirs is None:
        ctx.skip(CAT + "/directorios", "find expiró (90 s) o no está disponible: directorios escribibles sin revisar")
    by_sev = {}
    for row in parse_find_modes(dirs or ""):
        by_sev.setdefault(_prefix_sev(row["path"]), []).append("%04o %s %s" % (row["mode"], row["owner"], row["path"]))
    for sev, ev in sorted(by_sev.items(), reverse=True):
        out.append(Finding(
            "SEC-004", "Directorios escribibles por todos y sin sticky bit (%d)" % len(ev), lower(sev), CAT,
            "Cualquier usuario puede borrar o reemplazar archivos de otros dentro de ellos.",
            "chmod o-w o chmod +t (sticky) según el caso.", ev))
    return out


def _check_homes(ctx) -> List[Finding]:
    passwd = ctx.read("/etc/passwd")
    if passwd is None:
        return []
    humans = [u for u in parse_passwd(passwd) if u["uid"].isdigit() and int(u["uid"]) >= 1000
              and u["name"] != "nobody" and u["shell"].rsplit("/", 1)[-1] not in ("nologin", "false")]
    if len(humans) < 2:
        return []
    ev = []
    for u in humans:
        st = ctx.stat(u["home"])
        if st and st[0] & 0o005:
            ev.append("%04o %s" % (st[0], u["home"]))
    if not ev:
        return []
    return [Finding("SEC-005", "Directorios personales legibles por otros usuarios", Severity.LOW, CAT,
                    "Con varios usuarios en el equipo, cada uno puede recorrer los archivos de los demás.",
                    "chmod 750 sobre cada /home/usuario.", ev)]


@register(CAT, "Secretos legibles, copias de shadow y archivos escribibles")
def check_sensitive(ctx) -> List[Finding]:
    out: List[Finding] = []
    for fn in (_check_secrets, _check_account_backups, _check_world_writable, _check_homes):
        out.extend(fn(ctx))
    return out
