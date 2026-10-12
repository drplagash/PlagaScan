# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Tareas de cron y servicios de systemd de root que ejecutan algo que otros pueden modificar."""
import os
import re
from typing import Callable, Dict, List, Optional, Tuple

from . import register
from .common import is_wsl
from ..models import Finding, Severity

CAT = "scheduling"

_PATH_RE = re.compile(r"(?<![\w./-])(/[\w./+@%-]+)")
_WILDCARD_CMDS = ("tar", "chown", "chmod", "rsync", "zip", "7z")


def parse_crontab(text: str, system: bool, default_user: str = "root") -> List[Dict[str, str]]:
    """Trabajos de un crontab. `system` = formato /etc/crontab (con columna de usuario)."""
    jobs = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", line):
            continue
        parts = line.split(None, 1 if line.startswith("@") else 5)
        if line.startswith("@"):
            rest = parts[1].split(None, 1) if len(parts) > 1 else []
            user, cmd = (rest[0], rest[1]) if system and len(rest) == 2 else (default_user, parts[1] if len(parts) > 1 else "")
        else:
            if len(parts) < 6:
                continue
            tail = parts[5]
            if system:
                bits = tail.split(None, 1)
                if len(bits) < 2:
                    continue
                user, cmd = bits
            else:
                user, cmd = default_user, tail
        jobs.append({"user": user, "cmd": cmd})
    return jobs


def unsafe_reason(ctx, path: str, wsl: bool = False) -> Optional[Tuple[Severity, str]]:
    """Por qué un usuario sin privilegios podría reemplazar `path` (o None)."""
    if wsl and path.startswith("/mnt/"):
        return None
    st = ctx.stat(path)
    if st is None:
        return None
    mode, uid, _gid = st
    if mode & 0o002:
        return Severity.HIGH, "%s es escribible por todos (%04o)" % (path, mode)
    if uid != 0:
        return Severity.HIGH, "%s pertenece al uid %d (no root)" % (path, uid)
    if mode & 0o020:
        return Severity.MEDIUM, "%s es escribible por su grupo (%04o)" % (path, mode)
    parent = os.path.dirname(path)
    pst = ctx.stat(parent) if parent else None
    if pst and pst[0] & 0o002 and not pst[0] & 0o1000:
        return Severity.HIGH, "el directorio %s es escribible por todos: se puede reemplazar %s" % (parent, os.path.basename(path))
    if pst and pst[1] != 0 and parent not in ("/", ""):
        return Severity.MEDIUM, "el directorio %s pertenece al uid %d (no root)" % (parent, pst[1])
    return None


def _cmd_paths(cmd: str) -> List[str]:
    return [p for p in _PATH_RE.findall(cmd) if p.count("/") >= 2 or os.path.basename(p) not in ("", "dev", "null")]


def _check_cron(ctx) -> List[Finding]:
    wsl = is_wsl(ctx)
    jobs: List[Tuple[str, str, str]] = []  # (origen, usuario, comando)
    for path in ["/etc/crontab"] + ctx.glob("/etc/cron.d/*"):
        for j in parse_crontab(ctx.read(path) or "", system=True):
            jobs.append((path, j["user"], j["cmd"]))
    for path in ctx.glob("/var/spool/cron/crontabs/*") + ctx.glob("/var/spool/cron/*"):
        user = os.path.basename(path)
        for j in parse_crontab(ctx.read(path) or "", system=False, default_user=user):
            jobs.append((path, user, j["cmd"]))

    by_sev: Dict[Severity, List[str]] = {}
    wild: List[str] = []
    for origin, user, cmd in jobs:
        if user != "root":
            continue
        for p in _cmd_paths(cmd):
            r = unsafe_reason(ctx, p, wsl)
            if r:
                by_sev.setdefault(r[0], []).append("%s (cron de root en %s)" % (r[1], origin))
        words = cmd.split()
        if "*" in words and any(os.path.basename(w) in _WILDCARD_CMDS for w in words):
            wild.append("%s: %s" % (origin, cmd[:90]))

    out: List[Finding] = []
    for sev, ev in sorted(by_sev.items(), reverse=True):
        out.append(Finding(
            "SCH-001", "Tarea de cron de root ejecuta algo modificable por otros", sev, CAT,
            "Quien pueda escribir ese archivo (o su directorio) obtiene root en la próxima ejecución.",
            "Dejar el script root:root 755 en un directorio no escribible por otros.", sorted(set(ev))))
    if wild:
        out.append(Finding(
            "SCH-002", "Cron de root con comodín (*) en tar/chown/chmod/rsync", Severity.MEDIUM, CAT,
            "Un archivo llamado '--checkpoint-action=...' en ese directorio se interpreta como opción (inyección por comodín).",
            "Usar rutas explícitas o '--' antes del comodín.", wild))

    ev = []
    sev = Severity.HIGH
    for d in ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"):
        st = ctx.stat(d)
        if st and st[0] & 0o022:
            ev.append("directorio %s con modo %04o" % (d, st[0]))
        for f in ctx.glob(d + "/*"):
            r = unsafe_reason(ctx, f, wsl)
            if r and r[0] >= Severity.MEDIUM and not r[1].startswith("el directorio"):
                ev.append(r[1])
    if ev:
        out.append(Finding(
            "SCH-003", "Directorios o scripts de cron.* modificables por otros", sev, CAT,
            "Todo lo que hay en /etc/cron.* lo ejecuta root.", "chmod go-w y chown root:root.", sorted(set(ev))[:15]))
    return out


_EXEC_RE = re.compile(r"^\s*Exec(?:Start|StartPre|StartPost|Stop|Reload)\s*=\s*[-@+!:]*(/\S+)", re.M)


def _check_systemd_exec(ctx) -> List[Finding]:
    wsl = is_wsl(ctx)
    units: List[str] = []
    for d in ("/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"):
        units += ctx.glob(d + "/*.service")
    seen = set()
    ev: Dict[Severity, List[str]] = {}
    for unit in units:
        text = ctx.read(unit)
        if not text:
            continue
        user = re.search(r"^\s*User\s*=\s*(\S+)", text, re.M)
        if user and user.group(1) not in ("root", "0"):
            continue
        for p in _EXEC_RE.findall(text):
            if (unit, p) in seen:
                continue
            seen.add((unit, p))
            r = unsafe_reason(ctx, p, wsl)
            if r and r[0] >= Severity.MEDIUM:
                ev.setdefault(r[0], []).append("%s (ExecStart de %s)" % (r[1], os.path.basename(unit)))
    out = []
    for sev, rows in sorted(ev.items(), reverse=True):
        out.append(Finding(
            "SCH-004", "Servicio de systemd (root) ejecuta algo modificable por otros", sev, CAT,
            "Quien reemplace ese binario o script lo ejecuta como root al reiniciar el servicio.",
            "Dejar el archivo root:root sin escritura para grupo/otros.", sorted(set(rows))[:15]))
    return out


@register(CAT, "Cron y servicios de root que ejecutan archivos modificables")
def check_scheduling(ctx) -> List[Finding]:
    return _check_cron(ctx) + _check_systemd_exec(ctx)
