"""Permisos de archivos sensibles, PATH y opciones de montaje."""
from typing import List

from . import register
from ..models import Finding, Severity

CAT = "filesystem"

# ruta -> (modo máximo esperado, severidad base si hay exceso)
SENSITIVE = {
    "/etc/passwd": (0o644, Severity.HIGH),
    "/etc/group": (0o644, Severity.MEDIUM),
    "/etc/shadow": (0o640, Severity.HIGH),
    "/etc/gshadow": (0o640, Severity.HIGH),
    "/etc/sudoers": (0o440, Severity.HIGH),
    "/etc/ssh/sshd_config": (0o644, Severity.MEDIUM),
    "/etc/crontab": (0o644, Severity.MEDIUM),
    "/etc/ssh/ssh_host_rsa_key": (0o600, Severity.HIGH),
    "/etc/ssh/ssh_host_ed25519_key": (0o600, Severity.HIGH),
}


@register(CAT, "Permisos de archivos y PATH")
def check_filesystem(ctx) -> List[Finding]:
    out: List[Finding] = []

    for path, (maxmode, base) in SENSITIVE.items():
        st = ctx.stat(path)
        if st is None:
            continue
        mode, uid, _gid = st
        excess = mode & ~maxmode & 0o7777
        if not excess:
            continue
        sev = Severity.CRITICAL if mode & 0o002 else base
        out.append(Finding(
            "FS-001", "Permisos excesivos en %s" % path, sev, CAT,
            "Modo actual %04o, el máximo recomendado es %04o." % (mode, maxmode),
            "chmod %04o %s" % (maxmode, path), ["%s %04o uid=%d" % (path, mode, uid)]))

    # PATH peligroso
    bad = []
    for entry in (ctx.getenv("PATH") or "").split(":"):
        if entry in ("", "."):
            bad.append("entrada vacía o '.' en PATH")
            continue
        st = ctx.stat(entry)
        if st and st[0] & 0o002:
            bad.append("%s es escribible por todos" % entry)
    if bad:
        out.append(Finding(
            "FS-002", "PATH inseguro", Severity.MEDIUM, CAT,
            "Un directorio escribible o relativo en PATH permite secuestrar comandos.",
            "Quitar '.' y entradas vacías; corregir permisos de los directorios.", bad))

    # Archivos de configuración escribibles por todos
    ww = ctx.run(["find", "/etc", "-xdev", "-type", "f", "-perm", "-0002"], timeout=60)
    if ww:
        files = [l for l in ww.splitlines() if l]
        if files:
            out.append(Finding(
                "FS-003", "Archivos de /etc escribibles por cualquier usuario",
                Severity.HIGH, CAT,
                "Cualquier usuario local puede modificar configuración del sistema.",
                "chmod o-w sobre estos archivos tras verificar que no es intencional.",
                files[:15]))

    units = ctx.run(["find", "/etc/systemd/system", "/lib/systemd/system",
                     "/usr/lib/systemd/system", "-type", "f", "-perm", "-0002"], timeout=60)
    if units:
        files = [l for l in units.splitlines() if l]
        if files:
            out.append(Finding(
                "FS-004", "Unidades systemd escribibles por todos", Severity.CRITICAL, CAT,
                "Quien edite una unidad puede ejecutar código como root al reiniciar el servicio.",
                "chmod o-w sobre estas unidades.", files[:15]))

    # Opciones de montaje
    for mp in ("/tmp", "/dev/shm"):
        opts = ctx.run(["findmnt", "-n", "-o", "OPTIONS", mp])
        if opts is None or not opts.strip():
            continue
        if "noexec" not in opts:
            out.append(Finding(
                "FS-005", "%s montado sin noexec" % mp, Severity.LOW, CAT,
                "Permite ejecutar binarios descargados a un directorio temporal.",
                "Agregar noexec,nosuid,nodev en /etc/fstab (probar antes: algunos instaladores lo usan).",
                [opts.strip()]))
    return out
