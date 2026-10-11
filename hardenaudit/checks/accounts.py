"""Cuentas, contraseñas y grupos equivalentes a root."""
from typing import Dict, List

from . import register
from ..models import Finding, Severity

CAT = "accounts"

# Grupos cuyos miembros pueden convertirse en root con un comando.
ROOT_EQUIVALENT_GROUPS = {
    "docker": "puede montar / en un contenedor y leer/escribir todo el host",
    "lxd": "puede crear un contenedor privilegiado con el host montado",
    "lxc": "puede crear un contenedor privilegiado con el host montado",
    "disk": "lectura/escritura cruda de los discos (debugfs)",
    "shadow": "puede leer /etc/shadow",
}


def parse_passwd(text: str) -> List[Dict[str, str]]:
    rows = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        f = line.split(":")
        if len(f) >= 7:
            rows.append({"name": f[0], "pw": f[1], "uid": f[2], "gid": f[3],
                         "home": f[5], "shell": f[6]})
    return rows


def parse_group(text: str) -> Dict[str, List[str]]:
    groups = {}
    for line in text.splitlines():
        f = line.split(":")
        if len(f) >= 4:
            groups[f[0]] = [m for m in f[3].split(",") if m]
    return groups


@register(CAT, "Cuentas y grupos")
def check_accounts(ctx) -> List[Finding]:
    out: List[Finding] = []
    passwd = ctx.read("/etc/passwd")
    if passwd is None:
        ctx.skip(CAT, "/etc/passwd no es legible")
        return out
    users = parse_passwd(passwd)

    uid0 = [u["name"] for u in users if u["uid"] == "0" and u["name"] != "root"]
    if uid0:
        out.append(Finding(
            "ACC-001", "Cuentas adicionales con UID 0", Severity.CRITICAL, CAT,
            "Una cuenta con UID 0 es root a todos los efectos.",
            "Eliminar o cambiar el UID de estas cuentas salvo que sea intencional.",
            uid0))

    inline = [u["name"] for u in users if u["pw"] not in ("x", "*", "!", "")]
    if inline:
        out.append(Finding(
            "ACC-002", "Hashes de contraseña dentro de /etc/passwd", Severity.HIGH, CAT,
            "El hash está en un archivo legible por todos.",
            "Migrar a /etc/shadow con pwconv.", inline))

    shadow = ctx.read("/etc/shadow")
    if shadow is None:
        ctx.skip(CAT + "/shadow", "requiere root para leer /etc/shadow")
    else:
        empty, weak = [], []
        for line in shadow.splitlines():
            f = line.split(":")
            if len(f) < 2:
                continue
            if f[1] == "":
                empty.append(f[0])
            elif f[1].startswith("$1$"):
                weak.append(f[0])
        if empty:
            out.append(Finding(
                "ACC-003", "Cuentas sin contraseña", Severity.CRITICAL, CAT,
                "Cuentas con campo de contraseña vacío pueden entrar sin credenciales.",
                "Bloquearlas (passwd -l) o asignar contraseña.", empty))
        if weak:
            out.append(Finding(
                "ACC-004", "Contraseñas con hash MD5", Severity.MEDIUM, CAT,
                "El hash $1$ (MD5) se rompe con facilidad.",
                "Forzar el cambio de contraseña con ENCRYPT_METHOD SHA512/yescrypt.", weak))

    # Cuentas de servicio con shell interactiva
    interactive = {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash", "/usr/bin/bash",
                   "/usr/bin/zsh", "/usr/bin/sh"}
    svc = [u["name"] for u in users
           if u["shell"] in interactive and u["uid"].isdigit()
           and 0 < int(u["uid"]) < 1000 and u["name"] not in ("sync",)]
    if svc:
        out.append(Finding(
            "ACC-005", "Cuentas de sistema con shell interactiva", Severity.LOW, CAT,
            "Las cuentas de servicio no deberían poder iniciar sesión.",
            "Cambiar su shell a /usr/sbin/nologin.", svc))

    groups = parse_group(ctx.read("/etc/group") or "")
    for gname, why in ROOT_EQUIVALENT_GROUPS.items():
        members = groups.get(gname, [])
        if members:
            out.append(Finding(
                "ACC-006", "Miembros del grupo '%s' (equivalente a root)" % gname,
                Severity.HIGH, CAT,
                "Quien pertenece a este grupo %s." % why,
                "Quitar del grupo a quien no lo necesite.", members,
                ["https://gtfobins.github.io/gtfobins/docker/"] if gname == "docker" else []))
    return out
