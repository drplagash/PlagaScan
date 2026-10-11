"""Binarios abusables para escalar privilegios, al estilo GTFOBins.

Es una lista curada y propia (solo nombres y una pista corta): el detalle de
cada técnica está en https://gtfobins.github.io/ y se enlaza desde el reporte.

Tres contextos:
  SUID  - el binario tiene el bit SUID y es de root
  SUDO  - aparece en una regla de sudoers (idealmente NOPASSWD)
  CAPS  - tiene capabilities peligrosas (cap_setuid, cap_dac_*, ...)
"""

GTFOBINS_URL = "https://gtfobins.github.io/gtfobins/%s/"

# nombre -> pista corta
_SHELLS = {
    "bash": "lanza una shell conservando el euid (-p)",
    "sh": "lanza una shell conservando el euid (-p)",
    "dash": "lanza una shell conservando el euid (-p)",
    "zsh": "shell interactiva con privilegios",
    "ksh": "shell interactiva con privilegios",
    "csh": "shell interactiva con privilegios",
    "ash": "shell interactiva con privilegios",
    "busybox": "ejecuta sh y utilidades con privilegios",
}

_INTERPRETERS = {
    "python": "os.setuid(0) + os.system('/bin/sh')",
    "python2": "os.setuid(0) + os.system('/bin/sh')",
    "python3": "os.setuid(0) + os.system('/bin/sh')",
    "perl": "exec '/bin/sh'",
    "ruby": "exec '/bin/sh'",
    "php": "system('/bin/sh')",
    "node": "child_process.spawn('/bin/sh')",
    "lua": "os.execute('/bin/sh')",
    "tclsh": "exec /bin/sh",
    "wish": "exec /bin/sh",
    "expect": "spawn /bin/sh",
    "gawk": "system('/bin/sh')",
    "awk": "system('/bin/sh')",
    "mawk": "system('/bin/sh')",
    "gdb": "!/bin/sh o python os.system",
    "jjs": "Java.type('java.lang.Runtime').exec",
    "irb": "exec '/bin/sh'",
    "pry": "exec '/bin/sh'",
}

_FILE_TOOLS = {
    "cat": "lee cualquier archivo (/etc/shadow)",
    "head": "lee cualquier archivo",
    "tail": "lee cualquier archivo",
    "cp": "sobrescribe /etc/passwd o /etc/sudoers",
    "mv": "reemplaza archivos del sistema",
    "dd": "lee/escribe archivos arbitrarios",
    "tee": "escribe en archivos privilegiados",
    "install": "copia archivos con permisos arbitrarios",
    "sed": "lee/escribe archivos; ejecución con e",
    "sort": "lee archivos privilegiados",
    "base64": "lee archivos privilegiados",
    "xxd": "lee archivos privilegiados",
    "od": "lee archivos privilegiados",
    "cut": "lee archivos privilegiados",
    "diff": "lee archivos privilegiados",
    "tar": "lee/escribe archivos; --checkpoint-action=exec",
    "zip": "ejecuta comandos con -T -TT",
    "unzip": "escribe archivos arbitrarios",
    "rsync": "ejecuta comandos con -e",
    "scp": "ejecuta comandos con -S",
    "chmod": "cambia permisos de archivos del sistema",
    "chown": "cambia dueño de archivos del sistema",
    "ln": "enlaces simbólicos a archivos privilegiados",
    "truncate": "trunca archivos del sistema",
    "mount": "monta sobre archivos del sistema",
    "setfacl": "otorga acceso a archivos del sistema",
    "nl": "lee archivos privilegiados",
    "split": "lee/escribe archivos privilegiados",
}

_PAGERS_EDITORS = {
    "vi": "!/bin/sh desde el editor",
    "vim": "!/bin/sh desde el editor",
    "view": "!/bin/sh desde el editor",
    "rvim": "!/bin/sh desde el editor",
    "nano": "ejecuta comandos (^R^X) o edita archivos",
    "pico": "ejecuta comandos o edita archivos",
    "ed": "!/bin/sh desde el editor",
    "emacs": "M-x shell",
    "less": "!/bin/sh desde el pager",
    "more": "!/bin/sh desde el pager",
    "most": "!/bin/sh desde el pager",
    "man": "!/bin/sh desde el pager",
    "pg": "!/bin/sh desde el pager",
    "journalctl": "!/bin/sh desde el pager",
    "systemctl": "crea/edita unidades; pager con !sh",
    "git": "pager/hooks ejecutan comandos",
    "ftp": "!/bin/sh",
    "sftp": "ejecuta comandos con ProxyCommand",
    "mysql": "\\! /bin/sh",
    "psql": "\\! /bin/sh",
    "sqlite3": ".shell /bin/sh",
}

_NETWORK = {
    "nc": "shell inversa / lectura-escritura de archivos",
    "ncat": "shell inversa con -e",
    "netcat": "shell inversa / lectura-escritura de archivos",
    "socat": "shell inversa con EXEC:",
    "curl": "lee/escribe archivos (file://, -o)",
    "wget": "sobrescribe archivos con -O",
    "openssl": "shell inversa o lectura de archivos",
    "ssh": "ejecuta comandos con ProxyCommand",
    "nmap": "scripts NSE / --interactive en versiones viejas",
    "tcpdump": "-z ejecuta comandos tras rotar capturas",
    "ip": "netns exec ejecuta comandos",
    "ssh-keygen": "carga bibliotecas con -D",
}

_EXEC_WRAPPERS = {
    "env": "env /bin/sh -p",
    "find": "find . -exec /bin/sh -p \\;",
    "xargs": "xargs -a /dev/null sh",
    "time": "time /bin/sh",
    "timeout": "timeout 1 /bin/sh",
    "nice": "nice /bin/sh",
    "ionice": "ionice /bin/sh",
    "stdbuf": "stdbuf -i0 /bin/sh",
    "taskset": "taskset 1 /bin/sh",
    "setarch": "setarch $(arch) /bin/sh",
    "flock": "flock -u / /bin/sh",
    "watch": "watch -x sh -c ...",
    "strace": "strace -o /dev/null /bin/sh",
    "ltrace": "ltrace -b -L /bin/sh",
    "nsenter": "entra a namespaces del host",
    "unshare": "unshare /bin/sh",
    "chroot": "chroot / /bin/sh",
    "script": "script -qc /bin/sh /dev/null",
    "screen": "sesión con privilegios",
    "tmux": "sesión con privilegios",
    "cpulimit": "cpulimit -l 100 -f /bin/sh",
    "make": "make -s --eval=$'x:\\n\\t-'/bin/sh",
    "run-parts": "run-parts --new-session --regex '^sh$' /bin",
    "start-stop-daemon": "start-stop-daemon -n x -S -x /bin/sh",
    "rlwrap": "rlwrap /bin/sh",
    "ld.so": "ld.so /bin/sh",
    "pkexec": "pkexec /bin/sh (revisar versión de polkit)",
    "su": "con credenciales conocidas",
    "doas": "con regla permisiva",
}

_CONTAINERS = {
    "docker": "monta / en un contenedor privilegiado",
    "podman": "monta / en un contenedor privilegiado",
    "lxc": "contenedor privilegiado con el host montado",
    "lxd": "contenedor privilegiado con el host montado",
    "kubectl": "pods privilegiados con el host montado",
    "runc": "contenedor con el host montado",
    "ctr": "contenedor con el host montado",
}

_ALL = {}
for _group in (_SHELLS, _INTERPRETERS, _FILE_TOOLS, _PAGERS_EDITORS,
               _NETWORK, _EXEC_WRAPPERS, _CONTAINERS):
    _ALL.update(_group)

# Contextos. En SUID aplican casi todos; algunos solo tienen sentido con sudo
# (editores/pagers con sudo dan shell, con SUID suelen dar lectura/escritura).
SUID = dict(_ALL)
SUDO = dict(_ALL)
CAPS = {k: v for k, v in _ALL.items()
        if k in {**_INTERPRETERS, **_FILE_TOOLS, "gdb": "", "openssl": "",
                 "tar": "", "vim": "", "view": "", "rvim": "", "node": "",
                 "tcpdump": "", "nmap": "", "ip": "", "busybox": ""}}

# SUID legítimos de una instalación normal: no se reportan como abusables.
EXPECTED_SUID = {
    "su", "sudo", "mount", "umount", "passwd", "chsh", "chfn", "newgrp",
    "gpasswd", "fusermount", "fusermount3", "ping", "ping6", "pkexec",
    "unix_chkpwd", "pam_timestamp_check", "ssh-keysign", "dbus-daemon-launch-helper",
    "polkit-agent-helper-1", "Xorg.wrap", "crontab", "at", "chage", "expiry",
    "mount.nfs", "mount.cifs", "umount.nfs", "ntfs-3g", "vmware-user-suid-wrapper",
    "snap-confine", "ubuntu-core-launcher", "staprun", "traceroute6.iputils",
    "arping", "sudoedit", "mtr-packet", "pt_chown",
}

DANGEROUS_CAPS = {
    "cap_setuid": "cambiar el UID a 0",
    "cap_setgid": "cambiar el GID",
    "cap_dac_override": "saltarse los permisos de archivos",
    "cap_dac_read_search": "leer cualquier archivo",
    "cap_sys_admin": "casi equivale a root",
    "cap_sys_ptrace": "inyectar código en procesos",
    "cap_sys_module": "cargar módulos del kernel",
    "cap_chown": "cambiar el dueño de cualquier archivo",
    "cap_fowner": "saltarse chequeos de dueño",
    "cap_setfcap": "otorgar capabilities a otros binarios",
}


def reference(name: str) -> str:
    return GTFOBINS_URL % name
