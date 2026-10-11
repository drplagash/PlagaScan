# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Acceso al sistema auditado.

Todos los checks hablan con el sistema a través de `Context`. Así los tests
pueden reemplazarlo por un contexto falso sin tocar la máquina real.
La herramienta es de solo lectura: nunca modifica nada del sistema.
"""
import glob as _glob
import os
import subprocess
from typing import Dict, List, Optional, Tuple


class Context:
    def __init__(self, online: bool = False):
        self.online = online
        self.is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        self.skipped: List[Tuple[str, str]] = []
        # Datos compartidos entre checks (listeners, binarios SUID, ...).
        self.shared: Dict[str, object] = {}

    # --- ejecución de comandos -------------------------------------------
    def run(self, argv: List[str], timeout: int = 30) -> Optional[str]:
        """Devuelve stdout del comando, o None si no existe / expira.

        El código de retorno se ignora a propósito: muchos comandos de
        auditoría (dnf check-update, grep) usan rc != 0 con significado.
        """
        # Muchas herramientas (getcap, sshd, nft, ufw) viven en */sbin, que un
        # usuario normal no tiene en el PATH.
        env = dict(os.environ)
        env["PATH"] = env.get("PATH", "") + ":/usr/local/sbin:/usr/sbin:/sbin"
        env["LC_ALL"] = "C"
        try:
            p = subprocess.run(
                argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=timeout, universal_newlines=True, errors="replace", env=env,
            )
            return p.stdout
        except (OSError, subprocess.TimeoutExpired):
            return None

    # --- archivos ----------------------------------------------------------
    def read(self, path: str) -> Optional[str]:
        try:
            with open(path, "r", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def stat(self, path: str) -> Optional[Tuple[int, int, int]]:
        """(modo, uid, gid) o None."""
        try:
            st = os.stat(path)
            return (st.st_mode & 0o7777, st.st_uid, st.st_gid)
        except OSError:
            return None

    def glob(self, pattern: str) -> List[str]:
        return sorted(_glob.glob(pattern))

    def getenv(self, name: str) -> Optional[str]:
        return os.environ.get(name)

    # --- registro de omisiones --------------------------------------------
    def skip(self, check: str, reason: str) -> None:
        self.skipped.append((check, reason))
