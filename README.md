# PlagaScan
![PlagaScan - portada](docs/cover.jpg)

Auditor de hardening para Linux, **de solo lectura y sin dependencias** (Python 3.8+ y la librería estándar).
Revisa en segundos lo que suele abrir la puerta a un atacante local o remoto y te dice cómo arreglarlo.

```
$ sudo plagascan --min-severity medium
Puntaje: 62/100  Nota: C
CRITICAL=0  HIGH=3  MEDIUM=2  LOW=0  INFO=0

[HIGH    ] Binario SUID en una ubicación inusual [PRIV-001]
      - 4755 root /tmp/hatest/find
    Arreglo: Verificar el origen del archivo y quitar el bit: chmod u-s /tmp/hatest/find

[HIGH    ] Capabilities peligrosas en python3 [PRIV-003]
    /tmp/hatest/python3 tiene cap_setuid (cap_setuid: cambiar el UID a 0).
    Ref: https://gtfobins.github.io/gtfobins/python3/

[HIGH    ] sudo sin contraseña para cualquier comando (%kali-trusted) [PRIV-004]
```

## Qué revisa

| Categoría | Qué busca |
|---|---|
| `ssh` | `PermitRootLogin`, contraseñas vacías o habilitadas, `MaxAuthTries`, cifrados débiles. Respeta `Include` y `Match` como sshd. |
| `accounts` | UID 0 extra, contraseñas vacías / MD5, hashes en `/etc/passwd`, cuentas de servicio con shell, miembros de `docker`/`lxd`/`disk` (equivalentes a root). |
| `filesystem` | Permisos de `/etc/shadow`, `sudoers`, claves de host; `PATH` con `.` o directorios escribibles; archivos de `/etc` y unidades systemd escribibles por todos; `/tmp` sin `noexec`. |
| `network` | Puertos en escucha fuera de loopback, servicios riesgosos expuestos (Redis, Docker API, Telnet, MongoDB...), ausencia de firewall (ufw/nftables/iptables). |
| `privesc` | **SUID/SGID, capabilities y reglas de sudo cruzadas con una base de binarios abusables estilo [GTFOBins](https://gtfobins.github.io/)**; SUID en `/tmp` o `/home`; socket de Docker accesible. |
| `kernel` | ASLR, `kptr_restrict`, `ptrace_scope`, `protected_symlinks`, redirects ICMP, SYN cookies, etc. |
| `knownvulns` | Detección por versión de sudo (Baron Samedit, CVE-2025-32463), polkit (PwnKit), kernel (Dirty Pipe, Dirty COW). Sin red. |
| `packages` | Actualizaciones de seguridad pendientes (apt/dnf), reinicio requerido. Con `--online`: CVEs de los servicios expuestos y binarios SUID consultando [OSV.dev](https://osv.dev). |

## Uso

```bash
git clone https://github.com/drplagash/PlagaScan && cd PlagaScan
sudo python3 -m plagascan --all           # TODO en un comando (recomendado)
```

`--all` ejecuta **todos los checks** y además la consulta de CVEs por paquete a [OSV.dev](https://osv.dev) (`--online`).
Sin `--all` corre todos los checks locales y no usa la red. Si ya instalaste el paquete, el comando es `sudo plagascan --all`.

Otras formas de ejecutarlo:

```bash
sudo python3 -m plagascan                 # solo checks locales, sin red
python3 -m plagascan -f json -o out.json  # JSON para otras herramientas
python3 -m plagascan -f md -o reporte.md  # Markdown para documentar
sudo python3 -m plagascan --fail-on high  # exit 1 si hay HIGH o peor (CI)
python3 -m plagascan --only privesc --only ssh   # solo algunas categorías
python3 -m plagascan --list-checks
```

`--help` agrupa las opciones por tema (qué revisar, salida, CI).

Sin root funciona, pero omite lo que necesita permisos (`/etc/shadow`, `sudoers`, firewall, procesos de otros
usuarios) y **lo dice** en la sección "Checks omitidos" en lugar de fingir que está todo bien.

Instalación opcional como comando: `pip install .` (instala el comando `plagascan`).

## Puntaje

Cada equipo arranca con **100 puntos** y **cada hallazgo resta puntos según su gravedad**:

| Gravedad | Qué significa | Ejemplos | Resta |
|---|---|---|---|
| CRITICAL | Se puede explotar ya, sin esfuerzo | cuentas sin contraseña, socket de Docker abierto a todos | **−20** |
| HIGH | Camino claro a root o exposición seria | binario SUID abusable, `sudo NOPASSWD: ALL`, login de root por SSH | **−10** |
| MEDIUM | Debilita la seguridad; hace falta otra condición para explotarlo | SSH con contraseñas, sin firewall, actualizaciones de seguridad pendientes | **−4** |
| LOW | Buena práctica que falta | `/tmp` sin `noexec`, `kptr_restrict` en 0 | **−1** |
| INFO | Dato informativo | lista de puertos abiertos | 0 |

Se resta **por hallazgo, no por tipo**: tres binarios SUID abusables son tres hallazgos HIGH (−30).
El resultado (mínimo 0) se traduce en una nota:

| Puntaje | 90–100 | 75–89 | 60–74 | 40–59 | 0–39 |
|---|---|---|---|---|---|
| **Nota** | A | B | C | D | F |

### El peor hallazgo pone un techo

Restar puntos no alcanza: sin otra regla, un equipo con un solo hallazgo gravísimo sacaría buena nota por tener
todo lo demás en orden. Por eso **el peor hallazgo limita el puntaje máximo**:

| Si hay al menos un... | El puntaje no puede pasar de | Nota máxima |
|---|---|---|
| **CRITICAL** | 39 | **F** |
| **HIGH** | 74 | **C** |

El techo solo actúa cuando el puntaje por resta lo supera; si ya era más bajo, queda como estaba.
Cuando se aplica, el reporte lo dice: `Puntaje: 39/100  Nota: F  (limitado por hallazgos CRITICAL; por resta serían 80)`.

| Caso | Por resta | Puntaje final | Nota |
|---|---|---|---|
| Sin hallazgos | 100 | 100 | A |
| 20 LOW | 80 | 80 | B |
| 5 MEDIUM + 5 LOW | 75 | 75 | B |
| 1 HIGH | 90 | **74** (techo HIGH) | C |
| 4 HIGH | 60 | 60 (ya era menor al techo) | C |
| 1 CRITICAL | 80 | **39** (techo CRITICAL) | F |
| 1 CRITICAL + 1 HIGH | 70 | **39** (techo CRITICAL) | F |

Cómo leerlo:
- Sirve para **comparar el mismo equipo antes y después** de arreglar cosas: cada CRITICAL o HIGH que corrijas suma.
- **No sirve para comparar equipos distintos** ni es una certificación.
- El puntaje se calcula siempre con **todos** los hallazgos, aunque filtres la salida con `--min-severity`.
- Con `-f json` el resumen incluye `score_before_cap` y `capped_by` para usarlo desde otras herramientas.

## Límites (leelos antes de confiar en el reporte)

- **Solo lectura.** No modifica nada del sistema. Los arreglos se muestran, no se aplican.
- **Detección por versión = heurística.** Las distribuciones portan parches sin cambiar la versión upstream
  (un `sudo 1.8.31` de Ubuntu puede estar parcheado). Esos hallazgos dicen "posible" y hay que confirmarlos.
- **`--online` envía a api.osv.dev los nombres y versiones** de los paquetes de servicios expuestos y SUID. Nada más.
  Hoy solo cubre Debian y Ubuntu; OSV incluye avisos que Debian decidió no parchear (baja prioridad), así que "tiene CVEs"
  no siempre significa "es explotable".
- **SUID/SGID**: busca con `find -xdev`, o sea solo en el sistema de archivos raíz; no entra a otros montajes.
- La base de binarios abusables es una lista curada y propia. No reemplaza a GTFOBins: cada hallazgo enlaza a la ficha completa.
- No es un escáner de vulnerabilidades de red ni reemplaza a Lynis, OpenSCAP o CIS-CAT. Es una revisión rápida y legible.

## Desarrollo

```bash
python3 -m pytest        # los tests usan un contexto falso: no tocan tu sistema
```

Cada check es una función `fn(ctx) -> [Finding]` registrada con `@register(...)` en `plagascan/checks/`.
Todo acceso al sistema pasa por `Context`, que los tests reemplazan por un doble en memoria.

## Uso responsable

Ejecutalo solo en sistemas propios o con autorización. La herramienta no explota nada, pero el reporte
describe cómo escalar privilegios en la máquina auditada: tratalo como información sensible.

## Licencia

MIT

## Autor

DrPlaga
