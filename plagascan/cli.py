# Copyright (c) 2026 DrPlaga. Licencia MIT (ver LICENSE).
"""Interfaz de línea de comandos."""
import argparse
import sys
from typing import List, Optional

from . import __version__
from .checks import REGISTRY, categories, load_all
from .context import Context
from .models import Finding, Severity
from .report import render_json, render_markdown, render_text


def run_checks(ctx: Context, only: Optional[List[str]] = None,
               skip: Optional[List[str]] = None) -> List[Finding]:
    load_all()
    findings: List[Finding] = []
    for category, _desc, fn in REGISTRY:
        if only and category not in only:
            continue
        if skip and category in skip:
            continue
        try:
            findings.extend(fn(ctx))
        except Exception as exc:  # un check roto no debe tumbar el resto
            ctx.skip(category, "error interno: %s" % exc)
    return findings


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="plagascan",
        description="Auditor de hardening para Linux (solo lectura): SSH, cuentas, permisos, "
                    "puertos, SUID/sudo/capabilities (GTFOBins), kernel y CVEs.")
    p.add_argument("--online", action="store_true",
                   help="consulta OSV.dev por CVEs de los servicios expuestos (envía nombres de paquetes)")
    p.add_argument("-f", "--format", choices=("text", "json", "md"), default="text")
    p.add_argument("-o", "--output", help="escribir el reporte en un archivo")
    p.add_argument("--min-severity", default="info",
                   help="mostrar solo desde esta severidad (info, low, medium, high, critical)")
    p.add_argument("--fail-on", default=None,
                   help="salir con código 1 si hay hallazgos de esta severidad o mayor (para CI)")
    p.add_argument("--only", action="append", metavar="CATEGORIA", help="ejecutar solo estas categorías")
    p.add_argument("--skip", action="append", metavar="CATEGORIA", help="omitir estas categorías")
    p.add_argument("--list-checks", action="store_true", help="listar categorías y salir")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--force", action="store_true", help="ejecutar aunque el SO no sea Linux")
    p.add_argument("--version", action="version", version="plagascan " + __version__)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    load_all()
    if args.list_checks:
        for cat, desc in categories().items():
            print("%-12s %s" % (cat, desc))
        return 0
    if not sys.platform.startswith("linux") and not args.force:
        print("plagascan audita sistemas Linux (SO actual: %s). Usá --force para probar igual." %
              sys.platform, file=sys.stderr)
        return 2
    try:
        floor = Severity.parse(args.min_severity)
        fail_on = Severity.parse(args.fail_on) if args.fail_on else None
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2

    ctx = Context(online=args.online)
    findings = run_checks(ctx, args.only, args.skip)
    shown = [f for f in findings if f.severity >= floor]

    # El puntaje usa TODOS los hallazgos; --min-severity solo filtra lo que se muestra.
    if args.format == "json":
        text = render_json(shown, ctx.skipped, findings)
    elif args.format == "md":
        text = render_markdown(shown, ctx.skipped, findings)
    else:
        color = sys.stdout.isatty() and not args.no_color and not args.output
        text = render_text(shown, ctx.skipped, color, findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print("Reporte escrito en %s" % args.output)
    else:
        print(text)

    if fail_on is not None and any(f.severity >= fail_on for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
