"""Interface de linha de comando."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from seclog import __version__, report
from seclog.detectors import Thresholds, analyze
from seclog.models import SEVERITY_ORDER
from seclog.parsers import parse_line


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="seclog",
        description="Analisa logs SSH (auth.log) e web (Apache/Nginx) e detecta ataques.",
    )
    p.add_argument("files", nargs="+", type=Path, help="arquivos de log")
    p.add_argument("-f", "--format", choices=["text", "json", "html"], default="text")
    p.add_argument("-o", "--output", type=Path, help="salvar relatório em arquivo")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="ano dos logs syslog, que não trazem o ano (padrão: atual)")
    p.add_argument("--ssh-failures", type=int, default=5,
                   help="falhas SSH para considerar força bruta (padrão: 5)")
    p.add_argument("--window", type=int, default=10,
                   help="janela em minutos para força bruta SSH (padrão: 10)")
    p.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"],
                   default="none", help="sair com código 2 se houver alerta nesse nível ou acima")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    events, total_lines = [], 0
    for path in args.files:
        if not path.is_file():
            print(f"Erro: arquivo não encontrado: {path}", file=sys.stderr)
            return 1
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                total_lines += 1
                ev = parse_line(line, args.year)
                if ev:
                    events.append(ev)

    th = Thresholds(ssh_failures=args.ssh_failures, ssh_window_minutes=args.window)
    alerts = analyze(events, th)
    info = report.summary(alerts, total_lines, len(events))

    renderer = {"text": report.to_text, "json": report.to_json, "html": report.to_html}
    output = renderer[args.format](alerts, info)

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"Relatório salvo em {args.output}")
    else:
        print(output)

    if args.fail_on != "none":
        limit = SEVERITY_ORDER[args.fail_on.upper()]
        if any(SEVERITY_ORDER[a.severity] >= limit for a in alerts):
            return 2
    return 0
