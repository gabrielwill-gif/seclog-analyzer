"""Geração de relatórios em texto, JSON e HTML."""
from __future__ import annotations

import html
import json
from collections import Counter
from typing import List

from seclog.models import Alert


def summary(alerts: List[Alert], lines: int, events: int) -> dict:
    return {
        "lines_read": lines,
        "events_parsed": events,
        "alerts": len(alerts),
        "by_severity": dict(Counter(a.severity for a in alerts)),
        "unique_ips": len({a.ip for a in alerts}),
    }


def to_text(alerts: List[Alert], info: dict) -> str:
    out = ["=== SecLog Analyzer: Relatório ===",
           f"Linhas lidas: {info['lines_read']} | Eventos: {info['events_parsed']} | "
           f"Alertas: {info['alerts']} | IPs suspeitos: {info['unique_ips']}", ""]
    if not alerts:
        out.append("Nenhuma ameaça detectada.")
    for a in alerts:
        out.append(f"[{a.severity:<8}] {a.ip:<15} {a.description} ({a.mitre})")
    return "\n".join(out)


def to_json(alerts: List[Alert], info: dict) -> str:
    return json.dumps(
        {"summary": info, "alerts": [a.to_dict() for a in alerts]},
        indent=2, ensure_ascii=False,
    )


def to_html(alerts: List[Alert], info: dict) -> str:
    colors = {"CRITICAL": "#ff4d4f", "HIGH": "#fa8c16", "MEDIUM": "#fadb14", "LOW": "#8c8c8c"}
    rows = "".join(
        f"<tr><td style='color:{colors[a.severity]};font-weight:bold'>{a.severity}</td>"
        f"<td>{html.escape(a.ip)}</td><td>{html.escape(a.description)}</td>"
        f"<td>{html.escape(a.mitre)}</td><td>{a.count}</td>"
        f"<td>{a.first_seen:%Y-%m-%d %H:%M:%S}</td></tr>"
        for a in alerts
    )
    return f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8"><title>SecLog Analyzer</title>
<style>
body{{background:#0d1117;color:#c9d1d9;font-family:system-ui,sans-serif;margin:2rem}}
table{{border-collapse:collapse;width:100%}}
th,td{{border-bottom:1px solid #30363d;padding:.5rem;text-align:left}}
th{{color:#8b949e}}
</style></head><body>
<h1>SecLog Analyzer</h1>
<p>Linhas: {info['lines_read']} | Eventos: {info['events_parsed']} |
Alertas: {info['alerts']} | IPs suspeitos: {info['unique_ips']}</p>
<table><tr><th>Severidade</th><th>IP</th><th>Descrição</th><th>MITRE</th>
<th>Qtd</th><th>Primeiro evento</th></tr>{rows}</table>
</body></html>"""
