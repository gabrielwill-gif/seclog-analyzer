"""Regras de detecção. Cada regra recebe eventos e devolve alertas."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Dict, Iterable, List
from urllib.parse import unquote_plus

from seclog.models import SEVERITY_ORDER, Alert, Event


@dataclass
class Thresholds:
    ssh_failures: int = 5
    ssh_window_minutes: int = 10
    ssh_distinct_users: int = 4
    http_404: int = 15
    http_window_minutes: int = 5


WEB_SIGNATURES = {
    "SQL Injection": (
        re.compile(
            r"(union(\s|\+|/\*.*?\*/)+select|or\s+1\s*=\s*1|'\s*or\s*'"
            r"|sleep\(\d+\)|information_schema|--\s|;\s*drop\s)",
            re.I,
        ),
        "HIGH",
    ),
    "XSS": (re.compile(r"<script|javascript:|onerror\s*=|onload\s*=", re.I), "MEDIUM"),
    "Path Traversal": (
        re.compile(r"\.\./|\.\.\\|/etc/passwd|boot\.ini", re.I),
        "HIGH",
    ),
    "Command Injection": (
        re.compile(r"(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b", re.I),
        "HIGH",
    ),
}

SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|hydra|dirbuster|gobuster|wfuzz|zgrab)", re.I
)


def _group(events: Iterable[Event], kinds) -> Dict[str, List[Event]]:
    groups: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        if e.kind in kinds:
            groups[e.ip].append(e)
    return groups


def _peak(times, window: timedelta) -> int:
    """Maior número de eventos dentro de uma janela deslizante."""
    times = sorted(times)
    best, j = 0, 0
    for i, t in enumerate(times):
        while t - times[j] > window:
            j += 1
        best = max(best, i - j + 1)
    return best


def detect_ssh_bruteforce(events, th: Thresholds) -> List[Alert]:
    alerts = []
    window = timedelta(minutes=th.ssh_window_minutes)
    for ip, evs in _group(events, ("ssh_failed",)).items():
        times = [e.timestamp for e in evs]
        peak = _peak(times, window)
        if peak >= th.ssh_failures:
            alerts.append(
                Alert(
                    "ssh_bruteforce", "HIGH", ip,
                    f"{peak} falhas de login SSH em {th.ssh_window_minutes} min "
                    f"({len(evs)} no total)",
                    len(evs), "T1110", min(times), max(times),
                )
            )
    return alerts


def detect_ssh_user_enumeration(events, th: Thresholds) -> List[Alert]:
    alerts = []
    for ip, evs in _group(events, ("ssh_failed",)).items():
        users = {e.user for e in evs}
        if len(users) >= th.ssh_distinct_users:
            times = [e.timestamp for e in evs]
            alerts.append(
                Alert(
                    "ssh_user_enumeration", "MEDIUM", ip,
                    f"Tentativas com {len(users)} usuários diferentes "
                    f"(ex.: {', '.join(sorted(users)[:4])})",
                    len(evs), "T1087", min(times), max(times),
                )
            )
    return alerts


def detect_ssh_success_after_failures(events, th: Thresholds) -> List[Alert]:
    alerts = []
    fails = _group(events, ("ssh_failed",))
    for s in (e for e in events if e.kind == "ssh_success"):
        prior = [f for f in fails.get(s.ip, []) if f.timestamp < s.timestamp]
        if len(prior) >= th.ssh_failures:
            alerts.append(
                Alert(
                    "ssh_success_after_failures", "CRITICAL", s.ip,
                    f"Login bem-sucedido como '{s.user}' após {len(prior)} falhas: "
                    "possível conta comprometida",
                    len(prior) + 1, "T1078",
                    min(f.timestamp for f in prior), s.timestamp,
                )
            )
    return alerts


def detect_web_attacks(events, th: Thresholds) -> List[Alert]:
    alerts = []
    for ip, evs in _group(events, ("http",)).items():
        for name, (pattern, severity) in WEB_SIGNATURES.items():
            hits = []
            for e in evs:
                decoded = unquote_plus(unquote_plus(e.path or ""))
                if pattern.search(decoded):
                    hits.append(e)
            if hits:
                times = [h.timestamp for h in hits]
                sample = (hits[0].path or "")[:80]
                alerts.append(
                    Alert(
                        f"web_{name.lower().replace(' ', '_')}", severity, ip,
                        f"{name}: {len(hits)} requisição(ões). Exemplo: {sample}",
                        len(hits), "T1190", min(times), max(times),
                    )
                )
    return alerts


def detect_scanner_user_agent(events, th: Thresholds) -> List[Alert]:
    alerts = []
    for ip, evs in _group(events, ("http",)).items():
        tools, hits = set(), []
        for e in evs:
            m = SCANNER_UA.search(e.user_agent or "")
            if m:
                tools.add(m.group(1).lower())
                hits.append(e)
        if hits:
            times = [h.timestamp for h in hits]
            alerts.append(
                Alert(
                    "scanner_user_agent", "MEDIUM", ip,
                    f"Ferramenta de ataque identificada: {', '.join(sorted(tools))}",
                    len(hits), "T1595", min(times), max(times),
                )
            )
    return alerts


def detect_directory_scan(events, th: Thresholds) -> List[Alert]:
    alerts = []
    window = timedelta(minutes=th.http_window_minutes)
    for ip, evs in _group(events, ("http",)).items():
        nf = [e.timestamp for e in evs if e.status == 404]
        peak = _peak(nf, window)
        if peak >= th.http_404:
            alerts.append(
                Alert(
                    "directory_scan", "MEDIUM", ip,
                    f"{peak} respostas 404 em {th.http_window_minutes} min: "
                    "varredura de diretórios",
                    len(nf), "T1595.003", min(nf), max(nf),
                )
            )
    return alerts


RULES = [
    detect_ssh_bruteforce,
    detect_ssh_user_enumeration,
    detect_ssh_success_after_failures,
    detect_web_attacks,
    detect_scanner_user_agent,
    detect_directory_scan,
]


def analyze(events: List[Event], th: Thresholds = None) -> List[Alert]:
    th = th or Thresholds()
    alerts: List[Alert] = []
    for rule in RULES:
        alerts.extend(rule(events, th))
    alerts.sort(key=lambda a: (-SEVERITY_ORDER[a.severity], -a.count))
    return alerts
