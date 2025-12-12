#!/usr/bin/env python3
"""
Scanner de teste para identificar eventos de alto volume em TLDs específicos
(ex.: .builders, .sbs) nos logs do SPFBL.

Uso sugerido:
  python3 tld_spam_scan.py --tlds builders,sbs /var/log/spfbl/spfbl.2025-11-24.log /var/log/spfbl/spfbl.2025-11-25.log

O script não tem dados hardcoded: os TLDs e os arquivos de log são informados
por argumento. Ele lê linhas do SPFBL no formato:
  2025-11-24T15:00:02.294-0300 ... : SPF 'ip' 'mailfrom' 'helo' 'rcpt' => STATUS
e consolida contagens para cada TLD detectado em mailfrom ou HELO.
"""
import argparse
import datetime as dt
import gzip
import os
import re
import sys
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Optional, Set, Tuple

# Exemplo de linha alvo:
# 2025-11-24T15:00:02.294-0300 00004 SPFTCP001 SPFBL #id 177.11.54.162 helo mailfrom: SPF 'IP' 'MAILFROM' 'HELO' 'RCPT' => STATUS
LOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)\s+"
    r".*?: SPF '(?P<ip>[^']*)' '(?P<mailfrom>[^']*)' '(?P<helo>[^']*)' '(?P<rcpt>[^']*)' => (?P<status>[A-Z]+)"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detectar picos de mensagens por TLD em logs do SPFBL.")
    parser.add_argument(
        "--tlds",
        action="append",
        required=True,
        help="Lista de TLDs sem ponto (ex.: --tlds builders,sbs ou --tlds builders --tlds sbs).",
    )
    parser.add_argument(
        "--since",
        help="Data/hora inicial (ISO 8601, ex.: 2025-11-24T15:00). Opcional.",
    )
    parser.add_argument(
        "--until",
        help="Data/hora final (ISO 8601, ex.: 2025-11-24T18:00). Opcional.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Qtd de itens nos rankings (IP, RCPT, HELO, MAILFROM).",
    )
    parser.add_argument(
        "--burst-threshold",
        type=int,
        default=10,
        help="Mínimo de eventos por minuto para sinalizar pico por RCPT.",
    )
    parser.add_argument(
        "logs",
        nargs="+",
        help="Arquivos de log do SPFBL (.log ou .gz).",
    )
    return parser.parse_args()


def parse_timestamp(ts: str) -> Optional[dt.datetime]:
    """Retorna datetime a partir do timestamp do log, com ou sem offset."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = dt.datetime.strptime(ts, fmt)
            # Converte para naive se tiver tzinfo, para comparação consistente
            if parsed.tzinfo:
                parsed = parsed.replace(tzinfo=None)
            return parsed
        except ValueError:
            continue
    return None


def extract_domain(value: str) -> str:
    """Extrai domínio de um email/HELO; devolve em minúsculas."""
    if not value:
        return ""
    value = value.strip().lower()
    if "@" in value:
        return value.split("@", 1)[1]
    return value


def match_tlds(domain: str, tlds: Set[str]) -> Set[str]:
    """Retorna TLDs que casam com o domínio informado."""
    hits = set()
    for tld in tlds:
        if domain.endswith("." + tld) or domain == tld:
            hits.add(tld)
    return hits


def open_log(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return open(path, "r", encoding="utf-8", errors="ignore")


def scan_logs(
    log_paths: Iterable[str],
    tlds: Set[str],
    since: Optional[dt.datetime],
    until: Optional[dt.datetime],
) -> Dict[str, Dict[str, Counter]]:
    per_tld = {
        "events": Counter(),  # total de eventos por TLD
        "ip": defaultdict(Counter),
        "helo": defaultdict(Counter),
        "mailfrom": defaultdict(Counter),
        "rcpt": defaultdict(Counter),
        "status": defaultdict(Counter),
        "rcpt_minute": defaultdict(Counter),  # chave: (tld, rcpt)
    }

    for path in log_paths:
        if not os.path.exists(path):
            print(f"[WARN] Arquivo não encontrado: {path}", file=sys.stderr)
            continue
        with open_log(path) as fh:
            for line in fh:
                m = LOG_RE.match(line)
                if not m:
                    continue
                ts_raw = m.group("ts")
                event_ts = parse_timestamp(ts_raw)
                if since and event_ts and event_ts < since:
                    continue
                if until and event_ts and event_ts > until:
                    continue
                ip = m.group("ip")
                mailfrom = extract_domain(m.group("mailfrom"))
                helo = extract_domain(m.group("helo"))
                rcpt = m.group("rcpt").lower()
                status = m.group("status")

                matched = match_tlds(mailfrom, tlds) | match_tlds(helo, tlds)
                if not matched:
                    continue

                for tld in matched:
                    per_tld["events"][tld] += 1
                    per_tld["ip"][tld][ip] += 1
                    per_tld["helo"][tld][helo] += 1
                    per_tld["mailfrom"][tld][mailfrom] += 1
                    per_tld["rcpt"][tld][rcpt] += 1
                    per_tld["status"][tld][status] += 1
                    if event_ts:
                        minute = event_ts.strftime("%Y-%m-%d %H:%M")
                        per_tld["rcpt_minute"][(tld, rcpt)][minute] += 1
    return per_tld


def print_top(counter: Counter, top: int, label: str):
    if not counter:
        print(f"  [sem dados para {label}]")
        return
    for item, count in counter.most_common(top):
        print(f"  {item:<40} {count:6d}")


def main():
    args = parse_args()
    raw_tlds: List[str] = []
    for chunk in args.tlds:
        raw_tlds.extend(chunk.replace(",", " ").split())
    tlds = {t.strip(".").lower() for t in raw_tlds if t.strip(".")}
    if not tlds:
        print("Nenhum TLD informado.", file=sys.stderr)
        sys.exit(1)

    if args.since:
        since = dt.datetime.fromisoformat(args.since)
        if since.tzinfo:
            since = since.replace(tzinfo=None)
    else:
        since = None

    if args.until:
        until = dt.datetime.fromisoformat(args.until)
        if until.tzinfo:
            until = until.replace(tzinfo=None)
    else:
        until = None

    data = scan_logs(args.logs, tlds, since, until)
    events = data["events"]

    if not events:
        print("Nenhum evento encontrado para os TLDs informados.")
        return

    print("=== Resumo por TLD ===")
    for tld in sorted(events.keys()):
        total = events[tld]
        print(f"\nTLD .{tld}: {total} eventos")
        status_counts = data["status"][tld]
        if status_counts:
            status_str = ", ".join(f"{k}:{v}" for k, v in status_counts.most_common())
            print(f"  Status: {status_str}")

        print("  Top IPs:")
        print_top(data["ip"][tld], args.top, "IPs")
        print("  Top HELOs:")
        print_top(data["helo"][tld], args.top, "HELOs")
        print("  Top MAILFROM domínios:")
        print_top(data["mailfrom"][tld], args.top, "MAILFROM")
        print("  Top destinatários (RCPT):")
        print_top(data["rcpt"][tld], args.top, "RCPT")

        print("  Picos por minuto (>= %d)" % args.burst_threshold)
        spikes_shown = False
        for (tld_key, rcpt), minute_counts in data["rcpt_minute"].items():
            if tld_key != tld:
                continue
            max_minute, max_count = minute_counts.most_common(1)[0]
            if max_count >= args.burst_threshold:
                spikes_shown = True
                print(f"    {rcpt:<40} {max_count:4d} em {max_minute}")
        if not spikes_shown:
            print("    [nenhum pico acima do limiar]")


if __name__ == "__main__":
    main()
