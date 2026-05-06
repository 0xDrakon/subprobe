import csv
import json
import sys
import threading
import time
from typing import Optional

from colorama import Fore, Style

from ..banner import (
    FOUND_TAG, HTTP_TAG, INFO_TAG, DONE_TAG, WARN_TAG, ERROR_TAG,
    status_color, dim, sep, RESET,
)
from ..core.scanner import ScanResult, ScanStats

_print_lock = threading.Lock()
_current_progress = ""
_scan_start: float = 0.0


def set_scan_start(t: float) -> None:
    global _scan_start
    _scan_start = t


def _erase() -> None:
    sys.stderr.write("\033[2K\r")
    sys.stderr.flush()

def print_result(result: ScanResult, verbose: bool = False) -> None:
    with _print_lock:
        _erase()

        if verbose:
            _print_verbose(result)
        else:
            _print_compact(result)

        sys.stdout.flush()


def _print_compact(r: ScanResult) -> None:
    ips = r.ips
    if len(ips) > 3:
        ip_str = f"{', '.join(ips[:3])}  {Fore.WHITE}+{len(ips) - 3} more{RESET}"
    else:
        ip_str = ", ".join(ips)

    line = f"{FOUND_TAG} {Fore.GREEN}{r.subdomain}{RESET}  {Fore.CYAN}{ip_str}{RESET}"
    if r.cname:
        line += f"  {Fore.YELLOW}↳ {dim(r.cname)}{RESET}"

    print(line)

    if r.http_status is not None or r.https_status is not None:
        parts = []
        if r.http_status:
            col = status_color(r.http_status)
            parts.append(f"http:{col}{r.http_status}{RESET}")
        if r.https_status:
            col = status_color(r.https_status)
            parts.append(f"https:{col}{r.https_status}{RESET}")
        title_str = f'  {Fore.WHITE}"{r.title[:60]}"{RESET}' if r.title else ""
        print(f"    {Fore.WHITE}└─{RESET} {'  '.join(parts)}{title_str}")


def _print_verbose(r: ScanResult) -> None:
    print(f"{FOUND_TAG} {Fore.GREEN}{r.subdomain}{RESET}")

    all_ips = r.ips + ([f"{Fore.CYAN}[IPv6]{RESET} " + ip for ip in r.ipv6] if r.ipv6 else [])
    print(f"    {Fore.WHITE}├─ IPv4    {RESET}  {Fore.CYAN}{', '.join(r.ips)}{RESET}")

    if r.ipv6:
        print(f"    {Fore.WHITE}├─ IPv6    {RESET}  {Fore.CYAN}{', '.join(r.ipv6)}{RESET}")

    if r.cname:
        print(f"    {Fore.WHITE}├─ CNAME   {RESET}  {Fore.YELLOW}{r.cname}{RESET}")

    ttl_str = f"{r.ttl}s" if r.ttl is not None else "—"
    print(
        f"    {Fore.WHITE}├─ TTL     {RESET}  {Fore.WHITE}{ttl_str}{RESET}"
        f"    {dim(f'DNS: {r.dns_ms:.0f}ms')}"
    )

    if r.http_status is not None or r.https_status is not None:
        def _http_line(proto: str, code: Optional[int], ms: float, size: int) -> None:
            if code is None:
                return
            col = status_color(code)
            size_str = _human_size(size)
            print(
                f"    {Fore.WHITE}├─ {proto:<7}{RESET}"
                f"  {col}{code}{RESET}"
                f"  {dim(f'{ms:.0f}ms')}"
                f"  {dim(size_str)}"
            )
        _http_line("HTTP", r.http_status, r.http_ms, r.http_size)
        _http_line("HTTPS", r.https_status, r.https_ms, r.https_size)

    if r.title:
        print(f"    {Fore.WHITE}└─ Title   {RESET}  {Fore.WHITE}\"{r.title}\"{RESET}")
    else:
        pass


def _human_size(n: int) -> str:
    if n == 0:
        return "0 B"
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n //= 1024
    return f"{n:.0f} GB"

def update_progress(scanned: int, total: int, found: int) -> None:
    global _current_progress

    pct = (scanned / total * 100) if total else 0
    bar_len = 28
    filled = int(bar_len * scanned / total) if total else 0

    bar = f"{Fore.GREEN}{'█' * filled}{Fore.WHITE}{'░' * (bar_len - filled)}{RESET}"

    eta_str = ""
    if _scan_start and scanned > 0 and scanned < total:
        elapsed = time.perf_counter() - _scan_start
        rate = scanned / elapsed
        remaining = (total - scanned) / rate if rate > 0 else 0
        eta_str = f"  {Fore.WHITE}ETA {remaining:.0f}s{RESET}"

    progress = (
        f"\r {Fore.CYAN}▸{RESET} [{bar}] "
        f"{Fore.YELLOW}{pct:5.1f}%{RESET} "
        f"{Fore.WHITE}{scanned}/{total}{RESET}  "
        f"{FOUND_TAG} {Fore.GREEN}{found}{RESET}"
        f"{eta_str}"
    )
    _current_progress = progress
    sys.stderr.write(progress)
    sys.stderr.flush()

def print_scan_header(
    domain: str,
    wordlist_path: str,
    wordlist_count: int,
    concurrency: int,
    probe_http: bool,
    probe_aaaa: bool,
    output_file: Optional[str],
    json_file: Optional[str],
    csv_file: Optional[str],
    nameservers: list[str],
    dns_timeout: float,
    dns_retries: int,
    wildcard_detected: bool,
    wildcard_filtering: bool,
    filter_status: Optional[set[int]],
    match_status: Optional[set[int]],
    match_ip: Optional[str],
    follow_redirects: bool,
    verbose: bool,
) -> None:
    width = 60

    print(sep(width=width))

    def row(label: str, value: str) -> None:
        print(f"  {Fore.CYAN}{label:<16}{RESET}  {value}")

    row("Target",       f"{Fore.WHITE}{domain}{RESET}")
    row("Wordlist",     f"{Fore.WHITE}{wordlist_path}{RESET}  {Fore.YELLOW}({wordlist_count} entries){RESET}")
    row("Concurrency",  f"{Fore.YELLOW}{concurrency}{RESET}")
    row("DNS Timeout",  f"{Fore.WHITE}{dns_timeout}s{RESET}  {dim(f'retries: {dns_retries}')}")
    row("Resolvers",    f"{Fore.WHITE}{', '.join(nameservers[:3])}{'  ...' if len(nameservers) > 3 else ''}{RESET}")

    if wildcard_filtering:
        wc = (
            f"{Fore.YELLOW}detected + filtering{RESET}"
            if wildcard_detected
            else f"{Fore.GREEN}not detected{RESET}"
        )
        row("Wildcard DNS",  wc)

    row("HTTP Probe",   f"{Fore.GREEN}enabled{RESET}" if probe_http else f"{Fore.RED}disabled{RESET}")
    if probe_http:
        row("Redirects",    f"{Fore.GREEN}follow{RESET}" if follow_redirects else f"{Fore.RED}no-follow{RESET}")
    if probe_aaaa:
        row("IPv6 (AAAA)",  f"{Fore.GREEN}enabled{RESET}")
    if filter_status:
        row("Filter codes", f"{Fore.RED}{', '.join(str(c) for c in sorted(filter_status))}{RESET}")
    if match_status:
        row("Match codes",  f"{Fore.GREEN}{', '.join(str(c) for c in sorted(match_status))}{RESET}")
    if match_ip:
        row("Match IP",     f"{Fore.CYAN}{match_ip}{RESET}")
    if verbose:
        row("Verbose",      f"{Fore.GREEN}on{RESET}")
    if output_file:
        row("Output (txt)", f"{Fore.CYAN}{output_file}{RESET}")
    if json_file:
        row("Output (json)",f"{Fore.CYAN}{json_file}{RESET}")
    if csv_file:
        row("Output (csv)", f"{Fore.CYAN}{csv_file}{RESET}")

    print(sep(width=width))
    print()


def print_summary(
    stats: ScanStats,
    results: list[ScanResult],
    output_file: Optional[str],
    json_file: Optional[str],
    csv_file: Optional[str],
) -> None:
    _erase()
    width = 60
    print()
    print(sep(width=width))

    rate = stats.total / stats.elapsed if stats.elapsed else 0

    def row(label: str, value: str) -> None:
        print(f"  {Fore.CYAN}{label:<16}{RESET}  {value}")

    row("Status",    f"{Fore.GREEN}scan complete{RESET}")
    row("Scanned",   f"{Fore.WHITE}{stats.total:,}{RESET}")
    row("Found",     f"{Fore.GREEN}{stats.found:,}{RESET}")
    if stats.wildcard_filtered:
        row("WC Filtered", f"{Fore.YELLOW}{stats.wildcard_filtered:,}{RESET}")
    row("Elapsed",   f"{Fore.YELLOW}{stats.elapsed:.2f}s{RESET}  {dim(f'({rate:.0f} req/s)')}")

    if output_file and results:
        write_txt(results, output_file)
        row("Saved (txt)", f"{Fore.CYAN}{output_file}{RESET}")
    if json_file and results:
        write_json(results, json_file)
        row("Saved (json)", f"{Fore.CYAN}{json_file}{RESET}")
    if csv_file and results:
        write_csv(results, csv_file)
        row("Saved (csv)", f"{Fore.CYAN}{csv_file}{RESET}")

    print(sep(width=width))
    print()

def write_txt(results: list[ScanResult], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in results:
            parts = [r.subdomain, ", ".join(r.ips)]
            if r.ipv6:
                parts.append("ipv6:" + ", ".join(r.ipv6))
            if r.cname:
                parts.append(f"cname:{r.cname}")
            if r.ttl is not None:
                parts.append(f"ttl:{r.ttl}")
            if r.http_status:
                parts.append(f"http:{r.http_status}")
            if r.https_status:
                parts.append(f"https:{r.https_status}")
            if r.title:
                parts.append(f"title:{r.title}")
            f.write("\t".join(parts) + "\n")


def write_json(results: list[ScanResult], path: str) -> None:
    data = []
    for r in results:
        data.append({
            "subdomain":    r.subdomain,
            "ips":          r.ips,
            "ipv6":         r.ipv6,
            "cname":        r.cname,
            "ttl":          r.ttl,
            "dns_ms":       round(r.dns_ms, 1),
            "http_status":  r.http_status,
            "https_status": r.https_status,
            "title":        r.title,
            "http_ms":      round(r.http_ms, 1),
            "https_ms":     round(r.https_ms, 1),
            "http_size":    r.http_size,
            "https_size":   r.https_size,
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def write_csv(results: list[ScanResult], path: str) -> None:
    fields = [
        "subdomain", "ips", "ipv6", "cname", "ttl", "dns_ms",
        "http_status", "https_status", "title",
        "http_ms", "https_ms", "http_size", "https_size",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            w.writerow({
                "subdomain":    r.subdomain,
                "ips":          "; ".join(r.ips),
                "ipv6":         "; ".join(r.ipv6),
                "cname":        r.cname or "",
                "ttl":          r.ttl if r.ttl is not None else "",
                "dns_ms":       round(r.dns_ms, 1),
                "http_status":  r.http_status or "",
                "https_status": r.https_status or "",
                "title":        r.title or "",
                "http_ms":      round(r.http_ms, 1),
                "https_ms":     round(r.https_ms, 1),
                "http_size":    r.http_size,
                "https_size":   r.https_size,
            })

def print_info(msg: str) -> None:
    print(f"{INFO_TAG} {msg}")


def print_warn(msg: str) -> None:
    print(f"{WARN_TAG} {Fore.YELLOW}{msg}{RESET}")


def print_error(msg: str) -> None:
    print(f"{ERROR_TAG} {Fore.RED}{msg}{RESET}")
