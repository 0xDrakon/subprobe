import argparse
import asyncio
import os
import re
import sys
import time
from typing import Optional

import colorama
from colorama import Fore

from .banner import BANNER, RESET, sep
from .core.resolver import build_resolver, detect_wildcard
from .core.scanner import run_scan, ScanResult, DEFAULT_UA
from .utils.output import (
    print_result,
    update_progress,
    print_summary,
    print_scan_header,
    print_warn,
    print_error,
    set_scan_start,
    save_outputs,
)

DEFAULT_WORDLIST = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "wordlists", "default.txt"
)

DEFAULT_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _wl_count() -> str:
    try:
        with open(DEFAULT_WORDLIST) as f:
            return str(sum(1 for ln in f if ln.strip() and not ln.startswith("#")))
    except Exception:
        return "?"


class _BannerHelp(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        print(BANNER)
        print(parser.format_help())
        parser.exit()


def _build_parser() -> argparse.ArgumentParser:
    count = _wl_count()

    desc = (
        f"  {Fore.CYAN}Examples:{RESET}\n"
        f"    python3 main.py {Fore.YELLOW}-d{RESET} example.com\n"
        f"    python3 main.py {Fore.YELLOW}-d{RESET} example.com {Fore.YELLOW}--http -v -o{RESET} results.txt\n"
        f"    python3 main.py {Fore.YELLOW}-d{RESET} example.com {Fore.YELLOW}-w{RESET} wordlist.txt {Fore.YELLOW}-c{RESET} 500 {Fore.YELLOW}--json{RESET} out.json\n"
        f"    python3 main.py {Fore.YELLOW}-d{RESET} example.com {Fore.YELLOW}--http --match-status{RESET} 200,301 {Fore.YELLOW}--aaaa{RESET}\n"
        f"    python3 main.py {Fore.YELLOW}-d{RESET} example.com {Fore.YELLOW}--silent{RESET} | httpx\n"
    )

    parser = argparse.ArgumentParser(
        prog="subprobe",
        description=desc,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )

    grp = parser.add_argument_group(f"{Fore.CYAN}target{RESET}")
    grp.add_argument("-d", "--domain", required=True, metavar="DOMAIN",
                     help="target domain  (e.g. example.com)")

    grp = parser.add_argument_group(f"{Fore.CYAN}wordlist{RESET}")
    grp.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST, metavar="FILE",
                     help=f"primary wordlist  (default: built-in {count} entries)")
    grp.add_argument("--append", metavar="FILE",
                     help="append extra wordlist to the primary one")

    grp = parser.add_argument_group(f"{Fore.CYAN}dns{RESET}")
    grp.add_argument("-c", "--concurrency", type=int, default=300, metavar="N",
                     help="concurrent DNS resolvers  (default: 300)")
    grp.add_argument("--timeout", type=float, default=3.0, metavar="SEC",
                     help="DNS resolution timeout in seconds  (default: 3.0)")
    grp.add_argument("--retries", type=int, default=1, metavar="N",
                     help="DNS retry count on failure  (default: 1)")
    grp.add_argument("--resolvers", metavar="FILE",
                     help="file of custom nameservers, one IP per line")
    grp.add_argument("--aaaa", action="store_true",
                     help="also resolve AAAA (IPv6) records")
    grp.add_argument("--no-wildcard", action="store_true",
                     help="skip wildcard DNS detection and filtering")

    grp = parser.add_argument_group(f"{Fore.CYAN}http probing{RESET}")
    grp.add_argument("--http", action="store_true",
                     help="probe HTTP/HTTPS, status codes + page titles")
    grp.add_argument("--http-timeout", type=int, default=5, metavar="SEC",
                     help="HTTP request timeout in seconds  (default: 5)")
    grp.add_argument("--no-redirects", action="store_true",
                     help="do not follow HTTP redirects")
    grp.add_argument("--user-agent", default=DEFAULT_UA, metavar="UA",
                     help="custom User-Agent string for HTTP requests")
    grp.add_argument("--filter-status", metavar="CODES",
                     help="exclude results with these HTTP codes  (e.g. 404,403)  requires --http")
    grp.add_argument("--match-status", metavar="CODES",
                     help="only show results with these HTTP codes  (e.g. 200,301)  requires --http")
    grp.add_argument("--match-ip", metavar="IP",
                     help="only show subdomains resolving to this IP")

    grp = parser.add_argument_group(f"{Fore.CYAN}output{RESET}")
    grp.add_argument("-o", "--output", metavar="FILE",
                     help="save results as plain text")
    grp.add_argument("--json", metavar="FILE", dest="json_file",
                     help="save results as JSON")
    grp.add_argument("--csv", metavar="FILE", dest="csv_file",
                     help="save results as CSV")
    grp.add_argument("-v", "--verbose", action="store_true",
                     help="verbose output — TTL, timing, response size, all IPs")
    grp.add_argument("-q", "--quiet", action="store_true",
                     help="suppress banner and scan header, show results + summary only")
    grp.add_argument("--silent", action="store_true",
                     help="print found subdomains only, no decorations (pipe-friendly)")
    grp.add_argument("--no-color", action="store_true",
                     help="disable colored output")

    grp = parser.add_argument_group(f"{Fore.CYAN}misc{RESET}")
    grp.add_argument("-h", "--help", action=_BannerHelp, nargs=0,
                     help="show this help message and exit")

    return parser


def _parse_codes(raw: Optional[str], flag: str) -> Optional[set[int]]:
    if not raw:
        return None
    try:
        return {int(c.strip()) for c in raw.split(",") if c.strip()}
    except ValueError:
        print_error(f"Invalid status codes for {flag}: {raw!r}")
        sys.exit(1)


def load_wordlist(path: str, label: str = "Wordlist") -> list[str]:
    if not os.path.isfile(path):
        print_error(f"{label} not found: {path}")
        sys.exit(1)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        words = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not words:
        print_error(f"{label} is empty.")
        sys.exit(1)
    return words


def load_resolvers(path: Optional[str]) -> list[str]:
    if not path:
        return DEFAULT_NAMESERVERS
    if not os.path.isfile(path):
        print_warn(f"Resolver file not found: {path} — using defaults.")
        return DEFAULT_NAMESERVERS
    with open(path, "r", encoding="utf-8") as f:
        servers = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    return servers or DEFAULT_NAMESERVERS


def main() -> None:
    colorama.init(autoreset=False)
    parser = _build_parser()
    args = parser.parse_args()

    if args.no_color:
        colorama.deinit()

    silent = args.silent
    quiet  = args.quiet or silent

    if not quiet:
        print(BANNER)

    if not _DOMAIN_RE.match(args.domain):
        print_error(f"Invalid domain: {args.domain!r}  (expected e.g. example.com)")
        sys.exit(1)

    if args.filter_status and not args.http:
        print_warn("--filter-status has no effect without --http")
    if args.match_status and not args.http:
        print_warn("--match-status has no effect without --http")

    wordlist = load_wordlist(args.wordlist)
    if args.append:
        extra = load_wordlist(args.append, "Append wordlist")
        seen  = set(wordlist)
        wordlist += [w for w in extra if w not in seen]

    nameservers   = load_resolvers(args.resolvers)
    filter_status = _parse_codes(args.filter_status, "--filter-status")
    match_status  = _parse_codes(args.match_status,  "--match-status")

    wildcard_ips: Optional[set[str]] = None
    wildcard_detected = False

    if not args.no_wildcard:
        if not silent:
            sys.stderr.write(f"\r {Fore.CYAN}▸{RESET} Checking for wildcard DNS...")
            sys.stderr.flush()

        resolver = build_resolver(nameservers, timeout=args.timeout, retries=args.retries)
        try:
            wildcard_ips = asyncio.run(detect_wildcard(args.domain, resolver))
        except Exception:
            wildcard_ips = None

        if not silent:
            sys.stderr.write("\033[2K\r")
            sys.stderr.flush()

        if wildcard_ips:
            wildcard_detected = True
            if not silent:
                print_warn(
                    f"Wildcard DNS detected on {Fore.CYAN}{args.domain}{RESET} "
                    f"→ {Fore.YELLOW}{', '.join(sorted(wildcard_ips))}{RESET}  "
                    f"(results matching these IPs will be filtered)"
                )

    wl_display = (
        "built-in" if args.wordlist == DEFAULT_WORDLIST
        else os.path.basename(args.wordlist)
    )

    if not quiet:
        print_scan_header(
            domain=args.domain,
            wordlist_path=wl_display,
            wordlist_count=len(wordlist),
            concurrency=args.concurrency,
            probe_http=args.http,
            probe_aaaa=args.aaaa,
            output_file=args.output,
            json_file=args.json_file,
            csv_file=args.csv_file,
            nameservers=nameservers,
            dns_timeout=args.timeout,
            dns_retries=args.retries,
            wildcard_detected=wildcard_detected,
            wildcard_filtering=not args.no_wildcard,
            filter_status=filter_status,
            match_status=match_status,
            match_ip=args.match_ip,
            follow_redirects=not args.no_redirects,
            verbose=args.verbose,
        )

    found_count = 0
    set_scan_start(time.perf_counter())

    def on_found(result: ScanResult) -> None:
        nonlocal found_count
        found_count += 1
        if silent:
            print(result.subdomain, flush=True)
        else:
            print_result(result, verbose=args.verbose)

    def on_progress(scanned: int, total: int) -> None:
        if not silent:
            update_progress(scanned, total, found_count)

    try:
        results, stats = asyncio.run(
            run_scan(
                domain=args.domain,
                wordlist=wordlist,
                concurrency=args.concurrency,
                probe_http=args.http,
                probe_aaaa=args.aaaa,
                nameservers=nameservers,
                dns_timeout=args.timeout,
                dns_retries=args.retries,
                http_timeout=args.http_timeout,
                follow_redirects=not args.no_redirects,
                user_agent=args.user_agent,
                wildcard_ips=wildcard_ips,
                filter_status=filter_status,
                match_status=match_status,
                match_ip=args.match_ip,
                on_found=on_found,
                on_progress=on_progress,
            )
        )
    except KeyboardInterrupt:
        print()
        if not silent:
            print_warn("Scan interrupted.")
        sys.exit(0)

    saved = save_outputs(results, args.output, args.json_file, args.csv_file)

    if not silent:
        print_summary(stats, results, args.output, args.json_file, args.csv_file, saved=saved)

    colorama.deinit()


if __name__ == "__main__":
    main()
