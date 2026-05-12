# subprobe

```
         _               _
 ___ _ _| |_ ___ ___ ___| |_ ___
|_ -| | | . | . |  _| . | . | -_|
|___|___|___|  _|_| |___|___|___|
            |_| https://github.com/0xDrakon
```

**Fast, async subdomain enumeration tool built in Python.**
Designed for security researchers and penetration testers who need reliable, high-speed subdomain discovery with clean, readable output.

![subprobe in action](https://files.catbox.moe/yekmr1.png)

---

## Features

**DNS Resolution**
- Fully async A record resolution via `dnspython` with hundreds of concurrent lookups
- AAAA (IPv6) record resolution with `--aaaa`
- CNAME chain detection and display
- TTL value reporting in verbose mode
- Per-query DNS timing (visible with `-v`)
- Configurable DNS timeout and retry count
- Custom nameserver support via `--resolvers`

**Wildcard DNS Detection**
- Automatically probes two random subdomains before scanning begins
- Detects wildcard DNS configurations and records their IPs
- Silently filters any results matching wildcard IPs during the scan
- Shows count of wildcard-filtered entries in the summary
- Can be disabled with `--no-wildcard`

**HTTP and HTTPS Probing**
- Optional probing of both HTTP and HTTPS endpoints per subdomain
- Status code display with color coding by class (2xx green, 3xx yellow, 4xx red, 5xx magenta)
- Page title extraction from response body
- Response size tracking in bytes (shown in verbose mode)
- HTTP response timing in milliseconds (shown in verbose mode)
- Configurable request timeout
- Toggle redirect following with `--no-redirects`
- Custom User-Agent string support
- Filter results by HTTP status codes with `--filter-status` or `--match-status`

**Output Formats**
- Colored terminal output with progress bar and ETA
- Plain text file output with tab-separated fields (`-o`)
- JSON output with all fields including timing and sizes (`--json`)
- CSV output ready for spreadsheet import (`--csv`)
- Silent mode for piping into other tools (`--silent`)
- Quiet mode to suppress banner and header (`-q`)
- Verbose mode with full details per result (`-v`)
- No-color mode for terminals without ANSI support (`--no-color`)

**Performance**
- Asyncio-based with configurable concurrency (default: 300 simultaneous resolvers)
- Semaphore-controlled burst to avoid overwhelming resolvers
- Progress bar with live ETA estimate rendered to stderr
- Stdout stays clean for piping even during scanning
- Results sorted alphabetically after scan completes

**Platform Support**
- Windows (tested on Windows 10 and 11)
- Linux (Debian, Ubuntu, Arch, Kali, Parrot, and others)
- macOS (Intel and Apple Silicon)
- Cross-platform color output via `colorama`

---

## Requirements

- Python 3.10 or higher
- pip packages: `dnspython`, `aiohttp`, `colorama`

---

## Installation

**Clone and install dependencies:**

```bash
git clone https://github.com/0xDrakon/subprobe
cd subprobe
pip install -r requirements.txt
```

**On Kali / Parrot (externally managed environments):**

```bash
pip install -r requirements.txt --break-system-packages
```

**On Windows, use `python` instead of `python3`:**

```bash
python main.py -d example.com
```

---

## Usage

```
python3 main.py -d DOMAIN [options]
```

### Target

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Target domain **(required)** |

### Wordlist

| Flag | Description | Default |
|------|-------------|---------|
| `-w`, `--wordlist` | Primary wordlist file | Built-in (510 entries) |
| `--append` | Append an extra wordlist on top, no duplicates | |

### DNS

| Flag | Description | Default |
|------|-------------|---------|
| `-c`, `--concurrency` | Concurrent DNS resolvers | 300 |
| `--timeout` | DNS resolution timeout in seconds | 3.0 |
| `--retries` | DNS retry count on failure | 1 |
| `--resolvers` | File of custom nameserver IPs (one per line) | Cloudflare/Google/Quad9 |
| `--aaaa` | Also resolve AAAA (IPv6) records | off |
| `--no-wildcard` | Skip wildcard DNS detection and filtering | off |

### HTTP Probing

| Flag | Description | Default |
|------|-------------|---------|
| `--http` | Enable HTTP/HTTPS probing | off |
| `--http-timeout` | HTTP request timeout in seconds | 5 |
| `--no-redirects` | Do not follow HTTP redirects | follow redirects |
| `--user-agent` | Custom User-Agent string | Chrome/124 |
| `--filter-status` | Exclude results with these HTTP codes (e.g. `404,403`) | |
| `--match-status` | Only show results with these HTTP codes (e.g. `200,301`) | |
| `--match-ip` | Only show subdomains resolving to this IP | |

### Output

| Flag | Description |
|------|-------------|
| `-o`, `--output` | Save results as plain text |
| `--json` | Save results as JSON |
| `--csv` | Save results as CSV |
| `-v`, `--verbose` | Show TTL, DNS timing, HTTP sizes, response times, all IPs |
| `-q`, `--quiet` | Suppress banner and scan header |
| `--silent` | Print found subdomains only, no decorations |
| `--no-color` | Disable colored output |

---

## Examples

**Basic subdomain scan:**
```bash
python3 main.py -d example.com
```

**With HTTP probing and save results to all formats:**
```bash
python3 main.py -d example.com --http -o out.txt --json out.json --csv out.csv
```

**High concurrency with custom wordlist:**
```bash
python3 main.py -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c 500
```

**Only show subdomains with live HTTP 200 responses:**
```bash
python3 main.py -d example.com --http --match-status 200
```

**Exclude not-found and forbidden results:**
```bash
python3 main.py -d example.com --http --filter-status 404,403,410
```

**Verbose output with IPv6 resolution:**
```bash
python3 main.py -d example.com -v --aaaa
```

**Custom DNS resolvers with slower timeout for accuracy:**
```bash
python3 main.py -d example.com --resolvers resolvers.txt --timeout 5 --retries 2
```

**Pipe found subdomains into another tool:**
```bash
python3 main.py -d example.com --silent | httpx -silent
python3 main.py -d example.com --silent | nmap -iL -
python3 main.py -d example.com --silent > subs.txt
```

**Merge multiple wordlists:**
```bash
python3 main.py -d example.com -w primary.txt --append extra.txt
```

**Suppress banner for scripting:**
```bash
python3 main.py -d example.com -q --json results.json
```

---

## Output Format

**Default terminal output:**
```
[+] admin.example.com  93.184.216.34, 93.184.216.35
[+] mail.example.com   93.184.216.36  +1 more  -> mail.cdn.example.com
    └- http:200  https:301  "Admin Panel"
```

**Verbose terminal output (`-v`):**
```
[+] mail.example.com
    +- IPv4      93.184.216.34, 93.184.216.35
    +- IPv6      2606:2800:220:1:248:1893:25c8:1946
    +- CNAME     mail.cdn.example.com
    +- TTL       300s    DNS: 42ms
    +- HTTP      200  38ms  14 KB
    +- HTTPS     301  91ms  0 B
    +- Title     "Example Mail Portal"
```

**JSON output (`--json`):**
```json
[
  {
    "subdomain": "mail.example.com",
    "ips": ["93.184.216.34"],
    "ipv6": ["2606:2800:220:1:248:1893:25c8:1946"],
    "cname": "mail.cdn.example.com",
    "ttl": 300,
    "dns_ms": 42.1,
    "http_status": 200,
    "https_status": 301,
    "title": "Example Mail Portal",
    "http_ms": 38.4,
    "https_ms": 91.2,
    "http_size": 14336,
    "https_size": 0
  }
]
```

---

## Scan Summary

After every scan, subprobe prints a summary:

```
------------------------------------------------------------
  Status            scan complete
  Scanned           510
  Found             23
  WC Filtered       12
  Elapsed           4.81s  (106 req/s)
  Saved (json)      out.json
------------------------------------------------------------
```

---

## Default Nameservers

subprobe uses these resolvers by default (in rotation):

| Provider | IP |
|----------|----|
| Cloudflare | 1.1.1.1 |
| Google | 8.8.8.8 |
| Quad9 | 9.9.9.9 |
| OpenDNS | 208.67.222.222 |

You can override these by passing a file with `--resolvers`:
```
# resolvers.txt
1.1.1.1
8.8.8.8
94.140.14.14
```

---

## File Structure

```
subprobe/
+-- main.py                  Entry point
+-- requirements.txt
+-- wordlists/
|   +-- default.txt          Built-in wordlist (510 entries)
+-- subprobe/
    +-- __init__.py
    +-- banner.py            ASCII art, color tags, separator helpers
    +-- cli.py               Argument parsing, orchestration, wildcard detection
    +-- core/
    |   +-- resolver.py      Async DNS (A, AAAA, CNAME, wildcard probe)
    |   +-- scanner.py       Scan engine, HTTP probing, filtering logic
    +-- utils/
        +-- output.py        Progress bar, result printer, JSON/CSV/TXT writers
```

---

## Notes

- The progress bar is written to stderr so stdout stays clean for piping
- Wildcard DNS detection runs two probe queries before the scan starts
- Results are sorted alphabetically after the scan finishes
- `--silent` mode only prints subdomains with no color codes, safe for any downstream tool
- HTTP probing doubles the request count (one HTTP + one HTTPS per subdomain)

---

## Author

Made by [Drakon](https://github.com/0xDrakon)

---

## License

MIT
