# 🔍 Python Nmap Port Scanner

A command-line port scanning tool built on top of [`python-nmap`](https://pypi.org/project/python-nmap/), offering multiple scan profiles, colourized terminal reports, and exportable JSON/CSV/TXT results.

```
╔══════════════════════════════════════════════╗
║          Python Nmap Port Scanner            ║
║  Python 3.13.0   OS: Windows     [unprivileged]  ║
╚══════════════════════════════════════════════╝
```

---

## 📑 Table of Contents

- [Features](#-features)
- [Project Structure](#-project-structure)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Scan Profiles](#-scan-profiles)
- [Command-Line Options](#-command-line-options)
- [Examples](#-examples)
- [Sample Output](#-sample-output)
- [Output Formats](#-output-formats)
- [Notes on Privileges](#-notes-on-privileges)
- [Known Issues](#-known-issues)
- [Roadmap](#-roadmap)
- [License](#-license)
- [Author](#-author)

---

## ✨ Features

- 🚀 **8 built-in scan profiles** — quick, standard, full, service, OS, vuln, stealth, and UDP
- 🎨 **Colourized terminal reports** with an option to disable colour for log-safe output
- 📦 **Multi-format export** — save scan results as `.txt`, `.json`, and/or `.csv` simultaneously
- 🛡️ **Privilege-aware** — warns when a chosen profile (e.g. OS detection, stealth scan) needs root/administrator rights
- 🌐 **Flexible targets** — accepts a single IP, hostname, or CIDR range (e.g. `10.0.0.0/24`)
- ⚙️ **Custom nmap arguments** — pass any additional raw nmap flags via `--args`
- 🧱 **Structured, typed codebase** — built with Python `dataclasses` and `Enum` for clean, predictable data models

---

## 📂 Project Structure

```
Port_Scanner/
├── cli.py              # Command-line entry point (argument parsing + orchestration)
├── scanner.py          # Core scanning logic — wraps python-nmap, defines data models
├── reporter.py         # Formats scan results into text / JSON / CSV reports
├── utils.py            # Helper utilities — privilege checks, banner, input parsing
├── requirements.txt    # Python dependencies
├── LICENSE              # MIT License
└── README.md            # You are here
```

| File | Responsibility |
|---|---|
| `cli.py` | Parses CLI arguments, runs the scan, prints/saves the report |
| `scanner.py` | `PortScanner` class, `ScanProfile` enum, `ScanResult` / `HostResult` / `PortInfo` dataclasses |
| `reporter.py` | `text_report()`, `json_report()`, `csv_report()`, `save_report()`, `auto_filename()` |
| `utils.py` | `banner()`, `is_root()`, `check_privileges()`, `resolve_hostname()`, `parse_port_range()` |

---

## 📋 Requirements

- **Python** 3.10+ (uses modern type-hint syntax like `list[PortInfo]`)
- **Nmap** installed and available on your system `PATH`
  - Windows: [Download Nmap](https://nmap.org/download.html)
  - Linux: `sudo apt install nmap` (Debian/Ubuntu) or `sudo dnf install nmap` (Fedora)
  - macOS: `brew install nmap`
- **python-nmap** Python package (see `requirements.txt`)

> ⚠️ This tool is a wrapper around the Nmap binary — Nmap itself **must** be installed separately. The Python package only provides bindings to call it.

---

## 🛠️ Installation

```bash
# 1. Clone or download this project
cd Port_Scanner

# 2. (Recommended) Create a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify nmap is installed and on PATH
nmap --version
```

---

## 🚀 Usage

```bash
python cli.py <target> [options]
```

`<target>` can be:
- A single IP address → `192.168.1.10`
- A hostname → `scanme.nmap.org`
- A CIDR range → `10.0.0.0/24`

---

## 🎯 Scan Profiles

| Profile | Flag | Description | Root Required? |
|---|---|---|---|
| `quick` | `--profile quick` | Top 100 ports, fastest scan | No |
| `standard` | `--profile standard` *(default)* | Top 1000 ports | No |
| `full` | `--profile full` | All 65,535 ports | No |
| `service` | `--profile service` | Service & version detection | No |
| `os` | `--profile os` | OS fingerprinting | ✅ Yes |
| `vuln` | `--profile vuln` | Vulnerability scan via Nmap scripts | ✅ Yes |
| `stealth` | `--profile stealth` | SYN stealth scan | ✅ Yes |
| `udp` | `--profile udp` | UDP port scan | ✅ Yes |

---

## ⚙️ Command-Line Options

| Option | Short | Description | Default |
|---|---|---|---|
| `target` | — | IP, hostname, or CIDR range to scan (positional, required) | — |
| `--profile` | `-p` | Scan profile to use (see table above) | `standard` |
| `--args` | `-a` | Additional raw nmap arguments, e.g. `'--script http-headers'` | `""` |
| `--save` | `-s` | Comma-separated formats to save: `txt`, `json`, `csv` | `""` (not saved) |
| `--output` | `-o` | Explicit output file path (single format only) | `""` (auto-named) |
| `--quiet` | `-q` | Suppress progress messages; print only the final report | `False` |
| `--no-colour` / `--no-color` | — | Disable ANSI colour in terminal output | `False` |

Run `python cli.py --help` at any time to see this directly in your terminal.

---

## 💡 Examples

```bash
# Basic scan using the default "standard" profile
python cli.py scanme.nmap.org

# Quick scan of a single host, save as JSON
python cli.py 192.168.1.1 --profile quick --save json

# Full port scan across a subnet, save as JSON + CSV
python cli.py 10.0.0.0/24 --profile full --save json,csv

# Service/version detection with a specific output path
python cli.py scanme.nmap.org --profile service --output reports/scan_result.json

# OS fingerprinting (requires admin/root) with extra nmap flags
python cli.py 192.168.1.1 --profile os --args "--osscan-limit"

# Quiet mode — only the final report, no progress logs, no colour
python cli.py scanme.nmap.org --quiet --no-colour
```

---

## 🖥️ Sample Output

```
════════════════════════════════════════════════════════════
  NMAP PORT SCAN REPORT
════════════════════════════════════════════════════════════
  Target    : scanme.nmap.org
  Profile   : quick
  Started   : 2026-06-19 02:14:31
  Duration  : 4.87s

┌─ Host: 45.33.32.156 (scanme.nmap.org)  [UP]
│
│  PORT       STATE       SERVICE / PRODUCT
│  ──────────────────────────────────────────────
│  22/tcp     open        OpenSSH 6.6.1p1
│  80/tcp     open        Apache httpd 2.4.7
│  9929/tcp   open        nping-echo
└───────────────────────────────────────────────────────────

  Summary: 1 host(s) scanned, 1 up, 3 open port(s).
  nmap elapsed: 4.82s
```

---

## 📤 Output Formats

When using `--save`, reports are written using auto-generated filenames in the form:

```
scan_<target>_<YYYYMMDD>_<HHMMSS>.<ext>
```

For example: `scan_scanme.nmap.org_20260619_021431.json`

| Format | Extension | Description |
|---|---|---|
| Text | `.txt` | Same colour-free format as the terminal report |
| JSON | `.json` | Full structured data — hosts, ports, services, timing, stats |
| CSV | `.csv` | Flat row-per-port format, ideal for spreadsheets |

If `--output` is provided **without** `--save`, the format is inferred from the file extension (`.json`, `.csv`, otherwise plain text).

---

## 🔐 Notes on Privileges

Some scan profiles (`os`, `vuln`, `stealth`, `udp`) require elevated privileges because they rely on raw sockets or low-level packet crafting:

- **Windows:** Run your terminal "As Administrator"
- **Linux/macOS:** Run with `sudo python cli.py ...`

If you run a privileged profile without elevated rights, the tool will print a warning but still attempt the scan — results may be incomplete or inaccurate.

---

## 🐞 Known Issues

- `reporter.py → json_report()` currently references `result.errors` (plural) when building the JSON payload, while the `ScanResult` dataclass defines the field as `error` (singular). This will raise an `AttributeError` when generating a JSON report on a scan that has an error. **Fix:** change `"error": result.errors` to `"error": result.error` in `reporter.py`.
- OS fingerprinting and vulnerability scans can take significantly longer than other profiles — be patient on larger targets or subnets.
- Scanning networks/hosts you do not own or have explicit permission to test may violate local laws and the policies of your ISP or organization. **Always scan responsibly.**

---

## 🗺️ Roadmap

- [ ] Add a `--no-colour` aware progress bar
- [ ] Support YAML/INI config files for repeatable scan presets
- [ ] Add HTML report export
- [ ] Multi-threaded scanning for large CIDR ranges
- [ ] Optional database logging of historical scans

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

```
MIT License

Copyright (c) 2026 Jivan Suman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 👤 Author

**Jivan Suman**
GitHub: [@jvnsuman](https://github.com/jvnsuman)

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized security testing only**. Only scan systems and networks you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction.
