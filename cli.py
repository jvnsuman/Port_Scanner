#!/usr/bin/python
"""
cli.py - Command-line interface for Nmap Port Scanner.

Usage examples:
    python cli.py sacanme.nmap.org
    python cli.py 192.168.1.1 --profile service --save json
    python cli.py 10.0.0.0/24 --profile quick --output /temp/report.txt
    python cli.py scanme.nmap.org --profile full --save json,csv,txt
"""

import argparse
import sys
from scanner import PortScanner, ScanProfile
from reporter import text_report, json_report, csv_report, save_report, auto_filename
from utils import banner, check_privileges, print_progress


# -- Argument Parsing --

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port_scanner",
        description="Python Nmap Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Profiles:
    quick      — Top 100 ports, fastest
    standard   — top 1000 port (default)
    full       — All 65535 ports
    service    — Services/version detection
    os         — OS fingerprinting           [requires root]
    vuln       — Vulnerability scripts       [requires root]
    stealth    — SYN stealth scan            [requires root]
    udp        — UDP scan                    [requires root]

Examples:
    python cli.py scanme.nmap.org
    python cli.py 192.168.1.1 --profile service
    python cli.py 10.0.0.0/24 --profile quick --save json
    python cli.py scanme.nmap.org --profile os --output /temp/my_report.txt
""",
    )

    parser.add_argument("target",help="IP address,CIDR rang, or  hostname")
    parser.add_argument(
        "--profile", "-p",
        choices=[p.value for p in ScanProfile],
        default="standard",
        help="Scan profile (default: standard)",
    )
    parser.add_argument(
        "--args", "-a",
        default="",
        metavar="NMAP_ARGS",
        help="Additional raw nmap arguments (e.g. '--script http-headers')",
    )
    parser.add_argument(
        "--save", "-s",
        default="",
        metavar="FORMATS",
        help="Comma-separated output formats to  save: txt, json, csv (e.g. --save json,txt)",
    )
    parser.add_argument(
        "--output", "-o",
        default="",
        metavar="PATH",
        help="Explicit output file path (single format only; overrides -- save naming)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="suppress progress message; only print the final report",
    )
    parser.add_argument(
        "--no-colour", "--no-color",
        dest="no_colour",
        action="store_true",
        help="Disable ANSI colour output",
    )

    return parser


# -- Entrypoint --

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    colour = not args.no_colour

    if not args.quiet:
        print(banner())

    profile = ScanProfile(args.profile)

    # Privilege Warning
    warn = check_privileges(profile)
    if warn:
        print(f"\033[93m[!] {warn}\033[0m" if colour else f"[!] {warn}")

    # Run Scan
    scanner = PortScanner()
    cb = None if args.quiet else print_progress

    result = scanner.scan(
        target=args.target,
        profile=profile,
        extra_args=args.args,
        progress_cb=cb,
    )

    # Print text report to stdout
    print(text_report(result, colour=colour))

    # Save requested formats
    if args.save:
        formats = [f.strip().lower() for f in args.save.split(",") if f.strip()]
        for fmt in formats:
            if fmt == "txt":
                content = text_report(result, colour=False)
                ext = "txt"
            elif fmt == "json":
                content = json_report(result)
                ext = "json"
            elif fmt == "csv":
                content = csv_report(result)
                ext = "csv"
            else:
                print(f"[!] Unknown format '{fmt}' — skipping.")
                continue

            # Use explicit path only when a single formate is requested
            if args.output and len(formats) == 1:
                path = args.output
            else:
                path = auto_filename(result, ext)

            save_report(content, path)

    # Single explicit output path without --save → infer from extension
    if args.output and not args.save:
        ext = args.output.rsplit(".", 1)[-1].lower()
        if  ext == "json":
            content = json_report(result)
        elif ext == "csv":
            content = csv_report(result)
        else:
            content = text_report(result, colour=False)
        save_report(content, args.output)

    return 1 if result.error else 0


if __name__ == "__main__":
    sys.exit(main())
    
