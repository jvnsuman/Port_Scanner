"""
reporter.py - Formats ScanResult into human-readable text or JSON/CSV reports.
"""

import json
import csv
import io
from pathlib import Path
from datetime import datetime
from scanner import ScanResult, ScanProfile


# -- ANSI colors (disabled on windows or when writing to file)

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[2m"

def _state_colour(state: str, text: str) -> str:
    mapping = {"open": GREEN, "closed": RED, "filtered": YELLOW}
    return f"{mapping.get(state, '')}{text}{RESET}"


# -- Text Report --

def text_report(result: ScanResult, colour: bool = True) -> str:
    lines: list[str] = []

    def h(s: str) -> str:
        return f"{BOLD}{CYAN}{s}{RESET}" if colour else s
    
    def dim(s: str) -> str:
        return f"{DIM}{s}{RESET}" if colour else s
    
    #Header
    lines.append("")
    lines.append(h("=" * 60))
    lines.append(h("  NMAP PORT SCAN REPORT   "))
    lines.append(h("=" * 60))
    lines.append(f"  Target    : {result.target}")
    lines.append(f"  Profile   : {result.profile.value}")
    lines.append(f"  Started   : {result.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
    if result.finished_at:
        lines.append(f"   Duration  :  {result.duration:.2f}s")
    lines.append("")

    if result.error:
        lines.append(f"  {RED}ERROR: {result.error}{RESET}" if colour else f"  ERROR: {result.error}")
        lines.append("")
        return "\n".join(lines)
    
    if not result.hosts:
        lines.append("   No host found.   ")
        lines.append("")
        return "\n".join(lines)
    
    for hr in result.hosts:
        # Host Block
        state_tag = (f"{GREEN}UP{RESET}"  if hr.state == "up" else f"{RED}{hr.state.upper()}{RESET}") if  colour else hr.state.upper()
        host_label = hr.address
        if hr.hostname:
            host_label += f" ({hr.hostname})"
        lines.append(h(f"┌─ Host: {host_label}  [{state_tag}{BOLD}{CYAN}]") if colour else f"┌─ Host: {host_label}  [{hr.state.upper()}]")

        if hr.os_guess:
            acc = f"{hr.os_accuracy}%" if hr.os_accuracy else ""
            lines.append(f"│  OS Guess : {hr.os_guess} {dim(acc) if colour else acc}")

        open_ports = [p for p  in hr.ports if p.state == "open"]
        other_ports = [p for p in hr.ports if p.state !=  "open"]

        if not hr.ports:
            lines.append("|  No ports scanned / all filtered.")
        else:
            lines.append("|")
            lines.append("|  " + dim(f"{'PORT':<9}  {'STATE':<10}  SERVICE / PRODUCT") if colour else f"|  {'PORT':<10}  {'STATE':<10}  SERVICE / PRODUCT")
            lines.append("|  " + dim("─" * 50) if colour else "|  " + "─" * 50)

            for p in open_ports:
                svc = p.service
                if p.product:
                    svc = f"{p.product} {p.version}".strip()
                if p.extra:
                    svc += f" ({p.extra})"
                port_str = f"{p.port}/{p.protocol}"
                state_str = _state_colour(p.state, p.state) if colour else p.state
                lines.append(f"|  {port_str:<9}  {state_str:<10}  {svc}")

            if other_ports:
                closed = sum(1 for p in other_ports if p.state == "closed")
                filtered = sum(1 for p in other_ports if p.state == "filtered")
                summery_parts = []
                if closed: 
                    summery_parts.append(f"{closed} closed")
                if filtered:
                    summery_parts.append(f"{filtered} filtered")
                lines.append("|  " + dim(f" ...{','.join(summery_parts)} ports not shown") if colour else f"|  ...{', '.join(summery_parts)}ports not shown")

        lines.append("└" + "─" * 59)
        lines.append("")

    # footer summery
    up_count = sum(1 for h in result.hosts if h.state == "up")
    lines.append(dim(f"  Summary: {len(result.hosts)} host(s) scanned, {up_count} up, {result.total_open_ports} open port(s).") if colour else
                 f"  Summery: {len(result.hosts)} host(s) scanned, {up_count} up, {result.total_open_ports} open port(s).")
    if result.raw_states:   # was result.new_state
        elapsed = result.raw_states.get("elapsed", "?")
        lines.append(dim(f"  nmap elapsed: {elapsed}s") if colour else f"  nmap elapsed: {elapsed}s")
    lines.append("")

    return "\n".join(lines)


# -- JSON REPORT --

def json_report(result: ScanResult, indent: int = 2) -> str:
    def _port(p):
        return{
            "port": p.port,
            "protocol": p.protocol,
            "state": p.state,
            "service": p.service,
            "product": p.product,
            "version": p.version,
            "extra": p.extra,
            "cpe": p.cpe,
        }
    def _host(h):
        return {
            "address": h.address,
            "hostname": h.hostname,
            "state": h.state,
            "os_guess": h.os_guess,
            "os_accuracy": h.os_accuracy,
            "ports": [_port(p) for p in h.ports],
        }
    
    data = {
        "target": result.target,
        "profile": result.profile.value,
        "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat(),
        "duration_seconds": round(result.duration, 3),
        "total_open_ports": result.total_open_ports,
        "error": result.error,
        "hosts": [_host(h) for h in result.hosts],
        "stats": result.raw_states,
    }
    return json.dumps(data, indent=indent)

# -- CSV Report --

def  csv_report(result: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["host", "hostname", "host_state", "port", "protocol",   
                     "state", "services", "product", "version", "extra"])
    
    for h in result.hosts:
        for p in h.ports:
            writer.writerow([
                h.address, h.hostname, h.state,
                p.port, p.protocol, p.state,
                p.service, p.product, p.version, p.extra,
            ])
    return buf.getvalue()


# -- Save to File --

def save_report(content: str, path: str) -> None:
    """ Write report to *path*, creating parent directory and needed."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    print(f"[+] Report saved → {p.resolve()}")


def auto_filename(result: ScanResult, fmt: str) -> str:
    """ Generate a timestamped filename for a report."""
    safe_target = result.target.replace("/", "_").replace(":", "-")
    ts = result.started_at.strftime("%Y%m%d_%H%M%S")
    return f"scan_{safe_target}_{ts}.{fmt}"
            