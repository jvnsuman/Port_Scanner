"""
scanner.py - Core part of the port scanning logic using python-nmap.
supports quick, full, service, OS, and vulnerability scan profiles.
"""

import nmap
import socket
import ipaddress
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


# -- Enums & Data Models --

class ScanProfile(Enum):
    QUICK      = "quick"        # Top 100 ports, fast
    STANDARD   = "standard"     # Top 1000 Ports (nmap default)
    FULL       = "full"         # All 65535 ports
    SERVICE    = "service"      # Service/version detection
    OS         = "os"           # OS fingerprinting (requires root)
    VULN       = "vuln"         # Vulnerability scan via nmap scripts (requires root)
    STEALTH    = "stealth"      # SYN scan (requires root)
    UDP        = "udp"          # UDP scan (requires root)


@dataclass
class PortInfo:
    port:     int
    state:    str
    protocol: str
    service:  str  = "unknown"
    product:  str  = ""
    version:  str  = ""
    extra:    str  = ""
    cpe:      str  = ""

    def __str__(self) -> str:
        svc = self.service
        if self.product:
            svc = f"{self.product} {self.version}".strip()
        return f"{self.port}/{self.product:<3}  {self.state:<8}  {svc}"
    

@dataclass
class HostResult:
    address:     str
    hostname:    str             =""
    state:       str             ="unknown"
    os_guess:    str             =""
    os_accuracy: int             =0
    ports:       list[PortInfo]  = field(default_factory=list)
    scan_time:   float           =0.0


@dataclass
class ScanResult:
    target:         str
    profile:        ScanProfile
    started_at:     datetime                       
    finished_at:    Optional[datetime] = None
    hosts:          list[HostResult]   = field(default_factory=list)
    raw_states:     dict = field(default_factory=dict)   
    error:          Optional[str] = None                 

    @property
    def duration(self) -> float:
        if self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return 0.0
    
    @property
    def total_open_ports(self) -> int:
        return sum(1 for h in self.hosts for p  in h.ports if p.state == "open")


# -- Nmap Argument Profiles --

_PROFILE_ARGS:  dict[ScanProfile, str] = {
    ScanProfile.QUICK:     "-T4 --top-ports 100",
    ScanProfile.STANDARD:  "-T4 --top-ports 1000",
    ScanProfile.FULL:      "-T4 -p-",
    ScanProfile.SERVICE:   "-T4 -sV --version-intensity 5 --top-ports 1000",
    ScanProfile.OS:        "-T4 -O --osscan-guess --top-ports 1000",
    ScanProfile.VULN:      "-T4 --script vuln --top-ports 200",
    ScanProfile.STEALTH:   "-T4 -sS --top-ports 1000",
    ScanProfile.UDP:       "-T4 -sU --top-ports 100",
}


# -- Validator --

def validate_target(target: str) -> bool:
    """ Validates if the targets has valid single IP, hostname, or CIDR formate."""

    #CIDR?
    try:
        ipaddress.ip_network(target, strict=False)
        return True, "cidr"
    except ValueError:
        pass

    # Single IP?
    try:
        ipaddress.ip_address(target)
        return True, "ip"
    except ValueError:
        pass

    # Hostname?
    try:
        socket.getaddrinfo(target, None)
        return True, "hostname"
    except socket.gaierror:
        return False, f"cannot resolve '{target}'"
    

# -- Scanner --

class PortScanner:
    """ Wraps python-nmap with scructured results and errors. """

    def __init__(self) -> None:
        self._nm = nmap.PortScanner()

    # -- Public API --

    def scan(self, target: str, profile: ScanProfile = ScanProfile.STANDARD, extra_args: str = "", progress_cb=None,) -> ScanResult:
        """
        Run a scan and return a ScanResult.

        Args:
            target      - IP, CDIR, pr hostname to scan
            profile     - ScanProfile enum value
            extra_args  - Additional nmap arguments to append to the profile arguments
            progress_cb - Optional callback (msg: str) for status updates

        """
        result = ScanResult(
            target=target,
            profile=profile,
            started_at=datetime.now(), 
        )

        valid, reason = validate_target(target)
        if not valid:
            result.error =  reason
            result.finished_at = datetime.now()
            return result
        
        args = _PROFILE_ARGS[profile]
        if extra_args:
            args = f"{args} {extra_args}"

        if progress_cb:
            progress_cb(f"[*] scanning {target} with profile '{profile.value}' ...")
            progress_cb(f"[*] nmap args: {args}")


        try:
            self._nm.scan(hosts=target, arguments=args)
        except Exception as e:
            result.error = f"nmap scan failed: {e}"
            result.finished_at = datetime.now()
            return result
        
        result.raw_states = self._nm.scanstats()
        result.hosts = self._parse_hosts(profile)
        result.finished_at = datetime.now()

        if progress_cb:
            up = sum(1 for h in result.hosts if h.state == "up")
            progress_cb(f"[+] Done - {up} hosts up, host(s) up, {result.total_open_ports} open port(s).")
        
        return result
    

    def scan_async(
            self,
            target: str,
            profile: ScanProfile = ScanProfile.STANDARD,
            extra_args: str = "",
            callback= None,
    ) -> None:
        """
        fire an async nmap scam. `callback(host, scn_data)` is called per host.
        Note: python-nmap async requires a callback.
        """
        nma = nmap.PortScannerAsync()
        args = _PROFILE_ARGS[profile]
        if extra_args:
            args = f"{args} {extra_args}"
        nma.scan(hosts=target, arguments=args, callback=callback)
        nma.wait()
    

    # -- Parsing --

    def _parse_hosts (self, profile:ScanProfile) -> list[HostResult]:
        results = []
        for addr in self._nm.all_hosts():
            host_data = self._nm[addr]
            hr = HostResult(
                address=addr,
                hostname=self._get_hostname(host_data),
                state=host_data.state(),
            )

            # OS detection
            if profile in (ScanProfile.OS, ScanProfile.VULN):
                hr.os_guess, hr.os_accuracy = self._extract_os(host_data)


            # Ports
            for proto in host_data.all_protocols():
                for port_num in sorted(host_data[proto].keys()):
                    pdata = host_data[proto][port_num]
                    hr.ports.append(PortInfo(
                        port=port_num,
                        state=pdata.get("state", ""),
                        protocol=proto,
                        service=pdata.get("name", "unknown"),
                        product=pdata.get("product", ""),
                        version=pdata.get("version", ""),
                        extra=pdata.get("extrainfo", ""),
                        cpe=pdata.get("cpe", ""),
                    ))
            results.append(hr)
        return results
    
    @staticmethod
    def _get_hostname(host_data) -> str:
        try:
            return host_data.hostname() or ""
        except Exception:
            return ""
        
    @staticmethod
    def _extract_os(host_data) -> tuple[str, int]:
        try:
            osmatch = host_data.get("osmatch", [])
            if osmatch:
                best = osmatch[0]
                return best.get("name", ""), int(best.get("accuracy", 0))
        except Exception:
            pass
        return "", 0
    