"""
Scanner module registry and factory.
"""

from typing import Dict, Type
from wadix.scanners.base import BaseScanner
from wadix.scanners.recon import NmapScanner, WhatWebScanner, SubfinderScanner, AmassScanner
from wadix.scanners.web import NiktoScanner, TestSSLScanner, GobusterScanner, FfufScanner
from wadix.scanners.cms import WPScanScanner, DroopescanScanner
from wadix.scanners.vuln import NucleiScanner

SCANNER_CLASSES: Dict[str, Type[BaseScanner]] = {
    "nmap": NmapScanner,
    "whatweb": WhatWebScanner,
    "testssl": TestSSLScanner,
    "gobuster": GobusterScanner,
    "droopescan": DroopescanScanner,
    "nuclei": NucleiScanner,
    "nuclei_full": lambda **kw: NucleiScanner(full=True, **kw),
    "nikto": NiktoScanner,
    "wpscan": WPScanScanner,
    "ffuf": FfufScanner,
    "subfinder": SubfinderScanner,
    "amass": AmassScanner,
}

def get_scanner(name: str, **kwargs) -> BaseScanner:
    """Instantiate a scanner by name."""
    factory = SCANNER_CLASSES.get(name)
    if not factory:
        raise ValueError(f"Unknown scanner name: '{name}'")
    return factory(**kwargs)
