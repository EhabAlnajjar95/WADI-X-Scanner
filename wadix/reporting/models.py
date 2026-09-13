"""
Normalized data models for scanner findings, tool results, and reports.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"
    UNKNOWN  = "UNKNOWN"

    @property
    def score(self) -> int:
        mapping = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
            Severity.UNKNOWN: 0,
        }
        return mapping.get(self, 0)

    @property
    def color_code(self) -> str:
        mapping = {
            Severity.CRITICAL: "\033[91m", # BRED
            Severity.HIGH:     "\033[31m", # RED
            Severity.MEDIUM:   "\033[33m", # YELLOW
            Severity.LOW:      "\033[36m", # CYAN
            Severity.INFO:     "\033[34m", # BLUE
            Severity.UNKNOWN:  "\033[37m", # WHITE
        }
        return mapping.get(self, "")

    @classmethod
    def from_string(cls, val: str) -> "Severity":
        if not val:
            return cls.UNKNOWN
        val_upper = str(val).strip().upper()
        for member in cls:
            if member.value == val_upper:
                return member
        return cls.UNKNOWN


@dataclass
class Finding:
    tool: str
    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    matched_at: str = ""
    template_id: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    remediation: str = ""
    raw: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "matched_at": self.matched_at,
            "template_id": self.template_id,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "remediation": self.remediation,
        }


@dataclass
class ToolResult:
    tool_name: str
    description: str
    status: str  # "SUCCESS", "FAILED", "TIMEOUT", "SKIPPED"
    return_code: int = 0
    output_file: Optional[str] = None
    duration: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "description": self.description,
            "status": self.status,
            "return_code": self.return_code,
            "output_file": self.output_file,
            "duration_seconds": self.duration,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "error_message": self.error_message,
        }


@dataclass
class ScanSummary:
    target_url: str
    target_host: str
    target_port: int
    scan_profile: str
    start_time: str
    end_time: str
    total_duration_seconds: float
    output_directory: str
    tool_results: Dict[str, ToolResult] = field(default_factory=dict)
    all_findings: List[Finding] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=dict)

    def calculate_counts(self):
        counts = {s.value: 0 for s in Severity}
        for finding in self.all_findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        self.severity_counts = counts

    def to_dict(self) -> Dict[str, Any]:
        self.calculate_counts()
        return {
            "metadata": {
                "scanner": "WADI-X Security Scanner",
                "version": "3.1.0",
                "target_url": self.target_url,
                "target_host": self.target_host,
                "target_port": self.target_port,
                "scan_profile": self.scan_profile,
                "start_time": self.start_time,
                "end_time": self.end_time,
                "total_duration_seconds": self.total_duration_seconds,
                "output_directory": self.output_directory,
            },
            "summary": {
                "total_tools_run": len(self.tool_results),
                "successful_tools": sum(1 for r in self.tool_results.values() if r.status == "SUCCESS"),
                "failed_tools": sum(1 for r in self.tool_results.values() if r.status == "FAILED"),
                "timeout_tools": sum(1 for r in self.tool_results.values() if r.status == "TIMEOUT"),
                "total_findings": len(self.all_findings),
                "severity_breakdown": self.severity_counts,
            },
            "tools": {name: r.to_dict() for name, r in self.tool_results.items()},
            "findings": [f.to_dict() for f in sorted(self.all_findings, key=lambda x: x.severity.score, reverse=True)],
        }
