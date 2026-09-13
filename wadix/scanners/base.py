"""
Base scanner adapter class.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
import os
from wadix.core.target import TargetInfo
from wadix.core.executor import CommandExecutor, ExecutionResult
from wadix.core.installer import find_tool_path
from wadix.reporting.models import ToolResult, Finding, Severity

class BaseScanner(ABC):
    """Abstract base class for all tool scanner adapters."""

    name: str = "base"
    description: str = "Base Scanner"
    default_timeout: int = 300

    def __init__(self, timeout: Optional[int] = None):
        self.timeout = timeout or self.default_timeout

    def is_available(self) -> bool:
        """Check if this tool's executable is found on system."""
        return find_tool_path(self.name) is not None

    def get_executable(self) -> Optional[str]:
        return find_tool_path(self.name)

    @abstractmethod
    def build_command(self, target: TargetInfo, outdir: str) -> List[str]:
        """Construct the argument list for subprocess execution."""
        pass

    def parse_findings(self, exec_result: ExecutionResult, target: TargetInfo) -> List[Finding]:
        """Parse raw output or output files into structured Finding objects. Default returns empty."""
        return []

    def run(self, target: TargetInfo, outdir: str, executor: CommandExecutor) -> ToolResult:
        """Run the scanner, capture results, and return a normalized ToolResult."""
        tool_bin = self.get_executable()
        output_file = os.path.join(outdir, f"{self.name}.txt")

        if not tool_bin and not executor.dry_run:
            return ToolResult(
                tool_name=self.name,
                description=self.description,
                status="SKIPPED",
                return_code=-1,
                output_file=output_file,
                duration=0.0,
                error_message=f"Tool '{self.name}' is not installed",
            )

        cmd = self.build_command(target, outdir)
        exec_res = executor.run(cmd, output_file=output_file, timeout=self.timeout)

        status = "SUCCESS" if exec_res.success else "FAILED"
        if exec_res.timed_out:
            status = "TIMEOUT"
        elif exec_res.cancelled:
            status = "CANCELLED"

        findings = self.parse_findings(exec_res, target)

        return ToolResult(
            tool_name=self.name,
            description=self.description,
            status=status,
            return_code=exec_res.returncode,
            output_file=output_file,
            duration=exec_res.duration,
            findings=findings,
            stdout=exec_res.stdout,
            stderr=exec_res.stderr,
            error_message=exec_res.error_message,
        )
