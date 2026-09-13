"""
Safe subprocess execution layer with timeouts, interruption handling, and dry-run support.
"""

import subprocess
import time
import os
import signal
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from wadix.core.config import debug, error, warn, C

@dataclass
class ExecutionResult:
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    output_file: Optional[str] = None
    timed_out: bool = False
    cancelled: bool = False
    error_message: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.cancelled and self.error_message is None


class CommandExecutor:
    """Executes system security tools safely with timeout and signal handling."""

    def __init__(self, dry_run: bool = False, verbose: bool = False):
        self.dry_run = dry_run
        self.verbose = verbose
        self._current_process: Optional[subprocess.Popen] = None
        self._interrupted = False

    def interrupt(self):
        """Signal cancellation for current process."""
        self._interrupted = True
        if self._current_process and self._current_process.poll() is None:
            try:
                # Terminate process group if possible
                if os.name == "posix":
                    os.killpg(os.getpgid(self._current_process.pid), signal.SIGTERM)
                else:
                    self._current_process.terminate()
            except Exception as e:
                debug(f"Failed to cleanly terminate process: {e}")

    def run(
        self,
        cmd: List[str],
        output_file: Optional[str] = None,
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> ExecutionResult:
        """
        Execute command with list arguments (never shell=True).
        Saves output to output_file if specified.
        """
        cmd_str = " ".join(cmd)
        debug(f"Running command: {cmd_str} (timeout={timeout}s)")

        if self.dry_run:
            if self.verbose:
                print(f"{C.DIM}[DRY-RUN]{C.RESET} Would execute: {cmd_str}")
            # In dry-run, create an empty or simulated output file if requested
            if output_file:
                os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(f"[DRY-RUN] Simulated execution of: {cmd_str}\n")

            return ExecutionResult(
                command=cmd,
                returncode=0,
                stdout=f"[DRY-RUN] {cmd_str}",
                stderr="",
                duration=0.01,
                output_file=output_file,
            )

        if self._interrupted:
            return ExecutionResult(
                command=cmd,
                returncode=-1,
                stdout="",
                stderr="Execution cancelled prior to start",
                duration=0.0,
                cancelled=True,
                error_message="Scan cancelled by user",
            )

        # Merge environment variables if provided
        exec_env = os.environ.copy()
        if env:
            exec_env.update(env)

        start_time = time.time()
        stdout_text = ""
        stderr_text = ""
        timed_out = False
        cancelled = False
        err_msg = None
        ret_code = -1

        try:
            # Never shell=True to protect against command injection
            self._current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=cwd,
                env=exec_env,
            )

            try:
                stdout_text, stderr_text = self._current_process.communicate(timeout=timeout)
                ret_code = self._current_process.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                self.interrupt()
                try:
                    stdout_text, stderr_text = self._current_process.communicate(timeout=5)
                except Exception:
                    self._current_process.kill()
                err_msg = f"Command timed out after {timeout} seconds"
                ret_code = -1
            except KeyboardInterrupt:
                cancelled = True
                self._interrupted = True
                self.interrupt()
                err_msg = "Command interrupted by user"
                ret_code = -1
                raise

        except FileNotFoundError as e:
            err_msg = f"Tool executable not found: {cmd[0]}"
            ret_code = 127
        except PermissionError as e:
            err_msg = f"Permission denied executing: {cmd[0]}"
            ret_code = 126
        except Exception as e:
            err_msg = f"Unexpected execution error: {str(e)}"
            ret_code = 1
        finally:
            self._current_process = None

        duration = round(time.time() - start_time, 2)

        # If an output file was requested, save stdout (or stderr if stdout empty)
        if output_file:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
                with open(output_file, "w", encoding="utf-8", errors="replace") as f:
                    if stdout_text:
                        f.write(stdout_text)
                    elif stderr_text:
                        f.write(f"--- STDERR ---\n{stderr_text}")
                    elif err_msg:
                        f.write(f"--- ERROR ---\n{err_msg}\n")
            except Exception as e:
                warn(f"Failed to write output to {output_file}: {e}")

        return ExecutionResult(
            command=cmd,
            returncode=ret_code,
            stdout=stdout_text,
            stderr=stderr_text,
            duration=duration,
            output_file=output_file,
            timed_out=timed_out,
            cancelled=cancelled,
            error_message=err_msg,
        )
