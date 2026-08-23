import logging
import subprocess
import shlex
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def run(cmd, timeout: int = 300, stdin_data: Optional[bytes] = None,
        capture: bool = True, check: bool = False) -> Tuple[int, str, str]:
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)

    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout or '', proc.stderr or ''
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after %ds: %s", timeout, cmd[0])
        raise
    except FileNotFoundError:
        return -1, '', f'command not found: {cmd[0]}'


def quick_run(cmd, timeout: int = 60):
    rc, out, err = run(cmd, timeout=timeout, check=False)
    if rc != 0:
        raise RuntimeError(f"Command failed (rc={rc}): {err[:200]}")
    return out


def run_sandboxed(cmd, timeout: int = 120):
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, hard))
    except (ImportError, ValueError):
        pass

    return run(cmd, timeout=timeout)
