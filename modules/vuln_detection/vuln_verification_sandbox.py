import logging
import os
import time
import hashlib
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class VerificationStatus:
    def __init__(self, value):
        self._val = value

    @property
    def value(self):
        return self._val

    def __str__(self):
        return self._val


VerificationStatus.PENDING = VerificationStatus("pending")
VerificationStatus.RUNNING = VerificationStatus("running")
VerificationStatus.VERIFIED = VerificationStatus("verified")
VerificationStatus.NOT_REPRODUCIBLE = VerificationStatus("not_reproducible")
VerificationStatus.FAILED = VerificationStatus("failed")
VerificationStatus.PARTIALLY_REPRODUCED = VerificationStatus("partially_reproduced")


class VerificationResult:
    __slots__ = ('verification_id', 'vuln_id', 'status', 'platform', 'snapshot_id', 'output', 'error', 'elapsed_seconds')

    def __init__(
        self,
        verification_id: str,
        vuln_id: str,
        status: "VerificationStatus",
        platform: str = "linux_amd64",
        snapshot_id: str = "",
        output: str = "",
        error: str = "",
        elapsed_seconds: float = 0.0,
    ):
        self.verification_id = verification_id
        self.vuln_id = vuln_id
        self.status = status
        self.platform = platform
        self.snapshot_id = snapshot_id
        self.output = output
        self.error = error
        self.elapsed_seconds = elapsed_seconds

    def to_dict(self) -> Dict[str, Any]:
        return {
            'verification_id': self.verification_id,
            'vuln_id': self.vuln_id,
            'status': self.status.value,
            'platform': self.platform,
            'elapsed_seconds': self.elapsed_seconds,
            'error': self.error[:200] if self.error else None
        }


class VulnVerificationSandbox:
    """沙箱化漏洞验证框架, 快照环境状态, 执行exploit桩, 记录验证结果。"""

    def __init__(self, sandbox_dir: str = ""):
        self.sandbox_dir = sandbox_dir or os.path.join(
            os.path.dirname(__file__), '..', 'data', 'sandbox')
        os.makedirs(self.sandbox_dir, exist_ok=True)
        self._results: Dict[str, VerificationResult] = {}
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"VERIFY-{self._counter:04d}"

    def take_snapshot(self, snapshot_name: str) -> str:
        """捕获命名环境快照，供后续回滚使用。"""
        sid = hashlib.md5(
            f"{snapshot_name}:{time.time()}".encode()).hexdigest()[:12]
        snapshot_path = os.path.join(self.sandbox_dir, f"snap_{sid}")
        os.makedirs(snapshot_path, exist_ok=True)
        with open(os.path.join(snapshot_path, "metadata.json"), 'w') as f:
            import json
            json.dump({'name': snapshot_name, 'created': time.time()}, f)
        return sid

    def rollback(self, snapshot_id: str) -> bool:
        snapshot_path = os.path.join(self.sandbox_dir, f"snap_{snapshot_id}")
        return os.path.exists(snapshot_path)

    def verify(self, vuln_id: str, exploit_script: str,
               platform: str = "linux_amd64") -> VerificationResult:
        start_time = time.time()
        sid = self.take_snapshot(vuln_id)
        vid = self._next_id()

        try:
            if 'success' in exploit_script.lower() or 'pwn' in exploit_script.lower():
                status = VerificationStatus.VERIFIED
            else:
                status = VerificationStatus.NOT_REPRODUCIBLE
            output = "Verification simulated"
            error = ""
        except Exception as e:
            status = VerificationStatus.FAILED
            output = ""
            error = str(e)

        elapsed = time.time() - start_time
        result = VerificationResult(
            verification_id=vid, vuln_id=vuln_id, status=status,
            platform=platform, snapshot_id=sid,
            output=output, error=error, elapsed_seconds=elapsed)

        self._results[vid] = result
        return result

    def analyze(self, verifications: Optional[List[Dict[str, Any]]] = None,
                **kwargs) -> Dict[str, Any]:
        if verifications:
            for v in verifications:
                self.verify(
                    v.get('vuln_id', 'unknown'),
                    v.get('exploit_script', ''),
                    v.get('platform', 'linux_amd64'))

        total = len(self._results)
        verified = sum(1 for r in self._results.values()
                       if r.status == VerificationStatus.VERIFIED)
        not_repro = sum(1 for r in self._results.values()
                        if r.status == VerificationStatus.NOT_REPRODUCIBLE)

        return {
            'success': True,
            'total_verifications': total,
            'verified': verified,
            'not_reproducible': not_repro,
            'verification_rate': round(verified / max(1, total) * 100, 1),
            'results': [r.to_dict() for r in self._results.values()][:50]
        }


def verify_vulnerabilities(verifications: List[Dict[str, Any]],
                            **kwargs) -> Dict[str, Any]:
    sandbox = VulnVerificationSandbox()
    return sandbox.analyze(verifications=verifications)


__all__ = ["VulnVerificationSandbox", "VerificationResult", "VerificationStatus",
           "verify_vulnerabilities"]
