"""
OTA firmware diff analysis. Binary-diff two firmware revisions:
detect added/modified/deleted code blocks and classify each
change by security relevance (auth, crypto, boot chain, network surface).
"""

import hashlib
import re
from enum import IntEnum, Enum
from bisect import bisect_left
from dataclasses import dataclass
from collections import defaultdict


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class ChangeType(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"

class OTAFormat(str, Enum):
    RAW = "raw"
    DELTA = "delta"
    FULL = "full"


@dataclass
class CodeBlock:
    name: str
    offset: int
    size: int
    hash: str = ""

    def __hash__(self):
        return hash((self.name, self.offset, self.size))


@dataclass
class DiffEntry:
    change: ChangeType
    block: CodeBlock
    old_block: CodeBlock | None = None
    risk: RiskLevel = RiskLevel.LOW
    reason: str = ""


@dataclass
class OTADiffResult:
    old_file: str
    new_file: str
    diffs: list[DiffEntry]
    stats: dict = None

    def __post_init__(self):
        if self.stats is None:
            self.stats = {}


# Security-significant symbol name patterns mapped to risk levels
_SECURITY_SENSITIVE: list[tuple[str, RiskLevel, str]] = [
    ("auth", RiskLevel.HIGH, "authentication logic changed"),
    ("bypass", RiskLevel.HIGH, "possible auth bypass introduced"),
    ("password", RiskLevel.HIGH, "credential handling changed"),
    ("root", RiskLevel.HIGH, "privilege escalation changes"),
    ("admin", RiskLevel.HIGH, "admin privilege changes"),
    ("encrypt", RiskLevel.MEDIUM, "encryption logic changed"),
    ("decrypt", RiskLevel.MEDIUM, "decryption logic changed"),
    ("aes_", RiskLevel.MEDIUM, "AES crypto modified"),
    ("rsa_", RiskLevel.MEDIUM, "RSA crypto modified"),
    ("sha", RiskLevel.MEDIUM, "hash function changes"),
    ("ssl_", RiskLevel.MEDIUM, "TLS/SSL stack changed"),
    ("tls_", RiskLevel.MEDIUM, "TLS stack changed"),
    ("key_", RiskLevel.HIGH, "cryptographic key handling changed"),
    ("nonce", RiskLevel.MEDIUM, "nonce/IV handling changed"),
    ("socket", RiskLevel.LOW, "network socket code changed"),
    ("connect", RiskLevel.LOW, "network connection code changed"),
    ("recv", RiskLevel.LOW, "network receive changed"),
    ("http_", RiskLevel.LOW, "HTTP handling changed"),
    ("bootloader", RiskLevel.HIGH, "bootloader code changed"),
    ("firmware_update", RiskLevel.HIGH, "update mechanism changed"),
    ("signature", RiskLevel.HIGH, "signature verification changed"),
    ("certificate", RiskLevel.HIGH, "certificate handling changed"),
    ("unlock", RiskLevel.MEDIUM, "unlock mechanism changed"),
    ("debug", RiskLevel.MEDIUM, "debug interface changed"),
    ("cmd_", RiskLevel.LOW, "command handler changed (new attack surface)"),
    ("handler", RiskLevel.LOW, "handler logic changed"),
]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _find_function_boundaries(data: bytes) -> list[CodeBlock]:
    """Heuristic function boundary detection: scan for ARM/Thumb/x86 function prologues."""
    blocks = []

    # ARM32: push {..., lr}
    arm_prologue = re.compile(rb'\x00\x48\x2d\xe9|\x04\xe0\x2d\xe5')
    # Thumb: push {r4-r7, lr}
    thumb_prologue = re.compile(rb'\x80\xb5|\x2d\xe9\xf0[\x40-\x4f]')
    # x86/x64: push rbp; mov rbp, rsp
    x86_prologue = re.compile(rb'\x55\x48\x89[\xe5\xec]')

    for pattern, arch in ((arm_prologue, "arm"), (thumb_prologue, "thumb"),
                           (x86_prologue, "x86")):
        for m in pattern.finditer(data):
            off = m.start()
            # Estimate function size: span to next prologue, capped at 64 KB
            size = 64 * 1024
            for m2 in pattern.finditer(data, off + 1):
                size = m2.start() - off
                break
            block = CodeBlock(
                name=f"{arch}_fn_{off:06x}",
                offset=off, size=min(size, 65536),
                hash=_sha256(data[off:off + min(256, len(data) - off)]))
            blocks.append(block)

    # Fallback: partition into 4 KB fixed-size blocks when no prologue is detected
    if not blocks:
        chunk = 4096
        for off in range(0, len(data) - chunk, chunk):
            blocks.append(CodeBlock(
                name=f"blk_{off:08x}",
                offset=off, size=chunk,
                hash=_sha256(data[off:off + chunk])))

    return blocks


def _classify_risk(name: str) -> tuple[RiskLevel, str]:
    name_lower = name.lower()
    for pattern, risk, reason in _SECURITY_SENSITIVE:
        if pattern in name_lower:
            return risk, reason
    return RiskLevel.LOW, ""

class OTADiffAnalyzer:
    """Binary-diff engine: hashes code blocks across two firmware revisions and classifies deltas by risk."""

    def __init__(self, block_size: int = 4096):
        self._block_size = block_size
        self._last_result: OTADiffResult | None = None

    def analyze(self, old: bytes, new: bytes,
                old_path: str = "old.bin",
                new_path: str = "new.bin") -> OTADiffResult:
        """Compute function-level diff: hash-based block comparison with risk classification."""
        old_blocks = _find_function_boundaries(old)
        new_blocks = _find_function_boundaries(new)

        old_by_hash: dict[str, list[CodeBlock]] = defaultdict(list)
        for b in old_blocks:
            old_by_hash[b.hash].append(b)

        new_by_hash: dict[str, list[CodeBlock]] = defaultdict(list)
        for b in new_blocks:
            new_by_hash[b.hash].append(b)

        old_hashes = set(old_by_hash.keys())
        new_hashes = set(new_by_hash.keys())

        diffs = []

        # Deleted blocks: present in old firmware, absent in new
        for h in old_hashes - new_hashes:
            for b in old_by_hash[h]:
                risk, reason = _classify_risk(b.name)
                diffs.append(DiffEntry(ChangeType.DELETED, b, risk=risk, reason=reason))

        # Added blocks: present in new firmware, absent in old
        for h in new_hashes - old_hashes:
            for b in new_by_hash[h]:
                risk, reason = _classify_risk(b.name)
                reason = reason or "new code block introduced"
                diffs.append(DiffEntry(ChangeType.ADDED, b, risk=risk, reason=reason))

        # Modified blocks: matching name, diverging content hash
        for nb in new_blocks:
            for ob in old_blocks:
                if ob.name == nb.name and ob.hash != nb.hash:
                    risk, reason = _classify_risk(nb.name)
                    reason = reason or f"function {nb.name} modified"
                    diffs.append(DiffEntry(ChangeType.MODIFIED, nb,
                                           old_block=ob, risk=risk, reason=reason))
                    break

        # Deduplicate diff entries by (change type, name, hash) composite key
        seen = set()
        unique_diffs = []
        for d in diffs:
            key = (d.change, d.block.name, d.block.hash)
            if key not in seen:
                seen.add(key)
                unique_diffs.append(d)

        result = OTADiffResult(
            old_file=old_path, new_file=new_path,
            diffs=unique_diffs,
            stats={
                "added": sum(1 for d in unique_diffs if d.change == ChangeType.ADDED),
                "modified": sum(1 for d in unique_diffs if d.change == ChangeType.MODIFIED),
                "deleted": sum(1 for d in unique_diffs if d.change == ChangeType.DELETED),
                "high_risk": sum(1 for d in unique_diffs if d.risk == RiskLevel.HIGH),
                "medium_risk": sum(1 for d in unique_diffs if d.risk == RiskLevel.MEDIUM),
                "total_changed_blocks": len(unique_diffs),
            })
        self._last_result = result
        return result

    @property
    def last_result(self) -> OTADiffResult | None:
        return self._last_result
