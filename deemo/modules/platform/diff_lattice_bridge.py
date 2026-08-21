# 增加 FSS 阈值自适应, 基于历史 diff 的 FSS 分布动态调整阈值
# 修复 diff 块与格节点绑定时的 hash 碰撞处理

"""
 Diff→格桥接, 连接OTA差分分析与版本格。

将firmware/ota_diff_analyzer.py的OTADiffResult映射到VersionLattice，
创建VersionNode并检测漏洞引入/回归。

流程：
  1. old/new固件计算内容hash → 创建/查找VersionNode
  2. DiffEntry分类：
     - security_fix：安全敏感函数被修改/删除 → 可能是漏洞修复
     - vuln_introduction：新增安全敏感代码或删除边界检查 → 可能是漏洞引入
     - hardening：新增检查/校验 → 安全加固
     - refactor：非安全敏感变更
  3. vuln_introduction类变更注册到VersionNode.vuln_hashes
  4. VersionLattice.find_introduction_point()定位引入点

ref: Khorrami et al. "Binary Diff Summarization Using LLMs"
     — 将LLM辅助的diff摘要与版本格绑定，diff→漏洞引入见证的端到端自动化。
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .version_lattice import (
    VersionLattice, VersionNode, VulnIntroductionWitness, compute_content_hash,
)


class DiffClassification(str, Enum):
    SECURITY_FIX = "security_fix"           # 安全敏感代码被修改/删除
    VULN_INTRODUCTION = "vuln_introduction" # 新增代码可能引入漏洞
    HARDENING = "hardening"                 # 新增检查/校验
    REFACTOR = "refactor"                   # 非安全敏感变更
    UNKNOWN = "unknown"


@dataclass
class ClassifiedDiff:
    """经安全分类的差分条目, 在OTADiffResult.DiffEntry基础上增加分类标签。"""
    change_type: str                        # added / modified / deleted
    block_name: str
    offset: int
    size: int
    old_hash: str = ""
    new_hash: str = ""
    classification: DiffClassification = DiffClassification.UNKNOWN
    risk_level: str = "low"
    reason: str = ""
    vuln_hash: str = ""                     # 若为 vuln_introduction，分配唯一 ID


class DiffLatticeBridge:
    """OTA差分→版本格桥接器。

    用法::

        bridge = DiffLatticeBridge(lattice)
        bridge.ingest_diff(old_fw_path, new_fw_path, ota_diff_result)
        witness = bridge.locate_introductions()
    """

    # FSS分类阈值, 历史数据自适应调整的初始值
    _FSS_VULN_INTRO_THRESHOLD = 0.55
    _FSS_SECURITY_FIX_THRESHOLD = 0.60

    def __init__(self, lattice: VersionLattice):
        self._lattice = lattice
        self._classified_diffs: List[ClassifiedDiff] = []
        self._old_hash: str = ""
        self._new_hash: str = ""
        self._fss_history: List[float] = []  # 历史 FSS 值, 用于自适应阈值校准

    def ingest_diff(self, old_path: str, new_path: str,
                    diff_result: Any, old_version_tag: str = "",
                    new_version_tag: str = "") -> Tuple[VersionNode, VersionNode]:
        """摄入OTA差分结果, 创建VersionNode并分类所有DiffEntry。

        diff_result: firmware/ota_diff_analyzer.py的OTADiffResult对象。
        返回 (old_version_node, new_version_node)。
        """
        # 计算内容 hash
        old_content = self._read_file_content(old_path)
        new_content = self._read_file_content(new_path)
        self._old_hash = compute_content_hash(old_content) if old_content else ""
        self._new_hash = compute_content_hash(new_content) if new_content else ""

        now = time.time()

        # 创建VersionNode——版本号从标签解析或使用时间戳
        old_vt = self._parse_version(old_version_tag) if old_version_tag else (0, 0, 0)
        new_vt = self._parse_version(new_version_tag) if new_version_tag else (0, 0, 1)

        old_node = VersionNode(
            binary_hash=self._old_hash, timestamp=now - 86400,
            version_tuple=old_vt, version_tag=old_version_tag or "old",
        )
        new_node = VersionNode(
            binary_hash=self._new_hash, timestamp=now,
            version_tuple=new_vt, version_tag=new_version_tag or "new",
        )

        self._lattice.add_version(old_node)
        self._lattice.add_version(new_node, parent_hashes=[self._old_hash])

        # 分类所有差分条目
        self._classified_diffs = []
        new_vuln_hashes: set[str] = set()

        for diff_entry in getattr(diff_result, 'diffs', []):
            classified = self._classify_diff(diff_entry)
            self._classified_diffs.append(classified)

            if classified.classification == DiffClassification.VULN_INTRODUCTION:
                if classified.vuln_hash:
                    new_vuln_hashes.add(classified.vuln_hash)
            elif classified.classification == DiffClassification.SECURITY_FIX:
                # 安全修复意味着旧版本可能含漏洞, 标记旧节点
                if classified.vuln_hash and old_node.binary_hash:
                    old_node.vuln_hashes.add(classified.vuln_hash)

        # 更新新节点的漏洞 hash 集合
        new_node.vuln_hashes.update(new_vuln_hashes)

        # 更新格节点及_vuln_to_versions索引
        # add_version内部已按当时的vuln_hashes建索引，之后修改的
        # vuln_hashes需手动同步, 否则find_introduction_point查不到。
        if self._old_hash in self._lattice._nodes:
            self._lattice._nodes[self._old_hash] = old_node
            for vh in old_node.vuln_hashes:
                entry = (old_node.timestamp, old_node.binary_hash)
                existing = self._lattice._vuln_to_versions.get(vh, [])
                if entry not in existing:
                    existing.append(entry)
                self._lattice._vuln_to_versions[vh] = existing
        if self._new_hash in self._lattice._nodes:
            self._lattice._nodes[self._new_hash] = new_node
            for vh in new_node.vuln_hashes:
                entry = (new_node.timestamp, new_node.binary_hash)
                existing = self._lattice._vuln_to_versions.get(vh, [])
                if entry not in existing:
                    existing.append(entry)
                self._lattice._vuln_to_versions[vh] = existing

        return old_node, new_node

    def locate_introductions(self) -> List[VulnIntroductionWitness]:
        """对各VULN_INTRODUCTION变更，在格中定位引入点。"""
        witnesses = []
        for cd in self._classified_diffs:
            if cd.classification != DiffClassification.VULN_INTRODUCTION:
                continue
            if not cd.vuln_hash:
                continue
            witness = self._lattice.find_introduction_point(cd.vuln_hash)
            if witness:
                witness.diff_summary = (
                    f"{cd.change_type} {cd.block_name} @ offset {cd.offset:#x}, "
                    f"size {cd.size}B — {cd.reason}"
                )
                witnesses.append(witness)
        return witnesses

    def detect_regressions(self) -> List[str]:
        """检测已分类漏洞是否回归, 之前修复过的漏洞重新出现。

        比较SECURITY_FIX与VULN_INTRODUCTION的block_name交集。
        同一函数先被修复（SECURITY_FIX）后又被标记为引入（VULN_INTRODUCTION），
        表示修复可能被回退或不完整。
        """
        fixed_blocks = {
            cd.block_name for cd in self._classified_diffs
            if cd.classification == DiffClassification.SECURITY_FIX
        }
        introduced_blocks = {
            cd.block_name for cd in self._classified_diffs
            if cd.classification == DiffClassification.VULN_INTRODUCTION
        }
        return sorted(fixed_blocks & introduced_blocks)

    # 此段后续可微调，当前先保证正确性
    def _classify_diff(self, diff_entry: Any) -> ClassifiedDiff:
        """对单个DiffEntry做安全分类。

        分类依据：
          (a) FSS (Functional Sensitivity Score) — 若可用
          (b) 块名称安全敏感关键词匹配
          (c) 变更类型（删除/新增/修改）
        """
        change = str(getattr(diff_entry, 'change', 'modified'))
        block = getattr(diff_entry, 'block', None)
        block_name = getattr(block, 'name', '') if block else ''
        block_size = getattr(block, 'size', 0) if block else 0
        block_offset = getattr(block, 'offset', 0) if block else 0
        fss = getattr(block, 'fss', 0.0) if block else 0.0
        old_block = getattr(diff_entry, 'old_block', None)
        old_hash = getattr(old_block, 'hash', '') if old_block else ''
        new_hash = getattr(block, 'hash', '') if block else ''
        risk = str(getattr(diff_entry, 'risk', 'low'))
        reason = str(getattr(diff_entry, 'reason', ''))

        # 累计FSS历史供自适应阈值
        if fss > 0:
            self._fss_history.append(fss)
            if len(self._fss_history) > 100:
                self._fss_history.pop(0)

        classification = DiffClassification.UNKNOWN
        vuln_hash = ""

        # 安全敏感关键词, 与ota_diff_analyzer._SECURITY_SENSITIVE对齐
        _SENSITIVE_KEYWORDS = {
            'auth', 'bypass', 'password', 'root', 'admin', 'encrypt', 'decrypt',
            'aes_', 'rsa_', 'sha', 'ssl_', 'tls_', 'key_', 'nonce',
            'bootloader', 'firmware_update', 'signature', 'verify',
            'memcpy', 'strcpy', 'sprintf', 'gets', 'strcat',
            'memset', 'mlock', 'mmap', 'mprotect',
        }

        name_lower = block_name.lower()
        is_sensitive = any(kw in name_lower for kw in _SENSITIVE_KEYWORDS)

        # 自适应FSS阈值
        vuln_thresh = self._adaptive_fss_threshold()

        if change == 'deleted' and is_sensitive:
            classification = DiffClassification.SECURITY_FIX
            reason = reason or f"security-sensitive block '{block_name}' removed"
        elif change == 'added' and is_sensitive and fss > vuln_thresh:
            classification = DiffClassification.VULN_INTRODUCTION
            reason = reason or f"new security-sensitive block '{block_name}' with FSS={fss:.2f}"
            vuln_hash = self._make_vuln_hash(block_name, block_offset, new_hash)
        elif change == 'modified' and is_sensitive:
            if fss > self._FSS_SECURITY_FIX_THRESHOLD:
                classification = DiffClassification.SECURITY_FIX
            else:
                classification = DiffClassification.HARDENING
        elif change == 'added' and not is_sensitive:
            if fss > vuln_thresh:
                classification = DiffClassification.VULN_INTRODUCTION
                vuln_hash = self._make_vuln_hash(block_name, block_offset, new_hash)
            else:
                classification = DiffClassification.REFACTOR
        else:
            classification = DiffClassification.REFACTOR

        return ClassifiedDiff(
            change_type=change, block_name=block_name,
            offset=block_offset, size=block_size,
            old_hash=old_hash, new_hash=new_hash,
            classification=classification, risk_level=risk,
            reason=reason, vuln_hash=vuln_hash,
        )

    def _adaptive_fss_threshold(self) -> float:
        """基于历史FSS分布动态调整阈值, 取历史中位数。"""
        if len(self._fss_history) < 10:
            return self._FSS_VULN_INTRO_THRESHOLD
        sorted_fss = sorted(self._fss_history)
        mid = len(sorted_fss) // 2
        return sorted_fss[mid]

    @staticmethod
    def _make_vuln_hash(block_name: str, offset: int, content_hash: str) -> str:
        """为疑似漏洞引入生成唯一标识, 用于格vuln_hashes追踪。"""
        raw = f"{block_name}:{offset}:{content_hash}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @staticmethod
    def _read_file_content(path: str) -> Optional[bytes]:
        try:
            with open(path, 'rb') as f:
                return f.read()
        except (OSError, IOError):
            return None

    @staticmethod
    def _parse_version(tag: str) -> Tuple[int, ...]:
        """版本标签解析为元组, "v2.1.3" → (2, 1, 3)。"""
        import re
        nums = re.findall(r'\d+', tag)
        return tuple(int(n) for n in nums) if nums else (0, 0, 0)

    @property
    def classification_summary(self) -> Dict[str, int]:
        from collections import Counter
        return dict(Counter(cd.classification.value for cd in self._classified_diffs))
