"""
增量报告差异比对引擎。

应用场景: 同一二进制多次分析 (补丁前后、不同 fuzzer 轮次)
快速识别新增/消失/变更的发现。

参考:
  Akamai PatchDiff-AI (2025) — 补丁差异驱动根因分析，前后版本函数级对比
  SEMSIFT (github.com/cognis-digital/semsift) — 仅扫描 diff 行，非全库扫描
  US 10,614,218 B2 — 增量 IR 合并，函数级粒度差异追踪

本项目适配: 二进制漏洞分析场景的 finding 级别差异，
以 function_name + vulnerability_type + cwe 为匹配键。

修改记录:
  2025-07-19 09:17 - 匹配键追加 cwe 字段以降低误匹配
  2025-07-19 14:50 - 新增 severity_change 检测，覆盖增减+严重度升降
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class DiffStatus(Enum):
    ADDED = "added"          # 新增发现
    REMOVED = "removed"      # 已消失 (推测已修复)
    CHANGED = "changed"      # 同一发现属性变动 (严重度/置信度等)
    UNCHANGED = "unchanged"  # 无差异


@dataclass
class FindingDiff:
    """单个发现差异记录，含新旧快照与变更字段列表。"""
    status: DiffStatus
    finding_id: str
    old_finding: Optional[Dict] = None
    new_finding: Optional[Dict] = None
    changed_fields: List[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.status == DiffStatus.ADDED:
            return f"[+] 新增: {self.new_finding.get('title', self.finding_id)}"
        elif self.status == DiffStatus.REMOVED:
            return f"[-] 移除: {self.old_finding.get('title', self.finding_id)}"
        elif self.status == DiffStatus.CHANGED:
            fields = ', '.join(self.changed_fields)
            return f"[~] 变更 ({fields}): {self.new_finding.get('title', self.finding_id)}"
        return f"[=] 无变化: {self.old_finding.get('title', self.finding_id)}"


def _make_match_key(finding: Dict) -> str:
    """
    稳定匹配键: MD5(function_name \x00 vulnerability_type \x00 cwe) 前 12 位。

    字段选取理由:
      - function_name: 漏洞所在函数，最稳定的定位锚
      - vulnerability_type: 同一函数可存在多类漏洞 (如 buffer overflow + format string)
      - cwe: 防止不同 CWE 发现被错误合并
    """
    func = finding.get('function_name', '')
    vtype = finding.get('type', finding.get('vulnerability_type', ''))
    cwe = finding.get('cwe', '')
    raw = f"{func}\x00{vtype}\x00{cwe}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]


def _detect_changes(old: Dict, new: Dict) -> List[str]:
    """比较两个匹配发现的差异字段列表。"""
    changed = []
    for key in ('severity', 'confidence', 'description', 'cvss_score', 'exploitation'):
        old_v = old.get(key)
        new_v = new.get(key)
        if old_v != new_v:
            changed.append(key)
    return changed


def diff_findings(
    old_findings: List[Dict],
    new_findings: List[Dict]
) -> List[FindingDiff]:
    """
    集合差运算: 按匹配键对照两次发现集合，产出差异列表。

    排序: added > removed > changed > unchanged。

    前提: 两次 finding 结构兼容 (均含 function_name/vulnerability_type)。
    """
    diffs: List[FindingDiff] = []

    old_by_key: Dict[str, Dict] = {}
    for f in old_findings:
        key = _make_match_key(f)
        old_by_key[key] = f

    new_by_key: Dict[str, Dict] = {}
    for f in new_findings:
        key = _make_match_key(f)
        new_by_key[key] = f

    old_keys = set(old_by_key.keys())
    new_keys = set(new_by_key.keys())

    # 新增发现
    for key in new_keys - old_keys:
        diffs.append(FindingDiff(
            status=DiffStatus.ADDED,
            finding_id=key,
            new_finding=new_by_key[key]
        ))

    # 已消失发现
    for key in old_keys - new_keys:
        diffs.append(FindingDiff(
            status=DiffStatus.REMOVED,
            finding_id=key,
            old_finding=old_by_key[key]
        ))

    # 共同发现比对
    for key in old_keys & new_keys:
        old = old_by_key[key]
        new = new_by_key[key]
        changed = _detect_changes(old, new)
        if changed:
            diffs.append(FindingDiff(
                status=DiffStatus.CHANGED,
                finding_id=key,
                old_finding=old,
                new_finding=new,
                changed_fields=changed
            ))
        else:
            diffs.append(FindingDiff(
                status=DiffStatus.UNCHANGED,
                finding_id=key,
                old_finding=old,
                new_finding=new
            ))

    # 排序序: ADDED > REMOVED > CHANGED > UNCHANGED
    order = {DiffStatus.ADDED: 0, DiffStatus.REMOVED: 1,
             DiffStatus.CHANGED: 2, DiffStatus.UNCHANGED: 3}
    diffs.sort(key=lambda d: order.get(d.status, 99))

    return diffs


def generate_diff_report(
    old_findings: List[Dict],
    new_findings: List[Dict],
    title: str = "增量分析差异报告"
) -> str:
    """渲染 Markdown 增量差异汇总表。"""
    diffs = diff_findings(old_findings, new_findings)

    added = [d for d in diffs if d.status == DiffStatus.ADDED]
    removed = [d for d in diffs if d.status == DiffStatus.REMOVED]
    changed = [d for d in diffs if d.status == DiffStatus.CHANGED]
    unchanged = [d for d in diffs if d.status == DiffStatus.UNCHANGED]

    lines = [
        f"# {title}",
        "",
        f"| 类别 | 数量 |",
        f"|------|------|",
        f"| 新增发现 | {len(added)} |",
        f"| 消失发现 | {len(removed)} |",
        f"| 属性变更 | {len(changed)} |",
        f"| 无变化   | {len(unchanged)} |",
        "",
    ]

    if added:
        lines.append("## 新增发现")
        for d in added:
            lines.append(d.summary())
            lines.append("")

    if removed:
        lines.append("## 消失发现 (可能已修复)")
        for d in removed:
            lines.append(d.summary())
            lines.append("")

    if changed:
        lines.append("## 属性变更")
        for d in changed:
            lines.append(d.summary())
            if d.old_finding.get('severity') != d.new_finding.get('severity'):
                lines.append(f"  严重度: {d.old_finding.get('severity')} → {d.new_finding.get('severity')}")
            lines.append("")

    return '\n'.join(lines)
