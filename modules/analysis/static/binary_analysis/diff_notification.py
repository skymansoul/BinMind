from __future__ import annotations
import logging
from typing import Any

_log = logging.getLogger(__name__)


def notify_diff(old_result: dict, new_result: dict) -> list[str]:
    """比较新旧分析结果, 返回差异描述列表"""
    messages = []
    old_vulns = _extract_vuln_ids(old_result)
    new_vulns = _extract_vuln_ids(new_result)
    added = new_vulns - old_vulns
    removed = old_vulns - new_vulns
    if added:
        messages.append(f"新增漏洞: {', '.join(sorted(added))}")
        _log.info("diff: %d vulns added", len(added))
    if removed:
        messages.append(f"已消漏洞: {', '.join(sorted(removed))}")
        _log.info("diff: %d vulns removed", len(removed))
    old_count = len(old_vulns)
    new_count = len(new_vulns)
    if old_count != new_count and not added and not removed:
        messages.append(f"漏洞数量变化: {old_count} -> {new_count}")
    if not messages:
        messages.append("无变化")
    return messages


def _extract_vuln_ids(result: dict) -> set[str]:
    """从结果字典提取漏洞 ID 集合"""
    raw = result.get("vulns", result)
    if isinstance(raw, list):
        ids = set()
        for item in raw:
            if isinstance(item, dict):
                vid = item.get("id", item.get("addr", ""))
                if vid:
                    ids.add(str(vid))
            elif item:
                ids.add(str(item))
        return ids
    if isinstance(raw, dict):
        return set(str(k) for k in raw.keys())
    return set()
