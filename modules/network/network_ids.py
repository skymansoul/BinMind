"""IDS规则引擎——Suricata风格规则解析与匹配。

本模块为主入口，从子模块聚合全部公开符号，保持原有导入路径不变。
子模块拆分策略：
  - types: 数据结构与常量，无外部依赖
  - parser: 规则语法解析，依赖types
  - builtin: 内置规则定义，依赖types+parser
  - matching: 数据包匹配工具，依赖types
  - 本文件: RuleEngine主类，依赖上述全部子模块
"""
import logging
from typing import List, Dict, Optional, Any

from .network_ids_types import SuricataRule, _log
from .network_ids_parser import parse_suricata_rule
from .network_ids_builtin import BUILT_IN_RULES
from .network_ids_matching import rule_matches_packet

# 保持模块级常量可直接引用
__all__ = [
    "SuricataRule", "RuleEngine", "BUILT_IN_RULES",
    "parse_suricata_rule",
]


class RuleEngine:
    """Suricata风格规则引擎：加载规则、匹配包和流。

    匹配策略：先检查协议和端口（快速过滤），再逐条匹配content和pcre模式。
    流级别规则需在match_flow中基于FlowRecord统计特征匹配。
    """

    def __init__(self):
        self._rules: List[SuricataRule] = []
        self._rules_by_proto: Dict[str, List[SuricataRule]] = {
            "tcp": [], "udp": [], "icmp": [], "any": [],
        }
        self._rules_by_sid: Dict[int, SuricataRule] = {}

    def load_rules(self, rules_source: Any) -> int:
        """从文件或列表加载规则。

        参数可以是文件路径(str)或SuricataRule列表。自动按协议索引以提高
        匹配效率。返回加载的规则数量。
        """
        _rules: List[SuricataRule] = []
        if isinstance(rules_source, str):
            try:
                with open(rules_source, "r", encoding="utf-8", errors="replace") as _f:
                    for _line in _f:
                        _r = parse_suricata_rule(_line)
                        if _r:
                            _rules.append(_r)
            except Exception as e:
                _log.error("加载规则文件失败 %s: %s", rules_source, e)
                return 0
        elif isinstance(rules_source, list):
            for _item in rules_source:
                if isinstance(_item, SuricataRule):
                    _rules.append(_item)
                elif isinstance(_item, str):
                    _r = parse_suricata_rule(_item)
                    if _r:
                        _rules.append(_r)
        else:
            _log.warning("不支持的规则源类型: %s", type(rules_source))
            return 0

        self._rules.extend(_rules)
        # 建立索引
        for _r in _rules:
            _proto = _r.proto.lower()
            if _proto in self._rules_by_proto:
                self._rules_by_proto[_proto].append(_r)
            else:
                self._rules_by_proto["any"].append(_r)
            self._rules_by_sid[_r.sid] = _r

        return len(_rules)

    def match_packet(self, packet_data: Any) -> List[SuricataRule]:
        """对数据包匹配所有规则，返回触发的规则列表。

        packet_data可以是字节串(bytes)或包含protocol/ports等属性的对象。
        匹配流程：协议过滤 → 端口过滤 → content/pcre匹配。
        """
        _triggered: List[SuricataRule] = []
        _proto_str = "any"
        _dport = 0
        _payload = b""

        if isinstance(packet_data, bytes):
            _payload = packet_data
            _candidates = self._rules_by_proto.get("any", [])
        elif isinstance(packet_data, dict):
            _payload = packet_data.get("payload", b"")
            _p = packet_data.get("protocol", 6)
            if _p == 6:
                _proto_str = "tcp"
            elif _p == 17:
                _proto_str = "udp"
            elif _p == 1:
                _proto_str = "icmp"
            _dport = packet_data.get("dst_port", 0)
        else:
            _payload = getattr(packet_data, "payload", b"")
            _p = getattr(packet_data, "protocol", 6)
            if _p == 6:
                _proto_str = "tcp"
            elif _p == 17:
                _proto_str = "udp"
            elif _p == 1:
                _proto_str = "icmp"
            _dport = getattr(packet_data, "dst_port", 0)

        _candidates = list(self._rules_by_proto.get(_proto_str, []))
        _candidates.extend(self._rules_by_proto.get("any", []))

        for _rule in _candidates:
            if rule_matches_packet(_rule, _payload, _proto_str, _dport):
                _triggered.append(_rule)

        return _triggered

    def match_flow(self, flow: Any) -> List[SuricataRule]:
        """对流记录匹配基于流特征的规则（阈值、字节数等）。

        主要匹配dsize约束和threshold阈值规则。flow需提供bytes_sum、
        packets、src_port、dst_port等属性。
        """
        _triggered: List[SuricataRule] = []
        _bytes = getattr(flow, "bytes_sum", 0)
        _packets = getattr(flow, "packets", 0)

        for _rule in self._rules:
            # dsize匹配
            if _rule.dsize_min > 0 and _bytes < _rule.dsize_min:
                continue
            if _rule.dsize_max > 0 and _rule.dsize_max < 0xFFFFFFFF and _bytes > _rule.dsize_max:
                continue
            # threshold匹配
            if _rule.threshold_count > 0 and _packets < _rule.threshold_count:
                continue
            _triggered.append(_rule)

        return _triggered

    def get_rule(self, sid: int) -> Optional[SuricataRule]:
        return self._rules_by_sid.get(sid)

    def list_rules(self) -> List[SuricataRule]:
        return list(self._rules)

    def rule_count(self) -> int:
        return len(self._rules)

    # 对抗性规则硬化
    def harden_rules(self) -> Dict[int, Any]:
        """对加载的规则执行对抗性硬化分析。

        对每条规则: 提取约束→识别规避间隙→生成硬化建议。
        返回 {sid → HardeningProposal} 字典, 仅含需硬化的规则。

        副作用: 无。不自动修改规则, 硬化建议供人工审核。
        """
        try:
            from .adversarial_ids_hardener import batch_harden_rules
        except ImportError:
            from src.adversarial_ids_hardener import batch_harden_rules
        rule_texts = [r.raw for r in self._rules if r.raw]
        return batch_harden_rules(rule_texts)

    def get_hardening_summary(self) -> Dict[str, Any]:
        """返回规则集的硬化状态摘要。

        含: 总规则数/需硬化规则数/规避面总量/高危gap类型分布。
        """
        hardened = self.harden_rules()
        if not hardened:
            return {"total_rules": len(self._rules), "rules_needing_hardening": 0}

        total_surface_before = sum(
            p.evasion_surface_before for p in hardened.values())
        total_surface_after = sum(
            p.evasion_surface_after for p in hardened.values())

        gap_types: Dict[str, int] = {}
        for p in hardened.values():
            for mod in p.proposed_modifications:
                gtype = mod.split(' —— ')[1] if ' —— ' in mod else mod
                gap_types[gtype] = gap_types.get(gtype, 0) + 1

        return {
            "total_rules": len(self._rules),
            "rules_needing_hardening": len(hardened),
            "evasion_surface_total_before": total_surface_before,
            "evasion_surface_total_after": total_surface_after,
            "surface_reduction_ratio": round(
                1.0 - total_surface_after / max(total_surface_before, 1), 3),
            "top_gap_types": sorted(gap_types.items(),
                                    key=lambda x: -x[1])[:5],
        }
