# 增加 eBPF map 类型推断，区分 PERCPU_ARRAY 与常规 ARRAY 的泄漏风险

"""
TaintHop 自动推断器，从子模块分析结果自动推导跨层污点传播跳步。

替代手动调用 TaintBridge.register_* 的流程。输入各子模块的分析结果，
输出 TaintHop 列表，可直接喂入 TaintBridge.trace_paths()。

推断规则：
  (a) FlashLayoutParser 分区 → MMIO 源跳步：每个可读写分区映射到 RAX 槽位
  (b) EBPFAnalyzer 钩子 → 内核跳步：每个 helper call + map 访问生成跳步
  (c) SideChannelEvaluator 泄漏 → 侧信道跳步：每条超阈值的泄漏路径生成跳步
  (d) 跨跳步的字节映射通过 MMIOToRegisterMapper 自动对齐

与传统手动注册的区别：
  手动注册要求分析师了解物理地址、寄存器分配、缓存几何等底层细节。
  自动推断从现有分析器的结构化输出中提取这些信息，将专家知识编码为
  推断规则，降低使用门槛。

ref: STAFF 的污点源自动发现，从固件输入点自动标记
     污点源，本项目将类似思路扩展到 MMIO→内核→侧信道三层。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .taint_bridge import (
    TaintBridge, TaintHop, TaintHopDirection, MMIOToRegisterMapper,
)


class TaintHopInferrer:
    """从子模块分析结果自动推断 TaintHop。

    用法::

        inferrer = TaintHopInferrer()
        hops = inferrer.infer_from_flash_layout(flash_partitions)
        hops += inferrer.infer_from_ebpf_analysis(ebpf_bypasses)
        hops += inferrer.infer_from_sidechannel(sc_results)

        bridge = TaintBridge()
        for hop in hops:
            bridge._hops.append(hop)
        paths = bridge.trace_paths(source=hops[0].source_spec)
    """

    def __init__(self, mmio_mapper: Optional[MMIOToRegisterMapper] = None):
        self._mapper = mmio_mapper or MMIOToRegisterMapper()

    # Flash Layout → MMIO 源
    def infer_from_flash_layout(self,
                                partitions: List[Dict]) -> List[TaintHop]:
        """从 FlashLayoutParser 的输出推断 MMIO→内核污点跳步。

        partitions: FlashLayoutParser.parse_mtdparts() 的返回值。
        每个非只读分区对应一个 MMIO 源。
        """
        if not partitions:
            return []

        # 确保 mapper 已填充
        if not self._mapper._regions:
            self._mapper = MMIOToRegisterMapper.from_flash_layout(partitions)

        hops: List[TaintHop] = []
        for part in partitions:
            if part.get('readonly'):
                continue  # 只读分区不能作为污点注入点

            name = part.get('name', 'unknown')
            offset_kb = part.get('offset_kb', 0)
            size_kb = part.get('size_kb', 0)
            phys_start = offset_kb * 1024
            phys_end = phys_start + size_kb * 1024

            if phys_end <= phys_start:
                continue

            # 映射到寄存器
            reg_info = self._mapper.lookup(phys_start)
            if reg_info:
                reg_name, slot_range = reg_info
            else:
                reg_name, slot_range = 'RAX', (0, min(7, size_kb // 4))

            hop = TaintHop(
                direction=TaintHopDirection.MMIO_TO_KERNEL,
                source_spec=f"MMIO:flash:{name}:{phys_start:#x}",
                target_spec=f"reg:{reg_name}[{slot_range[0]}:{slot_range[1]}]",
                confidence=0.75 if not part.get('readonly') else 0.30,
                metadata={
                    'partition': name,
                    'phys_range': (phys_start, phys_end),
                    'size_kb': size_kb,
                },
            )
            hops.append(hop)

        return hops

    # eBPF 分析 → 内核钩子
    def infer_from_ebpf_analysis(self,
                                 bypasses: List[Any]) -> List[TaintHop]:
        """从 EBPFAnalyzer 的 bypass 输出推断内核→eBPF 污点跳步。

        bypasses: EBPFAnalyzer.analyze() 返回的 BypassPattern 列表。
        每个涉及 map 访问或 helper call 的 bypass 生成一个跳步。
        """
        hops: List[TaintHop] = []
        seen_regs: set[str] = set()

        for bp in bypasses:
            desc = getattr(bp, 'description', '')
            severity = getattr(bp, 'severity', 'medium')
            address = getattr(bp, 'address', 0)

            # 推断被拦截的寄存器，基于描述文本中的模式
            intercepted = self._extract_regs_from_description(desc)

            # eBPF map 类型影响泄漏风险评估
            is_percpu = 'percpu' in desc.lower()

            for reg in intercepted:
                if reg in seen_regs:
                    continue
                seen_regs.add(reg)

                conf = 0.80 if severity == 'critical' else (
                    0.65 if severity == 'high' else 0.50
                )
                # PERCPU map 泄漏风险更低，数据不跨 CPU
                if is_percpu:
                    conf *= 0.6

                hop = TaintHop(
                    direction=TaintHopDirection.KERNEL_TO_EBPF,
                    source_spec=f"reg:{reg}",
                    target_spec=f"ebpf_map:insn_{address}",
                    confidence=conf,
                    metadata={
                        'severity': severity,
                        'address': address,
                        'is_percpu': is_percpu,
                        'description': desc[:120],
                    },
                )
                hops.append(hop)

        return hops

    # 侧信道分析 → 泄漏点
    def infer_from_sidechannel(self,
                               sc_results: List[Any],
                               min_effect_size: float = 0.3) -> List[TaintHop]:
        """从 SideChannelEvaluator 的输出推断内核→侧信道污点跳步。

        sc_results: SideChannelEvaluator.evaluate() 返回的 EvaluationResult 列表。
        仅处理 leakage_detected=True 且效应量超过阈值的条目。
        """
        hops: List[TaintHop] = []

        for result in sc_results:
            leakage = getattr(result, 'leakage_detected', False)
            if not leakage:
                continue

            test_type = getattr(result, 'test_type', 'unknown')
            t_stat = getattr(result, 't_statistic', 0.0)
            mi_bps = getattr(result, 'mutual_information', 0.0)  # bits/sec

            # 效应量筛选，t 统计量 < 阈值或 MI 过低的跳过
            if abs(t_stat) < 3.0 and mi_bps < 0.1:
                continue

            # 推断泄漏的寄存器槽位，基于测试类型
            leak_slots = self._infer_leak_slots(test_type, result)

            conf = min(0.85, 0.35 + 0.10 * abs(t_stat) + 0.05 * mi_bps)

            for slot_spec in leak_slots:
                hop = TaintHop(
                    direction=TaintHopDirection.KERNEL_TO_SIDECHANNEL,
                    source_spec=slot_spec,
                    target_spec=f"sc:{test_type}:{abs(t_stat):.1f}",
                    confidence=conf,
                    metadata={
                        'test_type': test_type,
                        't_statistic': t_stat,
                        'mi_bps': mi_bps,
                        'p_value': getattr(result, 'p_value', 1.0),
                    },
                )
                hops.append(hop)

        return hops

    # 辅助：描述文本提取寄存器/测试类型映射槽位
    @staticmethod
    def _extract_regs_from_description(desc: str) -> List[str]:
        """从 bypass 描述中提取寄存器名，'r0', 'r1', ..., 'r10'。"""
        import re
        regs = re.findall(r'\br(\d+)\b', desc)
        return [f"R{int(r):d}" if int(r) > 0 else f"RAX" for r in regs[:4]]

    @staticmethod
    def _infer_leak_slots(test_type: str, result: Any) -> List[str]:
        """根据侧信道测试类型推断泄漏的寄存器槽位。

        CPA (Correlation Power Analysis) → 通常泄漏密钥字节在 AL 中。
        Welch's t-test → 非特定泄漏，默认标记 RAX[0:3]。
        Timing → 通常通过数据依赖的分支泄漏，影响 EFLAGS (不在槽位模型中，
        保守地标记为 RAX[0])。
        """
        if 'cpa' in test_type.lower():
            return ['RAX[0]']     # CPA 通常关联到密钥的最低位字节
        elif 'welch' in test_type.lower() or 'tvla' in test_type.lower():
            return ['RAX[0]', 'RAX[1]', 'RAX[2]', 'RAX[3]']
        elif 'timing' in test_type.lower():
            return ['RAX[0]']
        else:
            details = getattr(result, 'details', {})
            # 通用回退，默认 RAX[0]
            return ['RAX[0]']
