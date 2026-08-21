# 增加 MMIO→DMA 的污点传播路径，覆盖 GPU/PCIe 外设场景

"""
Cross-Layer Memory-Mapped Taint Bridge — 跨平台层 MMIO 污点传播追踪。

将固件 MMIO 区域映射、内核 eBPF 钩子、硬件侧信道泄漏点通过
subreg_taint 的字节级污点引擎连接起来，追踪数据从硬件寄存器到用户空间
的完整传播路径。

核心思路：
  固件配置的 MMIO 区间定义物理地址 → 内核驱动通过 ioremap 映射 →
  eBPF 钩子拦截 readl/writel → 侧信道 (cache timing/PMC) 泄漏 →
  用户空间恶意进程读取。

每个传播步骤建模为一个 TaintHop，携带：
  - 源地址/寄存器 + 目标地址/寄存器
  - 污点字节槽位映射（源 [byte_i] → 目标 [byte_j]）
  - 置信度（基于地址对齐、时序相关性等）

与传统污点分析的区别：
  传统污点分析在单一二进制或内核内部运行。本桥接器在固件/内核/硬件
  三个隔离的执行域之间传递污点，每个域内部使用自己的分析器（固件用
  静态 MMIO 扫描，内核用 eBPF 钩子分析，硬件用侧信道评估），本模块
  负责跨域的对齐与关联。

ref: STAFF — 全系统固件模糊测试的字节级污点跟踪，
     但仅覆盖固件→用户空间边界，不涉及硬件 MMIO 层。
     本项目将污点传播扩展到固件→内核→硬件三层。
ref: Intel SDM Vol.3 §11.12 — MMIO 范围通过 MTRR/PAT 配置内存类型，
     不同内存类型的访问模式差异可为侧信道提供区分度。
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class TaintHopDirection(str, Enum):
    MMIO_TO_KERNEL = "mmio→kernel"         # 硬件寄存器 → 内核驱动
    KERNEL_TO_EBPF = "kernel→ebpf"         # 内核函数 → eBPF 钩子
    EBPF_TO_USERSPACE = "ebpf→userspace"   # eBPF map → 用户空间
    KERNEL_TO_SIDECHANNEL = "kernel→sidechannel"  # 内核数据 → 侧信道泄漏
    SIDECHANNEL_TO_USERSPACE = "sidechannel→userspace"


@dataclass
class TaintHop:
    """单步污点传播，源地址/寄存器到目标地址/寄存器的字节级映射。"""
    direction: TaintHopDirection
    source_spec: str            # 源描述: "MMIO:0xfed00000" 或 "reg:RAX[3:0]"
    target_spec: str            # 目标描述
    byte_mapping: Dict[int, int] = field(default_factory=dict)
    # {source_byte_offset: target_byte_offset}，空表示全量传递
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def byte_count(self) -> int:
        return len(self.byte_mapping) if self.byte_mapping else 1


@dataclass
class TaintPath:
    """完整的跨层污点传播路径，从 MMIO 寄存器到用户空间。"""
    hops: List[TaintHop] = field(default_factory=list)
    source_node_id: str = ""     # 在 PropagationGraph 中的源节点
    target_node_id: str = ""     # 在 PropagationGraph 中的目标节点

    @property
    def length(self) -> int:
        return len(self.hops)

    @property
    def joint_confidence(self) -> float:
        """路径联合置信度，各跳置信度的乘积。"""
        result = 1.0
        for hop in self.hops:
            result *= hop.confidence
        return result


class MMIOToRegisterMapper:
    """MMIO 物理地址到 CPU 寄存器槽位的映射表。

    x86-64 平台：MMIO 读取通过 MOV 指令从物理地址加载到 RAX/EAX 等。
    本映射表维护 {物理地址范围: (寄存器名, 槽位范围)} 的关系。

    映射来源：
      - 固件 DSDT/SSDT 表中的 MMIO 区间声明
      - 内核 /proc/iomem 的输出
      - 固件 flash_layout 解析的 MTD 分区与物理地址对应
    """

    def __init__(self):
        self._regions: List[Tuple[int, int, str, Tuple[int, int]]] = []
        # [(start_addr, end_addr, register_name, (slot_low, slot_high))]

    def add_mmio_region(self, phys_start: int, phys_end: int,
                        target_reg: str, slot_range: Tuple[int, int]) -> None:
        """注册一个 MMIO 区间，物理地址 [start, end) 映射到寄存器槽位。"""
        self._regions.append((phys_start, phys_end, target_reg, slot_range))

    def lookup(self, phys_addr: int) -> Optional[Tuple[str, Tuple[int, int]]]:
        """查找给定物理地址的寄存器映射。"""
        for start, end, reg, slots in self._regions:
            if start <= phys_addr < end:
                offset = phys_addr - start
                slot_offset = offset % (slots[1] - slots[0] + 1)
                actual_slot = slots[0] + slot_offset
                return (reg, (actual_slot, actual_slot))
        return None

    @classmethod
    def from_flash_layout(cls, partitions: List[Dict]) -> MMIOToRegionMapper:
        """从固件 Flash 布局解析结果构建映射表。

        固件 MTD 分区表给出逻辑分区→物理地址的映射，结合内核
        /proc/iomem 可还原 MMIO 区间。此处实现的是简化版本，
        假设每个 MTD 分区映射到连续的物理地址段。
        """
        mapper = cls()
        for idx, part in enumerate(partitions):
            phys_start = part.get('offset_kb', 0) * 1024
            phys_end = phys_start + part.get('size_kb', 0) * 1024
            if phys_end <= phys_start:
                continue
            # 假设通过 RAX 读取（实际取决于驱动代码的反编译结果）
            slot_count = min(8, (phys_end - phys_start) // 4)
            mapper.add_mmio_region(phys_start, phys_end, 'RAX', (0, slot_count - 1))
        return mapper


class TaintBridge:
    """跨平台层污点传播桥接器。

    用法::

        bridge = TaintBridge()
        bridge.register_mmio_source("MMIO:0xfed00000", 16)
        bridge.register_kernel_hook("ebpf:sys_read", intercepts=["RAX"])
        bridge.register_sidechannel_leak("cache:l1d:set_128", leaks=["RAX[0]"])
        paths = bridge.trace_paths(source="MMIO:0xfed00000")
    """

    def __init__(self):
        self._hops: List[TaintHop] = []
        self._mmio_mapper = MMIOToRegisterMapper()

    @property
    def mapper(self) -> MMIOToRegisterMapper:
        return self._mmio_mapper

    def register_mmio_source(self, phys_spec: str, byte_count: int,
                             confidence: float = 0.80) -> None:
        """注册 MMIO 源，固件/内核通过 MMIO 读取的物理地址。

        phys_spec: "MMIO:0xfed00000" 格式的物理地址描述。
        """
        self._hops.append(TaintHop(
            direction=TaintHopDirection.MMIO_TO_KERNEL,
            source_spec=phys_spec,
            target_spec=f"reg:RAX[0:{byte_count - 1}]",
            confidence=confidence,
        ))

    def register_kernel_hook(self, ebpf_hook_spec: str,
                             intercepts: List[str],
                             confidence: float = 0.70) -> None:
        """注册内核 eBPF 钩子，拦截特定寄存器/内存位置。

        ebpf_hook_spec: "ebpf:sys_read" 或 "ebpf:kprobe:__x64_sys_read"
        intercepts: 被拦截的寄存器名列表 ["RAX", "RDI"]
        """
        for reg in intercepts:
            self._hops.append(TaintHop(
                direction=TaintHopDirection.KERNEL_TO_EBPF,
                source_spec=f"reg:{reg}",
                target_spec=f"ebpf_map:{ebpf_hook_spec}",
                confidence=confidence,
            ))

    def register_sidechannel_leak(self, channel_spec: str,
                                  leaks: List[str],
                                  confidence: float = 0.55) -> None:
        """注册硬件侧信道泄漏点，缓存集/PMC 事件/时序差异。

        channel_spec: "cache:l1d:set_128" 或 "pmc:BR_MISP_RETIRED"
        leaks: 泄漏的寄存器槽位 ["RAX[0]", "RBX[3:5]"]
        """
        for leak_spec in leaks:
            self._hops.append(TaintHop(
                direction=TaintHopDirection.KERNEL_TO_SIDECHANNEL,
                source_spec=leak_spec,
                target_spec=channel_spec,
                confidence=confidence,
            ))

    def register_userspace_sink(self, sink_spec: str,
                                source_hops: List[str],
                                confidence: float = 0.45) -> None:
        """注册用户空间的数据汇，恶意进程读取侧信道/ebpf map 的位置。

        sink_spec: "proc:/bin/malware:fd=3" 或 "socket:127.0.0.1:8080"
        source_hops: 前驱 hop 的 source_spec 列表
        """
        for src in source_hops:
            self._hops.append(TaintHop(
                direction=TaintHopDirection.SIDECHANNEL_TO_USERSPACE,
                source_spec=src,
                target_spec=sink_spec,
                confidence=confidence,
            ))

    def trace_paths(self, source: str = "",
                    max_depth: int = 4) -> List[TaintPath]:
        """从给定源追踪所有可达的污点传播路径。

        使用 BFS，从 source 出发，沿 _hops 的有向边遍历，
        直到到达用户空间或达到最大深度。
        """
        if not source:
            return []

        # 构建邻接表：source_spec → [hop_index]
        adj: Dict[str, List[int]] = defaultdict(list)
        for idx, hop in enumerate(self._hops):
            adj[hop.source_spec].append(idx)

        paths: List[TaintPath] = []
        from collections import deque
        queue: deque[Tuple[str, List[int], int]] = deque([(source, [], 0)])

        while queue:
            current_spec, hop_indices, depth = queue.popleft()
            if depth >= max_depth:
                continue

            for next_idx in adj.get(current_spec, []):
                if next_idx in hop_indices:
                    continue
                hop = self._hops[next_idx]
                new_indices = hop_indices + [next_idx]
                new_path = TaintPath(
                    hops=[self._hops[i] for i in new_indices],
                )

                if hop.direction in (TaintHopDirection.EBPF_TO_USERSPACE,
                                     TaintHopDirection.SIDECHANNEL_TO_USERSPACE):
                    paths.append(new_path)
                else:
                    queue.append((hop.target_spec, new_indices, depth + 1))

        # 按联合置信度降序排列
        paths.sort(key=lambda p: p.joint_confidence, reverse=True)
        return paths

    def hop_count_by_direction(self) -> Dict[TaintHopDirection, int]:
        from collections import Counter
        return dict(Counter(h.direction for h in self._hops))
