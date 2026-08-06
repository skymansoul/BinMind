"""
异构 Worker 能力匹配 (Heterogeneous Worker Capability Matching, HWCM)
----------------------------------------------------------------------
将任务需求 (GPU/内存/架构/特定工具) 与 worker 能力精确匹配,
避免将 GPU 密集型任务发送到仅有 CPU 的节点.

设计依据:
  二进制分析管道的任务异构性远超传统 MapReduce:
    - GNN 漏洞检测 → 需要 GPU (CUDA/ROCm)
    - 符号执行 → 需要大内存 (>16GB)
    - ARM 二进制分析 → 需要 QEMU-user 或 ARM 硬件
    - 固件解包 → 需要特定解包工具链 (binwalk, ubi_reader)
    - LLM 分析 → 需要 GPU + 足够 VRAM

  现有调度器 (Celery, Kubernetes) 基于 label/selector 做静态匹配,
  但二进制分析工具的可用性动态变化——QEMU 可能被安装/卸载,
  GPU 驱动可能升级导致 CUDA 版本变化.

  HWCM 维护动态能力向量 (每 worker 定期上报),
  任务声明需求向量, 调度时做加权余弦匹配.
"""
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class CapabilityVector:
    """Worker 能力向量 — 浮点编码的能力剖面."""
    gpu_score: float = 0.0       # 0=无GPU, 1=集成GPU, 5=A100
    memory_gb: float = 0.0       # 可用内存 (GB)
    cpu_cores: int = 0           # CPU 核心数
    arch_support: float = 0.0    # 0=仅x86, 0.5=x86+ARM模拟, 1=全架构原生
    tool_score: float = 0.0      # 二进制分析工具链得分 (0-1)
    llm_support: float = 0.0     # 0=无LLM, 1=本地LLM可用
    network_mbps: float = 0.0    # 网络带宽

    def to_list(self) -> List[float]:
        return [self.gpu_score, self.memory_gb, float(self.cpu_cores),
                self.arch_support, self.tool_score, self.llm_support,
                self.network_mbps]


@dataclass
class TaskRequirement:
    """任务需求向量 — 与 CapabilityVector 维度对应."""
    task_id: str
    needs_gpu: bool = False
    min_memory_gb: float = 0.0
    min_cpu_cores: int = 1
    target_arch: str = "x86_64"   # 目标架构
    needs_tools: List[str] = field(default_factory=list)
    needs_llm: bool = False
    priority: int = 5             # 1 (最高) - 10 (最低)

    def to_vector(self) -> List[float]:
        """需求编码为 [0,1] 范围的权重向量 (非阈值)."""
        return [
            1.0 if self.needs_gpu else 0.0,
            min(1.0, self.min_memory_gb / 32.0),
            min(1.0, self.min_cpu_cores / 16.0),
            0.5 if self.target_arch != 'x86_64' else 0.0,
            0.3 if self.needs_tools else 0.0,
            1.0 if self.needs_llm else 0.0,
            0.1,  # 网络需求通常不高
        ]


class CapabilityAwareScheduler:
    """能力感知调度器.

    用法:
      cas = CapabilityAwareScheduler()
      cas.update_worker('w1', CapabilityVector(gpu_score=4.5, memory_gb=32, ...))
      best = cas.match(TaskRequirement(task_id='t1', needs_gpu=True, ...))
      # best = 'w1' (有 GPU 的 worker)
    """

    def __init__(self):
        self._workers: Dict[str, CapabilityVector] = {}
        self._worker_meta: Dict[str, Dict[str, Any]] = {}
        self._task_history: Dict[str, List[str]] = defaultdict(list)
        self._last_update: Dict[str, float] = {}

    def update_worker(self, worker_id: str, caps: CapabilityVector,
                      meta: Optional[Dict[str, Any]] = None):
        self._workers[worker_id] = caps
        self._worker_meta[worker_id] = meta or {}
        self._last_update[worker_id] = time.time()

    def match(self, req: TaskRequirement,
              exclude: Optional[List[str]] = None) -> Optional[str]:
        """匹配最优 worker."""
        exclude_set = set(exclude or [])
        active = {
            wid: caps for wid, caps in self._workers.items()
            if wid not in exclude_set
            and time.time() - self._last_update.get(wid, 0) < 60
        }
        if not active:
            return None

        # 硬约束过滤
        feasible = {}
        for wid, caps in active.items():
            if req.needs_gpu and caps.gpu_score < 0.5:
                continue
            if caps.memory_gb < req.min_memory_gb:
                continue
            if caps.cpu_cores < req.min_cpu_cores:
                continue
            if req.needs_llm and caps.llm_support < 0.5:
                continue
            feasible[wid] = caps

        if not feasible:
            # 宽松匹配: 忽略 GPU 和 LLM 需求
            feasible = {
                wid: caps for wid, caps in active.items()
                if caps.memory_gb >= req.min_memory_gb * 0.5
                and caps.cpu_cores >= max(1, req.min_cpu_cores - 2)
            }

        if not feasible:
            return None

        # 加权余弦相似度排序
        req_vec = req.to_vector()
        scored = []
        for wid, caps in feasible.items():
            cap_vec = caps.to_list()
            # 余弦相似度
            dot = sum(r * c for r, c in zip(req_vec, cap_vec))
            nr = math.sqrt(sum(r * r for r in req_vec))
            nc = math.sqrt(sum(c * c for c in cap_vec))
            sim = dot / (nr * nc) if nr > 0 and nc > 0 else 0.0
            # 负载惩罚: 该 worker 最近 60s 内的任务计数
            recent_tasks = sum(
                1 for t in self._task_history.get(wid, [])
            )
            load_penalty = min(0.3, recent_tasks * 0.05)
            scored.append((sim - load_penalty, wid))

        scored.sort(reverse=True)
        return scored[0][1] if scored else None

    def assign_task(self, worker_id: str, task_id: str):
        """记录任务分配——用于负载追踪."""
        self._task_history[worker_id].append(task_id)
        # 清理 60s 外的旧记录
        now = time.time()
        self._task_history[worker_id] = [
            t for t in self._task_history[worker_id]
            if True  # 实际中按时间戳过滤
        ][-20:]  # 简化为保留最近 20 个

    def worker_summary(self, worker_id: str) -> Dict[str, Any]:
        caps = self._workers.get(worker_id)
        if caps is None:
            return {}
        return {
            'worker_id': worker_id,
            'gpu_score': caps.gpu_score,
            'memory_gb': caps.memory_gb,
            'cpu_cores': caps.cpu_cores,
            'arch_support': caps.arch_support,
            'llm_support': caps.llm_support,
            'last_update_ago_s': round(
                time.time() - self._last_update.get(worker_id, 0), 1
            ),
            'active_tasks': len(self._task_history.get(worker_id, [])),
        }


def make_capability_from_worker_info(info: Dict[str, Any]) -> CapabilityVector:
    """从 worker 上报的原始信息构造 CapabilityVector."""
    return CapabilityVector(
        gpu_score=float(info.get('gpu_count', 0)) * 1.5,
        memory_gb=float(info.get('total_memory_mb', 0)) / 1024.0,
        cpu_cores=int(info.get('cpu_cores', 1)),
        arch_support=0.5 if info.get('has_qemu') else 0.0,
        tool_score=0.7 if info.get('has_binwalk') else 0.3,
        llm_support=1.0 if info.get('has_local_llm') else 0.0,
        network_mbps=float(info.get('network_mbps', 1000.0)),
    )
