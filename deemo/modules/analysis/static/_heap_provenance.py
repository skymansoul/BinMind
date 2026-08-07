# 堆检测器 PcWBI 集成 mixin — 来源约束写界推断作为 finalize Stage 10.
#
# 决策逻辑:
#   Stage 1-9 输出经多阶段过滤的候选告警 (self._filtered_findings).
#   Stage 10 不再新增候选, 而是按"写入大小来源"对候选重新分级:
# CONFIRMED: 可证明存在溢出路径, 计入最终检出.
# BENIGN:    可证明所有路径安全, 从最终检出中剔除 (抑制误报).
#     - SUSPECTED: 信息不足, 不删除, 单独归入 suspected_findings 供人工复核.
#   分级数据写入每条 finding 的 wb_* 字段, 原始候选本身不删除,
#   保证"只增不减"约束下误报率可测量.
#
# 创建: 2026-05-26

from typing import Dict, List, Optional

from .provenance_domain import ProvValue
from .provenance_propagator import ProvenancePropagator
from .write_bound_infer import WbVerdict, WriteBoundInferer
from .interproc_summary import InterprocSummaryBuilder


class HeapProvenanceMixin:
    """来源约束写界推断, 由 HeapOverflowDetector 继承."""

    def _init_provenance(self):
        self._prov_propagator = ProvenancePropagator(
            arg_regs=list(self._args), use_win64_abi=self._win64)
        self._prov_summary_builder = InterprocSummaryBuilder(
            arg_regs=list(self._args))
        self._wb_inferer = WriteBoundInferer(self._alloc_model)
        self._suspected_findings: List[dict] = []
        self._benign_findings: List[dict] = []
        self._pcwbi_enabled: bool = True

    def set_pcwbi_enabled(self, enabled: bool):
        """消融开关: 关闭后 finalize 跳过 Stage 11, 返回基线候选集."""
        self._pcwbi_enabled = enabled

    def prov_build_summary(self, func_name: str,
                           instructions: List[dict]):
        """为单个用户函数构建来源摘要 (供带函数边界的驱动调用)."""
        self._prov_summary_builder.build(func_name, instructions,
                                         is_win64=self._win64)

    def prov_run(self, instructions: List[dict]) -> List[dict]:
        """执行 Stage 10 写界推断.

        输入: Stage 9 输出的候选告警.
        返回: 保留级告警列表.

        决策修正: 只抑制"可证明安全"(BENIGN) 的告警;
        SUSPECTED (信息不足, 未证安全) 必须保留在检出中,
        否则真实溢出因证据不足被丢弃 → 召回崩塌.
        被过滤告警仍以 wb_verdict=benign 标记, 供消融审计.
        """
        self._prov_propagator.reset()
        self._prov_propagator.set_instructions(instructions)
        for ins in instructions:
            self._prov_propagator.handle_instruction(ins)

        results = self._wb_inferer.infer(
            self._filtered_findings,
            get_write_prov=self._get_write_prov,
            get_alloc_prov=self._get_alloc_prov)

        confirmed, suspected, benign = [], [], []
        for r in results:
            self._apply_verdict(r.finding, r)
            if r.verdict == WbVerdict.CONFIRMED:
                confirmed.append(r.finding)
            elif r.verdict == WbVerdict.SUSPECTED:
                suspected.append(r.finding)
            else:
                benign.append(r.finding)

        self._suspected_findings = suspected
        self._benign_findings = benign
        return confirmed + suspected

    def _get_write_prov(self, write_addr: int,
                        size_op: str) -> Optional[ProvValue]:
        """查询写入大小操作数在写入点的来源."""
        if not size_op:
            return None
        reg = size_op.strip().lower().lstrip("%")
        return self._prov_propagator.get_at(write_addr, reg)

    def _get_alloc_prov(self, alloc_addr: int) -> Optional[ProvValue]:
        """查询分配点 size 参数的来源."""
        return self._prov_propagator.get_alloc_arg_source(alloc_addr)

    def _apply_verdict(self, finding: dict, result):
        """将分级结果写入 finding 的 wb_* 字段."""
        finding["wb_verdict"] = result.verdict
        finding["wb_reason"] = result.reason
        finding["wb_provenance"] = result.provenance
        finding["wb_filtered"] = result.verdict != WbVerdict.CONFIRMED

    @property
    def suspected_findings(self) -> List[dict]:
        return list(self._suspected_findings)

    @property
    def benign_findings(self) -> List[dict]:
        return list(self._benign_findings)

    def wb_stats(self) -> dict:
        return dict(self._wb_inferer.stats)


__all__ = ["HeapProvenanceMixin"]
