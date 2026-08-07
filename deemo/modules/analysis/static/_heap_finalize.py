# 堆溢出检测器finalize阶段.
# 包含多阶段FP过滤管线: 去重→Stage4路径敏感→Stage5结构推断→Stage3.5 Octagon→Stage1-3→DDSSC→SAWCE.
# 创建: 2026-07-21
# 修改: 2026-07-21 — 插入Stage 3.5 Octagon关系型域过滤

from typing import Dict, List

from .heap_constraint import Interval


class HeapFinalizeMixin:
    """finalize阶段多阶段FP过滤, 由HeapOverflowDetector继承."""

    @staticmethod
    def _dedup_by_alloc(findings: List[dict]) -> List[dict]:
        """按(alloc_addr, write_addr)去重 — 同一分配点的不同写入操作各自独立保留."""
        by_key: Dict[tuple, dict] = {}
        for f in findings:
            alloc_addr = f.get("_snapshot_alloc_addr",
                               f.get("alloc_addr", 0))
            write_addr = f.get("write_addr", 0)
            key = (alloc_addr, write_addr)
            if key in by_key:
                existing = by_key[key]
                if f.get("overflow_bytes", 0) > \
                        existing.get("overflow_bytes", 0):
                    by_key[key] = f
            else:
                by_key[key] = f
        return list(by_key.values())

    def finalize(self, instructions: List[dict]) -> List[dict]:
        """所有指令分析完毕后, 运行多阶段FP过滤."""
        deduped = self._dedup_by_alloc(self._raw_findings)

        stage4_survivors = []
        for f in deduped:
            if not self._stage4_path_sensitive_check(f):
                continue
            stage4_survivors.append(f)

        stage5_survivors = []
        for f in stage4_survivors:
            if not self._stage5_struct_field_check(f):
                continue
            stage5_survivors.append(f)

        # Stage 3.5: Octagon 关系型域过滤
        # 消除区间域无法判定的变量间等价/支配关系类误报
        octagon_builder = self._octagon_filter.build_domain(instructions)
        stage35_survivors = self._octagon_filter.filter(
            stage5_survivors, octagon_builder)

        stage123_survivors = self._fp_filter.filter(
            stage35_survivors, instructions, self._alloc_tracker)

        sym_expr_map = self._build_sym_expr_map(stage123_survivors)
        stage678_survivors = self._ddssc_filter.filter(
            stage123_survivors, instructions, self._alloc_tracker,
            self._known_constants, sym_expr_map)

        self._struct_size_tracker.set_instructions(instructions)
        self._struct_size_tracker.reset()
        for ins in instructions:
            self._struct_size_tracker.process(ins)
        corr_results = self._symbolic_correlator.correlate(
            self._struct_size_tracker, self._alloc_tracker)
        stage9_survivors = []
        for f in stage678_survivors:
            filter_reason = self._symbolic_correlator.filter_finding(
                f, corr_results)
            if filter_reason:
                f["fp_stage"] = "stage9_sawce_correlation"
                f["fp_reason"] = filter_reason
                continue
            stage9_survivors.append(f)

        loop_findings = self._loop_accumulator.analyze(
            instructions, self._alloc_tracker,
            use_win64_abi=self._win64)
        existing_alloc_addrs = {
            f.get("_snapshot_alloc_addr", f.get("alloc_addr", 0))
            for f in stage9_survivors}
        for lf in loop_findings:
            la = lf.get("_snapshot_alloc_addr", 0)
            if la not in existing_alloc_addrs:
                stage9_survivors.append(lf)
                existing_alloc_addrs.add(la)

        # Stage 10: AWSC 同源关联过滤
        # 消除"分配=写入且同根来源"类误报 (区间分析无法识别)
        stage10_survivors = self._awsc_filter.filter(
            stage9_survivors, instructions, self._alloc_tracker,
            self._user_func_ranges)

        # Stage 11: PcWBI 来源约束写界推断
        # 按写入大小来源将候选分级为 confirmed/suspected/benign,
        # 仅 confirmed 计入最终检出, suspected 归入疑似列表供复核.
        # enable_pcwbi=False 时跳过, 返回 AWSC 存活集 (消融基线).
        self._filtered_findings = stage10_survivors
        if getattr(self, "_pcwbi_enabled", True):
            self._filtered_findings = self.prov_run(instructions)
        return self._filtered_findings

    def _build_sym_expr_map(self, findings: List[dict]) -> Dict[int, dict]:
        """从findings和符号快照构建 {alloc_addr: {alloc_expr, write_expr}}."""
        expr_map: Dict[int, dict] = {}
        for f in findings:
            alloc_addr = f.get("_snapshot_alloc_addr",
                               f.get("alloc_addr", 0))
            if alloc_addr not in expr_map:
                snapshot = self._sym_snapshots.get(alloc_addr, {})
                expr_map[alloc_addr] = dict(snapshot)
        return expr_map

    def _stage4_path_sensitive_check(self, f: dict) -> bool:
        """路径敏感bounds check窄化: 若写入大小经约束窄化≤分配大小→过滤."""
        size_op = f.get("size_operand", "")
        alloc_sz = f.get("alloc_size", 0)
        if not size_op or alloc_sz <= 0:
            return True
        if f.get("note", "") == "direct_store_to_heap":
            return True
        if alloc_sz >= 2**31 - 1:
            return True
        narrowed = self._ps_vra.narrow_for_bounds_check(
            self._instructions, f.get("write_addr", 0), size_op)
        if narrowed and narrowed.hi <= alloc_sz:
            f["fp_stage"] = "stage4_path_sensitive"
            return False
        return True

    def _stage5_struct_field_check(self, f: dict) -> bool:
        """堆对象结构推断: 若写入是已知字段访问→过滤.

        守卫: 写量未知(≤0)时不做结构推断, 避免把memcpy类
        整体拷贝误判为字段访问而过滤真实溢出.
        """
        if f.get("note", "") == "direct_store_to_heap":
            return True
        ptr_reg = f.get("ptr_operand", "")
        if not ptr_reg:
            return True
        write_size = f.get("write_size", 0) or 0
        if write_size <= 0:
            return True
        if f.get("detection_method") in ("bwr", "loop_accumulation"):
            return True
        if self._struct_infer.is_field_access(
                ptr_reg, 0, write_size):
            f["fp_stage"] = "stage5_struct_field"
            return False
        return True
