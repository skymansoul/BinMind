# -*- coding: utf-8 -*-
# 循环累加溢出 finding 构建辅助


def build_offbyone(accum, alloc, alloc_size, total_write):
    """off-by-one finding: 写入 alloc+1 字节."""
    return {
        "type": "heap_overflow",
        "alloc_addr": alloc.alloc_site,
        "alloc_size": alloc_size,
        "alloc_request": getattr(alloc, "raw_alloc_size", None).lo
        if getattr(alloc, "raw_alloc_size", None) else alloc_size,
        "write_addr": accum.write_addrs[0] if accum.write_addrs else 0,
        "write_size": total_write,
        "overflow_bytes": 1,
        "severity": "high",
        "detection_method": "loop_accumulation",
        "loop_trip_count": "alloc+1",
        "single_write_size": accum.single_write_size,
        "ptr_operand": accum.ptr_reg,
        "_snapshot_alloc_addr": accum.alloc_addr,
        "note": f"loop bound == alloc size: writes "
                f"alloc+1 bytes (off-by-one) > alloc {alloc_size}B",
    }


def build_accum(accum, alloc, alloc_size, total_write, overflow):
    """累加溢出 finding: 单迭代写量 × 迭代次数 > 分配大小."""
    return {
        "type": "heap_overflow",
        "alloc_addr": alloc.alloc_site,
        "alloc_size": alloc_size,
        "alloc_request": getattr(alloc, "raw_alloc_size", None).lo
        if getattr(alloc, "raw_alloc_size", None) else alloc_size,
        "write_addr": accum.write_addrs[0] if accum.write_addrs else 0,
        "write_size": total_write,
        "overflow_bytes": overflow,
        "severity": "critical" if overflow > 64 else "high",
        "detection_method": "loop_accumulation",
        "loop_trip_count": accum.loop.trip_count,
        "single_write_size": accum.single_write_size,
        "ptr_operand": accum.ptr_reg,
        "_snapshot_alloc_addr": accum.alloc_addr,
        "note": f"loop body writes {accum.single_write_size}B"
                f" × {accum.loop.trip_count} iterations"
                f" = {total_write}B > alloc {alloc_size}B",
    }


__all__ = ["build_offbyone", "build_accum"]
