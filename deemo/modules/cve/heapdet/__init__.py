# heapdet - 来源约束写界推断 (PcWBI) 的二进制堆溢出检测驱动包.
#
# 定位: 对编译产物 (PE/ELF) 做 objdump 反汇编, 喂入 analysis/static 的
# 增强堆溢出检测器 (含 PcWBI Stage 10), 输出三级判定报告.
# 自包含可运行: 不依赖 angr; objdump 缺失时回退 angr 提指令.
#

from .scan import scan_binary, ScanReport

__all__ = ["scan_binary", "ScanReport"]
