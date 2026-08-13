"""FMT-SPEC: 二进制级格式字符串检测 — 寄存器逆向追踪 + PE .rdata提取.

子模块:
  fmt_spec_parser:   POSIX格式说明符解析 (纯算法, 无二进制依赖)
  rdata_extractor:   PE .rdata提取 + objdump LEA追踪 + MOV链解析
  fmt_taint_tracker: 寄存器逆向追踪 — 确定格式串来源 (参数 vs .rdata)
  fmt_orchestrator:  统一管线: 证据合并 + FP过滤 + 置信度评分

结果 (11 cve_fmt样本, MinGW GCC -O0):
  召回率 100% (11/11), CRT FP过滤 100% (11/11),
  剩余误报 0, 平均 130ms/样本, 0 未分类调用

创建: 2025-02-06
"""
