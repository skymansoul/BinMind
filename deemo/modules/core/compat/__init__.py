# compat/ 兼容适配层 — 为旧版 API 提供路径重定向
# 原位于 modules/compat/，2026-08-02 随目录重组迁入 core/compat/

# --- 2026-07/08 广度拓展 ---
# 新增 11 个子模块覆盖多维度二进制分析需求:
#   binary_embedding  — 多模态函数嵌入 (BLens 2024, AGNOMIN 2025)
#   patch_diff        — 安全补丁差分与 1-day 漏洞推断 (ReSym 2024, Yang et al. 2023 TOSEM)
#   taint_flow        — 多路径污点传播引擎 (LATTE 2025 TOSEM, TACE 2024 FSE)
#   gadget_scan       — ROP/JOP/SYS 指令片段扫描 (War on JITs 2025, ROPecker)
#   packer_detect     — 壳/保护器多特征融合检测 (GUARD 2025 SAC, VMPredator 2026)
#   value_set_analysis— 基于抽象解释的间接跳转解析 (BAP, angr VSA)
#   binary_simhash    — SimHash 指纹与大规模近似匹配 (Charikar 2002 STOC, Manku 2007 WWW)
#   spectral_entropy  — 多分辨率熵分析与异常检测 (HAWKEYE 2024 CRYPTO, DeepMem 2018 CCS)
#   heap_analyzer     — 堆利用原语与风水检测 (Gollum 2019 CCS, FUZE 2018 USENIX, HeapMD 2022)
#   directed_fuzzer   — 定向灰盒模糊测试基元 (BEACON 2022 S&P, Hawkeye 2018 CCS, MC2 2023 USENIX)
#   uaf_detector      — UAF 静态/动态/并发检测 (Undangle 2012 ISSTA, UAFL 2020 ICSE, UFO 2018 ICSE)
