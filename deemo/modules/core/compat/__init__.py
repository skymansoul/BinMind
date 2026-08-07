# compat/ 兼容适配层 — 为旧版 API 提供路径重定向
# 原位于 modules/compat/，2026-08-02 随目录重组迁入 core/compat/

# 2026-07/08 广度拓展
# 新增 11 个子模块覆盖多维度二进制分析需求:
#   binary_embedding  — 多模态函数嵌入
#   patch_diff        — 安全补丁差分与 1-day 漏洞推断
#   taint_flow        — 多路径污点传播引擎
#   gadget_scan       — ROP/JOP/SYS 指令片段扫描
#   packer_detect     — 壳/保护器多特征融合检测
#   value_set_analysis— 基于抽象解释的间接跳转解析 (BAP, angr VSA)
#   binary_simhash    — SimHash 指纹与大规模近似匹配
#   spectral_entropy  — 多分辨率熵分析与异常检测
#   heap_analyzer     — 堆利用原语与风水检测
#   directed_fuzzer   — 定向灰盒模糊测试基元
#   uaf_detector      — UAF 静态/动态/并发检测
# 2025-07 深度拓展
#   subreg_taint             — 子寄存器级污点追踪, x86/x64/ARM64 字节槽位模型
#   drift_calibrator         — 在线约束复杂度校准器, CUSUM 漂移检测 + SGD 重校准
#   cfg_entropy_fingerprint  — CFG 感知熵指纹, 拉普拉斯谱特征 + 熵加权邻接矩阵
# 2025-08 跨层/归一化拓展
#   compiler_artifact_normalizer — 编译器产物归一化, 展开折叠 + 惯用法替换 + 寄存器类映射
#   cross_layer_taint_router     — 跨层污点路由, 网络协议字段 ↔ CPU 寄存器字节槽映射
# 2026-07/08 检测深度升级
#   abstract_heap_model     — 堆分配器轻量抽象解释
#   taint_enhanced_heap     — 污点约束的堆溢出误报过滤
#   format_string_detector  — 格式符解析 + 污点联合检测 %n/位置参数/FORTIFY绕过
#   stack_overflow_analyzer — IR 级栈帧分析 + canary 感知 + 污点过滤
#   path_taint_integrator   — 路径敏感的 IR 级归一化特征提取 (跨编译器泛化)
#   vuln_synthesis          — 多检测器结果融合去重 + 统一 CWE 报告
#   scan_pipeline           — 检测管线编排器, 端到端串联所有模块
# 2026-08 深度升级: UAF/格式串/栈溢出 强度对齐
#   uaf_escape_analysis     — UAF 指针逃逸分析: 全局>堆>栈 可利用性分级
#   format_parser           — printf 格式符状态机解析器 (替代子串匹配)
#   format_confidence       — 格式串连续置信度评分 + FORTIFY 绕过检测
#   stack_severity          — 栈溢出 canary 感知严重度分级
#   fp_filter               — 三阶段堆溢出误报过滤 (值区间+约束+距离)
#   int_overflow_detector   — 整数溢出检测: mul/imul→malloc 链路追踪
# 2026-08 堆溢出误报专项压制 (核心创新)
#   value_range             — 稀疏值区间传播, 证明 alloc_size >= write_size 则过滤
#   alloc_constraints       — glibc/ptmalloc 分配器对齐/最小块约束建模
#   fp_filter               — 三阶段误报过滤: 值区间 + 约束模型 + 污点距离裁剪
