# -*- coding: utf-8 -*-
"""
BinMind 项目审计报告生成器 - 不落地脚本，仅用于生成docx
"""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from docx import Document
from docx.shared import Pt, Inches, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn

doc = Document()

# 设置默认字体
style = doc.styles['Normal']
font = style.font
font.name = '宋体'
font.size = Pt(11)
style.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')

# 辅助函数
def add_heading(text, level=1):
    h = doc.add_heading(text, level=level)
    for run in h.runs:
        run.font.name = '黑体'
        run.element.rPr.rFonts.set(qn('w:eastAsia'), '黑体')
    return h

def add_para(text, bold=False, size=11):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.bold = bold
    run.font.size = Pt(size)
    run.font.name = '宋体'
    run.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')
    return p

def add_table(headers, rows):
    table = doc.add_table(rows=1+len(rows), cols=len(headers), style='Table Grid')
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(headers):
        cell = table.rows[0].cells[i]
        p = cell.paragraphs[0]
        run = p.add_run(h)
        run.bold = True
        run.font.size = Pt(10)
        run.font.name = '宋体'
        run.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')
    for r_idx, row in enumerate(rows):
        for c_idx, val in enumerate(row):
            cell = table.rows[r_idx+1].cells[c_idx]
            p = cell.paragraphs[0]
            run = p.add_run(str(val))
            run.font.size = Pt(10)
            run.font.name = '宋体'
            run.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')
    return table

# ===== 封面 =====
title = doc.add_paragraph()
title.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = title.add_run('BinMind 项目审计报告')
run.bold = True
run.font.size = Pt(26)
run.font.name = '黑体'
run.element.rPr.rFonts.set(qn('w:eastAsia'), '黑体')

sub = doc.add_paragraph()
sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = sub.add_run('申报书与实际代码实现差异分析')
run.font.size = Pt(16)
run.font.name = '黑体'
run.element.rPr.rFonts.set(qn('w:eastAsia'), '黑体')

doc.add_paragraph()
info = doc.add_paragraph()
info.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = info.add_run('审计对象：BinMind 项目代码库\n对比基准：附件2-浙江传媒学院大学生创新训练项目学生申报书(2)\n审计日期：2026年8月21日')
run.font.size = Pt(12)
run.font.name = '宋体'
run.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')

doc.add_page_break()

# ===== 目录 =====
add_heading('目录', level=1)
toc_items = [
    '一、审计概述',
    '二、申报书核心内容摘要',
    '三、项目代码实际结构概览',
    '四、逐项对比分析',
    '  4.1 研究主题与定位',
    '  4.2 四层研究内容对比',
    '  4.3 技术路线对比',
    '  4.4 功能模块对比',
    '  4.5 参考工具与依赖对比',
    '  4.6 创新点对比',
    '  4.7 预期成果对比',
    '五、关键差异总结',
    '六、风险评估与建议',
]
for item in toc_items:
    p = doc.add_paragraph(item)
    p.paragraph_format.space_after = Pt(2)

doc.add_page_break()

# ===== 一、审计概述 =====
add_heading('一、审计概述', level=1)
add_para('本报告对 BinMind 项目代码库与《附件2-浙江传媒学院大学生创新训练项目学生申报书(2)》进行全面对比审计。审计目标为：识别申报书描述的研究内容、技术路线、功能模块与项目实际代码实现之间的吻合程度与差异，为项目后续调整和结题准备提供依据。')
add_para('审计方法：完整提取申报书文本内容，逐层扫描项目代码目录结构（约5970个Python文件），提取关键模块的类名、函数名和docstring信息，按申报书框架逐项映射比对。')
add_para('审计范围：deemo/ 目录下的全部代码，包括 core/（351文件）、modules/ai_ml/（120文件）、modules/analysis/（80+文件）、modules/binary_analysis/（106文件）、modules/exploit/（61文件）、modules/vuln/（堆/UAF/格式化字符串/整数溢出检测）、modules/network/（85文件）、modules/crypto/（17文件）、modules/platform/（33文件）等。')

doc.add_page_break()

# ===== 二、申报书核心内容摘要 =====
add_heading('二、申报书核心内容摘要', level=1)

add_heading('2.1 研究主题', level=2)
add_para('大语言模型辅助的二进制漏洞挖掘与验证。以"辅助式研判与半自动验证"为目标，不追求全自动利用，而是将LLM作为辅助组件引入漏洞研判流程。')

add_heading('2.2 四层研究内容', level=2)
add_para('1. 二进制程序理解与线索提取：结合反编译、控制流/调用关系及动态运行信息，利用LLM辅助伪代码解读、漏洞线索归纳和分析报告生成。')
add_para('2. 多方法协同的漏洞发现：以模糊测试、符号执行和规则检测为基础，根据样本特点选择或组合不同分析手段，利用模型辅助筛选测试重点、解释崩溃现象。')
add_para('3. 验证反馈与利用思路生成：对可疑点进行复现和验证，探索由模型辅助总结触发规律、生成验证脚本或提供利用思路。')
add_para('4. 系统集成与实验评测：搭建统一实验流程与结果管理模块，在CTF样本、教学样本和公开漏洞样本上开展测试。')

add_heading('2.3 技术路线', level=2)
add_para('样本准备 → 基础信息收集 → 发现漏洞 → 模型辅助解释与归纳 → 脚本化验证 → 结果反馈迭代 → 报告输出与实验评估')
add_para('关键技术依赖：pwnpasi（保护机制分析、PLT扫描、ROP gadget搜索、padding计算、格式化字符串偏移定位、canary泄露、ret2system/ret2libc/ROP链构造、exploit脚本生成、报告输出）')

add_heading('2.4 创新点', level=2)
add_para('1. 研究对象新颖性：面向真实二进制程序的辅助式分析思路。')
add_para('2. 技术创新：大语言模型辅助分析+传统程序分析工具协同。')
add_para('3. 贡献独特性：形成辅助式分析框架，给出从程序理解、漏洞发现到验证反馈的可组织流程。')

add_heading('2.5 预期成果', level=2)
add_para('1. 形成面向二进制漏洞挖掘的辅助式技术路线。')
add_para('2. 积累可复用成果（样本集、分析记录、验证脚本、流程图、技术报告）。')
add_para('3. 参加大创结题评审及网络安全竞赛。')
add_para('4. 争取申请专利或软著。')

doc.add_page_break()

# ===== 三、项目代码实际结构概览 =====
add_heading('三、项目代码实际结构概览', level=1)

add_heading('3.1 代码规模', level=2)
add_table(
    ['目录', '文件数', '主要功能域'],
    [
        ['deemo/core/', '351', '核心检测算法（CJ+BVF、GAPSBV、LSP、PS-CJ、HOVF等）'],
        ['deemo/modules/ai_ml/', '120+', 'GNN/LLM/RL辅助漏洞检测与二进制分析'],
        ['deemo/modules/analysis/', '80+', '静态数据流分析与漏洞检测引擎'],
        ['deemo/modules/binary_analysis/', '106', 'CFG构建、反编译、类型推断、IR、崩溃分析'],
        ['deemo/modules/exploit/', '61', 'exploit生成：堆布局求解、ROP、PoC、验证'],
        ['deemo/modules/vuln/detection/', '106', '漏洞检测编排（堆/UAF/格式化字符串/整数溢出）'],
        ['deemo/modules/vuln/src/', '130+', '漏洞检测核心算法实现'],
        ['deemo/modules/network/', '85', '网络协议分析（DNS/TLS/隐蔽信道/SDR/IDS）'],
        ['deemo/modules/crypto/', '17+45', '密码学检测（算法识别/误用/PQC/隐写/CBOM）'],
        ['deemo/modules/platform/', '33', '平台安全分析（漏洞传播图/固件/内核/合约）'],
        ['总计', '约5970', '全项目Python文件数'],
    ]
)

add_heading('3.2 核心技术体系（实际实现）', level=2)
add_para('项目实际实现的技术体系远超申报书描述，包含以下核心算法：')
add_table(
    ['算法/体系', '代码位置', '功能描述'],
    [
        ['GAPSBV-CJ', 'deemo/core/cj_solver.py', '约束联结求解器，联合可行性判定'],
        ['DD-BVF', 'deemo/core/cj_bvf_*.py', '反向值流追踪，CJ INCONCLUSIVE时触发安全证明'],
        ['PS-CJ', 'deemo/core/ps_cj_solver.py', '路径敏感约束联结求解器'],
        ['LSP', 'deemo/core/lsp_*.py', '三层分层安全证明（路径条件→不变式→分配器对齐）'],
        ['CAAWP', 'deemo/core/caawp_*.py', '上下文敏感仿射证明'],
        ['HOVF', 'deemo/core/hovf_*.py', '堆溢出组合裁决引擎（8个子模块）'],
        ['FOVF', 'deemo/core/fovf_*.py', '格式化字符串值流核验引擎'],
        ['UOVF', 'deemo/core/uovf_*.py', 'UAF值流门控核验引擎'],
        ['FCPV', 'deemo/core/fcpv_*.py', '格式化字符串约束感知验证'],
        ['PCFC', 'deemo/core/pcfc_*.py', '路径条件格式化字符串验证'],
        ['PCFV', 'vuln/src/heap/pcfv/', '路径条件值流验证（14文件）'],
        ['ACFPC', 'vuln/src/heap/acfpc/', '分配契约感知 falsposi 压缩（13文件）'],
        ['TOVS', 'vuln/src/heap/uaf_tovs/', '时序顺序验证系统（8文件）'],
        ['DDSSC', 'analysis/static/ddssc_*.py', '符号大小关联检测'],
        ['DESG', 'deemo/core/desg_builder.py', '支配增强语义图'],
    ]
)

add_heading('3.3 检测能力覆盖', level=2)
add_table(
    ['漏洞类型', '检测器位置', '检测器数量', '状态'],
    [
        ['堆溢出', 'core/heap_*.py + vuln/src/heap/', '40+', '已饱和(F1=1.0, FPR=0.0)'],
        ['UAF/Double-Free', 'core/uaf_*.py + vuln/src/uaf/', '22+', '已饱和'],
        ['格式化字符串', 'core/fmt_*.py + vuln/src/format/', '25+', '已饱和'],
        ['整数溢出', 'core/int_*.py + vuln/src/integer/', '17+', '已饱和'],
        ['栈溢出', 'core/stack_*.py', '11', '已实现'],
        ['ROP/CFI', 'core/gadget_*.py + detection/cfi_*.py', '5+', '已实现'],
        ['供应链', 'detection/supply_chain*.py', '2', '已实现'],
        ['沙箱逃逸', 'detection/sandbox_*.py + src/sandbox/', '3', '已实现'],
    ]
)

doc.add_page_break()

# ===== 四、逐项对比分析 =====
add_heading('四、逐项对比分析', level=1)

add_heading('4.1 研究主题与定位', level=2)
add_table(
    ['维度', '申报书描述', '实际代码实现', '差异评估'],
    [
        ['核心主题', '大语言模型辅助的二进制漏洞挖掘与验证', '多算法融合的二进制漏洞静态检测框架（LLM为辅助组件之一）', '实质性差异'],
        ['定位', '辅助式研判与半自动验证，不追求全自动', '以静态分析为核心的全自动检测体系，F1=1.0已饱和', '重大差异'],
        ['LLM角色', '模型参与研判的核心辅助组件', '120+个AI/ML文件中LLM仅占部分（伪代码解读、崩溃分析、污点推断等），核心检测不依赖LLM', '定位差异'],
        ['研究范围', '聚焦漏洞线索提取、结果解释与验证支撑', '覆盖堆溢出/UAF/格式化字符串/整数溢出/栈溢出/ROP/供应链/密码学/网络协议等全领域', '范围远超申报'],
    ]
)

add_heading('4.2 四层研究内容对比', level=2)

add_para('第一层：二进制程序理解与线索提取', bold=True)
add_table(
    ['子项', '申报书描述', '实际代码实现', '差异'],
    [
        ['反编译', '结合反编译结果', 'decompiler.py + ir_normalizer.py + source_ir_extractor.py + c_to_pseudocode.py', '吻合'],
        ['控制流/调用关系', '结合控制流/调用关系', 'cfg_extractor.py + cfg_parser.py + call_graph_enhancer.py + cfg_path_splitter.py', '吻合且超出'],
        ['动态运行信息', '结合动态运行信息', 'crash_analysis.py + exploit_executor.py + qemu_tracer.py', '吻合'],
        ['LLM伪代码解读', '利用LLM辅助伪代码解读', 'pseudocode_explainer.py + pseudocode_compressor.py + pseudocode_renamer.py + decomp_ai.py', '吻合且超出'],
        ['LLM漏洞线索归纳', 'LLM辅助漏洞线索归纳', 'llm_vuln_detector.py + llm_finding_triage.py + llm_taint_inference.py', '吻合'],
        ['LLM分析报告生成', 'LLM辅助分析报告生成', 'report.py + report_enhancement.py + binary_documenter.py', '吻合'],
    ]
)

add_para('第二层：多方法协同的漏洞发现', bold=True)
add_table(
    ['子项', '申报书描述', '实际代码实现', '差异'],
    [
        ['模糊测试', '以模糊测试为基础', 'entropy_scheduler.py + fuzzing_orchestrator.py + pipeline_plugins_fuzz.py', '吻合'],
        ['符号执行', '以符号执行为基础', 'symexec.py + selective_symexec.py + path_diversity_explorer.py + path_sensitive_vrf.py', '吻合且超出'],
        ['规则检测', '以规则检测为基础', 'rule_engine.py + pattern_fallback.py + asm_detector.py + ir_rule_engine.py', '吻合'],
        ['多方法协同', '根据样本特点选择或组合', 'detection_orchestrator.py + adaptive_scheduler.py + pipeline.py (1062行)', '吻合且大幅超出'],
        ['LLM筛选测试重点', '模型辅助筛选测试重点', 'ai_path_prioritizer.py + rl_mutate.py + neural_branch_predictor.py', '吻合'],
        ['LLM解释崩溃', '模型辅助解释崩溃现象', 'crash_analyzer_llm.py + crash_llm_helpers.py + multimodal_crash.py', '吻合'],
    ]
)

add_para('第三层：验证反馈与利用思路生成', bold=True)
add_table(
    ['子项', '申报书描述', '实际代码实现', '差异'],
    [
        ['可疑点复现验证', '对可疑点进行复现和验证', 'exploit_verifier.py + exploit_executor.py + runtime_vuln_verifier.py + vuln_verification_sandbox.py', '吻合'],
        ['LLM触发规律总结', '模型辅助总结触发规律', 'crash_exploit_distance.py + behavioral_exploitability.py + crash_primitive_fingerprint_*.py', '部分吻合'],
        ['LLM验证脚本生成', '模型辅助生成验证脚本', 'exploit_gen.py + poc_generator.py + exploit_template_engine.py + program_synth_exploit.py', '吻合且超出'],
        ['LLM利用思路', '模型提供利用思路', 'exploit_strategy_generator.py + bypass_advisor.py + exploit_decision_tree.py', '吻合且超出'],
        ['反馈闭环', '人工复核形成闭环迭代', 'feedback_loop.py + review_gate.py + feedback_llm_helpers.py', '吻合'],
    ]
)

add_para('第四层：系统集成与实验评测', bold=True)
add_table(
    ['子项', '申报书描述', '实际代码实现', '差异'],
    [
        ['统一实验流程', '搭建统一实验流程', 'pipeline.py (1062行) + pipeline_enhancements.py (1480行) + 8批增强层', '吻合且大幅超出'],
        ['结果管理模块', '结果管理模块', 'experiment_tracker_*.py (5文件) + vuln_db.py + sample_manager_*.py (5文件)', '吻合且超出'],
        ['CTF/教学/公开样本', '在CTF/教学/公开漏洞样本上测试', 'tests/目录含大量样本 + run_all_tests.py + run_quick_benchmark.py + regression_runner', '吻合'],
        ['评估维度', '发现效率/结果质量/辅助效果/适用范围', 'collect_results.py + plot_comparison.py + comparison_table.tex + benchmark_results.csv', '吻合'],
    ]
)

add_heading('4.3 技术路线对比', level=2)
add_table(
    ['阶段', '申报书描述', '实际代码实现', '差异'],
    [
        ['样本准备', '选取CTF/教学/公开漏洞样本', 'sample_manager_*.py + cve_samples/ + compile_samples.py', '吻合'],
        ['基础信息收集', 'checksec/ELF解析/PLT扫描/ROP搜索/字符串提取', 'checksec_*.py (7文件) + plt_scanner.py + binary_info.py + static_analysis.py + libc_identifier.py', '吻合且超出'],
        ['漏洞发现', '模糊测试/符号执行/规则检测', '全文检测体系（堆/UAF/格式化/整数/栈/ROP等6+类）', '吻合且大幅超出'],
        ['模型辅助解释', 'LLM对反编译/汇编/报错/轨迹语义归纳', 'pseudocode_explainer.py + crash_analyzer_llm.py + llm_taint_inference.py + multimodal_crash.py', '吻合'],
        ['脚本化验证', '工具生成验证脚本+LLM辅助payload构造', 'exploit_gen.py + feedback_loop.py + exploit_template_engine.py', '吻合且超出'],
        ['结果反馈迭代', '调整参数/偏移/利用思路', 'feedback_loop.py + review_gate.py + adaptive_scheduler.py', '吻合'],
        ['报告输出', '参考pwnpasi自动生成报告', 'report.py + report_enhancement.py + vulnerability_reporter.py', '吻合'],
    ]
)

add_heading('4.4 功能模块对比', level=2)
add_para('以下逐项对比申报书技术路线5.1节中明确提及的具体功能模块：')
add_table(
    ['功能模块', '申报书来源', '实际代码实现', '吻合度'],
    [
        ['checksec保护机制分析', 'pwnpasi', 'checksec.py + checksec_api.py + checksec_detectors.py + checksec_elf.py + checksec_elf_parser.py + checksec_constants.py (7文件)', '完全吻合'],
        ['ELF解析', 'pwnpasi', 'binary_info.py + checksec_elf_parser.py + pe_imports.py', '完全吻合'],
        ['PLT函数扫描', 'pwnpasi', 'plt_scanner.py + plt_resolver.py', '完全吻合'],
        ['ROP gadget搜索', 'pwnpasi', 'gadget_classifier.py + rop_gadget_semantic_search.py + rop_grader.py + rop_semantic_verifier.py', '完全吻合且超出'],
        ['字符串提取', 'pwnpasi', 'static_analysis.py (scan_strings) + rodata_extract.py', '完全吻合'],
        ['本地/远程交互', 'pwnpasi', 'exploit_executor.py + exploit_executor_docker.py + feedback_loop.py', '完全吻合'],
        ['padding计算', 'pwnpasi', 'stack_frame_analyzer.py (estimate_buffer_padding) + stack_overflow_strategy.py (build_exploit_params)', '完全吻合'],
        ['格式化字符串偏移定位', 'pwnpasi', 'fmt_offset_analyzer.py + fmt_offset_computer.py + format_offset_calc.py (3种实现)', '完全吻合且超出'],
        ['canary泄露', 'pwnpasi', 'stack_canary_bypass.py + canary_bypass_analyzer.py + stack_overflow_canary.py', '完全吻合且超出'],
        ['ret2system', 'pwnpasi', 'exploit_strategy.py + exploit_primitives.py + exploit_template_library.py', '完全吻合'],
        ['ret2libc', 'pwnpasi', 'libc_identifier.py + exploit_template_engine.py + libc_database_extender.py', '完全吻合且超出'],
        ['ROP链构造', 'pwnpasi', 'gadget_composer.py + exploit_chaining.py + rop_gadget_semantic_search.py', '完全吻合且超出'],
        ['exploit脚本生成', 'pwnpasi', 'exploit_gen.py + poc_generator.py + exploit_template_engine.py + exploit_transpiler.py + msf_module_generator.py', '完全吻合且超出'],
        ['报告输出', 'pwnpasi', 'report.py + report_enhancement.py + vulnerability_reporter.py + binary_documenter.py', '完全吻合'],
        ['模糊测试', '技术路线', 'entropy_scheduler.py + fuzzing_orchestrator.py + hls_fuzz.py + protocol_fuzz_orchestrator.py', '完全吻合且超出'],
        ['符号执行', '技术路线', 'symexec.py + selective_symexec.py + path_diversity_explorer.py + llm_guided_symbex.py + ml_guided_symbex.py', '完全吻合且超出'],
        ['规则检测', '技术路线', 'rule_engine.py + ir_rule_engine.py + pattern_fallback.py + asm_detector.py', '完全吻合'],
        ['LLM辅助分析', '技术路线', '120+ AI/ML文件（pseudocode_explainer/crash_analyzer_llm/llm_vuln_detector等）', '完全吻合且大幅超出'],
        ['libc依赖识别', '技术路线', 'libc_identifier.py (234行) + libc_database_extender.py', '完全吻合且超出'],
    ]
)

add_heading('4.5 参考工具与依赖对比', level=2)
add_table(
    ['工具', '申报书描述', '实际代码中的使用', '差异'],
    [
        ['pwnpasi', '主要参考源码，借鉴信息收集/利用脚本生成/报告输出', '代码未直接import pwnpasi，但功能模块已全部重新实现并大幅增强', '参考关系吻合，实现独立'],
        ['angr', '辅助符号执行工具', 'symexec.py中check_angr() + constraint_verifier.py使用angr符号执行', '吻合'],
        ['AutoPWN-Suite', '调研了解的工具', '代码中未见直接依赖', '仅调研层面，无代码依赖'],
        ['radare2 (r2)', '未在申报书提及', 'decompiler.py/plt_scanner.py/cfg_extractor_r2.py等大量使用r2命令', '超出申报范围'],
        ['Ghidra', '未在申报书提及', 'decompiler.py中_decompile_ghidra() + ghidra_headless.py + ghidra_script_generator.py', '超出申报范围'],
        ['pwntools', '未在申报书提及', 'exploit_gen.py中_pwntools_arch() + exploit_executor.py使用pwntools', '超出申报范围'],
        ['Z3', '未在申报书提及', 'cj_solver.py/fovf_engine.py/algebraic_heap_solver.py等使用Z3约束求解', '超出申报范围'],
        ['Docker', '未在申报书提及', 'exploit_executor_docker.py + sandbox_exec.py', '超出申报范围'],
        ['OpenAI/Claude/Ollama', 'LLM为辅助组件', '_config_ai.py支持OpenAI/Azure/Ollama/llamacpp/Custom多后端', '吻合且超出'],
    ]
)

add_heading('4.6 创新点对比', level=2)
add_table(
    ['申报书创新点', '实际代码体现', '评估'],
    [
        ['研究对象新颖性：面向真实二进制程序的辅助式分析', '代码支持ELF/PE/Mach-O多格式，含跨编译器泛化、混淆容忍', '吻合且超出'],
        ['技术创新：LLM辅助+传统工具协同', '实现了GAPSBV-CJ/DD-BVF/LSP/PS-CJ等原创算法体系，LLM仅作辅助增强', '实际创新远超申报描述'],
        ['贡献独特性：形成辅助式分析框架', '形成了完整的静态检测+动态验证+exploit生成+报告输出全链路框架', '吻合且大幅超出'],
        ['未提及的实际创新', '15+原创算法体系（CJ/BVF/LSP/CAAWP/HOVF/FOVF/UOVF/FCPV/PCFC/PCFV/ACFPC/TOVS/DDSSC/DESG等）', '申报书未充分描述'],
        ['未提及的实际创新', '堆溢出检测已饱和(F1=1.0, FPR=0.0)', '申报书未提及此成果'],
        ['未提及的实际创新', 'UAF/格式化字符串/整数溢出检测均已达饱和', '申报书未提及此成果'],
        ['未提及的实际创新', '网络协议分析(85文件)/密码学检测(62文件)/平台安全(33文件)', '申报书完全未涉及'],
    ]
)

add_heading('4.7 预期成果对比', level=2)
add_table(
    ['预期成果', '申报书描述', '实际代码现状', '差异'],
    [
        ['辅助式技术路线', '完成基本流程设计并在若干典型样本上验证', '已实现完整pipeline（1062+1480行），在多类样本上达到饱和', '大幅超出'],
        ['可复用成果', '样本集/分析记录/验证脚本/流程图/技术报告', 'cve_samples/含大量样本 + run_all_tests.py + report.py + experiment_tracker', '吻合且超出'],
        ['竞赛与评审', '参加大创结题及网络安全竞赛', '代码已具备展示价值，但无竞赛记录', '待推进'],
        ['专利/软著', '若形成较稳定方案则申请', '15+原创算法体系已达可申请专利深度', '待推进'],
    ]
)

doc.add_page_break()

# ===== 五、关键差异总结 =====
add_heading('五、关键差异总结', level=1)

add_heading('5.1 差异类型分类', level=2)

add_para('A. 代码实现远超申报书描述（正向差异）', bold=True)
add_table(
    ['编号', '差异项', '详情'],
    [
        ['D-01', '算法体系远超申报', '申报书仅描述"LLM辅助+传统工具协同"，实际实现了15+原创算法体系（GAPSBV-CJ、DD-BVF、LSP、PS-CJ、CAAWP、HOVF、FOVF、UOVF、FCPV、PCFC、PCFV、ACFPC、TOVS、DDSSC、DESG），每个体系含5-30个子模块'],
        ['D-02', '检测能力远超申报', '申报书聚焦"辅助式研判"，实际4类核心漏洞检测均已达饱和（F1=1.0, FPR=0.0）'],
        ['D-03', '功能领域远超申报', '申报书未提及网络协议分析(85文件)、密码学检测(62文件)、平台安全(33文件)、供应链分析、沙箱逃逸检测、ROP语义分类等'],
        ['D-04', '二进制分析深度远超申报', '申报书仅提checksec/PLT/ROP搜索，实际含跨编译器泛化、IR统一层、类型推断、SSA构建、间接跳转恢复、反混淆等106个文件'],
        ['D-05', 'exploit生成能力远超申报', '申报书仅提脚本生成，实际含堆布局求解(Z3)、heap feng shui、ROP语义搜索、exploit链最小化、稳定性fuzz、多架构支持等61个文件'],
        ['D-06', 'AI/ML应用远超申报', '申报书仅提LLM辅助，实际含GNN漏洞检测、强化学习利用、对抗鲁棒微调、对比图检索、神经符号类型推断等120+文件'],
    ]
)

add_para('B. 申报书描述与代码实现的定位差异（需关注）', bold=True)
add_table(
    ['编号', '差异项', '详情'],
    [
        ['D-07', '核心定位偏差', '申报书定位为"辅助式研判，不追求全自动"，实际代码以全自动静态检测为核心，已达到检测饱和。LLM在体系中是辅助增强而非核心驱动'],
        ['D-08', 'pwnpasi依赖关系描述不准确', '申报书频繁提及"参考pwnpasi源码"，实际代码已完全独立实现，未import pwnpasi，功能远超pwnpasi能力范围。申报书应修正为"参考pwnpasi设计思路，独立实现并大幅扩展"'],
        ['D-09', '创新点描述不充分', '申报书创新点仅描述"LLM辅助+工具协同"，但实际核心创新在于原创的约束联结求解体系和多层安全证明体系。建议在结题时补充算法创新点的系统描述'],
        ['D-10', '进度与成果不匹配', '申报书进度安排2026年7-8月才"开展基础功能验证"，但代码已展示出远超基础验证的完成度。需在结题报告中说明进度提前的原因和过程'],
    ]
)

add_para('C. 申报书提及但代码中未体现的内容（负向差异）', bold=True)
add_table(
    ['编号', '差异项', '详情'],
    [
        ['D-11', '人工复核机制', '申报书强调"人工复核为保障"，代码中review_gate.py存在但仅是程序化门控，未见实际的人工复核流程记录'],
        ['D-12', '实验样本库', '申报书提及"CTF样本、教学样本和公开漏洞样本"，代码中有样本目录和编译脚本，但未见系统的样本来源标注和分类管理'],
        ['D-13', '竞赛展示材料', '申报书预期参加竞赛，代码中未见竞赛展示用的演示材料或文档'],
    ]
)

doc.add_page_break()

# ===== 六、风险评估与建议 =====
add_heading('六、风险评估与建议', level=1)

add_heading('6.1 风险评估', level=2)
add_table(
    ['风险编号', '风险描述', '风险等级', '影响'],
    [
        ['R-01', '申报书与实际成果定位偏差较大，结题时可能被质疑"申报内容与实际不符"', '高', '影响结题评审'],
        ['R-02', '15+原创算法未在申报书中描述，知识产权保护存在空白', '高', '影响专利申请'],
        ['R-03', '代码规模庞大(5970文件)但缺乏系统文档，可维护性和可解释性存疑', '中', '影响持续性'],
        ['R-04', '部分模块存在编码问题(如acfpc/_smoke_test.py BOM编码)和空文件', '低', '影响代码质量'],
        ['R-05', 'network/crypto/platform等模块与申报书主题关联度低，可能被视为"功能堆砌"', '中', '影响评审印象'],
    ]
)

add_heading('6.2 建议', level=2)

add_para('建议一：修正申报书定位描述', bold=True)
add_para('在结题报告中将项目定位从"LLM辅助的辅助式分析"调整为"多算法融合的二进制漏洞静态检测框架，LLM作为辅助增强组件"。明确核心创新在于原创约束联结求解体系，而非LLM辅助。')

add_para('建议二：系统梳理创新点', bold=True)
add_para('将15+原创算法体系整理为正式的技术创新点列表，每个体系包含：算法名称、核心思想、代码位置、实验数据、与现有工作的对比。为专利申请做准备。')

add_para('建议三：修正pwnpasi描述', bold=True)
add_para('将申报书中"参考pwnpasi源码"的表述修正为"参考pwnpasi等工具的设计思路，独立实现并大幅扩展"。避免知识产权歧义。')

add_para('建议四：精简非核心模块', bold=True)
add_para('network(85文件)、crypto(62文件)、platform(33文件)等模块与二进制漏洞挖掘主题关联度低。建议在结题时将其定位为"框架可扩展性的验证"而非核心功能，避免被质疑功能堆砌。')

add_para('建议五：补充实验记录', bold=True)
add_para('完善样本来源标注、实验过程记录和评估数据，使实验评测部分与申报书预期成果形成完整对应。')

add_para('建议六：准备进度说明', bold=True)
add_para('结题时需说明项目进度为何大幅提前于申报书安排（代码完成度远超2026年8月应达到的阶段），合理解释团队投入和技术积累过程。')

# 结尾
doc.add_paragraph()
end = doc.add_paragraph()
end.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = end.add_run('— 审计报告结束 —')
run.font.size = Pt(12)
run.font.name = '宋体'
run.element.rPr.rFonts.set(qn('w:eastAsia'), '宋体')

# 保存
output_path = r'C:\Users\Administrator\Desktop\BinMind\BinMind项目审计报告_申报书对比.docx'
doc.save(output_path)
print(f'报告已生成: {output_path}')
