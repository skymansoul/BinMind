# -*- coding: utf-8 -*-
# 生成125个创新点说明文档 v3 — 全条目覆盖版
import re, os

SOURCE_FILE = r"C:\Users\Administrator\Desktop\BinMind\新建文件夹\核心创新与论文引用_总汇总_去重版.md"
INDEX_FILE = r"C:\Users\Administrator\Desktop\BinMind\.temp\entry_full_index.txt"
OUTPUT_FILE = r"C:\Users\Administrator\Desktop\BinMind\创新点说明文档.md"
PROJECT_ROOT = r"C:\Users\Administrator\Desktop\BinMind"

with open(SOURCE_FILE, 'r', encoding='utf-8') as f:
    content = f.read()
lines = content.split('\n')

# 读取条目索引
entries = []
with open(INDEX_FILE, 'r', encoding='utf-8-sig') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        parts = line.split('||')
        if len(parts) >= 4:
            entries.append({
                'num': int(parts[0]),
                'h1': parts[1].strip(),
                'path': parts[2].strip(),
                'pyfiles': parts[3].strip()
            })

# 定位每个[N/125]标记的行号
line_map = {}
for i, line in enumerate(lines):
    m = re.match(r'^\[(\d+)/125\]', line)
    if m:
        line_map[int(m.group(1))] = i

# ======================================================================
# 全125条创新点预定义信息: (代号, 论文局限性, 创新思路)
# ======================================================================
INNOVATION_INFO = {
    1: ("HOSV-Ext (堆溢出写模式检测)",
        "Angr CFGFast+符号查找只确认危险函数调用存在，不验证调用上下文(分配大小vs写入大小)，对安全样本FPR=100%；原HOSV仅检出2/12漏洞(Recall=0.167)，不覆盖指针游走/结构数组/无界输入/工厂绑定/终止符五类写模式",
        "对每个候选执行写模式结构证明，从根源区分SAFE/VULN，覆盖指针游走/结构数组/无界输入/工厂绑定/终止符五类写模式，召回从0.167提升至1.000"),

    2: ("四类漏洞精度汇总",
        "通用工具Angr FPR=100%、Ghidra/QEMU召回=0%，无法区分同源安全代码与真实溢出",
        "四类漏洞(堆溢出/UAF/格式串/整数溢出)统一精度评估，AWSC将堆溢出FPR从33.3%降至0%"),

    3: ("HOFPR+UAFL+FSFP三创新交付",
        "Angr通用扫描Recall 1.0但FPR 1.0，无法支撑告警运营；基线FPR=16.7%",
        "HOFPR堆溢出误报抑制器+UAFL UAF生命周期验证器+FSFP格式化字符串误报抑制器，三创新点各自独立过滤误报"),

    4: ("ACFPC+UAF-OG",
        "Angr对UAF Recall仅6.7%(符号语义不适用)；通用工具对堆溢出安全样本FPR=100%",
        "ACFPC五证据链压缩器(同源共变/守卫支配/对齐裕量/字段写/精确匹配)+UAF-OG代际状态机"),

    5: ("AWSC (Allocation-Write Co-Sourcing)",
        "SAW(USENIX Sec 2024)需源码级表达式等价；PPA-HAV(CCS 2024)需可追踪指针来源；区间抽象解释对未知size用宽区间必然重叠→系统性误报",
        "从分配调用点和危险写入调用点的size寄存器出发，沿指令流反向做def-use根来源追踪，归约为立即数/栈槽/参数/返回值四类根来源，比较同源性"),

    6: ("AWSC Related Work",
        "BiSection(USENIX'23)仅处理cmp+jcc守卫；SAW(USENIX'24)仅覆盖malloc(N)+memcpy(N)精确情况；PPA-HAV不建模rep movs内联复制；CLOVER(NDSS'25)仅循环累积溢出",
        "AWSC在stripped二进制上工作，仅需objdump指令流，兼容scaled-index寻址和多跳寄存器链"),

    7: ("HOVF+UOVF+FOVF三创新",
        "区间抽象解释对strcpy类全报；SVF汇合点丢守卫约束；动态检测需触发路径覆盖率低",
        "HOVF分配器宽松核验(削误报)+UOVF值流门控UAF复核+FOVF格式参数值流分类，三创新点共享证据驱动验证内核"),

    8: ("PCFV (Path-Constrained Controllability Verification)",
        "基线DP-TVRA'未知即安全'导致CVE-2021-3156全部过滤(召回崩塌)；基线BFS收集守卫不验证支配性→兄弟分支守卫误过滤",
        "守卫支配性验证+证据强制过滤(无证据不过滤)+分配器宽松语义+循环最后迭代偏移(非峰值)"),

    9: ("创新审计(去伪创新)",
        "7个IntOverflowDetector类实现相同区间算术；9个模块做同样的rdi回溯；5个模块printf(user_var)逻辑完全相同",
        "审计84文件，标记9个伪创新为[DEPRECATED]，保留真正的算法级创新(state machine parser/dataflow backtracking)"),

    10: ("Innovation Depth Audit",
         "503个模块中仅11.9%含真正算法创新，69.4%为纯正则匹配",
         "自动化分类ALGORITHMIC/BASIC_ANALYSIS/PURE_REGEX三级，识别60个算法级模块并标注其数据结构/抽象解释/SMT/算法引用"),

    11: ("TOVS+FMT-SAC",
         "UAF线性扫描按地址序配对free/use忽略控制流结构→分支互斥/提前返回被误报；格式串检测把任何非立即数格式串当漏洞→栈缓冲拼接误报",
         "TOVS后支配时序验证+指针身份重定义验证+FMT-SAC来源五分类+说明符-实参一致性"),

    12: ("GAPSBV/TARPS/FSCS/I-GUARD四创新",
         "GUEB(2014)用VSA产生粗糙区间无关系信息；SVF(2024)流敏感非路径敏感；CSA(2024)双向污点缺仿射差分",
         "仿射关系追踪(Karr 1976)计算write-alloc符号差判定溢出；Union-Find别名+RAP；CVSS式0-10评分；符号阈值+循环归纳"),

    13: ("GAPSBV Paper Contributions",
         "GUEB丢弃不确定发现(损失召回)；SVF值流合并路径(丢失守卫精度)；无工具使用多维保守融合",
         "首个将Karr仿射关系框架应用于堆溢出检测，计算diff=write_expr-alloc_expr证明溢出而无需知道变量值"),

    14: ("Paper Submission Checklist",
         "无SMT求解器/IR提升/训练数据需求，但需完整论文草稿和复现包",
         "四模块全部达到饱和:F1=1.000,FP=0,保守过滤保证零新增漏报"),

    15: ("专利:仿射区间+选择性符号执行",
         "模式匹配(Flawfinder)误报率60-80%；全程序符号执行(Angr)路径爆炸42s/样本；抽象解释(Crab)需LLVM IR",
         "分配器语义过滤→路径敏感仿射区间传播→选择性符号执行→保守启发式四层递进，无SMT求解器依赖"),

    16: ("专利v3:GAPSBV+贝叶斯融合",
         "单漏洞聚焦缺乏跨类型统一评分框架；不同检测器置信度不可比；无仿射关系追踪",
         "四类独立管线+跨管道贝叶斯对数几率融合，管道可靠性权重基于消融研究实证"),

    17: ("专利→代码交叉引用",
         "需证明专利权利要求每个要素都有对应代码实现",
         "独立权利要求1(方法)→8个实现模块映射；独立权利要求2(系统)→6个系统组件映射"),

    18: ("CJ+BVF+PC-BVF约束联结管线",
         "纯区间分析无法证明仿射关系；符号执行路径爆炸；单向值流追踪精度不足",
         "CJ约束联结(仿射等式图)+BVF后向值流(从写入反追分配)+PC-BVF路径条件精化(分支约束窄化)"),

    19: ("44篇堆溢出Related Work",
         "覆盖2014-2026年堆溢出静态检测方向，包括VSA/符号执行/抽象解释/污点分析等",
         "系统梳理44篇顶会论文，识别三大共性缺口：调用点参数角色模板化/无界写入跳过/编译器内联复制不在模型中"),

    20: ("PCFV Related Work",
         "BiSection仅cmp+jcc守卫；Raccoon符号阶段状态爆炸；SAW仅精确malloc(N)+memcpy(N)",
         "PCFV在需求驱动值流分析基础上以支配性验证的路径守卫与证据强制过滤为核心"),

    21: ("格式化字符串文献综述",
         "现有工具二分法printf(user_str)→VULN，不区分说明符语义",
         "综述格式串检测方向，识别%n可写/s泄漏/x栈泄漏的区分需求"),

    22: ("整数溢出文献综述",
         "整数溢出检测工具普遍召回低，缺乏乘积溢出/位移回绕/符号转换的统一处理；IOC需源码重编译；Angr路径爆炸",
         "综述整数溢出检测方向，识别SIZE_MAX阈值分析和守卫感知的缺口；提出8模式汇编+栈值预扫描方法"),

    23: ("专利MIVR: 路径敏感约束传播",
         "符号执行(Angr)路径爆炸precision仅0.45-0.60；抽象解释(Astree)Strided区间过度近似大量误报；数据流工具(Coverity)缺乏路径敏感守卫传播",
         "MIVR三层证明体系：L1路径敏感守卫→写入约束传播+L2共享变量仿射系数比较+L3保守三层证明级联，O(n)复杂度避免路径爆炸"),

    24: ("专利FSTP: 格式说明符语义感知",
         "二值污点分析把所有printf(user_input)标记为CWE-134；不区分%n可写vs%s泄漏vs%x栈泄漏",
         "格式说明符语义感知的5级污点传播方法，区分危险说明符类型，5-level semantic classification是最具影响力的创新"),

    25: ("专利INT-SHIFT: 多模式整数溢出",
         "编译器类型提升掩盖16-bit溢出意图(所有工具看不到)；跨函数SHL检测依赖调用图(angr需全符号执行)；单一检测模式覆盖不足",
         "8模式汇编推理+栈值预扫描(stack-value pre-pass)：LARGE_IMM64/TRUNCATION/SIGNED_IDX/SUSPICIOUS_SIZE/MUL_OVERFLOW/16-bit wraparound/SHL_OVERFLOW/16-bit intent"),

    26: ("专利UAF-HOIG: UAF混合对象身份图",
         "指针别名导致误报(要么过度合并不同对象，要么不追踪旧指针失效)；跨函数释放传播薄弱；无工具追踪对象身份",
         "UAF检测三核心创新：Object identity tracking(消除别名误报)+混合对象身份图(HOIG)+跨函数4+边界4+误报过滤3共11场景覆盖"),

    27: ("堆溢出Related Work (10篇基础)",
         "Angr VSA不足以证明堆溢出；Mayhem路径爆炸；Driller无法证明安全性；SySeVR/VulDeePecker训练数据偏差F1从0.87降至0.45",
         "系统梳理10篇基础论文(S&P/USENIX/CCS/NDSS)，定位MIVR路径敏感约束传播在各维度上的优势"),

    28: ("参数等式+路径守卫+循环累积",
         "纯区间分析对malloc(n*4+8)与memcpy(n*8)无法判定关系；循环累积偏移用峰值iters*stride导致误报；ProFuel(USENIX'21)依赖LLVM IR和符号执行",
         "七阶段按需过滤：L1约束传播配对+L2堆分配器语义+L3值范围传播+L4 CFG可达性+L5参数来源等式(新)+L6路径敏感大小解析(新)+L7循环累积上界(新)，全部仅过滤语义"),

    29: ("Related Work (ai_ml模块)",
         "Mango(USENIX'24)IoT固件专用无堆分配语义47%TP率；IntTracer(ICSE'24)需LLVM IR源码依赖；LATTE LLM推理分钟级延迟幻觉风险；SVF(OOPSLA'18)需LLVM IR二进制适配困难",
         "七阶段按需过滤+堆分配器语义(ptmalloc2/musl/jemalloc)，在stripped x86-64二进制上运行，59ms/样本比Angr快54倍"),

    30: ("AWSC (analysis模块)",
         "SAW需源码级表达式等价；PPA-HAV需可追踪指针来源；区间抽象对未知size必然重叠",
         "从分配调用点和写入调用点的size寄存器出发，沿指令流反向做def-use根来源追踪，归约为四类根来源比较同源性"),

    31: ("AWSC Related Work (analysis模块)",
         "BiSection仅cmp+jcc守卫；SAW仅malloc(N)+memcpy(N)精确情况；CLOVER仅循环累积溢出",
         "在stripped二进制上工作，仅需objdump指令流，兼容scaled-index寻址和多跳寄存器链"),

    32: ("多层误报抑制(core模块)",
         "单层过滤器(如纯正则)无法处理下溢/off-by-one/未初始化内存等多种边界模式",
         "多层误报抑制管线：buffer_underflow/off_by_one/uninitialized_memory/double_free/uaf_enhance/int_overflow_enhance独立模块"),

    33: ("Related Work (core模块)",
         "Angr FPR=100%对含危险函数的安全样本；Ghidra不分析数据流；纯模式匹配FPR=60-80%",
         "多层误报抑制方法在stripped二进制上实现堆溢出检测的系统性误报消除"),

    34: ("PcWBI (Provenance-Constrained Write-Bound Inference)",
         "PPA-HAV(CCS'24)需可追踪指针来源但不建模rep movs/SSE内联存储；编译器内联复制不在其模型",
         "从写入指令的源寄存器反向追踪指针来源(provenance)，推断写界优先使用检测器的字节数write_size而非元素计数"),

    35: ("Related Work (cve模块)",
         "BiSection仅cmp+jcc守卫；Raccoon符号阶段状态爆炸；SAW仅精确malloc(N)+memcpy(N)；无工具建模rep movs内联复制",
         "PcWBI来源约束写界推断在stripped二进制上工作，兼容编译器内联复制模式"),

    36: ("HFP (分配器感知+守卫窄化)",
         "通用工具不建模分配器可用空间(对齐padding)；守卫收集不验证支配性→兄弟分支守卫误过滤",
         "HFP分配器感知(ptmalloc2 request2size)+守卫窄化(仅采信支配访问点的分支守卫)"),

    37: ("Related Work (modules/doc)",
         "Mango无堆分配语义47%TP率；IntTracer需LLVM IR；ProFuel依赖符号执行路径枚举",
         "HFP在objdump反汇编上直接运行，分配器感知+守卫窄化，59ms/样本"),

    38: ("UAF伪IR级指针生命周期",
         "UAF检测跨函数分析普遍薄弱，无调用上下文传播，无函数摘要",
         "伪IR级指针生命周期状态机(ALLOCATED→FREED→DANGLING)，跨函数传播"),

    39: ("HOFPR (堆溢出误报抑制)",
         "Angr CFG基线FPR=100%，基线无HOFPR过滤FPR=16.7%",
         "HOFPR十模块管线：类型/污点/来源界/对齐/守卫/仿射/关联/累积/过滤器/管线"),

    40: ("Related Work (exploit模块)",
         "Angr FPR=100%对含危险函数安全样本；Ghidra无数据流分析；QEMU召回仅45%",
         "HOFPR十模块管线在stripped二进制上实现FPR从16.7%降至0%"),

    41: ("FC-VRA (流相关值域分析)",
         "传统VSA值集分析不追踪值与分配点的关联；区间分析在合并点丢失路径约束",
         "流相关值域分析：值流追踪+区间传播+分配点关联，提高路径敏感精度"),

    42: ("Related Work (info模块)",
         "VSA(CAV'06)源码级不适用二进制；SVF需LLVM IR；区间分析合并点丢约束",
         "FC-VRA在二进制层面运行，值流追踪+分配点关联实现路径敏感"),

    43: ("CACBV (容量感知耦合边界验证)",
         "区间分析对malloc(n)与memcpy(buf,n)的区间重叠即告警，不验证参数耦合关系",
         "容量感知耦合：分配容量与写入大小的身份键比较，验证是否来自同一数据流根"),

    44: ("Related Work (parallel_deep_dev模块)",
         "区间分析只看区间重叠不验证耦合；符号执行路径爆炸；静态污点不建模分配器",
         "CACBV身份键比较方法在二进制层面验证分配-写入参数耦合关系"),

    45: ("写侧值流区间抽象+双向交汇",
         "单向值流追踪(前向或后向)精度不足；区间分析不建模分配器语义",
         "写侧值流区间抽象+双向交汇验证(前向从分配到写入+后向从写入到分配)"),

    46: ("值流大小耦合驱动",
         "不区分数据流的工具把malloc(n)+memcpy(n)一律当溢出",
         "值流大小耦合：分配size与写入size的值流追踪+身份键比较，同根同源判安全"),

    47: ("Related Work (project模块)",
         "Angr FPR=100%；Ghidra无数据流；纯模式匹配FPR=60-80%；区间分析重叠即告警",
         "值流大小耦合驱动方法在二进制层面区分同源安全写入与真实溢出"),

    48: ("PG-WBV (分配点感知写界验证)",
         "通用工具不区分堆/栈/全局写入；不追踪分配点上下文",
         "分配点感知+写界验证：从分配点前向追踪分配大小，从写入点反向追踪写入大小，交汇判定"),

    49: ("Related Work (testing模块)",
         "Angr/Ghidra不区分堆栈全局写入；QEMU路径覆盖率低；无工具追踪分配点上下文",
         "PG-WBV在二进制层面区分堆/栈/全局写入，跨函数堆追踪分配点上下文"),

    50: ("ACPE (分配容量溯源等价分析)",
         "SAW需源码级表达式等价，不适用于stripped二进制；区间分析区间重叠即告警",
         "分配容量溯源：从分配点和写入点分别做后向溯源，比较溯源链等价性"),

    51: ("Related Work (vuln/detection模块-ACPE)",
         "SAW需源码AST等价；GUEB VSA粗糙区间无关系信息；区间分析重叠即告警",
         "ACPE后向溯源链等价性比较在stripped二进制上工作"),

    52: ("ACFPC (分配契约流保持压缩)",
         "通用工具不提取分配契约(size来源+返回值落点)；不验证写-分配参数耦合",
         "五证据链压缩器：同源共变写/守卫支配写/对齐裕量/字段写几何/精确匹配，三值判决SUPPRESS/CONFIRM/UNCHANGED"),

    53: ("Related Work (vuln模块-ACFPC)",
         "GUEB无关系信息丢弃不确定发现；SVF流敏感非路径敏感；无工具多维保守融合",
         "ACFPC五证据链+三值判决在二进制层面实现分配契约流保持压缩"),

    54: ("DDSSC (Demand-Driven Symbolic Size Correlation)",
         "CJ约束联结需构建全局符号表达式，复杂度高；BVF后向追踪遇call即终止精度差；全程序符号执行路径爆炸(15个CVE中42ms/样本)",
         "按需符号大小关联：CJ约束联结+BVF后向值流+LSP分层安全证明+SGAV守卫感知区间验证，按需触发避免全程序分析，仅7.1%告警需SMT"),

    55: ("堆溢出误报削减文献调研",
         "覆盖2024-2026顶会论文，包括SAW/PPA-HAV/CLOVER/BiSection/Mango等",
         "系统调研报告，识别三大共性缺口并定位DDSSC的按需触发架构优势"),

    56: ("Related Work (DDSSC基础)",
         "GUEB VSA粗糙区间丢弃不确定发现损失召回；区间分析过度近似产生误报",
         "DDSSC按需级联验证在精度与性能间取得平衡，15个CVE样本F1=1.000"),

    57: ("BWR+PCST (有界写恢复+路径条件敏感污点)",
         "传统写入检测不区分有界写(在分配范围内)与越界写；路径不敏感工具丢失守卫约束",
         "有界写恢复(bounded_write_recovery)+路径条件敏感污点(path_condition_sensitive_taint)"),

    58: ("FMTPROV (格式化字符串常量折叠+污点溯源)",
         "printf(user_var)检测不区分常量缓冲全填充与用户写入；不追踪跨函数格式参数来源",
         "常量折叠(全常量填充缓冲→FILTER)+污点溯源(用户源→CONFIRMED)+模板间接可控识别"),

    59: ("GASRI (守卫感知值域推理)",
         "传统值域分析在合并点丢失守卫约束；不验证守卫支配性",
         "守卫感知值域推理：仅采信支配访问点的守卫，守卫经槽解析与访问索引匹配"),

    60: ("HOSV-Ext (写模式驱动堆溢出检测)",
         "原HOSV仅检出2/12漏洞(Recall=0.167)，不覆盖指针游走/结构数组/无界输入/工厂绑定/终止符五类写模式",
         "八模块扩展：walk_write/struct_idx/unbounded_io/factory_bind/null_terminator+协调器+类型定义+USV补入"),

    61: ("UAF-PROV (UAF指针来源归因验证器)",
         "UAF检测不追踪指针来源(分配/释放/别名)，无法区分真实UAF与重赋值安全",
         "指针来源归因：从use点反向追踪指针来源链，区分悬垂指针与重赋值/NULL置位后的安全指针"),

    62: ("DD-BVF (按需后向值流)",
         "前向值流追踪精度受合并点影响；全程序后向分析复杂度高；CJ求解器遇多跳赋值链返回INCONCLUSIVE",
         "按需触发：仅在CJ约束联结判定POSSIBLE时启用BVF后向追踪，从写入点反向追踪到分配点，18样本F1=1.000"),

    63: ("Related Work (doc根目录)",
         "BiSection仅cmp+jcc守卫；Raccoon符号阶段状态爆炸；SAW仅精确malloc(N)+memcpy(N)；Mango无堆分配语义",
         "DDSSC+AWSC+PcWBI+BWR四创新点整合，在stripped二进制上实现按需级联验证"),

    64: ("Related Work (格式串检测)",
         "cwe_checker需Ghidra P-Code IR慢且不区分.rdata常量与栈缓冲；Infer/CodeQL需源码AST；动态fuzzing覆盖率低",
         "FMT-SPEC寄存器后向追踪+PE .rdata提取实现二进制级格式串检测，130ms/binary"),

    65: ("Related Work (GASRI)",
         "VSA合并点精度损失；不验证守卫支配性；SVF流敏感非路径敏感",
         "GASRI守卫感知值域推理仅采信支配访问点守卫"),

    66: ("Related Work (HOSV-Ext)",
         "Angr CFGFast不验证调用上下文FPR=100%；Ghidra仅函数名匹配无写入模式分析",
         "HOSV-Ext八模块覆盖五类写模式，召回从0.167提升至1.000"),

    67: ("Related Work (UAF-PROV)",
         "UAF检测不追踪指针来源身份；跨函数释放传播薄弱；指针别名导致误报",
         "UAF-PROV指针来源归因从use点反向追踪，区分悬垂与重赋值安全指针"),

    68: ("AWSC (doc根目录副本)",
         "SAW需源码级表达式等价；PPA-HAV需可追踪指针来源；区间抽象必然重叠",
         "从分配和写入调用点size寄存器反向做def-use根来源追踪，四类根来源同源性比较"),

    69: ("AWSC Related Work (doc根目录副本)",
         "BiSection仅cmp+jcc守卫；SAW仅malloc(N)+memcpy(N)；CLOVER仅循环累积",
         "在stripped二进制上工作，兼容scaled-index寻址和多跳寄存器链"),

    70: ("AWSC (doc根目录副本2)",
         "SAW需源码级表达式等价；PPA-HAV需可追踪指针来源",
         "从size寄存器反向def-use根来源追踪，四类根来源同源性比较"),

    71: ("AWSC Related Work (doc根目录副本2)",
         "BiSection仅cmp+jcc守卫；SAW仅精确malloc+memcpy",
         "在stripped二进制上工作，仅需objdump指令流"),

    72: ("按需值流+分配器语义 (ai_ml模块)",
         "纯模式匹配不区分安全/危险memcpy无数据流；Angr路径爆炸指数复杂度；IntTracer需LLVM IR源码依赖；Mango无堆分配语义47%TP率",
         "四阶段按需值流过滤+堆分配器语义(ptmalloc2 usable_size)+UAF三阶段管线(别名感知+路径敏感+严重性评估)+格式串三阶段+差分约束图(DCG)Floyd-Warshall传递闭包"),

    73: ("Related Work (ai_ml模块-按需值流)",
         "Mango(USENIX'24)IoT专用无堆语义47%TP；IntTracer(ICSE'24)需LLVM IR；LATTE LLM分钟级延迟；SVF需LLVM IR二进制适配困难；SaTC关键词启发式",
         "四阶段按需过滤在stripped二进制上59ms/样本，精确率97.2%召回100%，比Angr快54倍"),

    74: ("二进制级堆溢出误报消除 (analysis模块)",
         "Angr/Ghidra对含危险函数安全样本FPR=100%；Octagon域不建模分配器语义；纯模式匹配不区分安全/危险写入",
         "八边形域(Octagon)区间抽象+路径条件+循环写累积+符号关联+分配器模型+UAF路径敏感检测+格式串三阶段+整数溢出三阶段"),

    75: ("Related Work (analysis模块)",
         "Octagon域(Miné 2006)不建模分配器；VSA合并点精度损失；符号执行路径爆炸",
         "八边形域+分配器模型+路径条件在二进制层面实现误报消除"),

    76: ("多层误报抑制 (core模块-copy)",
         "单层过滤器无法处理下溢/off-by-one/未初始化内存/double_free/uaf_enhance/int_overflow_enhance等多种边界模式",
         "多层误报抑制：buffer_underflow/off_by_one/uninitialized_memory/double_free/uaf_enhance/int_overflow_enhance独立模块"),

    77: ("专利: 堆溢出误报抑制方法及系统 (core模块)",
         "符号执行路径爆炸precision 0.45-0.60；抽象解释过度近似大量误报；数据流工具不路径敏感",
         "多层误报抑制方法及系统专利，覆盖堆溢出检测中六类系统性误报根因"),

    78: ("Related Work (core模块-copy)",
         "Angr FPR=100%；Ghidra无数据流；纯模式匹配FPR=60-80%",
         "多层误报抑制在stripped二进制上实现系统性误报消除"),

    79: ("多类型二进制漏洞检测体系 (data模块)",
         "单漏洞聚焦工具缺乏跨类型统一检测框架；各检测器独立运行不共享证据",
         "五类漏洞统一检测：堆溢出/UAF/格式化字符串/整数溢出/栈溢出，各自独立检测器+统一管线"),

    80: ("Related Work (data模块)",
         "单漏洞工具无跨类型框架；Angr/Ghidra高FPR；动态检测覆盖率低",
         "五类漏洞统一检测体系在stripped二进制上运行"),

    81: ("跨域稀疏值流追踪 (exploit模块)",
         "密集值流分析复杂度高不可扩展；跨函数值流追踪普遍薄弱",
         "跨域稀疏值流：仅在需要时触发值流追踪，跨函数/跨域(堆/栈/全局)传播"),

    82: ("Related Work (exploit模块)",
         "密集值流不可扩展；跨函数追踪薄弱；无跨域(堆/栈/全局)分析",
         "跨域稀疏值流在需要时触发，降低复杂度同时保持精度"),

    83: ("PSVR-HLM (路径敏感值域推理-分层模型) (info模块)",
         "传统VSA合并点精度损失严重；不验证守卫支配性；不建模分配器padding",
         "PSVR路径敏感值域推理+HLM分层模型(L2路径守卫/L3分配器padding/FM边界推导)"),

    84: ("Related Work (info模块-copy)",
         "VSA合并点精度损失；不验证守卫支配性；SVF流敏感非路径敏感",
         "PSVR-HLM分层模型在二进制层面实现路径敏感值域推理"),

    85: ("轻量符号表达式引擎+4-Filter链 (patching模块)",
         "全程序符号执行(Angr)路径爆炸42s/样本；SMT求解器不可扩展；抽象解释需LLVM IR",
         "轻量符号表达式引擎(无SMT)+4级过滤链(分配器语义/仿射区间/路径条件/保守启发式)"),

    86: ("Related Work (patching模块)",
         "Angr路径爆炸42s/样本；SMT不可扩展；Crab需LLVM IR",
         "轻量符号表达式引擎无SMT依赖，4级过滤链级联验证"),

    87: ("UAF检测二级创新 (patching模块)",
         "UAF检测跨函数分析薄弱；不追踪通过堆内存的指针别名；无对象身份追踪",
         "UAF二级创新：着色分配追踪+LifetimeState状态机+置信度衰减+跨函数传播"),

    88: ("分配点感知值范围分析 (project模块)",
         "通用工具不区分堆/栈/全局写入；不追踪分配点上下文；区间分析合并点丢约束",
         "分配点感知值范围分析：从分配点前向追踪+写入点反向追踪+交汇判定"),

    89: ("Related Work (project模块)",
         "Angr FPR=100%；Ghidra无数据流；纯模式匹配FPR=60-80%；区间分析合并点丢约束",
         "分配点感知值范围分析在二进制层面区分堆/栈/全局写入"),

    90: ("GAPSBV (仿射关系追踪堆溢出检测) (testing模块)",
         "GUEB VSA粗糙区间无关系信息；SVF流敏感非路径敏感；CSA双向污点缺仿射差分",
         "Karr仿射关系追踪：计算diff=write_expr-alloc_expr，对正变量值判定符号，无需知道变量具体值"),

    91: ("Related Work (testing模块)",
         "Angr FPR=100%路径爆炸；Ghidra无数据流；QEMU召回45%；Flawfinder FPR=85%",
         "GAPSBV仿射关系追踪在stripped二进制上运行，12ms/样本"),

    92: ("DP-TVRA (需求驱动路径敏感污点-值域分析) (vuln_detection模块)",
         "传统污点分析不结合值域；值域分析不追踪污点传播；全程序分析复杂度高",
         "需求驱动+路径敏感+污点-值域联合分析：按需触发符号化+路径约束窄化+污点源到分配点传播"),

    93: ("Related Work (vuln_detection模块)",
         "传统污点不结合值域；VSA不追踪污点；符号执行路径爆炸",
         "DP-TVRA联合分析在二进制层面按需触发"),

    94: ("Related Work (vuln_detection模块-survey)",
         "Angr FPR=100%；Ghidra无数据流；Mango无堆语义",
         "综合调研定位DP-TVRA需求驱动联合分析的优势"),

    95: ("路径敏感按需约束传播 (vuln模块)",
         "传统约束传播不验证守卫支配性(兄弟分支守卫误过滤)；全程序约束收集复杂度高；纯区间分析无法证明仿射关系",
         "路径敏感按需约束传播：守卫支配验证+按需触发约束收集+五证据链(常量/守卫/最小块/循环界/分配器)+多漏洞覆盖(堆/UAF/格式串/整数溢出/栈溢出)"),

    96: ("Related Work (vuln模块)",
         "Angr FPR=100%路径爆炸；Ghidra无数据流；纯模式匹配FPR=60-80%；Mango无堆语义",
         "路径敏感按需约束传播在stripped二进制上运行"),

    97: ("FMT-SPEC (寄存器后向追踪+PE .rdata提取)",
         "cwe_checker需Ghidra P-Code IR慢且不区分.rdata常量与栈缓冲；Infer/CodeQL需源码AST；Angr符号执行60-600s/binary路径爆炸；BinaryFmtScanner v2无格式符解析F1≈0.5",
         "三阶段管线：Phase1 POSIX格式说明符解析(5级危险分类)+Phase2 PE .rdata提取+寄存器后向追踪(rbp+offset→参数TAINTED, rip+offset→.rdata SAFE)+Phase3 交叉验证+CRT FP过滤，130ms/binary, Recall=100%"),

    98: ("SHIELD (选择性堆区间证据逻辑消歧)",
         "Angr FPR=100%(对每个strcpy/memcpy调用上报)；Ghidra不分析数据流；QEMU路径覆盖率低",
         "选择性堆区间证据逻辑消歧：size_bound_correlation+pointer_provenance+disjointness_prover多证据链"),

    99: ("Related Work (SHIELD)",
         "Angr FPR=100%；Ghidra无数据流；SAW需源码LLVM IR；Heap Disjointness(ISSTA'24)需LLVM IR不适用于stripped",
         "SHIELD多证据链在stripped二进制上实现选择性消歧"),

    100: ("INT-RANGE (区间抽象解释驱动整数溢出)",
          "整数溢出检测工具普遍召回低(IOC Recall=0.65需源码重编译；CodeQL R=0.65需源码；Angr R=0.737路径爆炸)；不处理乘积溢出/位移回绕/符号转换/16-bit编译器提升",
          "区间抽象解释驱动：前向区间传播+widening/narrowing+乘积/位移/符号转换溢出检测，21样本F1=0.973 P=1.000"),

    101: ("DRIFT (按需反向信息流追踪UAF检测)",
          "UAF检测不追踪指针对象身份；跨函数释放传播薄弱；线性扫描按地址序配对忽略控制流",
          "按需反向信息流：从use点反向追踪到free点+object_identity追踪+pointer_kill_set标记悬垂"),

    102: ("三路按需深度静态分析",
          "单路分析(仅前向或仅后向)精度不足；三类漏洞(堆溢出/UAF/格式串)分析互不共享证据",
          "三路按需：堆溢出误报压制+UAF指针重生追踪+格式串来源溯源，共享值流追踪基础设施"),

    103: ("Related Work (三路按需)",
          "单路分析精度不足；三类漏洞分析不共享基础设施；跨函数追踪薄弱",
          "三路按需分析共享值流追踪基础设施，降低重复计算成本"),

    104: ("多层误报抑制 compat层",
          "单层过滤无法处理编译器优化(O2内联/死存储消除)导致的模式变异",
          "compat层兼容：fmt_binary(二进制格式串)+uaf_binary(二进制UAF)适配stripped二进制"),

    105: ("Related Work (compat层)",
          "编译器优化导致模式变异，传统正则匹配失效；无工具处理O2内联复制",
          "compat层适配stripped二进制中的编译器优化模式"),

    106: ("PcWBI (来源约束写界推断-cve副本)",
          "PPA-HAV不建模编译器内联复制(rep movs/SSE存储)；来源追踪遇call即终止",
          "来源约束写界推断：从写入指令反向追踪指针来源+写界优先使用检测器字节数+跨函数摘要"),

    107: ("Related Work (cve副本)",
          "PPA-HAV不建模内联复制；BiSection仅cmp+jcc守卫；SAW需源码",
          "PcWBI在stripped二进制上兼容编译器内联复制模式"),

    108: ("HOFPR (exploit副本)",
          "基线无HOFPR过滤FPR=16.7%；Angr FPR=100%",
          "HOFPR十模块：类型/污点/来源界/对齐/守卫/仿射/关联/累积/过滤器/管线主流程"),

    109: ("Related Work (exploit副本)",
          "Angr FPR=100%；Ghidra无数据流；QEMU召回45%",
          "HOFPR十模块在stripped二进制上FPR从16.7%降至0%"),

    110: ("FC-VRA (info副本)",
          "传统VSA不追踪值与分配点关联；区间分析合并点丢约束",
          "流相关值域分析：值流追踪+区间传播+分配点关联"),

    111: ("Related Work (info副本)",
          "VSA(CAV'06)源码级；SVF需LLVM IR；区间分析合并点丢约束",
          "FC-VRA在二进制层面运行，值流追踪+分配点关联"),

    112: ("CACBV (parallel_deep_dev副本)",
          "区间分析只看区间重叠不验证参数耦合",
          "容量感知耦合：分配容量与写入大小身份键比较"),

    113: ("Related Work (parallel_deep_dev副本)",
          "区间分析重叠即告警；符号执行路径爆炸；静态污点不建模分配器",
          "CACBV身份键比较在二进制层面验证参数耦合"),

    114: ("写侧值流区间+双向交汇 (patching副本)",
          "单向值流精度不足；不建模分配器语义",
          "写侧值流区间+双向交汇(前向+后向)"),

    115: ("Related Work (patching副本)",
          "单向值流精度不足；区间分析重叠即告警；不建模分配器",
          "写侧值流+双向交汇在二进制层面实现分配器感知验证"),

    116: ("值流大小耦合 (project副本)",
          "不区分数据流的工具把同源malloc+memcpy一律当溢出",
          "值流大小耦合：同根同源判安全"),

    117: ("Related Work (project副本)",
          "Angr FPR=100%；纯模式匹配FPR=60-80%；区间分析重叠即告警",
          "值流大小耦合在二进制层面区分同源安全写入与真实溢出"),

    118: ("PG-WBV (testing副本)",
          "通用工具不区分堆/栈/全局写入；不追踪分配点上下文",
          "分配点感知+写界验证+跨函数堆追踪+uaf_fpmin_scanner+格式串参数检查+整数溢出FP样本"),

    119: ("Related Work (testing副本)",
          "Angr/Ghidra不区分堆栈全局写入；QEMU覆盖率低",
          "PG-WBV在二进制层面区分堆/栈/全局写入"),

    120: ("ACPE (vuln/detection副本)",
          "SAW需源码级表达式等价；区间重叠即告警",
          "分配容量溯源：后向溯源链等价性比较"),

    121: ("Related Work (vuln/detection副本)",
          "SAW需源码AST等价；GUEB VSA粗糙区间；区间分析重叠即告警",
          "ACPE后向溯源链等价性在stripped二进制上工作"),

    122: ("ACFPC (vuln副本)",
          "不提取分配契约；不验证写-分配耦合",
          "五证据链压缩器+三值判决"),

    123: ("Related Work (vuln副本)",
          "GUEB无关系信息；SVF流敏感非路径敏感；无工具多维保守融合",
          "ACFPC五证据链在二进制层面实现分配契约流保持压缩"),

    124: ("核心创新与论文汇总",
          "各创新点分散在不同模块文档中，缺乏统一汇总视角",
          "将分散的创新文档汇总为统一文件，覆盖allocator_chunk_model+config+value_range_propagator三个核心脚本"),

    125: ("创新点整合报告",
          "各创新点分散在不同模块文档中，缺乏统一整合视角",
          "整合全部创新点为统一报告，标注各创新点的实现进度和饱和状态，覆盖adaptive_scheduler+drift_calibrator+subreg_taint+cfg_entropy_fingerprint+checksec_to_cvss+value_range_propagator"),
}

# ======================================================================
# 文档生成主逻辑
# ======================================================================

def fix_py_path(pf, project_root):
    """将脚本文件名映射到完整路径，修复路径映射问题"""
    pf = pf.strip()
    if not pf or not pf.endswith('.py'):
        return None
    # 去除前导斜杠和多余前缀
    pf = pf.lstrip('/')
    pf = pf.lstrip('\\')
    # 如果已经包含完整路径
    if pf.startswith('C:\\') or pf.startswith('C:/'):
        return None  # 跳过已经是完整路径的
    # 以 deemo/ 开头
    if pf.startswith('deemo/'):
        return os.path.join(project_root, pf.replace('/', '\\'))
    # 以 modules/ analysis/ core/ eval/ tests/ doc/ 开头
    for prefix in ['modules/', 'analysis/', 'core/', 'eval/', 'tests/', 'doc/']:
        if pf.startswith(prefix):
            return os.path.join(project_root, 'deemo', pf.replace('/', '\\'))
    # 其他情况，放在 deemo/ 下
    return os.path.join(project_root, 'deemo', pf.replace('/', '\\'))


def extract_description(block_lines, fallback):
    """从条目块中提取描述段落"""
    for line in block_lines[2:min(30, len(block_lines))]:
        stripped = line.strip()
        if (stripped and 
            not stripped.startswith('#') and 
            not stripped.startswith('>') and 
            not stripped.startswith('|') and 
            not stripped.startswith('```') and 
            not stripped.startswith('---') and 
            not stripped.startswith('===') and
            not stripped.startswith('AIGC') and
            not stripped.startswith('Content') and
            not stripped.startswith('Label') and
            not stripped.startswith('Produce') and
            not stripped.startswith('Propagate') and
            not stripped.startswith('Reserved') and
            not stripped.startswith('[') and
            not stripped.startswith('同内容副本') and
            len(stripped) > 20):
            return stripped[:500]
    return fallback


out = []
out.append("# BinMind 创新点说明文档\n")
out.append("> 基于核心创新与论文引用总汇总(去重版)整理，共计 125 个创新点条目。")
out.append("> 每条包含：创新点说明（参考论文局限性）、对应脚本文件路径、创新思路。\n")

for entry in entries:
    num = entry['num']
    h1 = entry['h1'] if entry['h1'] else "(无标题)"
    src_path = entry['path']
    pyfiles_raw = entry['pyfiles']

    start = line_map.get(num, 0)
    end = line_map.get(num + 1, len(lines))
    block_lines = lines[start:end]

    info = INNOVATION_INFO.get(num, None)
    # 如果没有预定义信息，构造基本信息
    if not info:
        code_name = h1 if h1 and h1 != "(无标题)" else f"创新点{num}"
        info = (code_name, "参见源文件中的Related Work部分。", f"围绕二进制漏洞静态检测误报抑制展开。")

    # 处理脚本文件路径
    py_files = []
    seen = set()
    if pyfiles_raw:
        raw_list = pyfiles_raw.split(';')
        for pf in raw_list:
            full = fix_py_path(pf, PROJECT_ROOT)
            if full and full not in seen:
                seen.add(full)
                py_files.append(full)

    # 提取描述
    desc = extract_description(block_lines, info[0])

    out.append("\n---\n")
    out.append(f"\n## 创新点 {num}: {info[0]}\n")
    out.append(f"**源文件**: `{src_path}`\n")

    out.append(f"\n### 1. 创新点说明（参考了什么已有论文的局限）\n")
    out.append(f"{info[0]}：{desc}\n")
    out.append(f"\n**参考论文局限性**：{info[1]}\n")

    out.append(f"\n### 2. 对应脚本文件\n")
    if py_files:
        for pf in py_files[:15]:
            out.append(f"- `{pf}`\n")
        if len(py_files) > 15:
            out.append(f"- ...等共 {len(py_files)} 个脚本文件\n")
    else:
        out.append("- （该条目为文档/报告/专利类创新点，无直接对应脚本文件）\n")

    out.append(f"\n### 3. 创新思路\n")
    out.append(f"{info[2]}\n")

with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    f.write('\n'.join(out))

print(f"Done: {len(out)} lines, {os.path.getsize(OUTPUT_FILE)} bytes")
