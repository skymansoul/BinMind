# -*- coding: utf-8 -*-
# 生成125个创新点说明文档 v2
import re, os

SOURCE_FILE = r"C:\Users\Administrator\Desktop\BinMind\新建文件夹\核心创新与论文引用_总汇总_去重版.md"
INDEX_FILE = r"C:\Users\Administrator\Desktop\BinMind\.temp\entry_full_index.txt"
OUTPUT_FILE = r"C:\Users\Administrator\Desktop\BinMind\创新点说明文档.md"
PROJECT_ROOT = r"C:\Users\Administrator\Desktop\BinMind"

with open(SOURCE_FILE, 'r', encoding='utf-8') as f:
    content = f.read()
lines = content.split('\n')

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

line_map = {}
for i, line in enumerate(lines):
    m = re.match(r'^\[(\d+)/125\]', line)
    if m:
        line_map[int(m.group(1))] = i

out = []
out.append("# BinMind 创新点说明文档\n")
out.append("> 基于核心创新与论文引用总汇总(去重版)整理，共计 125 个创新点条目。")
out.append("> 每条包含：创新点说明、参考论文局限性、对应脚本文件路径、创新思路。\n")

# Known innovation summaries for key entries
INNOVATION_INFO = {
    1: ("HOSV-Ext", "Angr CFGFast+符号查找只确认危险函数调用存在，不验证调用上下文(分配大小vs写入大小)，对安全样本FPR=100%", "对每个候选执行写模式结构证明，从根源区分SAFE/VULN，覆盖指针游走/结构数组/无界输入/工厂绑定/终止符五类写模式"),
    2: ("AWSC/UAF/FMT/INT精度汇总", "通用工具Angr FPR=100%、Ghidra/QEMU召回=0%，无法区分同源安全代码与真实溢出", "四类漏洞统一精度评估，AWSC将堆溢出FPR从33.3%降至0%"),
    3: ("HOFPR/UAFL/FSFP三创新点交付", "Angr通用扫描Recall 1.0但FPR 1.0，无法支撑告警运营；基线FPR=16.7%", "HOFPR堆溢出误报抑制器+UAFL UAF生命周期验证器+FSFP格式化字符串误报抑制器，三创新点各自独立过滤误报"),
    4: ("ACFPC+UAF-OG", "Angr对UAF Recall仅6.7%(符号语义不适用)；通用工具对堆溢出安全样本FPR=100%", "ACFPC五证据链压缩器(同源共变/守卫支配/对齐裕量/字段写/精确匹配)+UAF-OG代际状态机"),
    5: ("AWSC(Allocation-Write Co-Sourcing)", "SAW(USENIX Sec 2024)需源码级表达式等价；PPA-HAV(CCS 2024)需可追踪指针来源；区间抽象解释对未知size用宽区间必然重叠→系统性误报", "从分配调用点和危险写入调用点的size寄存器出发，沿指令流反向做def-use根来源追踪，归约为立即数/栈槽/参数/返回值四类根来源，比较同源性"),
    6: ("AWSC Related Work", "BiSection(USENIX'23)仅处理cmp+jcc守卫；SAW(USENIX'24)仅覆盖malloc(N)+memcpy(N)精确情况；PPA-HAV不建模rep movs内联复制；CLOVER(NDSS'25)仅循环累积溢出", "AWSC在stripped二进制上工作，仅需objdump指令流，兼容scaled-index寻址和多跳寄存器链"),
    7: ("HOVF+UOVF+FOVF三创新", "区间抽象解释对strcpy类全报；SVF汇合点丢守卫约束；动态检测需触发路径覆盖率低", "HOVF分配器宽松核验(削误报)+UOVF值流门控UAF复核+FOVF格式参数值流分类，三创新点共享证据驱动验证内核"),
    8: ("PCFV(Path-Constrained Controllability Verification)", "基线DP-TVRA'未知即安全'导致CVE-2021-3156全部过滤(召回崩塌)；基线BFS收集守卫不验证支配性→兄弟分支守卫误过滤", "守卫支配性验证+证据强制过滤(无证据不过滤)+分配器宽松语义+循环最后迭代偏移(非峰值)"),
    9: ("创新审计(去伪创新)", "7个IntOverflowDetector类实现相同区间算术；9个模块做同样的rdi回溯；5个模块printf(user_var)逻辑完全相同", "审计84文件，标记9个伪创新为[DEPRECATED]，保留真正的算法级创新(state machine parser/dataflow backtracking)"),
    10: ("Innovation Depth Audit", "503个模块中仅11.9%含真正算法创新，69.4%为纯正则匹配", "自动化分类ALGORITHMIC/BASIC_ANALYSIS/PURE_REGEX三级，识别60个算法级模块并标注其数据结构/抽象解释/SMT/算法引用"),
    11: ("TOVS+FMT-SAC", "UAF线性扫描按地址序配对free/use忽略控制流结构→分支互斥/提前返回被误报；格式串检测把任何非立即数格式串当漏洞→栈缓冲拼接误报", "TOVS后支配时序验证+指针身份重定义验证+FMT-SAC来源五分类+说明符-实参一致性"),
    12: ("GAPSBV/TARPS/FSCS/I-GUARD四创新", "GUEB(2014)用VSA产生粗糙区间无关系信息；SVF(2024)流敏感非路径敏感；CSA(2024)双向污点缺仿射差分", "仿射关系追踪(Karr 1976)计算write-alloc符号差判定溢出；Union-Find别名+RAP；CVSS式0-10评分；符号阈值+循环归纳"),
    13: ("GAPSBV Paper Contributions", "GUEB丢弃不确定发现(损失召回)；SVF值流合并路径(丢失守卫精度)；无工具使用多维保守融合", "首个将Karr仿射关系框架应用于堆溢出检测，计算diff=write_expr-alloc_expr证明溢出而无需知道变量值"),
    14: ("Paper Submission Checklist", "无SMT求解器/IR提升/训练数据需求，但需完整论文草稿和复现包", "四模块全部达到饱和:F1=1.000,FP=0,保守过滤保证零新增漏报"),
    15: ("专利:仿射区间+选择性符号执行", "模式匹配(Flawfinder)误报率60-80%；全程序符号执行(Angr)路径爆炸42s/样本；抽象解释(Crab)需LLVM IR", "分配器语义过滤→路径敏感仿射区间传播→选择性符号执行→保守启发式四层递进，无SMT求解器依赖"),
    16: ("专利v3:GAPSBV+贝叶斯融合", "单漏洞聚焦缺乏跨类型统一评分框架；不同检测器置信度不可比；无仿射关系追踪", "四类独立管线+跨管道贝叶斯对数几率融合，管道可靠性权重基于消融研究实证"),
    17: ("专利→代码交叉引用", "需证明专利权利要求每个要素都有对应代码实现", "独立权利要求1(方法)→8个实现模块映射；独立权利要求2(系统)→6个系统组件映射"),
    18: ("CJ+BVF+PC-BVF约束联结管线", "纯区间分析无法证明仿射关系；符号执行路径爆炸；单向值流追踪精度不足", "CJ约束联结(仿射等式图)+BVF后向值流(从写入反追分配)+PC-BVF路径条件精化(分支约束窄化)"),
    19: ("44篇堆溢出Related Work", "覆盖2014-2026年堆溢出静态检测方向，包括VSA/符号执行/抽象解释/污点分析等", "系统梳理44篇顶会论文，识别三大共性缺口：调用点参数角色模板化/无界写入跳过/编译器内联复制不在模型中"),
    20: ("PCFV Related Work", "BiSection仅cmp+jcc守卫；Raccoon符号阶段状态爆炸；SAW仅精确malloc(N)+memcpy(N)", "PCFV在需求驱动值流分析基础上以支配性验证的路径守卫与证据强制过滤为核心"),
    21: ("格式化字符串文献综述", "现有工具二分法printf(user_str)→VULN，不区分说明符语义", "综述格式串检测方向，识别%n可写/s泄漏/x栈泄漏的区分需求"),
    22: ("整数溢出文献综述", "整数溢出检测工具普遍召回低，缺乏乘积溢出/位移回绕/符号转换的统一处理", "综述整数溢出检测方向，识别SIZE_MAX阈值分析和守卫感知的缺口"),
    28: ("参数等式+路径守卫+循环累积", "纯区间分析对malloc(n*4+8)与memcpy(n*8)无法判定关系；循环累积偏移用峰值iters*stride导致误报", "参数等式配对(constraint_based_pairing)+路径守卫收集+循环累积最后迭代偏移base+(iters-1)*stride"),
    34: ("PcWBI(Provenance-Constrained Write-Bound Inference)", "PPA-HAV(CCS'24)需可追踪指针来源但不建模rep movs/SSE内联存储；编译器内联复制不在其模型", "从写入指令的源寄存器反向追踪指针来源(provenance)，推断写界优先使用检测器的字节数write_size而非元素计数"),
    36: ("HFP(分配器感知+守卫窄化)", "通用工具不建模分配器可用空间(对齐padding)；守卫收集不验证支配性", "HFP分配器感知(ptmalloc2 request2size)+守卫窄化(仅采信支配访问点的分支守卫)"),
    38: ("伪IR级指针生命周期分析", "UAF检测跨函数分析普遍薄弱，无调用上下文传播，无函数摘要", "伪IR级指针生命周期状态机(ALLOCATED→FREED→DANGLING)，跨函数传播"),
    39: ("HOFPR(堆溢出误报抑制)", "Angr CFG基线FPR=100%，基线无HOFPR过滤FPR=16.7%", "HOFPR十模块管线：类型/污点/来源界/对齐/守卫/仿射/关联/累积/过滤器/管线"),
    41: ("FC-VRA(流相关值域分析)", "传统VSA值集分析不追踪值与分配点的关联；区间分析在合并点丢失路径约束", "流相关值域分析：值流追踪+区间传播+分配点关联，提高路径敏感精度"),
    43: ("CACBV(容量感知耦合边界验证)", "区间分析对malloc(n)与memcpy(buf,n)的区间重叠即告警，不验证参数耦合关系", "容量感知耦合：分配容量与写入大小的身份键比较，验证是否来自同一数据流根"),
    45: ("写侧值流区间抽象+双向交汇", "单向值流追踪(前向或后向)精度不足；区间分析不建模分配器语义", "写侧值流区间抽象+双向交汇验证(前向从分配到写入+后向从写入到分配)"),
    46: ("值流大小耦合驱动", "不区分数据流的工具把malloc(n)+memcpy(n)一律当溢出", "值流大小耦合：分配size与写入size的值流追踪+身份键比较，同根同源判安全"),
    48: ("PG-WBV(分配点感知写界验证)", "通用工具不区分堆/栈/全局写入；不追踪分配点上下文", "分配点感知+写界验证：从分配点前向追踪分配大小，从写入点反向追踪写入大小，交汇判定"),
    50: ("ACPE(分配容量溯源等价分析)", "SAW需源码级表达式等价，不适用于stripped二进制；区间分析区间重叠即告警", "分配容量溯源：从分配点和写入点分别做后向溯源，比较溯源链等价性"),
    52: ("ACFPC(分配契约流保持压缩)", "通用工具不提取分配契约(size来源+返回值落点)；不验证写-分配参数耦合", "五证据链压缩器：同源共变写/守卫支配写/对齐裕量/字段写几何/精确匹配，三值判决SUPPRESS/CONFIRM/UNCHANGED"),
    54: ("DDSSC(Demand-Driven Symbolic Size Correlation)", "CJ约束联结需构建全局符号表达式，复杂度高；BVF后向追踪遇call即终止精度差", "按需符号大小关联：CJ约束联结+BVF后向值流+LSP分层安全证明+SGAV守卫感知区间验证，按需触发避免全程序分析"),
    57: ("BWR+PCST(有界写恢复+路径条件敏感污点)", "传统写入检测不区分有界写(在分配范围内)与越界写；路径不敏感工具丢失守卫约束", "有界写恢复(bounded_write_recovery)+路径条件敏感污点(path_condition_sensitive_taint)"),
    58: ("FMTPROV(格式化字符串常量折叠+污点溯源)", "printf(user_var)检测不区分常量缓冲全填充与用户写入；不追踪跨函数格式参数来源", "常量折叠(全常量填充缓冲→FILTER)+污点溯源(用户源→CONFIRMED)+模板间接可控识别"),
    59: ("GASRI(守卫感知值域推理)", "传统值域分析在合并点丢失守卫约束；不验证守卫支配性", "守卫感知值域推理：仅采信支配访问点的守卫，守卫经槽解析与访问索引匹配"),
    60: ("HOSV-Ext(写模式驱动堆溢出检测)", "原HOSV仅检出2/12漏洞(Recall=0.167)，不覆盖指针游走/结构数组/无界输入/工厂绑定/终止符五类写模式", "八模块扩展：walk_write/struct_idx/unbounded_io/factory_bind/null_terminator+协调器+类型定义+USV补入"),
    61: ("UAF-PROV(UAF指针来源归因验证器)", "UAF检测不追踪指针来源(分配/释放/别名)，无法区分真实UAF与重赋值安全", "指针来源归因：从use点反向追踪指针来源链，区分悬垂指针与重赋值/NULL置位后的安全指针"),
    62: ("DD-BVF(按需后向值流)", "前向值流追踪精度受合并点影响；全程序后向分析复杂度高", "按需触发：仅在CJ约束联结判定POSSIBLE时启用BVF后向追踪，从写入点反向追踪到分配点"),
    72: ("按需值流+分配器语义", "传统分析不建模ptmalloc2对齐padding；值流追踪遇函数边界即终止", "按需值流分析+堆分配器语义(对齐padding/最小块/usable_size)+跨函数追踪"),
    74: ("二进制级堆溢出误报消除", "Angr/Ghidra对含危险函数的安全样本FPR=100%；Octagon域不建模分配器语义", "八边形域(Octagon)区间抽象+路径条件+循环写累积+符号关联+分配器模型+UAF路径敏感检测"),
    76: ("多层误报抑制(buffer_underflow/off_by_one等)", "单层过滤器(如纯正则)无法处理下溢/off-by-one/未初始化内存等多种边界模式", "多层误报抑制：buffer_underflow/off_by_one/uninitialized_memory/double_free/uaf_enhance/int_overflow_enhance独立模块"),
    79: ("多类型二进制漏洞检测体系", "单漏洞聚焦工具缺乏跨类型统一检测框架", "五类漏洞统一检测：堆溢出/UAF/格式化字符串/整数溢出/栈溢出，各自独立检测器+统一管线"),
    81: ("跨域稀疏值流追踪", "密集值流分析复杂度高不可扩展；跨函数值流追踪普遍薄弱", "跨域稀疏值流：仅在需要时触发值流追踪，跨函数/跨域(堆/栈/全局)传播"),
    83: ("PSVR-HLM(路径敏感值域推理-分层模型)", "传统VSA合并点精度损失严重；不验证守卫支配性", "PSVR路径敏感值域推理+HLM分层模型(L2路径守卫/L3分配器padding/FM边界推导)"),
    85: ("轻量符号表达式引擎+4-Filter链", "全程序符号执行(Angr)路径爆炸42s/样本；SMT求解器不可扩展", "轻量符号表达式引擎(无SMT)+4级过滤链(分配器语义/仿射区间/路径条件/保守启发式)"),
    87: ("UAF检测二级创新", "UAF检测跨函数分析薄弱；不追踪通过堆内存的指针别名", "UAF二级创新：着色分配追踪+LifetimeState状态机+置信度衰减+跨函数传播"),
    90: ("GAPSBV(仿射关系追踪堆溢出检测)", "GUEB VSA粗糙区间无关系信息；SVF流敏感非路径敏感；CSA双向污点缺仿射差分", "Karr仿射关系追踪：计算diff=write_expr-alloc_expr，对正变量值判定符号，无需知道变量具体值"),
    92: ("DP-TVRA(需求驱动路径敏感污点-值域分析)", "传统污点分析不结合值域；值域分析不追踪污点传播", "需求驱动+路径敏感+污点-值域联合分析：按需触发符号化+路径约束窄化+污点源到分配点传播"),
    95: ("路径敏感按需约束传播", "传统约束传播不验证守卫支配性(兄弟分支守卫误过滤)；全程序约束收集复杂度高", "路径敏感按需约束传播：守卫支配验证+按需触发约束收集+五证据链(常量/守卫/最小块/循环界/分配器)"),
    97: ("FMT-SPEC(寄存器后向追踪+PE .rdata提取)", "格式串检测不区分.rdata常量与栈缓冲格式串；不做寄存器级后向追踪", "寄存器后向追踪(x86-64 RDI/RSI/RDX约定)+PE .rdata节提取常量格式串+DFA解析说明符"),
    98: ("SHIELD(选择性堆区间证据逻辑消歧)", "Angr FPR=100%(对每个strcpy/memcpy调用上报)；Ghidra不分析数据流", "选择性堆区间证据逻辑消歧：size_bound_correlation+pointer_provenance+disjointness_prover多证据链"),
    100: ("INT-RANGE(区间抽象解释驱动整数溢出)", "整数溢出检测工具普遍召回低；不处理乘积溢出/位移回绕/符号转换", "区间抽象解释驱动：前向区间传播+widening/narrowing+乘积/位移/符号转换溢出检测"),
    101: ("DRIFT(按需反向信息流追踪UAF检测)", "UAF检测不追踪指针对象身份；跨函数释放传播薄弱", "按需反向信息流：从use点反向追踪到free点+object_identity追踪+pointer_kill_set标记悬垂"),
    102: ("三路按需深度静态分析", "单路分析(仅前向或仅后向)精度不足；三类漏洞(堆溢出/UAF/格式串)分析互不共享证据", "三路按需：堆溢出误报压制+UAF指针重生追踪+格式串来源溯源，共享值流追踪基础设施"),
    104: ("多层误报抑制(compat层)", "单层过滤无法处理编译器优化(O2内联/死存储消除)导致的模式变异", "compat层兼容：fmt_binary(二进制格式串)+uaf_binary(二进制UAF)适配stripped二进制"),
    106: ("PcWBI(来源约束写界推断)", "PPA-HAV不建模编译器内联复制(rep movs/SSE存储)；来源追踪遇call即终止", "来源约束写界推断：从写入指令反向追踪指针来源+写界优先使用检测器字节数+跨函数摘要"),
    108: ("HOFPR(堆溢出误报抑制)", "基线无HOFPR过滤FPR=16.7%；Angr FPR=100%", "HOFPR十模块：类型/污点/来源界/对齐/守卫/仿射/关联/累积/过滤器/管线主流程"),
    110: ("FC-VRA(流相关值域分析)", "传统VSA不追踪值与分配点关联；区间分析合并点丢约束", "流相关值域分析：值流追踪+区间传播+分配点关联"),
    112: ("CACBV(容量感知耦合边界验证)", "区间分析只看区间重叠不验证参数耦合", "容量感知耦合：分配容量与写入大小身份键比较"),
    114: ("写侧值流区间抽象+双向交汇", "单向值流精度不足；不建模分配器语义", "写侧值流区间+双向交汇(前向+后向)"),
    116: ("值流大小耦合驱动", "不区分数据流的工具把同源malloc+memcpy一律当溢出", "值流大小耦合：同根同源判安全"),
    118: ("PG-WBV(分配点感知写界验证)", "通用工具不区分堆/栈/全局写入", "分配点感知+写界验证+跨函数堆追踪"),
    120: ("ACPE(分配容量溯源等价分析)", "SAW需源码级表达式等价；区间重叠即告警", "分配容量溯源：后向溯源链等价性比较"),
    122: ("ACFPC(分配契约流保持压缩)", "不提取分配契约；不验证写-分配耦合", "五证据链压缩器+三值判决"),
    125: ("创新点整合报告", "各创新点分散在不同模块文档中，缺乏统一整合视角", "整合全部创新点为统一报告，标注各创新点的实现进度和饱和状态"),
}

for entry in entries:
    num = entry['num']
    h1 = entry['h1'] if entry['h1'] else "(无标题)"
    src_path = entry['path']
    pyfiles_raw = entry['pyfiles']

    start = line_map.get(num, 0)
    end = line_map.get(num + 1, len(lines))
    block_lines = lines[start:end]

    # Process py files
    py_files = []
    if pyfiles_raw:
        raw_list = pyfiles_raw.split(';')
        for pf in raw_list:
            pf = pf.strip()
            if pf and pf.endswith('.py'):
                if pf.startswith('deemo/'):
                    full = os.path.join(PROJECT_ROOT, pf.replace('/', '\\'))
                elif pf.startswith('modules/') or pf.startswith('analysis/') or pf.startswith('core/') or pf.startswith('eval/') or pf.startswith('tests/') or pf.startswith('doc/'):
                    full = os.path.join(PROJECT_ROOT, 'deemo', pf.replace('/', '\\'))
                else:
                    full = os.path.join(PROJECT_ROOT, 'deemo', pf.replace('/', '\\'))
                py_files.append(full)

    seen = set()
    unique_py = []
    for pf in py_files:
        if pf not in seen:
            seen.add(pf)
            unique_py.append(pf)

    # Get pre-defined info or extract from block
    info = INNOVATION_INFO.get(num, None)

    out.append("\n---\n")
    out.append(f"\n## 创新点 {num}: {h1}\n")
    out.append(f"**源文件**: `{src_path}`\n")

    out.append(f"\n### 1. 创新点说明\n")
    if info:
        out.append(f"{info[0]}: {h1}\n")
    else:
        out.append(f"{h1}\n")

    # Extract first meaningful paragraph
    desc_found = False
    for line in block_lines[2:min(30, len(block_lines))]:
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and not stripped.startswith('>') and not stripped.startswith('|') and not stripped.startswith('```') and not stripped.startswith('---') and len(stripped) > 20:
            out.append(f"\n{stripped[:500]}\n")
            desc_found = True
            break
    if not desc_found and not info:
        out.append(f"\n该创新点来自 {src_path}，围绕二进制漏洞静态检测的误报抑制展开。\n")

    out.append(f"\n### 2. 参考论文局限性\n")
    if info:
        out.append(f"- {info[1]}\n")
    else:
        # Extract from block
        limitations = []
        for line in block_lines:
            stripped = line.strip()
            if re.search(r'(limitation|缺陷|不足|gap|局限|cannot|does not|unable|fails|State explosion|precision loss|not covered|out of scope|not model|not handle|退化|误报|漏报|爆炸|不可解|缺失)', stripped, re.IGNORECASE):
                if len(stripped) > 15 and len(stripped) < 400 and not stripped.startswith('|') and not stripped.startswith('```'):
                    limitations.append(stripped)
        if limitations:
            for ls in limitations[:3]:
                out.append(f"- {ls}\n")
        else:
            out.append("- 参见源文件中的 Related Work 部分。\n")

    out.append(f"\n### 3. 对应脚本文件\n")
    if unique_py:
        for pf in unique_py[:15]:
            out.append(f"- `{pf}`\n")
        if len(unique_py) > 15:
            out.append(f"- ...等共 {len(unique_py)} 个脚本文件\n")
    else:
        out.append("- （该条目为文档/报告类创新点，无直接对应脚本文件）\n")

    out.append(f"\n### 4. 创新思路\n")
    if info:
        out.append(f"- {info[2]}\n")
    else:
        # Try to extract method description
        approach = []
        for line in block_lines:
            stripped = line.strip()
            if re.search(r'(核心方法|核心创新|技术思想|关键技术|核心步骤|method|approach|innovation|technique)', stripped, re.IGNORECASE):
                if len(stripped) > 15 and len(stripped) < 400:
                    approach.append(stripped)
        if approach:
            for a in approach[:3]:
                out.append(f"- {a}\n")
        else:
            out.append(f"- {h1}：通过轻量级静态分析方法实现漏洞检测误报抑制。\n")

with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
    f.write('\n'.join(out))

print(f"Done: {len(out)} lines, {os.path.getsize(OUTPUT_FILE)} bytes")
