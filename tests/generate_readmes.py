"""
一次性为所有堆溢出测试样本生成 README.md。
已存在 README.md 的目录不会被覆盖。
"""
import os, glob

SAMPLES_DIR = os.path.dirname(os.path.abspath(__file__)) + "/cve_samples"

README_TEMPLATES = {
    "heap_overflow_01": """# heap_overflow_01 — strcpy into malloc(64)

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **漏洞类型**: 无界字符串复制
- **触发条件**: `argv[1]` 长度 > 64 字节
- **检测要点**: 静态分析应识别 `malloc(64)` 后的 `strcpy(buf, input)` 中 input 无长度检查
- **预期**: 检出 (TP), confidence ≥ 0.60
""",
    "heap_overflow_02": """# heap_overflow_02 — sprintf 到堆缓冲区

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **漏洞类型**: 格式化字符串导致的溢出
- **触发条件**: 格式化输出长度 > malloc 分配大小
- **检测要点**: 追踪 sprintf 的目标缓冲区与分配大小关系
- **预期**: 检出 (TP), confidence ≥ 0.55
""",
    "heap_overflow_03": """# heap_overflow_03 — 用户控制的malloc大小+memcpy

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **漏洞类型**: 分配大小与写入大小来自不同源, 存在约束不匹配
- **触发条件**: size1 < size2 且均来自输入参数
- **检测要点**: 追踪分配大小与写入大小的值流关系
- **预期**: 检出 (TP) 或 无法确定 (若size参数无法静态解析)
""",
    "heap_overflow_04": """# heap_overflow_04 — realloc 后溢出

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **漏洞类型**: realloc 扩展后仍写入超出新大小的数据
- **触发条件**: realloc 新大小 < memcpy 大小
- **检测要点**: realloc 上下文追踪 — 取最后一次分配大小
- **预期**: 检出 (TP), 需要 heap_context_tracker 正确识别 realloc
""",
    "heap_overflow_05": """# heap_overflow_05 — memcpy 第三个参数 > 目标分配

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **漏洞类型**: memcpy 的 size 参数超出 dst 分配
- **触发条件**: `malloc(32)`, `memcpy(dst, src, 256)` — 大小不匹配
- **检测要点**: 比较 memcpy 第三个参数与 malloc 参数
- **预期**: 检出 (TP), confidence ≥ 0.80
""",
    "heap_overflow_06": """# heap_overflow_06 — calloc 分配后溢出

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **漏洞类型**: calloc(nmemb, size) 后的越界写入
- **触发条件**: 写入索引 ≥ nmemb 或 写入总字节 > nmemb*size
- **检测要点**: calloc 语义: 总大小 = nmemb * size, 需要追踪乘法结果
- **预期**: 检出 (TP)
""",
    "heap_overflow_07": """# heap_overflow_07 — 多级指针解引用后的堆写

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **漏洞类型**: 结构体嵌套导致的误判与真实溢出边界
- **触发条件**: 通过多层指针访问堆缓冲区
- **检测要点**: 指针别名追踪 — 区分不同堆对象
- **预期**: 检出 (TP), 检验 alias 分析是否误滤除
""",
    "heap_overflow_08": """# heap_overflow_08 — 循环中递增偏移写入

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **漏洞类型**: for循环中 p[i] 写入, i 上界 > 分配元素数
- **触发条件**: 循环迭代次数 > 分配可容纳的元素数
- **检测要点**: 循环边界推断 — 比较循环上界与分配大小
- **预期**: 检出 (TP), 核心测试 loop_bound_inferrer 模块
""",
    "heap_overflow_09": """# heap_overflow_09 — strncat 误用

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **漏洞类型**: strncat 的 n 参数不计算已存在内容长度
- **触发条件**: strncat(buf, src, sizeof(buf)) 而非 sizeof(buf)-strlen(buf)-1
- **检测要点**: strncat 的大小参数语义分析
- **预期**: 检出 (TP), confidence ≥ 0.55
""",
    "heap_overflow_10": """# heap_overflow_10 — 循环累积 strcat 超 chunk 边界

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **漏洞类型**: strcat 循环 — 每次追加不检查累积长度
- **触发条件**: 10 次 strcat("AAAA") 共 40B > malloc(32)
- **检测要点**: 循环内累积写入的边界分析 (loop unrolling heuristic)
- **预期**: 检出 (TP), 测试循环累积写入检测
""",
    "heap_overflow_11": """# heap_overflow_11 — 间接调用中的堆溢出

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **漏洞类型**: 通过函数指针调用写入函数
- **触发条件**: 间接调用的写入函数参数不受控
- **检测要点**: 间接调用目标解析 — 可能需要调用图分析
- **预期**: 可能漏报 (FN) — 间接调用是静态分析的固有限制
""",
    "heap_overflow_12": """# heap_overflow_12 — multithread 竞态窗口的堆溢出

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **漏洞类型**: 多线程同时操作堆指针, 竞态导致大小检查被绕过
- **触发条件**: 线程A检查大小后线程B修改了大小
- **检测要点**: 并发路径的静态分析 — 保守地不应滤除
- **预期**: 检出 (TP) — 静态分析应保守地标记
""",
    "heap_overflow_13": """# heap_overflow_13 — 跨函数堆溢出 (caller/callee)

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **漏洞类型**: caller 分配, callee 写入 — 大小信息在跨函数边界丢失
- **触发条件**: func1 调用 malloc(N), 将指针传给 func2, func2 写入 >N 字节
- **检测要点**: 过程间值流追踪 — 从caller的malloc到callee的store
- **预期**: 需要过程间分析才能检出 — 测试跨函数追踪能力
""",
    "heap_overflow_14": """# heap_overflow_14 — 整数溢出导致的堆分配不足

- **CWE**: CWE-122 (Heap-based Buffer Overflow) + CWE-190 (Integer Overflow)
- **漏洞类型**: 乘法溢出 → 分配大小过小 → 后续写入溢出
- **触发条件**: n * sizeof(elem) 溢出后得到小值, malloc(small) 后写入全量
- **检测要点**: 整数溢出与堆溢出的联合检测 — 追踪乘法表达式
- **预期**: 检出 (TP) 或 需要 int_overflow 联合分析
""",
    "heap_overflow_15": """# heap_overflow_15 — off-by-one 堆溢出

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **漏洞类型**: 循环边界条件 off-by-one 导致额外1字节写入
- **触发条件**: `memset(p, 'A', 33)` 但 `malloc(32)` — 写入多1字节
- **检测要点**: 边界比较: 33 > 32 → 精确检测off-by-one
- **预期**: 检出 (TP), 依赖精确的边界比较 (1字节级别)
""",
}

def main():
    for dirname, content in README_TEMPLATES.items():
        dirpath = os.path.join(SAMPLES_DIR, dirname)
        readme_path = os.path.join(dirpath, "README.md")
        if not os.path.isdir(dirpath):
            print(f"SKIP {dirname}: directory not found")
            continue
        if os.path.exists(readme_path):
            print(f"SKIP {dirname}: README.md already exists")
            continue
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"OK {dirname}/README.md")

if __name__ == "__main__":
    main()
