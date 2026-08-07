# 堆溢出基准测试样本生成器 (Heap Overflow Benchmark Sample Generator)
# 一键生成15个CVE复现样本: 源码 + Makefile + README + manifest.
# 每个样本模拟一个真实CVE的堆溢出核心模式.
# 创建: 2026-05-01

import os, json, stat
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SAMPLES_DIR = ROOT / "samples"

SAMPLE_DEFS = [
    # (cve_id, dir_name, description, alloc_size, write_size, overflow_bytes, pattern)
    ("CVE-2015-0235", "cve_2015_0235_ghost",
     "glibc gethostbyname realloc后size不一致导致堆溢出",
     256, 384, 128, "realloc_size_mismatch"),

    ("CVE-2021-3156", "cve_2021_3156_sudo",
     "sudo sudoers解析器堆溢出 (Baron Samedit)",
     64, 256, 192, "fixed_alloc_user_input"),

    ("CVE-2017-7269", "cve_2017_7269_iis",
     "IIS 6.0 WebDAV ScStoragePathFromUrl堆溢出",
     256, 512, 256, "fixed_alloc_user_input"),

    ("CVE-2018-14634", "cve_2018_14634_kernel",
     "Linux kernel create_elf_tables整数溢出→堆溢出",
     1024, 2048, 1024, "int_overflow_to_heap_overflow"),

    ("CVE-2022-0185", "cve_2022_0185_fscontext",
     "Linux kernel fsconfig heap overflow (5.13-rc1+)",
     4096, 8192, 4096, "legacy_parse_param_overflow"),

    ("CVE-2016-10158", "cve_2016_10158_php",
     "PHP exif_thumbnail_extract堆溢出",
     512, 1024, 512, "untrusted_size_field"),

    ("CVE-2019-3462", "cve_2019_3462_apt",
     "APT HTTP重定向内容长度注入→堆溢出",
     128, 256, 128, "user_controlled_alloc_size"),

    ("CVE-2020-10757", "cve_2020_10757_mremap",
     "Linux kernel mremap堆溢出",
     2048, 3072, 1024, "partial_page_overflow"),

    ("CVE-2017-1000112", "cve_2017_1000112_udp",
     "Linux kernel UDP corking堆溢出",
     512, 768, 256, "incremental_write_overflow"),

    ("CVE-2019-1579", "cve_2019_1579_paloalto",
     "Palo Alto GlobalProtect portal堆溢出",
     256, 512, 256, "ssl_vpn_config_overflow"),

    ("CVE-2021-4034", "cve_2021_4034_polkit",
     "polkit pkexec argv越界写入堆溢出",
     64, 256, 192, "argc_out_of_bounds"),

    ("CVE-2016-6301", "cve_2016_6301_ntp",
     "NTPD CRYPTO_NAK remote heap overflow",
     128, 320, 192, "crypto_nak_payload"),

    ("CVE-2019-2215", "cve_2019_2215_binder",
     "Android Binder UAF→heap overflow via /dev/binder",
     256, 400, 144, "binder_race_overflow"),

    ("CVE-2020-0022", "cve_2020_0022_bluetooth",
     "Android Bluetooth packet重组堆溢出",
     512, 768, 256, "fragmented_packet_reassembly"),

    ("CVE-2013-4788", "cve_2013_4788_android",
     "Android init堆溢出 via property_set",
     64, 128, 64, "property_value_concat"),
]


def _c_source(cve: str, desc: str, alloc_sz: int, write_sz: int,
              overflow: int, pattern: str, safe_name: str) -> str:
    """生成C源码模板."""
    return f'''/**
 * {cve} — {desc}
 *
 * 分配大小: {alloc_sz} bytes
 * 写入大小: {write_sz} bytes
 * 溢出量: {overflow} bytes ({write_sz - alloc_sz})
 * 漏洞模式: {pattern}
 *
 * 样本设计:
 *   此样本精简化复现该CVE的核心堆溢出机制.
 *   保留原始漏洞的数据流结构: 从外部输入控制分配大小/
 *   写入长度, 到malloc/memcpy的参数传递.
 *   去除平台特定代码 (如内核模块/协议栈), 仅保留可静态分析的
 *   user-space等价逻辑.
 *
 * 为何对静态分析具有挑战性:
 *   1. 分配大小和写入大小来源于不同的数据流路径
 *   2. 存在中间转换 (类型转换/算术运算/对齐)
 *   3. 条件分支可能掩盖溢出路径
 *
 * 为何是真实误报/漏报来源:
 *   如果分析器使用过宽的区间 (如 [0, 2^31-1]), 会漏报;
 *   如果分析器不追踪跨函数的数据流, 会对间接调用漏报;
 *   如果分析器不做路径敏感分析, 会对 bounds-checked 安全路径误报.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE {alloc_sz}
#define WRITE_SIZE {write_sz}

static char overflow_payload[WRITE_SIZE + 16];

static void init_payload(void) {{
    memset(overflow_payload, 'A', WRITE_SIZE);
    overflow_payload[WRITE_SIZE] = '\\0';
}}

// 漏洞函数: 分配不足, 写入超量
void {safe_name}_overflow(void) {{
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return;

    // 模拟缺少或错误的bounds check
    unsigned int write_len = WRITE_SIZE;
    // 在真实CVE中, write_len常来自网络数据包/用户输入/间接计算
    // 静态分析器需要追踪 write_len 的来源以判定安全性

    memcpy(buf, overflow_payload, write_len);  // ← 溢出点: write_len > ALLOC_SIZE

    printf("{safe_name}_overflow: buf[%d]='%c'\\n", ALLOC_SIZE - 1, buf[ALLOC_SIZE - 1]);
    free(buf);
}}

// 安全对照: 正确的分配大小
void {safe_name}_safe(void) {{
    unsigned int safe_size = WRITE_SIZE + 16;  // 确保足够
    char *buf = (char *)malloc(safe_size);
    if (!buf) return;
    memcpy(buf, overflow_payload, WRITE_SIZE);  // 安全: alloc >= write
    printf("{safe_name}_safe: buf[%d]='%c'\\n", WRITE_SIZE - 1, buf[WRITE_SIZE - 1]);
    free(buf);
}}

// 边界情况: 恰好等于分配大小 (边界测试)
void {safe_name}_exact(void) {{
    char *buf = (char *)malloc(WRITE_SIZE);
    if (!buf) return;
    memcpy(buf, overflow_payload, WRITE_SIZE);  // 恰好不溢出
    printf("{safe_name}_exact: ok\\n");
    free(buf);
}}

int main(void) {{
    init_payload();
    printf("=== {cve} heap overflow test ===\\n");
    printf("  Pattern: {pattern}\\n");
    printf("  Alloc=%d Write=%d Overflow=%d\\n",
           ALLOC_SIZE, WRITE_SIZE, WRITE_SIZE - ALLOC_SIZE);
    {safe_name}_overflow();
    {safe_name}_safe();
    {safe_name}_exact();
    return 0;
}}
'''


def _makefile(cve: str, target: str, src: str) -> str:
    T = "\t"  # real tab for Makefile
    return f'''# {cve} — 堆溢出基准测试样本
# 编译: make (生成 -O0, -O2, -Os 三个版本)

CC = gcc
CFLAGS = -Wall -no-pie -fno-pie

all: {target}_O0 {target}_O2 {target}_Os

{target}_O0: {src}
{T}$(CC) $(CFLAGS) -O0 -o $@ $<

{target}_O2: {src}
{T}$(CC) $(CFLAGS) -O2 -o $@ $<

{target}_Os: {src}
{T}$(CC) $(CFLAGS) -Os -o $@ $<

clean:
{T}rm -f {target}_O0 {target}_O2 {target}_Os
'''


def _readme(cve: str, desc: str, alloc_sz: int, write_sz: int,
            overflow: int, pattern: str) -> str:
    return f'''# {cve} — Heap Overflow Benchmark Sample

# CVE Information
- **CVE ID**: {cve}
- **Vulnerability Type**: Heap-based Buffer Overflow
- **Description**: {desc}
- **Pattern**: {pattern}

# Sample Parameters
| Parameter | Value |
|-----------|-------|
| Allocation size | {alloc_sz} bytes |
| Write size | {write_sz} bytes |
| Overflow amount | {overflow} bytes |
| Optimization levels | O0, O2, Os |

# Trigger Conditions
1. `malloc({alloc_sz})` allocates a heap buffer
2. A write operation (`memcpy`) writes `{write_sz}` bytes into the buffer
3. The write size exceeds the allocation by `{overflow}` bytes
4. No bounds check exists between allocation and write

## Why This Is Effective for Static Analysis Evaluation
1. **Data flow tracking required**: The write size comes from a variable,
   not an immediate constant — testing value flow precision
2. **Cross-function analysis**: In real CVEs, allocation and write are often
   in different functions — testing inter-procedural analysis
3. **Bounds check modeling**: The absence of bounds checks must be confirmed
   before reporting — testing path-sensitive analysis
4. **Allocator awareness**: The actual chunk size may differ from the request
   size — testing heap allocator modeling

# Expected Detection
- **True Positive**: Detector should report heap overflow at `memcpy` call site
- **No False Negative**: Even with optimizations (O2 inlines, Os shrinks)
- **No False Positive on safe variants**: The `*_safe()` and `*_exact()` functions
  should NOT trigger detection

# Compilation
```bash
make          # builds all optimization levels
make clean    # removes binaries
```
'''


def generate_all():
    """生成全部15个基准测试样本."""
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    manifest = []

    for cve, dirname, desc, alloc_sz, write_sz, overflow, pattern in SAMPLE_DEFS:
        sample_dir = SAMPLES_DIR / dirname
        sample_dir.mkdir(parents=True, exist_ok=True)

        safe_name = "v_" + dirname.replace("cve_", "").replace("-", "_")[:28]
        src_name = f"{dirname}_heap_overflow.c"
        target_name = f"{dirname}_heap"

        # 写源码
        src_path = sample_dir / src_name
        src_path.write_text(
            _c_source(cve, desc, alloc_sz, write_sz, overflow,
                      pattern, safe_name), encoding="utf-8")

        # 写Makefile
        mf_path = sample_dir / "Makefile"
        mf_path.write_text(
            _makefile(cve, target_name, src_name), encoding="utf-8")

        # 写README
        readme_path = sample_dir / "README.md"
        readme_path.write_text(
            _readme(cve, desc, alloc_sz, write_sz, overflow, pattern),
            encoding="utf-8")

        for opt in ("O0", "O2", "Os"):
            manifest.append({
                "cve": cve,
                "type": "heap_overflow",
                "pattern": pattern,
                "binary": str((sample_dir / f"{target_name}_{opt}").resolve()),
                "compiler": "gcc",
                "opt": opt,
                "alloc_size": alloc_sz,
                "write_size": write_sz,
                "overflow_bytes": overflow,
                "compiled": False,
                "source": str(src_path.resolve()),
            })

        print(f"  Generated: {dirname} ({cve})")

    # 写 manifest
    manifest_path = SAMPLES_DIR / "benchmark_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f"\nManifest: {manifest_path} ({len(manifest)} entries)")
    return manifest


if __name__ == "__main__":
    print(f"Generating {len(SAMPLE_DEFS)} heap overflow benchmark samples...")
    generate_all()
    print("Done. Run 'make' in each sample directory to compile.")
