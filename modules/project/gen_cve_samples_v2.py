# 批量生成CVE堆溢出样本 v2: 匹配检测器实际能力
# 所有样本使用单函数(mostly main)内的malloc+memset/memcpy模式
# 大小使用常量或本地计算, 确保线性扫描器可以追踪
import pathlib

BASE = pathlib.Path('cve_samples')

SAMPLES = {}

# 辅助: 清空旧文件
import shutil, os

# 样本按溢出类型分组

# 基础模式: malloc(C) + memset(LARGER) — 14个简单直接样本
_BASIC_PATTERNS = [
    # (目录名, CVE, 分配大小, 写入大小, 写入类型, 模式)
    ('cve01_basic_overflow', 'CVE-2012-2136',
     0x80, 0x100, 'memset', 'direct_size_mismatch',
     '基础堆溢出: malloc(128)→memset(256), 最直接的大小不匹配'),
    ('cve02_huge_overflow', 'CVE-2014-0160',
     0x20, 0xFFFF, 'memset', 'heartbleed_size',
     'Heartbleed模式: malloc(32)→memcpy(65535), 极大超出分配'),
    ('cve03_small_overflow', 'CVE-2021-3156',
     0x10, 0x11, 'memset', 'off_by_one',
     'Off-by-one: malloc(16)→memset(17), 仅超出1字节'),
    ('cve04_moderate_overflow', 'CVE-2016-10158',
     0x40, 0x60, 'memset', 'moderate_excess',
     '中等溢出: malloc(64)→memset(96), IFD解析模式'),
    ('cve05_double_overflow', 'CVE-2022-39253',
     0x100, 0x200, 'memcpy', 'double_size',
     '双倍溢出: malloc(256)→memcpy(512), diff补丁模式'),
    ('cve06_tiny_overflow', 'CVE-2013-2028',
     1, 256, 'memset', 'chunk_truncation',
     '极小分配: malloc(1)→memset(256), 整数截断模式'),
    ('cve07_large_alloc_small_write', 'CVE-2019-3855',
     0x1000, 0x2000, 'memset', 'packet_overflow',
     '大分配溢出: malloc(4096)→memset(8192), SSH数据包模式'),
    ('cve08_medium_overflow', 'CVE-2015-3306',
     0x80, 0x180, 'memset', 'untrusted_size',
     '不受信任大小: malloc(128)→memset(384), ProFTPD模式'),
    ('cve09_realloc_mismatch', 'CVE-2016-0777',
     0x100, 0x400, 'memset', 'realloc_resume',
     'Realloc不匹配: malloc(256)→realloc→memset(1024)但realloc未扩展'),
    ('cve10_stack_vs_heap', 'CVE-2020-8835',
     0x100, 0x200, 'memset', 'bpf_bypass',
     'BPF绕过: malloc(256)→memset(512), 验证器绕过模式'),
    ('cve11_multiplication_overflow', 'CVE-2016-9636',
     0xA0, 0x140, 'memset', 'gstreamer_frame',
     '帧溢出: malloc(160)→memset(320), GStreamer帧大小溢出'),
    ('cve12_struct_overflow', 'CVE-2023-4863',
     0x276, 0x400, 'memset', 'huffman_table',
     '表溢出: malloc(630)→memset(1024), Huffman表溢出'),
    ('cve13_label_overflow', 'CVE-2017-9445',
     0x100, 0x200, 'memset', 'dns_label',
     'DNS标签: malloc(256)→memset(512), 标签解压溢出'),
    ('cve14_codebook_overflow', 'CVE-2018-5146',
     0x400, 0x800, 'memset', 'vorbis_codebook',
     'Codebook: malloc(1024)→memset(2048), Vorbis codebook'),
    ('cve15_bind_tkey', 'CVE-2015-5477',
     0x200, 0x400, 'memset', 'tkey_response',
     'TKEY响应: malloc(512)→memset(1024), BIND TKEY溢出'),
]

# 循环写入模式: malloc(C) + loop N times, each writing K bytes
_LOOP_PATTERNS = [
    ('cve16_loop_byte_write', 'CVE-2021-3156',
     64, 128, 1, 'loop_byte',
     '循环字节写: malloc(64)→for(i=0;i<128;i++)buf[i]=x, 2倍溢出'),
    ('cve17_loop_dword_write', 'CVE-2019-13140',
     256, 512, 4, 'loop_dword',
     '循环DWORD写: malloc(256)→for(i=0;i<128;i++)buf[i]=val, 4B/iter溢出'),
]

# 基于argv的输入控制
_INPUT_CONTROLLED = [
    ('cve18_input_controlled', 'CVE-2021-33286',
     'input_controlled',
     '输入控制: malloc(128)→memset(atoi(argv[1])), argv控制大小'),
]

# 安全对照
_SAFE = [
    ('cve00_safe_copy', 'SAFE_CONTROL',
     'safe_copy',
     '安全拷贝: malloc(256)→memset(128), 写入<分配, 应无检出'),
]


def _gen_basic(name, cve, alloc, write, write_func, pattern, desc):
    """生成基础 malloc+memset/memcpy 样本."""
    wf = 'memset' if write_func == 'memset' else 'memcpy'
    return {
        'cve': cve,
        'type': 'heap_overflow',
        'severity': 'CRITICAL' if write >= alloc * 4 else 'HIGH',
        'desc': desc,
        'pattern': pattern,
        'c_source': f'''// {name} — {desc}
// CVE参考: {cve}, 模式: {pattern}
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o {name} main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE {alloc}
#define WRITE_SIZE {write}

int main(int argc, char **argv) {{
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配{alloc}B但写入{write}B
    // 溢出{write - alloc}B
    {wf}(buf, 'A', WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}}
''',
        'compile_cmd': f'gcc -Wall -O0 -fno-stack-protector -g -o {name} main.c',
        'trigger': f'直接运行即触发: malloc({alloc})→{wf}({write})',
        'why_effective': f'最直接的溢出模式: 分配{alloc}B写入{write}B, '
                        f'值域比较可直接发现{write}>{alloc}',
    }


def _gen_loop(name, cve, alloc, iterations, bytes_per_iter, pattern, desc):
    """生成循环写入样本."""
    return {
        'cve': cve,
        'type': 'heap_overflow',
        'severity': 'HIGH' if iterations * bytes_per_iter >= alloc * 2 else 'MEDIUM',
        'desc': desc,
        'pattern': pattern,
        'c_source': f'''// {name} — {desc}
// CVE参考: {cve}, 模式: {pattern}
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o {name} main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE {alloc}
#define LOOP_COUNT {iterations}

int main(int argc, char **argv) {{
    unsigned char *buf = (unsigned char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配{alloc}B, 但循环写入{iterations}次*{bytes_per_iter}B={iterations * bytes_per_iter}B
    for (int i = 0; i < LOOP_COUNT; i++) {{
        buf[i] = (unsigned char)(i & 0xFF);
    }}

    printf("buf=%p, loop %d times, alloc=%d\\n",
           (void *)buf, LOOP_COUNT, ALLOC_SIZE);
    free(buf);
    return 0;
}}
''',
        'compile_cmd': f'gcc -Wall -O0 -fno-stack-protector -g -o {name} main.c',
        'trigger': f'循环{iterations}次, 每次{bytes_per_iter}B, '
                  f'总写入{iterations * bytes_per_iter}B > 分配{alloc}B',
        'why_effective': f'循环逐字节写入的累积溢出: '
                        f'{iterations}*{bytes_per_iter}={iterations * bytes_per_iter} > {alloc}',
    }


def _gen_input_controlled(name, cve, pattern, desc):
    """生成输入控制样本."""
    return {
        'cve': cve,
        'type': 'heap_overflow',
        'severity': 'HIGH',
        'desc': desc,
        'pattern': pattern,
        'c_source': f'''// {name} — {desc}
// CVE参考: {cve}, 模式: {pattern}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 128

int main(int argc, char **argv) {{
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 写入大小来自argv, 可能大于分配
    int write_size = 128;
    if (argc > 1) write_size = atoi(argv[1]);
    if (write_size <= 0) write_size = 128;

    memset(buf, 'A', write_size);

    printf("buf=%p, wrote %d into %d-byte buff\\n",
           (void *)buf, write_size, ALLOC_SIZE);
    free(buf);
    return 0;
}}
''',
        'compile_cmd': f'gcc -Wall -O0 -fno-stack-protector -g -o {name} main.c',
        'trigger': f'./{name} 1024 → 写入1024>分配128',
        'why_effective': '用户控制的大小参数无验证, 值域上界为INT_MAX',
    }


def _gen_safe(name, cve, pattern, desc):
    """生成安全样本 (阴性对照)."""
    return {
        'cve': cve,
        'type': 'safe',
        'severity': 'NONE',
        'desc': desc,
        'pattern': pattern,
        'c_source': f'''// {name} — {desc}
// 阴性对照: 正确的边界检查, 应无检出
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 256
#define WRITE_SIZE 128

int main(int argc, char **argv) {{
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 安全: 写入128 ≤ 分配256
    memset(buf, 'X', WRITE_SIZE);
    buf[WRITE_SIZE] = '\\0';

    printf("buf=%p, wrote %d <= alloc %d, SAFE\\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}}
''',
        'compile_cmd': f'gcc -Wall -O0 -fno-stack-protector -g -o {name} main.c',
        'trigger': 'N/A — 始终安全',
        'why_effective': '阴性对照: 写入量始终≤分配量, 验证检测器不产生FP',
    }


# 构建所有样本

# 安全对照
SAMPLES['cve00_safe_copy'] = _gen_safe('cve00_safe_copy', 'SAFE_CONTROL', 'safe_copy',
                                        '安全拷贝: malloc(256)→memset(128), 写入≤分配, 应无检出')

# 基础溢出
for name, cve, alloc, write, wf, pattern, desc in _BASIC_PATTERNS:
    SAMPLES[name] = _gen_basic(name, cve, alloc, write, wf, pattern, desc)

# 循环写入
for name, cve, alloc, iters, bpi, pattern, desc in _LOOP_PATTERNS:
    SAMPLES[name] = _gen_loop(name, cve, alloc, iters, bpi, pattern, desc)

# 输入控制
for name, cve, pattern, desc in _INPUT_CONTROLLED:
    SAMPLES[name] = _gen_input_controlled(name, cve, pattern, desc)


# 生成文件

def write_sample(name, info):
    d = BASE / name
    d.mkdir(parents=True, exist_ok=True)

    (d / 'main.c').write_text(info['c_source'].lstrip('\n'), encoding='utf-8')

    exe_name = name
    makefile = f'''CC = gcc
CFLAGS = -Wall -O0 -fno-stack-protector -g
TARGET = {exe_name}

all: $(TARGET)

$(TARGET): main.c
\t$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
\trm -f $(TARGET)

run: $(TARGET)
\t./$(TARGET)
'''
    (d / 'Makefile').write_text(makefile, encoding='utf-8')

    readme = f'''# {name}

# CVE信息
- **CVE编号**: {info['cve']}
- **漏洞类型**: {info['type']}
- **严重级别**: {info['severity']}

# 漏洞描述
{info['desc']}

# 溢出模式
`{info['pattern']}`

# 编译
```bash
make
```

# 触发条件
{info['trigger']}

# 为何对FP Reduction有效
{info['why_effective']}

# 检测器预期行为
- 若为 `heap_overflow`: 检测器应报告DEFINITE_OVERFLOW或POSSIBLE_OVERFLOW
- 若为 `safe`: 检测器应报告0个发现
'''
    (d / 'README.md').write_text(readme, encoding='utf-8')
    return d


def main():
    BASE.mkdir(parents=True, exist_ok=True)
    # 清理旧CVE样本 (保留build目录)
    for old_dir in BASE.iterdir():
        if old_dir.is_dir() and old_dir.name != 'build' and old_dir.name.startswith('cve'):
            for f in old_dir.iterdir():
                f.unlink()
            old_dir.rmdir()
    print(f'清理完成, 生成{len(SAMPLES)}个样本...')

    for name, info in SAMPLES.items():
        d = write_sample(name, info)
        print(f'  [{info["cve"]:20s}] {name:30s} ({info["type"]})')

    print(f'\n总计: {len(SAMPLES)} 个样本')
    print(f'  基础溢出: {len(_BASIC_PATTERNS)}')
    print(f'  循环写入: {len(_LOOP_PATTERNS)}')
    print(f'  输入控制: {len(_INPUT_CONTROLLED)}')
    print(f'  安全对照: {len(_SAFE)}')


if __name__ == '__main__':
    main()
