# coding: utf-8
"""生成各 CVE 样本目录的 Makefile 与 README.md (一次性元数据生成器).

Makefile: 直接 gcc 编译 vuln.c → {name}.exe/.elf
README:   CVE 编号、触发条件、为何有效 (从 ground_truth.json 与样本特征)
"""

import json, os, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
GT_PATH = os.path.join(ROOT, 'ground_truth.json')
OUT_EXT = '.exe' if sys.platform == 'win32' else '.elf'

GT = {}
if os.path.exists(GT_PATH):
    with open(GT_PATH, 'r', encoding='utf-8') as f:
        GT = json.load(f)

# 触发条件补充说明 (手工维护的样本语义)
TRIGGER_NOTES = {
    'CVE-2014-0160_heartbleed': '服务端读取 TLS heartbeat 请求; 声明 payload 长度但未核对实际可用数据, memcpy 越界写入',
    'CVE-2015-0235_ghost': 'gethostbyname 解析超长主机名; strcpy 无边界检查写入 16 字节缓冲',
    'CVE-2016-10190': 'FFmpeg 处理畸形 chunk; 按声明大小分配后写入超量数据',
    'CVE-2019-9213': 'mmap 零页映射绕过; 极小分配配合大写入',
    'CVE-2020-29370': '用户可控长度传入 memcpy, 无边界检查; 分配固定 64 字节',
    'CVE-2021-3156': 'sudoedit 对命令行的转义处理; 分配长度与写入长度变量不一致',
    'CVE-2022-0185': 'fsconfig 参数构造; malloc(64) + snprintf 上限 256',
    'CVE-2023-0461': 'io_uring fixed buffer 注册; 用户大小超过分配 (含 min-cap 守卫仍溢出)',
    'vuln_int_overflow_heap': 'count*elem 32 位乘积回绕 → malloc(1); 64 位实际乘积大写入',
    'vuln_multipath': 'if-else 多路径: 危险分支写入 256 超出分配 128',
    'vuln_recursive': '递归处理中分配逐层递减, 写入量固定超分配',
    'vuln_strcat_chain': '循环 strcat 累积追加, 4×20=80 超出 malloc(64)',
    'fp_alloc_align': 'malloc(5) 实际 usable≥16 (glibc 对齐), 写 16 字节不越界',
    'fp_internal_copy': 'malloc(32) + memcpy(64) 但数据为内部常量, 不可攻击者控制',
    'safe_01': 'malloc(256) ≥ memcpy(128), 大小可证安全',
    'safe_02': 'malloc(256) == memcpy(256), 同一变量同源',
    'safe_heap': 'malloc(512) ≥ min-cap 守卫上限 256, 守卫精化可证安全',
}

MAKEFILE_T = """# {name} — {cve}
CC ?= gcc
CFLAGS ?= -std=c11 -O0 -g -Wall -fno-stack-protector
TARGET = {name}{ext}

all: $(TARGET)

$(TARGET): vuln.c
	$ $(CFLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET)
"""

README_T = """# {name}

- **CVE / 漏洞**: {cve}
- **漏洞类型**: heap_overflow = {vuln}
- **触发条件**: {trigger}
- **为何有效 (对检测的意义)**: {why}

# 编译

```bash
make            # 生成 {name}{ext}
# 或直接: gcc -std=c11 -O0 -g -Wall -o {name}{ext} vuln.c
```

# 检测要点

本样本被设计为 {role}, 用于验证堆溢出误报抑制方法对以下
检测难点的处理: {challenge}
"""


def main():
    created = 0
    for name, info in sorted(GT.items()):
        subdir = os.path.join(ROOT, name)
        if not os.path.isdir(subdir):
            continue
        is_vuln = info.get('heap_overflow', False)
        cve = info.get('cve', 'N/A')
        trigger = TRIGGER_NOTES.get(name, '外部输入触发路径; 无边界检查')
        role = '真阳性 (TP)' if is_vuln else '安全负例 (TN/FP 压测)'
        challenge = (
            '分配器对齐约束 / 守卫上限 / 双侧可控性 中至少一类误报根因'
            if not is_vuln else
            '动态大小提取 / 污点可控性 / 守卫不误过滤 的交叉验证')

        with open(os.path.join(subdir, 'Makefile'), 'w', encoding='utf-8') as f:
            f.write(MAKEFILE_T.format(name=name, cve=cve, ext=OUT_EXT))
        with open(os.path.join(subdir, 'README.md'), 'w', encoding='utf-8') as f:
            f.write(README_T.format(
                name=name, cve=cve, vuln=is_vuln, trigger=trigger,
                why=info.get('desc', ''), role=role, challenge=challenge,
                ext=OUT_EXT))
        created += 1
    print(f'Generated Makefile + README.md for {created} samples')


if __name__ == '__main__':
    main()
