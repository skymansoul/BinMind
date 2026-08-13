# 样本模板 — C 源码 / Makefile / README 的生成模板.
#
# 模板按 pattern 选型, 元数据定义于 sample_specs.py.
# vuln/safe 两类模板的差异在于写入模式与预期判定, 由生成器分发.
#
# 创建: 2025-03-03

_VULN_TEMPLATES = {
    "fixed_alloc_tainted_write": """/* {cve} {desc}.
 * 触发: 固定 {alloc} 字节堆缓冲, 将 {write} 字节输入 memcpy 写入.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void trigger(char *payload) {{
    char *buf = (char *)malloc({alloc});
    if (!buf) return;
    memcpy(buf, payload, {write});
    printf("buf[0]=%c\\n", buf[0]);
    free(buf);
}}

int main(int argc, char **argv) {{
    static char payload[{write} + 16];
    memset(payload, 'A', sizeof(payload));
    printf("{sample} start\\n");
    trigger(payload);
    return 0;
}}
""",
    "off_by_one_alloc_linked": """/* {cve} {desc}.
 * 触发: 按参数长度分配, memcpy 写入 len+1 字节 (off-by-one).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {{
    size_t len = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(len);
    if (!buf) return 1;
    memcpy(buf, argv[2], len + 1);
    printf("buf[0]=%c\\n", buf[0]);
    free(buf);
    return 0;
}}
""",
    "alloc_param_tainted_write": """/* {cve} {desc}.
 * 触发: 分配大小依赖输入参数, 写入大小为其2倍.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {{
    size_t n = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(n);
    if (!buf) return 1;
    memcpy(buf, argv[2], n * 2);
    printf("buf[0]=%c\\n", buf[0]);
    free(buf);
    return 0;
}}
""",
    "intof_alloc_tainted_write": """/* {cve} {desc}.
 * 触发: 分配大小按 count*16, 写入大小按 count*32 增长更快;
 * 真实CVE经整数回绕使分配收缩, 此处保留静态可判的增长关系.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {{
    unsigned int count = (unsigned int)atoi(argv[1]);
    size_t sz = (size_t)count * 16;
    char *buf = (char *)malloc(sz);
    if (!buf) return 1;
    memcpy(buf, argv[2], (size_t)count * 32);
    printf("buf[0]=%c\\n", buf[0]);
    free(buf);
    return 0;
}}
""",
    "fixed_alloc_tainted_write_param": """/* {cve} {desc}.
 * 触发: 固定 {alloc} 字节堆缓冲, memcpy 写入长度由输入决定.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {{
    size_t len = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc({alloc});
    if (!buf) return 1;
    memcpy(buf, argv[2], len);
    printf("buf[0]=%c\\n", buf[0]);
    free(buf);
    return 0;
}}
""",
}

_SAFE_TEMPLATES = {
    "alloc_linked_write": """/* {cve} 安全对照: 分配与写入同源等大, 不可能溢出.
 * 预期: 检测器应判定 BENIGN (来源约束识别共享变量).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {{
    size_t n = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(n);
    if (!buf) return 1;
    memcpy(buf, argv[2], n);
    printf("buf[0]=%c\\n", buf[0]);
    free(buf);
    return 0;
}}
""",
    "guarded_write": """/* {cve} 安全对照: 写入前显式边界检查 len<=64.
 * 预期: 检测器应识别守卫约束, 判定 BENIGN.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {{
    size_t len = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    if (len <= 64) {{
        memcpy(buf, argv[2], len);
        printf("buf[0]=%c\\n", buf[0]);
    }}
    free(buf);
    return 0;
}}
""",
    "allocator_padding": """/* {cve} 安全对照: 写入落在分配器 padding 区内.
 * malloc(62) glibc chunk 80字节, usable 72字节; 写入63字节安全.
 * 预期: 分配器语义模型判定 BENIGN.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {{
    char *buf = (char *)malloc(62);
    if (!buf) return 1;
    memcpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAA", 63);
    printf("buf[0]=%c\\n", buf[0]);
    free(buf);
    return 0;
}}
""",
    "alloc_plus_one": """/* {cve} 安全对照: malloc(n+1) + memcpy(n) (strcpy惯用法).
 * 预期: 符号相关性判定 BENIGN.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {{
    size_t n = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(n + 1);
    if (!buf) return 1;
    memcpy(buf, argv[2], n);
    printf("buf[0]=%c\\n", buf[0]);
    free(buf);
    return 0;
}}
""",
    "exact_constant": """/* {cve} 安全对照: malloc(256) + memcpy(256) 常量等大.
 * 预期: 常量路径判定 BENIGN.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {{
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    memcpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 256);
    printf("buf[0]=%c\\n", buf[0]);
    free(buf);
    return 0;
}}
""",
}

MAKEFILE = """# {sample} 编译入口.
# Windows (mingw) 产出 vuln.exe (PE), Linux 产出 vuln (ELF).
CC ?= gcc
CFLAGS ?= -O0 -Wall -Wno-stringop-overflow

EXE = vuln$(if $(filter Windows_NT,$(OS)),.exe,)

all: $(EXE)

$(EXE): vuln.c
	$(CC) $(CFLAGS) vuln.c -o $@

O2: vuln.c
	$(CC) -O2 -Wall -Wno-stringop-overflow vuln.c -o vuln_O2$(if $(filter Windows_NT,$(OS)),.exe,)

clean:
	-rm -f vuln vuln.exe vuln_O2 vuln_O2.exe

.PHONY: all O2 clean
"""

README = """# {sample}

- CVE: {cve}
- 类型: {type}
- 模式: {pattern}
- Ground truth: 预期 {expected}

## 漏洞描述

{desc}

## 触发条件

{vuln} 输入 {trigger} 使写入大小超过分配可用大小,
构成堆溢出 (CWE-122 / CWE-787).

## 为何该样本可验证检测器有效性

- 分配/写入尺寸均可从反汇编恢复 (常量或经 atoi 输入).
- 期望 {expected} 判定: 检测器应在不丢失召回的前提下
  正确区分真实溢出与同源/守卫/padding 安全写入.
"""

TRIGGERS = {
    "fixed_alloc_tainted_write": "payload 长度超过分配大小",
    "off_by_one_alloc_linked": "argv[1] 为分配长度, argv[2] 为 len+1 字节数据",
    "alloc_param_tainted_write": "argv[1] 为分配长度, argv[2] 为 2*len 字节数据",
    "intof_alloc_tainted_write": "argv[1] 极大使 sz 回绕到极小值, argv[2] 覆盖",
    "fixed_alloc_tainted_write_param": "argv[1] 指定超限长度",
    "alloc_linked_write": "argv[1] 任意值, 写入与分配同源等大",
    "guarded_write": "argv[1] > 64 时守卫阻止写入",
    "allocator_padding": "固定 63 字节写入, 在 usable 72 之内",
    "alloc_plus_one": "argv[1] 任意值, 写入恒比分配小1",
    "exact_constant": "固定等大常量写入",
}


def select_template(pattern: str, is_vuln: bool):
    if not is_vuln:
        return _SAFE_TEMPLATES[pattern]
    return _VULN_TEMPLATES[pattern]
