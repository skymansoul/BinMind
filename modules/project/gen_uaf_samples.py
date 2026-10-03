# UAF挑战样本生成器: 覆盖use-after-free的各类模式
# 分类:
#   A类: 直接解引用UAF — free后通过同一指针或别名读写
#   B类: 函数调用UAF — free后将悬挂指针传给memcpy/strlen等
#   C类: 双重释放 — 同一指针free两次
#   D类: 安全对照 — 正确清除或无UAF的模式
import pathlib

BASE = pathlib.Path('cve_samples')


def _gen_uaf01_basic_deref_write():
    """A类: 基本UAF写入 — malloc → free → 通过原指针写入."""
    return {
        'name': 'uaf01_basic_deref_write',
        'cve': 'CVE-UAF-DEREF-WRITE',
        'type': 'uaf',
        'severity': 'CRITICAL',
        'pattern': 'uaf_deref_write',
        'desc': 'malloc→free→memset通过原指针: free后通过同一指针写入堆块, 确定性UAF',
        'c_source': '''// uaf01_basic_deref_write — 基本UAF写入
// CVE参考: CVE-UAF-DEREF-WRITE, 模式: uaf_deref_write
// 检测目标: 线形扫描器能否追踪malloc→free→写入的生命周期?
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    memset(buf, 0, 128);
    free(buf);
    // UAF: 释放后写入
    memset(buf, 'X', 64);
    printf("UAF write: buf=%p\\n", (void *)buf);
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o uaf01_basic_deref_write main.c',
    }


def _gen_uaf02_basic_deref_read():
    """A类: 基本UAF读取 — malloc → free → 从原指针读取."""
    return {
        'name': 'uaf02_basic_deref_read',
        'cve': 'CVE-UAF-DEREF-READ',
        'type': 'uaf',
        'severity': 'HIGH',
        'pattern': 'uaf_deref_read',
        'desc': 'malloc→free→通过原指针读取: free后读取堆块内容, 信息泄露类UAF',
        'c_source': '''// uaf02_basic_deref_read — 基本UAF读取
// CVE参考: CVE-UAF-DEREF-READ, 模式: uaf_deref_read
// 检测目标: free后的读取操作是否被检测
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    strcpy(buf, "sensitive_data");
    free(buf);
    // UAF: 释放后读取
    char leaked = buf[0];
    printf("leaked=%c\\n", leaked);
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o uaf02_basic_deref_read main.c',
    }


def _gen_uaf03_alias_write():
    """A类: 别名UAF — ptr2 = ptr1; free(ptr1); *ptr2 = ..."""
    return {
        'name': 'uaf03_alias_write',
        'cve': 'CVE-UAF-ALIAS',
        'type': 'uaf',
        'severity': 'CRITICAL',
        'pattern': 'uaf_alias',
        'desc': '别名传播UAF: ptr2=ptr1→free(ptr1)→通过ptr2写入, 别名追踪是关键能力',
        'c_source': '''// uaf03_alias_write — 别名传播UAF
// CVE参考: CVE-UAF-ALIAS, 模式: uaf_alias
// 检测目标: 指针别名传播后free, 别名是否被标记为悬挂
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    char *alias = buf;  // 别名
    free(buf);
    // UAF: 通过别名写入
    memset(alias, 'Y', 32);
    printf("UAF via alias: %p\\n", (void *)alias);
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o uaf03_alias_write main.c',
    }


def _gen_uaf04_double_free():
    """C类: 双重释放 — free(ptr); free(ptr)."""
    return {
        'name': 'uaf04_double_free',
        'cve': 'CVE-UAF-DOUBLE-FREE',
        'type': 'uaf',
        'severity': 'MEDIUM',
        'pattern': 'double_free',
        'desc': '双重释放: free(ptr)后再free(ptr), 不需要别名追踪, 直接寄存器判断即可',
        'c_source': '''// uaf04_double_free — 双重释放
// CVE参考: CVE-UAF-DOUBLE-FREE, 模式: double_free
// 检测目标: 同一寄存器中的指针被free两次
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    free(buf);
    // UAF: 双重释放
    free(buf);
    printf("double free: %p\\n", (void *)buf);
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o uaf04_double_free main.c',
    }


def _gen_uaf05_call_arg_memcpy():
    """B类: 函数调用UAF — free后call memcpy(dangling, ...)."""
    return {
        'name': 'uaf05_call_arg_memcpy',
        'cve': 'CVE-UAF-CALL-ARG',
        'type': 'uaf',
        'severity': 'CRITICAL',
        'pattern': 'uaf_call_arg_dst',
        'desc': 'free后call memcpy(dangling_ptr, src, n): 悬挂指针作为写入目标传给memcpy',
        'c_source': '''// uaf05_call_arg_memcpy — 函数调用参数UAF
// CVE参考: CVE-UAF-CALL-ARG, 模式: uaf_call_arg_dst
// 检测目标: 悬挂指针作为函数参数 (第一个参数=目标缓冲区) 传递给memcpy
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    memset(buf, 0, 128);
    free(buf);
    // UAF: 悬挂指针作为memcpy的目标
    memcpy(buf, "overflow", 9);
    printf("UAF memcpy: %s\\n", buf);
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o uaf05_call_arg_memcpy main.c',
    }


def _gen_uaf06_call_arg_strlen():
    """B类: free后call strlen(dangling) — 读取悬挂指针."""
    return {
        'name': 'uaf06_call_arg_strlen',
        'cve': 'CVE-UAF-CALL-DEREF',
        'type': 'uaf',
        'severity': 'HIGH',
        'pattern': 'uaf_call_arg_deref',
        'desc': 'free后call strlen(dangling_ptr): 解引用函数检测, 指针内容被读取',
        'c_source': '''// uaf06_call_arg_strlen — 解引用函数UAF
// CVE参考: CVE-UAF-CALL-DEREF, 模式: uaf_call_arg_deref
// 检测目标: 悬挂指针传给strlen等解引用函数
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    strcpy(buf, "test_data");
    free(buf);
    // UAF: strlen读取已释放的指针
    size_t len = strlen(buf);
    printf("UAF strlen: len=%zu\\n", len);
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o uaf06_call_arg_strlen main.c',
    }


def _gen_uaf07_safe_xor_clear():
    """D类: 安全 — free后xor reg,reg 清除指针."""
    return {
        'name': 'uaf07_safe_xor_clear',
        'cve': 'SAFE-PTR-CLEAR',
        'type': 'safe',
        'severity': 'NONE',
        'pattern': 'safe_ptr_clear',
        'desc': '安全: free后立即xor ptr,ptr清零→无UAF, 验证悬挂清除逻辑',
        'c_source': '''// uaf07_safe_xor_clear — 安全指针清除
// CVE参考: SAFE-PTR-CLEAR, 模式: safe_ptr_clear
// 检测目标: free→xor reg,reg后不应报告UAF (指针被正确清除)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    memset(buf, 'A', 64);
    printf("before free: %p\\n", (void *)buf);
    free(buf);
    buf = NULL;  // 安全: 清除悬挂指针
    // 此后无UAF
    printf("cleared: %p\\n", (void *)buf);
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o uaf07_safe_xor_clear main.c',
    }


def _gen_uaf08_loop_uaf():
    """A类: 循环中的UAF — malloc→free→循环写入."""
    return {
        'name': 'uaf08_loop_uaf',
        'cve': 'CVE-UAF-LOOP',
        'type': 'uaf',
        'severity': 'CRITICAL',
        'pattern': 'uaf_loop_write',
        'desc': '循环UAF: free后在循环中通过悬挂指针写入, 每个迭代都是UAF',
        'c_source': '''// uaf08_loop_uaf — 循环中的UAF
// CVE参考: CVE-UAF-LOOP, 模式: uaf_loop_write
// 检测目标: 循环内通过悬挂指针写入, 确保循环内的每次访问都被检测
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int *arr = (int *)malloc(100 * sizeof(int));
    if (!arr) return 1;
    for (int i = 0; i < 100; i++) arr[i] = i;
    free(arr);
    // UAF: 循环写入已释放的数组
    for (int i = 0; i < 10; i++) {
        arr[i] = 0;
    }
    printf("loop UAF: %p\\n", (void *)arr);
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o uaf08_loop_uaf main.c',
    }


def _gen_uaf09_safe_no_free():
    """D类: 安全 — 有malloc但无free, 正常使用."""
    return {
        'name': 'uaf09_safe_no_free',
        'cve': 'SAFE-NO-UAF',
        'type': 'safe',
        'severity': 'NONE',
        'pattern': 'safe_no_free',
        'desc': '安全对照: malloc→使用→无free, 正常堆使用, 不应报告任何UAF',
        'c_source': '''// uaf09_safe_no_free — 无free的正常使用
// CVE参考: SAFE-NO-UAF, 模式: safe_no_free
// 检测目标: 确保正常malloc→使用→free→不再使用的模式不产生误报
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    memset(buf, 'Z', 256);
    printf("normal use: %p\\n", (void *)buf);
    free(buf);
    // 之后不再使用buf → 无UAF
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o uaf09_safe_no_free main.c',
    }


def _gen_uaf10_realloc_uaf():
    """A类: realloc后的UAF — realloc返回新指针, 旧指针悬挂."""
    return {
        'name': 'uaf10_realloc_uaf',
        'cve': 'CVE-UAF-REALLOC',
        'type': 'uaf',
        'severity': 'CRITICAL',
        'pattern': 'uaf_realloc',
        'desc': 'realloc UAF: realloc移动后使用旧指针, 需追踪realloc的返回值vs旧指针',
        'c_source': '''// uaf10_realloc_uaf — realloc后的UAF
// CVE参考: CVE-UAF-REALLOC, 模式: uaf_realloc
// 检测目标: realloc可能返回新地址, 旧指针变为悬挂
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    memset(buf, 'A', 32);
    char *new_buf = (char *)realloc(buf, 256);
    if (!new_buf) { free(buf); return 1; }
    // UAF: realloc后使用旧指针buf (可能已释放)
    memset(buf, 'B', 16);
    printf("realloc UAF: old=%p new=%p\\n", (void *)buf, (void *)new_buf);
    free(new_buf);
    return 0;
}
''',
        'compile_cmd': 'gcc -Wall -O0 -fno-stack-protector -g -o uaf10_realloc_uaf main.c',
    }


CHALLENGE_SAMPLES = {}


def register_all():
    samples = [
        _gen_uaf01_basic_deref_write(),
        _gen_uaf02_basic_deref_read(),
        _gen_uaf03_alias_write(),
        _gen_uaf04_double_free(),
        _gen_uaf05_call_arg_memcpy(),
        _gen_uaf06_call_arg_strlen(),
        _gen_uaf07_safe_xor_clear(),
        _gen_uaf08_loop_uaf(),
        _gen_uaf09_safe_no_free(),
        _gen_uaf10_realloc_uaf(),
    ]
    for s in samples:
        CHALLENGE_SAMPLES[s['name']] = s
    return CHALLENGE_SAMPLES


def write_samples():
    """写入所有UAF挑战样本到磁盘."""
    register_all()
    BASE.mkdir(parents=True, exist_ok=True)

    for name, info in CHALLENGE_SAMPLES.items():
        d = BASE / name
        d.mkdir(parents=True, exist_ok=True)
        (d / 'main.c').write_text(info['c_source'].lstrip('\n'), encoding='utf-8')

        readme = f'''# {name}

# 挑战类型
- **样本分类**: {info['type']}
- **严重级别**: {info['severity']}
- **模式**: `{info['pattern']}`

# 描述
{info['desc']}

# 方法对比
- **ASA-VRA (堆溢出)**: 不适用 — 此样本测试UAF检测而非堆溢出
- **UAF检测器**: 应正确识别悬挂指针使用模式
- **旧方法预期**: 无UAF检测能力 → 漏报
- **新方法预期**: 正确检测 {info['pattern']}
'''
        (d / 'README.md').write_text(readme, encoding='utf-8')

    print(f'生成 {len(CHALLENGE_SAMPLES)} 个UAF挑战样本')


if __name__ == '__main__':
    write_samples()
