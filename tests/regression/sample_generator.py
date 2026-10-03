"""
合成漏洞样本生成器。

生成 10 个独立的漏洞样本, 每个放在独立子目录,
包含 vuln.c + build.sh + README.md。
"""

import os
import stat

_SAMPLE_DIR = os.path.join(os.path.dirname(__file__), 'samples', 'synthetic')

_SAMPLES: list = [
# 栈溢出 (4)
    {
        'id': 'STACK_BOF_01',
        'desc': 'gets() 无条件栈溢出',
        'ref': 'CWE-242 / 模拟 CVE-2014-0160 Heartbleed 的栈模式',
        'code': r'''#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input);  // 无长度检查
    printf("copied: %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    vulnerable(argv[1]);
    return 0;
}
''',
        'compile': 'gcc -o vuln vuln.c -fno-stack-protector -z execstack',
    },
    {
        'id': 'STACK_BOF_02',
        'desc': 'read() 固定大小超出栈缓冲区',
        'ref': '模拟 CVE-2017-1000253 (PIE 栈溢出模式)',
        'code': r'''#include <stdio.h>
#include <unistd.h>

void process(int fd) {
    char buf[128];
    ssize_t n = read(fd, buf, 512);  // read 512 into buf[128]
    if (n > 0) buf[n] = '\0';
    printf("read %zd bytes\n", n);
}

int main() {
    process(0);
    return 0;
}
''',
        'compile': 'gcc -o vuln vuln.c -fno-stack-protector',
    },
    {
        'id': 'STACK_BOF_03',
        'desc': 'sprintf 栈缓冲区格式化溢出',
        'ref': '模拟 CVE-2016-4484 (LUKS cryptsetup 栈溢出)',
        'code': r'''#include <stdio.h>
#include <string.h>

void process(char *user_input) {
    char buf[32];
    sprintf(buf, "prefix_%s_suffix", user_input);  // user_input 可能很长
    printf("result: %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process(argv[1]);
    return 0;
}
''',
        'compile': 'gcc -o vuln vuln.c -fno-stack-protector',
    },
    {
        'id': 'STACK_BOF_04',
        'desc': 'multi-byte strcat 追加导致累积溢出',
        'ref': '一般栈溢出模式, 多次追加无长度检查',
        'code': r'''#include <stdio.h>
#include <string.h>

void build_path(char *dir, char *file) {
    char path[64] = {0};
    strcat(path, "/home/user/");
    strcat(path, dir);
    strcat(path, "/");
    strcat(path, file);  // 累积追加可能溢出
    printf("path: %s\n", path);
}

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    build_path(argv[1], argv[2]);
    return 0;
}
''',
        'compile': 'gcc -o vuln vuln.c -fno-stack-protector',
    },

# 格式化字符串 (2)
    {
        'id': 'FMT_STR_01',
        'desc': 'printf(user_input) 直接使用用户输入作为格式化字符串',
        'ref': 'CWE-134 / 模拟 scut/team teso 格式字符串攻击',
        'code': r'''#include <stdio.h>

void log_message(char *msg) {
    printf(msg);  // 用户输入直接作为 fmt 参数
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    log_message(argv[1]);
    return 0;
}
''',
        'compile': 'gcc -o vuln vuln.c',
    },
    {
        'id': 'FMT_STR_02',
        'desc': 'fprintf(stderr, user) 间接格式化字符串',
        'ref': 'CWE-134 变体, 通过 fprintf 传递用户输入',
        'code': r'''#include <stdio.h>

void error_out(char *msg) {
    fprintf(stderr, msg);  // msg 来自用户输入
    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    error_out(argv[1]);
    return 0;
}
''',
        'compile': 'gcc -o vuln vuln.c',
    },

# UAF (2)
    {
        'id': 'UAF_01',
        'desc': 'free 后解引用堆指针',
        'ref': 'CWE-416 / 模拟 CVE-2019-11477 (TCP SACK 的 UAF 模式)',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char *data; int len; } Buffer;

void process(char *input) {
    Buffer *b = malloc(sizeof(Buffer));
    b->data = strdup(input);
    b->len = strlen(input);
    printf("len=%d\n", b->len);
    free(b->data);
    free(b);
    printf("freed=%s\n", b->data);  // UAF: b 已被释放
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process(argv[1]);
    return 0;
}
''',
        'compile': 'gcc -o vuln vuln.c',
    },
    {
        'id': 'UAF_02',
        'desc': 'double-free 同一指针释放两次',
        'ref': 'CWE-415 / 一般 double-free 模式',
        'code': r'''#include <stdio.h>
#include <stdlib.h>

void alloc_and_free() {
    char *buf = malloc(256);
    if (!buf) return;
    snprintf(buf, 256, "test data");
    printf("buf=%s\n", buf);
    free(buf);
    free(buf);  // double-free
}

int main() {
    alloc_and_free();
    return 0;
}
''',
        'compile': 'gcc -o vuln vuln.c',
    },

# 堆溢出 (2)
    {
        'id': 'HEAP_BOF_01',
        'desc': 'malloc 后 memcpy 超出分配大小',
        'ref': 'CWE-122 / 通用堆缓冲区溢出',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process(char *input) {
    size_t input_len = strlen(input);
    char *buf = malloc(64);
    if (!buf) return;
    memcpy(buf, input, input_len);  // input_len 可能 > 64
    buf[63] = '\0';
    printf("buf=%s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process(argv[1]);
    return 0;
}
''',
        'compile': 'gcc -o vuln vuln.c',
    },
    {
        'id': 'HEAP_BOF_02',
        'desc': 'realloc 后使用旧 size 拷贝',
        'ref': 'CWE-122 变体, realloc 大小推断错误',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process(char *input) {
    size_t len = strlen(input);
    char *buf = malloc(32);
    buf = realloc(buf, 32);
    strncpy(buf, input, len);  // len 可能 > 32
    buf[31] = '\0';
    printf("buf=%s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    process(argv[1]);
    return 0;
}
''',
        'compile': 'gcc -o vuln vuln.c',
    },
]


def generate_samples() -> list:
    """生成所有合成样本。返回 [(sample_id, output_dir)] 列表。"""
    os.makedirs(_SAMPLE_DIR, exist_ok=True)
    generated = []
    for s in _SAMPLES:
        sid = s['id']
        out_dir = os.path.join(_SAMPLE_DIR, sid)
        os.makedirs(out_dir, exist_ok=True)
        _write_file(os.path.join(out_dir, 'vuln.c'), s['code'])
        _write_file(os.path.join(out_dir, 'build.sh'), _build_script(s))
        _write_file(os.path.join(out_dir, 'README.md'), _readme(s))
        os.chmod(os.path.join(out_dir, 'build.sh'),
                 stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        generated.append((sid, out_dir))
        print(f"  [{sid}] {s['desc']}")
    return generated


def _build_script(s: dict) -> str:
    return f"""#!/bin/bash
# 编译配置: 默认 | 无mitigation | ASAN
set -e
BASE="{s['id']}"
echo "=== Building ${{BASE}} ==="
{s['compile']} -o "${{BASE}}_default"
{s['compile']} -o "${{BASE}}_no_mitigation"
gcc -o "${{BASE}}_asan" vuln.c -fsanitize=address -g -O0 2>/dev/null || echo "(ASAN not supported, skipping)"
echo "Build complete: ${{BASE}}_default, ${{BASE}}_no_mitigation, ${{BASE}}_asan"
"""


def _readme(s: dict) -> str:
    return f"""# {s['id']}

# 漏洞类型
{s['desc']}

#
{s['ref']}

# 编译
```bash
./build.sh
```

# 触发
```bash
./STACK_BOF_01_default $(python3 -c "print('A'*100)")
```
"""


def _write_file(path: str, content: str) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content.lstrip('\n'))


if __name__ == '__main__':
    print("Generating synthetic samples...")
    result = generate_samples()
    print(f"Done: {len(result)} samples generated")
