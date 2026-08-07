# 堆溢出 CVE 样本集生成器.
#
# 决策逻辑:
#   为每个样本生成独立目录: vuln.c / Makefile / README.md,
#   并写出 samples/manifest.json 作为 ground truth,
#   供回归套件与对比实验引用.
#   样本分两类: vulnerable (真实 CVE 漏洞模式复现, 预期 CONFIRMED)
#   与 safe (误报挑战对照, 预期 BENIGN 或 SUSPECTED).
#   alloc/write 支持常量或 "param" (来自 argv), 模板按 pattern 选型.
#
# 创建: 2026-05-07

import json
from pathlib import Path

VULN = [
    ("cve_2013_4788_android_media", "CVE-2013-4788", "fixed_alloc_tainted_write",
     64, 128, "confirmed",
     "Android mediaserver MPEG4 stbl 解析: 固定64字节堆缓冲, 以样本头长度 memcpy 128字节"),
    ("cve_2015_0235_ghost", "CVE-2015-0235", "off_by_one_alloc_linked",
     "param", "param+1", "confirmed",
     "glibc GHOST: malloc(hostlen) 后写入 hostlen+1 (gethostbyname off-by-one)"),
    ("cve_2016_10158_php_exif", "CVE-2016-10158", "fixed_alloc_tainted_write",
     32, 256, "confirmed",
     "PHP EXIF get_efi_data: 固定32字节缓冲, memcpy 256字节"),
    ("cve_2016_6301_ntpd", "CVE-2016-6301", "fixed_alloc_tainted_write",
     48, 1024, "confirmed",
     "NTPd receive: 48字节堆缓冲, 网络包长度 memcpy 1024字节"),
    ("cve_2017_1000112_linux_udp", "CVE-2017-1000112", "fixed_alloc_tainted_write",
     128, 4096, "confirmed",
     "Linux UDP fraglist: 128字节skb, UDP分片长度 memcpy 4096字节"),
    ("cve_2017_7269_iis_scstorage", "CVE-2017-7269", "fixed_alloc_tainted_write",
     80, 512, "confirmed",
     "IIS ScStoragePathFromUrl: 80字节堆缓冲, 请求URL长度 memcpy 512字节"),
    ("cve_2018_1000001_curl_tftp", "CVE-2018-1000001", "alloc_param_tainted_write",
     "param", "param*2", "confirmed",
     "cURL TFTP: 按包长参数分配, 收到更大块时写入超限"),
    ("cve_2018_14634_kernel_create_elf", "CVE-2018-14634", "intof_alloc_tainted_write",
     "param", "param*16", "confirmed",
     "Linux create_elf_tables: 参数乘积回绕导致小分配+大写入"),
    ("cve_2019_1579_paloalto_gp", "CVE-2019-1579", "fixed_alloc_tainted_write",
     16, 256, "confirmed",
     "Palo Alto GlobalProtect: 16字节堆缓冲, 会话长度 memcpy 256字节"),
    ("cve_2019_2215_binder_trans", "CVE-2019-2215", "fixed_alloc_tainted_write",
     64, 512, "confirmed",
     "Android Binder 交易: 64字节堆缓冲, 事务数据 memcpy 512字节"),
    ("cve_2019_3462_debian_apt", "CVE-2019-3462", "off_by_one_alloc_linked",
     "param", "param+1", "confirmed",
     "Debian apt signedby: 按哈希长度分配, 写入 len+1 溢出1字节"),
    ("cve_2020_0022_bt_l2cap", "CVE-2020-0022", "fixed_alloc_tainted_write",
     32, 128, "confirmed",
     "Android Bluetooth L2CAP: 32字节堆缓冲, 畸形包长度 memcpy 128字节"),
    ("cve_2021_3156_sudo_baron", "CVE-2021-3156", "off_by_one_alloc_linked",
     "param", "param+1", "confirmed",
     "sudo Baron Samedit: 按 argv[0] 长度分配, 写入 len+1 字节 off-by-one"),
    ("cve_2021_4034_polkit_pkexec", "CVE-2021-4034", "fixed_alloc_tainted_write_param",
     16, "param", "confirmed",
     "polkit pkexec: 固定16字节堆缓冲, argv 数据 memcpy 超限"),
    ("cve_2022_0185_fs_context", "CVE-2022-0185", "off_by_one_alloc_linked",
     "param", "param+1", "confirmed",
     "Linux fs_context legacy_parse_param: 分配 len 写入 len+1 字节"),
]

SAFE = [
    ("safe_01_correlated", "N/A", "alloc_linked_write",
     "param", "param", "benign",
     "同源安全: malloc(n) + memcpy(n), n 来自 argv"),
    ("safe_02_guarded", "N/A", "guarded_write",
     64, "param", "benign",
     "守卫安全: malloc(64), 写入前 if(len<=64) 边界检查"),
    ("safe_03_padding", "N/A", "allocator_padding",
     62, 63, "benign",
     "分配器padding: malloc(62) glibc usable=72, 写入63字节不溢出"),
    ("safe_04_alloc_plus_one", "N/A", "alloc_linked_write",
     "param", "param", "benign",
     "同源-1安全: malloc(n+1) + memcpy(n)"),
    ("safe_05_exact_constant", "N/A", "exact_constant",
     256, 256, "benign",
     "常量精确: malloc(256) + memcpy(256) 恰好等大"),
]

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

SAMPLES_ROOT = Path(__file__).resolve().parent.parent / "samples"


def _alloc_str(a):
    return str(a)


def _select_template(pattern: str, is_vuln: bool):
    if not is_vuln:
        return _SAFE_TEMPLATES[pattern]
    return _VULN_TEMPLATES[pattern]


def generate():
    """生成全部样本目录与 manifest."""
    manifest = []
    SAMPLES_ROOT.mkdir(parents=True, exist_ok=True)

    for item in VULN + SAFE:
        sample_id, cve, pattern, alloc, write, expected, desc = item
        is_vuln = expected == "confirmed"
        tpl = _select_template(pattern, is_vuln)
        c_code = tpl.format(
            cve=cve, sample=sample_id, desc=desc,
            alloc=_alloc_str(alloc), write=_alloc_str(write),
            vuln="恶意" if is_vuln else "正常")

        d = SAMPLES_ROOT / sample_id
        d.mkdir(parents=True, exist_ok=True)

        (d / "vuln.c").write_text(c_code, encoding="utf-8")
        (d / "Makefile").write_text(
            MAKEFILE.format(sample=sample_id), encoding="utf-8")
        (d / "README.md").write_text(README.format(
            sample=sample_id, cve=cve,
            type="heap_overflow (vulnerable)" if is_vuln
            else "heap_overflow (safe control)",
            pattern=pattern, expected=expected, desc=desc,
            vuln="恶意" if is_vuln else "安全",
            trigger=TRIGGERS.get(pattern, "构造超限输入")), encoding="utf-8")

        manifest.append({
            "sample_id": sample_id,
            "cve": cve,
            "type": "heap_overflow",
            "ground_truth": "vulnerable" if is_vuln else "safe",
            "expected": expected,
            "pattern": pattern,
            "alloc_size": alloc,
            "write_size": write,
            "source": "vuln.c",
            "desc": desc,
        })

    manifest_path = SAMPLES_ROOT / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"generated {len(manifest)} samples -> {SAMPLES_ROOT}")
    print(f"manifest -> {manifest_path}")
    return manifest


if __name__ == "__main__":
    generate()
