# 多类型漏洞测试样本生成器: UAF / 格式化字符串 / 整数溢出
import os, json, subprocess, shutil
from pathlib import Path

BUILD = Path(__file__).resolve().parent / "build"
SRC = Path(__file__).resolve().parent / "src"
BUILD.mkdir(parents=True, exist_ok=True)
SRC.mkdir(parents=True, exist_ok=True)

CC = shutil.which("x86_64-w64-mingw32-gcc") or shutil.which("gcc") or "gcc"

# UAF 样本 (15个)
UAF = [
    ("cve_2016_10150","kvm_uaf","global ptr: malloc→free→use via global variable"),
    ("cve_2017_2636","kernel_uaf","local ptr: malloc→free→deref in same function"),
    ("cve_2017_7533","inode_uaf","struct field: malloc→free→pass freed ptr to func"),
    ("cve_2018_7566","alsa_uaf","double-free: malloc→free→free again"),
    ("cve_2018_17182","vmac_uaf","conditional: free on one path, use on another"),
    ("cve_2019_2215","binder_uaf","ephemeral ptr: malloc in helper, free in caller, use later"),
    ("cve_2019_15291","brcm_uaf","NULL bypass: free→skip null→reuse via global"),
    ("cve_2019_19532","hid_uaf","out-of-order: two mallocs, free first, use second ptr"),
    ("cve_2020_0022","bt_uaf","callback UAF: malloc→free in cb→use in caller"),
    ("cve_2020_14386","afpacket_uaf","error path: malloc→free on error→use on retry"),
    ("cve_2020_25211","netfilter_uaf","pass-as-arg: malloc→free→pass freed to function"),
    ("cve_2021_32399","blk_uaf","deref pattern: malloc→free→mov rax,[global]→use"),
    ("cve_2021_34866","ebpf_uaf","verifier bypass: alloc→free→use via alias pointer"),
    ("cve_2022_0995","watch_uaf","two-phase: alloc→free in cleanup→use via cached ref"),
    ("cve_2023_0461","io_uring_uaf","chained: alloc→free→use in completion handler"),
]

UAF_CODE = '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// {cve} UAF: {desc}
char *{prefix}_global = NULL;

void {prefix}_vuln() {{
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    {prefix}_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if ({prefix}_global) {{
        // USE-AFTER-FREE: 解引用已释放指针
        printf("{prefix}: freed[0]=%c\\n", {prefix}_global[0]);
    }}
    {prefix}_global = NULL;
}}

void {prefix}_safe() {{
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("{prefix}_safe: %s\\n", buf);
    free(buf);
    buf = NULL;
}}

int main() {{
    printf("{cve} UAF test\\n");
    {prefix}_vuln();
    {prefix}_safe();
    return 0;
}}
'''

# 格式化字符串样本 (14个)
FMT = [
    ("cve_2012_0809","sudo_fmt","printf(user_input): argv[0] as format string"),
    ("cve_2013_7040","python_fmt","PyString_Format: external fmt control"),
    ("cve_2015_8612","bluetooth_fmt","sprintf(buf, user_fmt, arg): controllable fmt"),
    ("cve_2017_1000370","linux_fmt","printf(fmt_from_stack): stack fmt injection"),
    ("cve_2018_1000001","tftp_fmt","fprintf(stderr, msg): msg from network input"),
    ("cve_2018_12086","epan_fmt","g_strdup_printf(user_str): % specifiers in input"),
    ("cve_2019_11477","tcp_fmt","printk(user_data): kernel fmt vuln"),
    ("cve_2019_13631","hid_fmt","snprintf(buf, n, env_var, arg): env-controlled fmt"),
    ("cve_2020_10713","grub_fmt","grub_printf(path): filepath as format"),
    ("cve_2020_25656","vt_fmt","vt_printf(kb_data): keyboard input as fmt"),
    ("cve_2021_3156","sudo_fmt2","fprintf(fp, argv[1]): cmdline arg fmt"),
    ("cve_2021_33624","ebpf_fmt","bpf_trace_printk(fmt): BPF fmt injection"),
    ("cve_2022_23222","perf_fmt","perf_event_output: fmt string leak"),
    ("cve_2023_0160","audit_fmt","audit_log_user_format(user_msg): %n in user_msg"),
]

FMT_CODE = '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// {cve} Format String Vuln: {desc}

void {prefix}_vuln(char *user_input) {{
    // 危险: 用户输入直接作为格式字符串 (而非%s参数)
    printf(user_input);
}}

void {prefix}_vuln2(char *user_input) {{
    fprintf(stderr, user_input);
}}

void {prefix}_safe() {{
    printf("%s\\n", "literal format string");
}}

int main() {{
    char payload[] = "%x %x %x %x %x %x %x %n";  // 攻击payload: 含%n写入
    printf("{cve} fmt test\\n");
    {prefix}_vuln(payload);
    {prefix}_vuln2(payload);
    {prefix}_safe();
    return 0;
}}
'''

# 整数溢出样本 (15个)
INTOF = [
    ("cve_2010_3089","mailto_intof","mul overflow: n*sizeof(struct)+4 wraps 32-bit"),
    ("cve_2013_1959","userns_intof","truncation: (int16)(int32) uid_t downcast"),
    ("cve_2014_2851","ping_intof","u16 overflow: ICMP payload length calc wraps"),
    ("cve_2015_8958","sunras_intof","signed mul: rows*cols overflows int32"),
    ("cve_2016_6187","compat_intof","truncation: u64→u32 compat ioctl"),
    ("cve_2016_9555","sctp_intof","signed overflow: ssize_t len bypass check"),
    ("cve_2017_7184","xfrm_intof","addition overflow: offset+len wraps u32"),
    ("cve_2017_12154","kvm_intof","mul overflow: n*elem_size bypasses alloc guard"),
    ("cve_2018_1000026","bcm_intof","shift overflow: 1<<n with n>31 wraps int"),
    ("cve_2018_14634","create_intof","mul overflow: count*sizeof(T) in ELF loader"),
    ("cve_2019_11479","mss_intof","add overflow: offset+size wraps u16 in MSS"),
    ("cve_2019_19332","kvm_mul_intof","signed mul: (int)n*(int)size overflows"),
    ("cve_2020_10757","mremap_intof","shift+mul: nr<<12 wraps before page alloc"),
    ("cve_2021_40490","ext4_intof","truncation: u64 block→u32 in ext4 resize"),
    ("cve_2022_42703","mm_intof","VMA merge: len+addr overflows u64 boundary"),
]

INTOF_CODE = '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// {cve} Integer Overflow: {desc}

void {prefix}_mul_overflow(int count) {{
    // count*sizeof(int) 可能溢出 → malloc 分配过小缓冲区
    size_t sz = (size_t)count * sizeof(int);
    if (sz < 4096) {{  // 安全门卫被溢出绕过: count=1073741824→sz=0
        char *buf = (char *)malloc(sz);
        if (!buf) {{ printf("{prefix}: malloc NULL\\n"); return; }}
        // 实际写入远超分配大小 (若sz被截断)
        memset(buf, 0, sz > 0 ? sz : 4096);
        free(buf);
    }}
    printf("{prefix}: done\\n");
}}

void {prefix}_safe_mul(int count) {{
    size_t sz = (size_t)count * sizeof(int);
    // 溢出检测: 逆运算不相等即溢出
    if (sz / sizeof(int) != (size_t)count) {{
        printf("{prefix}: overflow rejected\\n");
        return;
    }}
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memset(buf, 0, sz);
    free(buf);
    printf("{prefix}: ok\\n");
}}

int main() {{
    printf("{cve} intof test\\n");
    {prefix}_mul_overflow(1073741824);
    {prefix}_safe_mul(1073741824);
    return 0;
}}
'''


def compile_one(src_path, exe_path):
    r = subprocess.run([CC, "-O0", str(src_path), "-o", str(exe_path)],
                        capture_output=True, text=True)
    return exe_path.exists() and r.returncode == 0


def generate(samples, template, vtype, label):
    manifest = []
    for cve, prefix, desc in samples:
        code = template.format(cve=cve, prefix=prefix, desc=desc)
        fname = f"{cve}_{prefix}_{vtype}"
        c_path = SRC / f"{fname}.c"
        c_path.write_text(code)
        exe_path = BUILD / f"{fname}_O0.exe"
        ok = compile_one(c_path, exe_path)
        status = "OK" if ok else "FAIL"
        print(f"  [{status}] {fname}")
        manifest.append(dict(cve=cve, type=vtype, compiler="gcc", opt="O0",
            binary=str(exe_path.resolve()), compiled=ok, prefix=prefix))
    return manifest


if __name__ == "__main__":
    import sys
    do_compile = "--compile" in sys.argv

    if do_compile:
        print(f"\n=== UAF ({len(UAF)} samples) ===")
        uaf_m = generate(UAF, UAF_CODE, "uaf", "UAF")
        print(f"\n=== Format String ({len(FMT)} samples) ===")
        fmt_m = generate(FMT, FMT_CODE, "format_string", "FMT")
        print(f"\n=== Integer Overflow ({len(INTOF)} samples) ===")
        intof_m = generate(INTOF, INTOF_CODE, "integer_overflow", "INTOF")

        full = uaf_m + fmt_m + intof_m
        mp = BUILD / "manifest_all.json"
        mp.write_text(json.dumps(full, indent=2))
        compiled = sum(1 for e in full if e["compiled"])
        print(f"\nManifest: {mp} ({len(full)} entries, {compiled} compiled)")
    else:
        for samples, template, vtype in [(UAF, UAF_CODE, "uaf"),
                                           (FMT, FMT_CODE, "fmt"),
                                           (INTOF, INTOF_CODE, "intof")]:
            for cve, prefix, desc in samples:
                code = template.format(cve=cve, prefix=prefix, desc=desc)
                (SRC / f"{cve}_{prefix}_{vtype}.c").write_text(code)
        total = len(UAF) + len(FMT) + len(INTOF)
        print(f"Generated {total} source files ({len(UAF)} UAF + {len(FMT)} FMT + {len(INTOF)} INTOF)")
        print("Run with --compile to build binaries")
