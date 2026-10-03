# 堆溢出测试样本生成器
# 为每个CVE生成含明确 malloc(N)+memcpy(M>N) 溢出模式的二进制样本
import os, json, subprocess, shutil
from pathlib import Path

BUILD = Path(__file__).resolve().parent / "build"
BUILD.mkdir(parents=True, exist_ok=True)

# 17个样本定义: (cve_id, alloc_size, write_size, function_prefix)
HEAP_SAMPLES = [
    ("cve_2013_4788", 64, 256, "android_media"),
    ("cve_2015_0235", 128, 512, "ghost_glibc"),
    ("cve_2016_10158", 32, 256, "php_exif"),
    ("cve_2016_6301", 48, 1024, "ntp_recv"),
    ("cve_2016_6301_ntpd", 64, 320, "ntpd_ctl"),
    ("cve_2017_1000112", 128, 4096, "linux_udp"),
    ("cve_2017_7269", 80, 512, "iis_scstorage"),
    ("cve_2018_1000001", 64, 256, "libcurl_tftp"),
    ("cve_2018_14634", 32, 256, "kernel_create"),
    ("cve_2019_1579", 16, 256, "paloalto_web"),
    ("cve_2019_2215", 64, 512, "binder_use"),
    ("cve_2019_3462", 96, 512, "debian_apt"),
    ("cve_2020_0022", 32, 128, "bluetooth_l2cap"),
    ("cve_2020_10757", 128, 1024, "kernel_mremap"),
    ("cve_2021_3156", 64, 256, "sudo_edit"),
    ("cve_2021_4034", 128, 2048, "polkit_dbus"),
    ("cve_2022_0185", 48, 512, "fs_context"),
]

TEMPLATE = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// {cve} 堆溢出模拟: malloc({alloc_sz}) + memcpy({write_sz})
// → {overflow} 字节溢出
void {prefix}_overflow() {{
    char *buf = (char *)malloc({alloc_sz});
    if (!buf) return;
    memcpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", {write_sz});
    printf("{prefix}: buf[0]=%c\\n", buf[0]);
    free(buf);
}}

// 安全对照: malloc({safe_sz}) + memcpy({safe_sz}/2) → 不溢出
void {prefix}_safe() {{
    char *buf = (char *)malloc({safe_sz});
    if (!buf) return;
    memcpy(buf, "safe data here", 14);
    printf("{prefix}_safe: %s\\n", buf);
    free(buf);
}}

int main(int argc, char **argv) {{
    printf("{cve} heap overflow test\\n");
    {prefix}_overflow();
    {prefix}_safe();
    return 0;
}}
"""


def generate_sources():
    """生成C源文件."""
    src_dir = BUILD.parent / "src"
    src_dir.mkdir(parents=True, exist_ok=True)

    for cve, alloc_sz, write_sz, prefix in HEAP_SAMPLES:
        safe_sz = max(alloc_sz * 2, write_sz + 64)
        overflow = write_sz - alloc_sz
        c_code = TEMPLATE.format(
            cve=cve, alloc_sz=alloc_sz, write_sz=write_sz,
            overflow=overflow, prefix=prefix, safe_sz=safe_sz)

        fname = f"{cve}_heap_overflow"
        c_path = src_dir / f"{fname}.c"
        with open(c_path, "w") as f:
            f.write(c_code)
        print(f"  Generated {c_path.name}")


def compile_all():
    """用 mingw-gcc 编译所有样本."""
    src_dir = BUILD.parent / "src"
    compiler = shutil.which("x86_64-w64-mingw32-gcc") or shutil.which("gcc")
    if not compiler:
        print("[ERROR] No compiler found")
        return []

    manifest = []
    for cve, alloc_sz, write_sz, prefix in HEAP_SAMPLES:
        fname = f"{cve}_heap_overflow"
        c_path = src_dir / f"{fname}.c"
        exe_path = BUILD / f"{fname}_O0.exe"
        if not c_path.exists():
            print(f"  [SKIP] {fname}.c not found")
            continue

        cmd = [compiler, "-O0", str(c_path), "-o", str(exe_path)]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"  [FAIL] {fname}: {r.stderr[:120]}")
            continue

        compiled = exe_path.exists()
        if compiled:
            print(f"  [OK] {fname} ({alloc_sz}/{write_sz}) → {exe_path.name}")
        manifest.append({
            "cve": cve, "type": "heap_overflow",
            "compiler": "gcc", "opt": "O0",
            "binary": str(exe_path.resolve()),
            "compiled": compiled,
            "alloc_size": alloc_sz, "write_size": write_sz,
        })

    # 写manifest
    manifest_path = BUILD / "manifest_heap.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\nManifest: {manifest_path} ({len(manifest)} entries)")
    return manifest


if __name__ == "__main__":
    import sys
    if "--compile" in sys.argv:
        compile_all()
    else:
        generate_sources()
        print("\nRun with --compile to build binaries")
