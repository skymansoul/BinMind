#!/usr/bin/env python
# coding: utf-8
# tests/heap_fp_regression/compile_samples.py — 样本编译模块
# 对 heap_fp_benchmark 下每个样本编译两种变体:
#   build/<sid>/sample.exe        — 未加壳 (导入表可见)
#   build/<sid>/sample_packed.exe — 加壳仿真 (危险API经 GetProcAddress 运行时解析,
#                                   导入表仅剩 kernel32 的 LoadLibrary/GetProcAddress)
# 加壳仿真的意义: 通用工具 (Angr/Ghidra) 依赖导入符号表识别危险函数,
# 加壳后导入表不可见, 其召回会显著下降; 我们的源码级 FC-VRA 不受影响。
# 输出 build/manifest.json 记录每个样本的产物路径。
# 用法: python compile_samples.py [--samples ../heap_fp_benchmark] [--out build]

import json
import shutil
import subprocess
import sys
from pathlib import Path

_ANALYSIS_DIR = Path(__file__).parent.parent.parent / "analysis"

# 危险函数名 → 包装宏 (导入隐藏用)
_PACKED_RENAMES = {
    "malloc": "p_malloc", "calloc": "p_calloc", "realloc": "p_realloc",
    "memcpy": "p_memcpy", "memmove": "p_memmove", "strcpy": "p_strcpy",
    "strncpy": "p_strncpy", "sprintf": "p_sprintf", "snprintf": "p_snprintf",
    "strcat": "p_strcat", "gets": "p_gets", "read": "p_read",
    "recv": "p_recv", "fread": "p_fread", "free": "p_free",
    "scanf": "p_scanf",
}

_PACKER_HEADER = r'''
/* 加壳仿真: 危险API运行时解析, 隐藏导入表 */
#include <windows.h>
#include <stddef.h>
static void *(*p_malloc)(size_t);
static void *(*p_calloc)(size_t, size_t);
static void *(*p_realloc)(void *, size_t);
static void *(*p_memcpy)(void *, const void *, size_t);
static void *(*p_memmove)(void *, const void *, size_t);
static char *(*p_strcpy)(char *, const char *);
static char *(*p_strncpy)(char *, const char *, size_t);
static int (*p_sprintf)(char *, const char *, ...);
static int (*p_snprintf)(char *, size_t, const char *, ...);
static char *(*p_strcat)(char *, const char *);
static char *(*p_gets)(char *);
static long (*p_read)(int, void *, unsigned long);
static int (*p_fread)(void *, size_t, size_t, void *);
static void (*p_free)(void *);
static int (*p_scanf)(const char *, ...);
static int g_init = 0;
static void _init_apis(void) {
    if (g_init) return;
    g_init = 1;
    HMODULE m = GetModuleHandleA("msvcrt.dll");
    if (!m) m = LoadLibraryA("msvcrt.dll");
    p_malloc = (void *(*)(size_t))GetProcAddress(m, "malloc");
    p_calloc = (void *(*)(size_t, size_t))GetProcAddress(m, "calloc");
    p_realloc = (void *(*)(void *, size_t))GetProcAddress(m, "realloc");
    p_memcpy = (void *(*)(void *, const void *, size_t))GetProcAddress(m, "memcpy");
    p_memmove = (void *(*)(void *, const void *, size_t))GetProcAddress(m, "memmove");
    p_strcpy = (char *(*)(char *, const char *))GetProcAddress(m, "strcpy");
    p_strncpy = (char *(*)(char *, const char *, size_t))GetProcAddress(m, "strncpy");
    p_sprintf = (int (*)(char *, const char *, ...))GetProcAddress(m, "sprintf");
    p_snprintf = (int (*)(char *, size_t, const char *, ...))GetProcAddress(m, "snprintf");
    p_strcat = (char *(*)(char *, const char *))GetProcAddress(m, "strcat");
    p_gets = (char *(*)(char *))GetProcAddress(m, "gets");
    p_read = (long (*)(int, void *, unsigned long))GetProcAddress(m, "read");
    p_fread = (int (*)(void *, size_t, size_t, void *))GetProcAddress(m, "fread");
    p_free = (void (*)(void *))GetProcAddress(m, "free");
    p_scanf = (int (*)(const char *, ...))GetProcAddress(m, "scanf");
}
'''

_PACKED_SRC_HOOKS = {
    "malloc": "p_malloc", "calloc": "p_calloc", "realloc": "p_realloc",
    "memcpy": "p_memcpy", "memmove": "p_memmove", "strcpy": "p_strcpy",
    "strncpy": "p_strncpy", "sprintf": "p_sprintf", "snprintf": "p_snprintf",
    "strcat": "p_strcat", "read": "p_read", "fread": "p_fread",
    "free": "p_free", "scanf": "p_scanf",
}


def _gcc_flags() -> list:
    return ["-Wall", "-Wextra", "-O0", "-g", "-o"]


def _run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def _strip_import_directory(pe_path: Path) -> bool:
    """剥离 PE 导入目录 (模拟加壳后导入表不可见)。

    UPX 等加壳器的导入表在运行时由脱壳stub重建; 静态分析看到的
    是空白导入目录。直接定位 OptionalHeader.DataDirectory[1]
    (IMAGE_DIRECTORY_ENTRY_IMPORT) 的 8 字节 (RVA+Size) 并置零。
    失败时返回 False (保持原样)。
    """
    import struct
    try:
        data = bytearray(pe_path.read_bytes())
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        magic = struct.unpack_from("<H", data, lfanew + 24)[0]
        # PE32+ 可选头固定部分 112 字节; PE32 为 96 字节
        dd_base = lfanew + (136 if magic == 0x20B else 120)
        import_off = dd_base + 1 * 8  # 目录项1 = Import
        if import_off + 8 <= len(data):
            data[import_off:import_off + 8] = b"\x00" * 8
            pe_path.write_bytes(bytes(data))
            return True
        return False
    except Exception:
        return False


def compile_sample(src_dir: Path, build_dir: Path, packed_dir: Path):
    sid = src_dir.name
    vuln = src_dir / "vuln.c"
    if not vuln.exists():
        return None
    out = build_dir / sid
    out.mkdir(parents=True, exist_ok=True)
    packed_out = packed_dir / sid
    packed_out.mkdir(parents=True, exist_ok=True)

    exe = out / "sample.exe"
    r = _run(["gcc", "-Wall", "-Wextra", "-O0", "-g",
              "-o", str(exe), str(vuln)], cwd=out)
    if r.returncode != 0:
        return {"sample": sid, "status": "build_failed",
                "error": r.stderr[:300]}

    # 加壳变体: 源码级重写 (危险函数 → 指针调用) + 初始化钩子
    packed_src = packed_out / "sample_packed.c"
    src_text = vuln.read_text(encoding="utf-8", errors="replace")
    for old, new in _PACKED_SRC_HOOKS.items():
        src_text = src_text.replace(f"{old}(", f"{new}(")
    # main 入口注入初始化调用 (两种签名)
    if "int main(void) {" in src_text:
        src_text = src_text.replace("int main(void) {",
                                    "int main(void) { _init_apis(); ", 1)
    if "int main(int argc, char **argv) {" in src_text:
        src_text = src_text.replace("int main(int argc, char **argv) {",
                                    "int main(int argc, char **argv) { "
                                    "_init_apis(); ", 1)
    packed_full = _PACKER_HEADER + "\n" + src_text
    packed_src.write_text(packed_full, encoding="utf-8")
    packed_exe = packed_out / "sample_packed.exe"
    r2 = _run(["gcc", "-Wall", "-Wextra", "-O0", "-g",
               "-o", str(packed_exe), str(packed_src)], cwd=packed_out)
    if r2.returncode != 0:
        return {"sample": sid, "status": "ok", "unpacked": str(exe),
                "packed": str(packed_exe), "packed_status": "packed_build_failed"}
    # 剥离导入目录 → 导入不可见 (加壳仿真)
    stripped = _strip_import_directory(packed_exe)
    status = "packed_ok(import_stripped)" if stripped else "packed_ok(import_present)"
    return {"sample": sid, "status": "ok", "unpacked": str(exe),
            "packed": str(packed_exe), "packed_status": status}


def main():
    base = Path(__file__).parent
    samples_dir = (base / ".." / "heap_fp_benchmark").resolve()
    build_dir = (base / "build").resolve()
    packed_dir = (base / "build_packed").resolve()
    if len(sys.argv) > 1:
        samples_dir = Path(sys.argv[1]).resolve()
    if "--out" in sys.argv:
        build_dir = Path(sys.argv[sys.argv.index("--out") + 1]).resolve()

    manifest = []
    for d in sorted(samples_dir.iterdir()):
        if d.is_dir() and (d / "vuln.c").exists():
            info = compile_sample(d, build_dir, packed_dir)
            if info:
                manifest.append(info)
                print(f"  {info['sample']}: {info['status']} "
                      f"(packed={info.get('packed_status')})")

    with open(build_dir / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    print(f"manifest: {build_dir / 'manifest.json'}")


if __name__ == "__main__":
    main()
