# intof 精度基准 — 独立 vuln/safe 二进制生成器
#
# 决策:
#   现有 samples_intof 将 vuln/safe 函数混编于同一二进制, 检测结果
#   无法按函数归属归因到"应检出"或"不应检出". 本生成器解析模板
#   源码, 将 main 体替换为仅调用 vuln 函数 或 仅调用 safe 函数,
#   输出独立二进制, 使检出可精确归因.
#
# 判定: vuln 二进制检出=TP; safe 二进制检出=FP.
# 创建: 2023-06-23

import json
import re
import subprocess
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gen_intof_templates import get_template, SAMPLE_DEFS

ROOT = Path(__file__).resolve().parent
BIN_DIR = ROOT / "bin"
BIN_DIR.mkdir(parents=True, exist_ok=True)


def _split_calls(src: str, vuln_func: str, safe_func: str):
    """提取两个函数的调用名 (去掉前缀 v_)."""
    v_call = vuln_func.replace("_vuln", "", 1)
    s_call = safe_func.replace("_safe", "", 1)
    return v_call, s_call


def build_variant(src: str, func_name: str, keep_vuln: bool) -> str:
    """生成只调用指定函数的独立 C 源码.

    func_name: 要保留的函数名 (含 _vuln/_safe 后缀).
    keep_vuln: True 保留 vuln 函数, False 保留 safe 函数.
    模板不含 #include, 需补全标准头 (size_t/malloc/memset/printf).
    """
    # 提取目标函数定义
    m = re.search(
        r'(void ' + re.escape(func_name) + r'\s*\(.*?\n\}\n)',
        src, re.DOTALL)
    if not m:
        return None
    func_def = m.group(1)

    # 保留 volatile sink 定义行 (模板内)
    sink_def = ""
    m2 = re.search(r'static volatile void \*volatile_vuln_sink;[^\n]*', src)
    if m2:
        sink_def = m2.group(0) + "\n"

    header = ("#include <stdio.h>\n"
              "#include <stdlib.h>\n"
              "#include <string.h>\n"
              "#include <stdint.h>\n\n")

    variant = header + sink_def + "\n" + func_def + "\n"
    variant += "int main(int argc, char **argv) {\n"
    variant += f"    (void)argc; (void)argv;\n"
    variant += f"    {func_name};\n"
    variant += "    return 0;\n"
    variant += "}\n"
    return variant


def main():
    manifest = []
    for cve, name, desc, pattern in SAMPLE_DEFS:
        safe_name = f"v_{name}_safe"
        src = get_template(pattern, safe_name)
        funcs = re.findall(r'void (\w+)\s*\(', src)
        vuln_f = [f for f in funcs if f.endswith("_vuln")]
        safe_f = [f for f in funcs if f.endswith("_safe")]
        if not vuln_f or not safe_f:
            print(f"  SKIP {name}: func pattern not found")
            continue
        for variant_key, keep_vuln, fname in (
                ("vuln", True, vuln_f[0]),
                ("safe", False, safe_f[0])):
            variant_src = build_variant(src, fname, keep_vuln)
            if variant_src is None:
                print(f"  SKIP {name}_{variant_key}")
                continue
            for opt in ("O0", "O2", "Os"):
                src_path = ROOT / f"{name}_{variant_key}.c"
                exe_path = BIN_DIR / f"{name}_{variant_key}_{opt}.exe"
                src_path.write_text(variant_src, encoding="utf-8")
                r = subprocess.run(
                    ["gcc", f"-{opt}", "-no-pie", "-fno-pie", "-fno-builtin",
                     "-o", str(exe_path), str(src_path)],
                    capture_output=True, text=True, timeout=60)
                compiled = r.returncode == 0 and exe_path.exists()
                if not compiled:
                    print(f"  COMPILE ERR {name}_{variant_key} {opt}: "
                          f"{(r.stderr or '')[:100]}")
                manifest.append({
                    "cve": cve, "name": name, "pattern": pattern,
                    "variant": variant_key, "opt": opt,
                    "is_vuln": keep_vuln,
                    "binary": str(exe_path.resolve()),
                    "compiled": compiled,
                })
        print(f"  {name}: vuln+safe generated")

    out = ROOT / "intof_manifest.json"
    out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    cc = sum(1 for m in manifest if m["compiled"])
    print(f"intof_manifest.json: {len(manifest)} entries, {cc} compiled")


if __name__ == "__main__":
    main()
