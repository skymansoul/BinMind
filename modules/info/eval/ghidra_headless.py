# eval/ghidra_headless — Ghidra 无头模式自动化分析脚本
# 对目标 ELF 执行: 导入表提取 → 危险函数识别 → 交叉引用追踪
# 若 Ghidra 未安装则输出 SKIP。
# 使用方式: $GHIDRA_HOME/support/analyzeHeadless <proj_dir> <proj_name> -import <target> -postScript <this_script>

import subprocess, json, os, sys, tempfile
from pathlib import Path

GHIDRA_SCRIPT = r'''
# @category BinMind.Eval
# Automated heap overflow vulnerability audit for headless analysis

import json
dangerous = {"memcpy","strcpy","sprintf","gets","system","execve","popen","malloc","free","realloc"}
found = []
try:
    fm = currentProgram.getFunctionManager()
    for fname in dangerous:
        funcs = fm.getFunctions(fname)
        for func in funcs:
            xrefs = getReferencesTo(func.getEntryPoint())
            callers = []
            for xref in xrefs:
                if xref.getReferenceType().isCall():
                    caller_func = fm.getFunctionContaining(xref.getFromAddress())
                    if caller_func:
                        callers.append(str(caller_func.getName()))
            found.append({
                "function": fname,
                "address": str(func.getEntryPoint()),
                "caller_count": len(callers),
                "callers": callers[:5],
            })
except Exception as e:
    found = [{"error": str(e)}]

# output as JSON to stdout
print("__GHIDRA_OUTPUT_START__")
print(json.dumps({"tool":"ghidra","found":len(found),"functions":found}))
print("__GHIDRA_OUTPUT_END__")
'''


def analyze(target: str, ghidra_home: str = None) -> dict:
    """运行 Ghidra 无头分析。"""
    if ghidra_home is None:
        ghidra_home = os.environ.get("GHIDRA_HOME", "/opt/ghidra")
    headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
    if not os.path.exists(headless) and not os.path.exists(headless + ".bat"):
        # 也尝试常见路径
        for candidate in ["/opt/ghidra/support/analyzeHeadless",
                          "/usr/local/ghidra/support/analyzeHeadless",
                          "C:/ghidra/support/analyzeHeadless.bat"]:
            if os.path.exists(candidate):
                headless = candidate
                break
        else:
            return {"tool": "ghidra", "error": "ghidra_not_found", "available": False,
                    "hint": "set GHIDRA_HOME env var or install ghidra"}

    # 写脚本到临时文件
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(GHIDRA_SCRIPT)
        script_path = f.name

    proj_dir = tempfile.mkdtemp(prefix="ghidra_")
    try:
        proc = subprocess.run(
            [headless, proj_dir, "BinMindEval", "-import", target,
             "-postScript", script_path, "-deleteProject"],
            capture_output=True, text=True, timeout=300,
        )
        output = proc.stdout + proc.stderr
        # 提取 JSON 输出
        if "__GHIDRA_OUTPUT_START__" in output:
            start = output.index("__GHIDRA_OUTPUT_START__") + len("__GHIDRA_OUTPUT_START__")
            end = output.index("__GHIDRA_OUTPUT_END__")
            return json.loads(output[start:end].strip())
        return {"tool": "ghidra", "error": "no_output", "raw": output[:500]}
    except subprocess.TimeoutExpired:
        return {"tool": "ghidra", "error": "timeout", "available": True}
    except Exception as e:
        return {"tool": "ghidra", "error": str(e)[:200]}
    finally:
        os.unlink(script_path)
        # 清理项目目录
        import shutil
        try: shutil.rmtree(proj_dir, ignore_errors=True)
        except: pass


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    if target and os.path.exists(target):
        result = analyze(target)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps({"error": "usage: python ghidra_headless.py <elf>"}))
