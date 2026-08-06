# Ghidra headless 自动化分析脚本
"""通过Ghidra的analyzeHeadless模式对binary做基础安全分析。
需要设置GHIDRA_HOME环境变量指向Ghidra安装目录。
无Ghidra时导出空结果并标记error。"""
import os, sys, json, time, subprocess, tempfile

def analyze_binary(binary_path: str) -> dict:
    t0 = time.time()
    result = {"tool": "Ghidra", "binary": binary_path, "detected": False,
              "functions_analyzed": 0, "time_secs": 0, "error": None}
    ghidra_home = os.environ.get("GHIDRA_HOME", "")
    if not ghidra_home:
        result["error"] = "GHIDRA_HOME not set"
        return result
    try:
        tmp = tempfile.mkdtemp()
        headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
        # PostScript: 对binary做快速分析，导出函数列表
        post_script = os.path.join(os.path.dirname(__file__), "ghidra_post_script.py")
        cmd = [headless, tmp, "BinMind_Bench", "-import", binary_path,
               "-postScript", post_script, "-deleteProject", "-noanalysis"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        result["detected"] = "dangerous" in proc.stdout.lower()
    except FileNotFoundError:
        result["error"] = "analyzeHeadless not found"
    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)[:200]
    result["time_secs"] = round(time.time() - t0, 2)
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python ghidra_headless.py <binary>"); sys.exit(1)
    print(json.dumps(analyze_binary(sys.argv[1]), indent=2))
