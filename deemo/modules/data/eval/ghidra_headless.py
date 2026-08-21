# Ghidra Headless 自动化静态审计 - 批量分析危险函数调用

import os, sys, json, time, subprocess, tempfile

def find_ghidra_headless() -> str:
    """查找 analyzeHeadless 二进制."""
    home = os.environ.get("GHIDRA_HOME","")
    for base in [home, "/opt/ghidra", os.path.expanduser("~/ghidra")]:
        for suffix in ["support/analyzeHeadless","support/analyzeHeadless.bat"]:
            p = os.path.join(base, suffix)
            if os.path.isfile(p): return p
    return ""

def analyze_with_ghidra(binary_path: str, timeout: int = 180) -> list:
    """运行 Ghidra headless 分析, 提取危险函数调用点."""
    headless = find_ghidra_headless()
    if not headless: return [{"error": "ghidra_not_found"}]

    try:
        with tempfile.TemporaryDirectory() as tmp:
            proj = os.path.join(tmp, "Proj")
            out_json = os.path.join(tmp, "out.json")
            script = os.path.join(tmp, "scan.py")
            with open(script, "w") as f:
                f.write("""
import json, sys
dangerous = {"memcpy","strcpy","sprintf","gets","scanf","strcat","free","malloc",
             "calloc","system","execve","printf"}
findings = []
for f in currentProgram.getListing().getFunctions(True):
    n = f.getName().lower()
    for d in dangerous:
        if d in n: findings.append({"function":f.getName(),"address":str(f.getEntryPoint()),"type":"dangerous_call"})
with open(sys.argv[1],"w") as out: json.dump({"tool":"ghidra","findings":findings,"total":len(findings)}, out)
""")
            cmd = [headless, proj, "VulnProj", "-import", binary_path,
                   "-scriptPath", tmp, "-postScript", "scan.py", out_json,
                   "-deleteProject"]
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if os.path.isfile(out_json):
                with open(out_json) as f: return json.load(f).get("findings",[])
    except subprocess.TimeoutExpired: return [{"error":"timeout"}]
    except Exception as e: return [{"error":str(e)}]
    return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error":"usage: ghidra_headless.py <binary>"})); sys.exit(1)
    binary = sys.argv[1]
    if not os.path.isfile(binary):
        print(json.dumps({"error":f"not_found:{binary}"})); sys.exit(1)
    t0 = time.time()
    findings = analyze_with_ghidra(binary)
    elapsed = (time.time()-t0)*1000
    print(json.dumps({"tool":"ghidra","binary":binary,"elapsed_ms":elapsed,
                      "findings":findings,"total":len(findings)}, default=str))
