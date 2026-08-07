# Ghidra Headless 适配器 — 批量脚本自动化分析
# 调用 analyzeHeadless 在无GUI模式下运行自定义分析脚本.
# 创建: 2026-07-14

import os, sys, json, time, subprocess, tempfile

def find_ghidra() -> str:
    """查找 Ghidra 安装路径."""
    for candidate in [
        os.environ.get("GHIDRA_HOME", ""),
        "/opt/ghidra", "/usr/local/ghidra",
        os.path.expanduser("~/ghidra"),
    ]:
        headless = os.path.join(candidate, "support", "analyzeHeadless")
        if os.path.isfile(headless) or os.path.isfile(headless + ".bat"):
            return candidate
    return ""

# Ghidra headless 分析脚本 (Java/Python, 写入临时文件执行)
_GHIDRA_SCRIPT = '''
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;

public class VulnScanner extends GhidraScript {
    private static final String[] DANGEROUS = {
        "memcpy","strcpy","sprintf","gets","scanf","strcat",
        "free","system","execve","printf","malloc","calloc"
    };

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionIterator funcs = listing.getFunctions(true);
        println("{\\"findings\\": [");
        boolean first = true;
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function f = funcs.next();
            String name = f.getName().toLowerCase();
            for (String d : DANGEROUS) {
                if (name.contains(d)) {
                    if (!first) println(",");
                    first = false;
                    printf("{\\"function\\":\\"%s\\",\\"address\\":\\"%s\\",\\"type\\":\\"dangerous_call\\"}",
                           f.getName(), f.getEntryPoint().toString());
                }
            }
        }
        println("],\\"tool\\":\\"ghidra\\"}");
    }
}
'''

class GhidraAdapter:
    """Ghidra headless 包装器.

    创建临时项目→导入二进制→运行分析脚本→收集结果.
    """

    def __init__(self, ghidra_home: str = ""):
        self._home = ghidra_home or find_ghidra()
        self._headless = ""
        if self._home:
            for suffix in ["support/analyzeHeadless", "support/analyzeHeadless.bat"]:
                p = os.path.join(self._home, suffix)
                if os.path.isfile(p):
                    self._headless = p; break

    def analyze(self, binary_path: str, timeout_sec: int = 180) -> list:
        """运行 Ghidra headless 分析, 返回危险函数列表."""
        if not self._headless:
            return [{"error": "ghidra_not_found"}]

        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = os.path.join(tmpdir, "project")
            script_path = os.path.join(tmpdir, "VulnScanner.java")

            # 写入分析脚本 (简化版: 使用 Ghidra Python API)
            py_script = os.path.join(tmpdir, "vuln_scan.py")
            with open(py_script, "w") as f:
                f.write('''
import json, sys
from ghidra.program.model.listing import FunctionIterator
from java.io import File

DANGEROUS = {"memcpy","strcpy","sprintf","gets","scanf","strcat","free","system","execve","printf","malloc","calloc"}

def scan():
    program = getCurrentProgram()
    listing = program.getListing()
    findings = []
    for func in listing.getFunctions(True):
        name = func.getName().lower()
        for d in DANGEROUS:
            if d in name:
                findings.append({"function":func.getName(),"address":str(func.getEntryPoint()),"type":"dangerous_call"})
    out = File(getScriptArgs()[0])
    with open(str(out), "w") as f:
        json.dump({"tool":"ghidra","findings":findings,"total_findings":len(findings)}, f)
scan()
''')

            out_json = os.path.join(tmpdir, "output.json")
            cmd = [
                self._headless,
                project_dir, "VulnProject",
                "-import", binary_path,
                "-scriptPath", tmpdir,
                "-postScript", "vuln_scan.py", out_json,
                "-deleteProject",
            ]

            try:
                subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout_sec)
                if os.path.isfile(out_json):
                    with open(out_json) as f:
                        return json.load(f).get("findings", [])
            except subprocess.TimeoutExpired:
                return [{"error": "timeout"}]
            except FileNotFoundError:
                return [{"error": "ghidra_not_found"}]

        return [{"error": "unknown"}]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: python ghidra_adapter.py <binary>"}))
        sys.exit(1)

    binary = sys.argv[1]
    if not os.path.isfile(binary):
        print(json.dumps({"error": f"file not found: {binary}"}))
        sys.exit(1)

    adapter = GhidraAdapter()
    t0 = time.time()
    findings = adapter.analyze(binary, timeout_sec=120)
    elapsed = (time.time() - t0) * 1000
    output = {"tool": "ghidra", "binary": binary, "elapsed_ms": elapsed,
              "findings": findings, "total_findings": len(findings)}
    print(json.dumps(output, default=str))
