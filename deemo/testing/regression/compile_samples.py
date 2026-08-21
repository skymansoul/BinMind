# 编译模块 - 遍历samples目录, 对每个CVE样本执行make。
# 独立于扫描逻辑, 可单独运行做批量编译验证。

import os, subprocess, sys, json

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")

def compile_all(samples_dir: str = None) -> dict:
    """编译所有样本, 返回 {sample_name: {success, binary_path, error}}。"""
    base = samples_dir or SAMPLES_DIR
    if not os.path.isdir(base):
        return {"_error": f"目录不存在: {base}"}

    results = {}
    for entry in sorted(os.listdir(base)):
        sample_path = os.path.join(base, entry)
        if not os.path.isdir(sample_path):
            continue
        makefile = os.path.join(sample_path, "Makefile")
        if not os.path.exists(makefile):
            results[entry] = {"success": False,
                              "error": "无Makefile"}
            continue

        try:
            proc = subprocess.run(
                ["make", "-C", sample_path, "clean"],
                capture_output=True, text=True, timeout=15)
            proc = subprocess.run(
                ["make", "-C", sample_path],
                capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                # 查找编译产物
                binaries = [f for f in os.listdir(sample_path)
                           if os.path.isfile(os.path.join(sample_path, f))
                           and not f.endswith(('.c', '.h', '.md', '.txt'))]
                results[entry] = {
                    "success": True,
                    "binary_path": os.path.join(sample_path,
                        binaries[0]) if binaries else "",
                    "binaries": binaries,
                }
            else:
                results[entry] = {"success": False,
                    "error": proc.stderr[:200]}
        except subprocess.TimeoutExpired:
            results[entry] = {"success": False, "error": "编译超时"}
        except FileNotFoundError:
            results[entry] = {"success": False, "error": "make命令不可用-需安装build-essential"}
        except Exception as e:
            results[entry] = {"success": False, "error": str(e)[:200]}

    return results


if __name__ == "__main__":
    results = compile_all()
    print(json.dumps(results, indent=2, ensure_ascii=False))
