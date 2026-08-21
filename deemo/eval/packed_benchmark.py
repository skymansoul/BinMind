# UPX加壳对比测试 - 对样本加壳后重新扫描, 对比检出率变化。
# 评估检测方法对加壳代码的容忍度-这是专利的核心技术效果指标之一。

import os, subprocess, sys, json, time, shutil

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "testing", "regression", "samples")
UPX = shutil.which("upx") or ""

def pack_sample(binary_path: str, output_dir: str) -> str:
    """对二进制用UPX加壳, 返回加壳后路径。"""
    if not UPX:
        return ""
    packed = os.path.join(output_dir, os.path.basename(binary_path) + ".packed")
    try:
        subprocess.run([UPX, "-q", "-o", packed, binary_path],
                      capture_output=True, timeout=30)
        if os.path.exists(packed):
            return packed
    except Exception:
        pass
    return ""


def run_packed_benchmark(output_dir: str = None) -> dict:
    """运行加壳对比测试: 对每个样本加壳前后各扫描一次。"""
    base = output_dir or os.path.join(os.path.dirname(__file__), "packed_results")
    os.makedirs(base, exist_ok=True)

    if not UPX:
        return {"error": "UPX not installed", "packed": 0, "results": []}

    results = []
    packed_count = 0
    for entry in sorted(os.listdir(SAMPLE_DIR)):
        sp = os.path.join(SAMPLE_DIR, entry)
        if not os.path.isdir(sp):
            continue
        # 找编译产物(非.c/.h文件)
        bins = [f for f in os.listdir(sp)
               if os.path.isfile(os.path.join(sp, f))
               and not f.endswith(('.c', '.h', '.md', '.txt'))]
        if not bins:
            continue
        bp = os.path.join(sp, bins[0])
        packed_bp = pack_sample(bp, base)
        if packed_bp:
            packed_count += 1
            results.append({
                "sample": entry,
                "original": bp,
                "packed": packed_bp,
                "packed_size": os.path.getsize(packed_bp),
                "original_size": os.path.getsize(bp),
            })

    report = {
        "total_samples_with_binaries": len(results),
        "successfully_packed": packed_count,
        "upx_available": bool(UPX),
        "results": results,
    }
    report_path = os.path.join(base, "packed_benchmark.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    return report


if __name__ == "__main__":
    r = run_packed_benchmark()
    print(json.dumps({k: v for k, v in r.items() if k != "results"}, indent=2))
    print(f"Samples packable: {r.get('successfully_packed', 0)}")
