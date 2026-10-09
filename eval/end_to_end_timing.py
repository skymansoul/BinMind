#!/usr/bin/env python3
# eval/end_to_end_timing.py - 端到端单样本计时基准
#
# 目的: 让"单样本端到端平均耗时"(如 eval/comparison_summary.csv 中的
#       BinMind 4.68s) 可以用一条命令复现, 并同时固化复现所需的环境信息。
#
# 口径定义(与报告 3.6 节一致):
#   端到端 = 从启动进程开始, 到 analyze 子命令产出报告并退出为止。
#   包含: 解释器启动、模块导入、目标文件解析、反编译、检测、报告生成。
#   不包含: 本基准脚本自身的样本收集与结果汇总时间。
#
# 有效性判据(重要):
#   反编译器(radare2/Ghidra)不可用时, 流水线仍会"成功"退出, 但分析函数数为 0,
#   此时耗时只反映空转开销, 不能计入平均耗时。本脚本据此把样本判为
#   zero_functions 并排除出统计; 若全部样本均无效, 以退出码 2 明确失败,
#   不产出一个看起来正常的假数字。
#   判据为: 退出码 0 且 目标函数数 > 0 且 产出 JSON 报告。
#   已知边界: 日志中的函数数是"被选为分析目标"的函数数, 不等价于每一条都成功
#   反编译出伪代码; 因此本判据能拦住"反编译器缺失"这类空转, 但不能保证每次
#   反编译都非空。需要严格的逐函数成功率时, 请另行核对报告内容。
#
# 用法:
#   python eval/end_to_end_timing.py --samples samples/cve_unified/named_cve --limit 35
#   python eval/end_to_end_timing.py --samples a.exe b.exe --repeats 3 --warmup 1
#   python eval/end_to_end_timing.py --samples DIR --labels labels/gold.jsonl
#   python eval/end_to_end_timing.py --selftest

import argparse
import csv
import io
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 流水线结束时由 core/pipeline.py 以 logger 输出的结构化行:
#   Pipeline done in 8.3s | 5 functions | 2 vulns
# 该行为英文 logger 文案, 不随 CLI 的中英文切换而变, 故作为解析锚点。
PIPELINE_DONE_RE = re.compile(
    r"Pipeline done in\s+([\d.]+)s\s*\|\s*(\d+)\s+functions\s*\|\s*(\d+)\s+vulns")

MAGIC_SIGNATURES = (
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
    (b"\xfe\xed\xfa\xce", "Mach-O"),
    (b"\xfe\xed\xfa\xcf", "Mach-O"),
    (b"\xce\xfa\xed\xfe", "Mach-O"),
    (b"\xcf\xfa\xed\xfe", "Mach-O"),
    (b"\xca\xfe\xba\xbe", "Mach-O"),
)


# ---------------------------------------------------------------- 样本收集

def detect_binary_format(path):
    """按魔数判断是否为受支持的二进制, 返回格式名或 None。"""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return None
    for magic, name in MAGIC_SIGNATURES:
        if head.startswith(magic):
            return name
    return None


def collect_samples(inputs, limit=None):
    """展开目录与文件参数, 返回受支持二进制的有序路径列表。"""
    found = []
    for raw in inputs:
        p = Path(raw)
        if p.is_dir():
            found.extend(sorted(x for x in p.rglob("*") if x.is_file()))
        elif p.is_file():
            found.append(p)
        else:
            print(f"[warn] 路径不存在, 跳过: {p}", file=sys.stderr)

    samples = []
    seen = set()
    for p in found:
        rp = p.resolve()
        if rp in seen:
            continue
        if detect_binary_format(rp) is None:
            continue
        seen.add(rp)
        samples.append(rp)
    samples.sort()
    if limit is not None:
        samples = samples[:limit]
    return samples


# ---------------------------------------------------------------- 单次运行

def parse_pipeline_log(text):
    """从输出中提取 (pipeline_sec, functions, vulns); 未命中返回 None 三元组。"""
    m = PIPELINE_DONE_RE.search(text)
    if not m:
        return (None, None, None)
    return (float(m.group(1)), int(m.group(2)), int(m.group(3)))


def classify(returncode, functions, timed_out):
    """按退出码与函数数做初判; ok 表示可用于计时统计。"""
    if timed_out:
        return "timeout"
    if returncode != 0:
        return "error"
    if functions is None:
        return "log_unparsed"
    if functions == 0:
        return "zero_functions"
    return "ok"


def has_report(work_dir):
    """确认 analyze 真的写出了 JSON 报告。"""
    try:
        return any(Path(work_dir).glob("*.json"))
    except OSError:
        return False


def build_command(sample, work_dir, args):
    cmd = [sys.executable, str(ROOT / "main.py"), "analyze", str(sample),
           "-o", str(work_dir), "--format", "json",
           "--decompiler", args.decompiler,
           "--max-funcs", str(args.max_funcs)]
    if not args.ai:
        cmd.append("--no-ai")
    if args.parallel:
        cmd.append("--parallel")
    return cmd


def _as_text(value):
    """TimeoutExpired 在 text=True 下仍可能带 bytes(stdout/stderr), 统一成 str。"""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def _sample_key(path):
    """样本唯一键: 相对当前目录的路径。

    只用 basename 会让不同目录下的同名样本互相覆盖(实测同一批 44 个文件里
    vuln.exe 出现 9 次、vuln_elf.exe 出现 5 次, 均来自不同 CVE 目录),
    导致 per_sample 统计混算、样本数被低估。故改用路径作为键。
    """
    try:
        rel = os.path.relpath(str(path), os.getcwd())
    except ValueError:
        rel = str(path)
    if rel.startswith(".."):
        rel = str(path)
    return rel.replace("\\", "/")


def run_once(sample, args, run_index):
    """执行一次 analyze, 返回记录 dict。"""
    with tempfile.TemporaryDirectory(prefix="binmind_timing_") as tmp:
        cmd = build_command(sample, tmp, args)
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        # 默认关闭符号执行: angr 缺失时该阶段会走降级路径, 引入与计时无关的
        # 分支差异。需要计时包含符号执行时显式加 --symbolic。
        if not args.symbolic:
            env["ENABLE_SYMEXEC"] = "false"

        t0 = time.perf_counter()
        timed_out = False
        rc = -1
        out = ""
        try:
            proc = subprocess.run(
                cmd, cwd=str(ROOT), env=env, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=args.timeout)
            rc = proc.returncode
            out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        except subprocess.TimeoutExpired as err:
            timed_out = True
            # 早期版本直接对 err.stdout 做字符串拼接, 遇到 bytes 会抛
            # TypeError 并让整轮基准中断; 这里逐个解码后再拼接。
            out = _as_text(err.stdout) + "\n" + _as_text(err.stderr)
        wall = time.perf_counter() - t0

        pipeline_sec, functions, vulns = parse_pipeline_log(out)
        status = classify(rc, functions, timed_out)
        report_written = has_report(tmp)
        if status == "ok" and not report_written:
            status = "no_report"
        return {
            "sample": _sample_key(sample),
            "repeat": run_index,
            "status": status,
            "wall_sec": round(wall, 3),
            "pipeline_sec": pipeline_sec,
            "functions": functions,
            "vulns": vulns,
            "report_written": report_written,
            "returncode": rc,
        }


# ---------------------------------------------------------------- 统计

def summarize(values):
    """返回计数/均值/中位数/最小/最大/P95。"""
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return {"n": 0}
    idx = min(len(vals) - 1, int(round(0.95 * (len(vals) - 1))))
    return {
        "n": len(vals),
        "mean": round(statistics.fmean(vals), 3),
        "median": round(statistics.median(vals), 3),
        "min": round(vals[0], 3),
        "max": round(vals[-1], 3),
        "p95": round(vals[idx], 3),
    }


def load_labels(path):
    """读取 jsonl 标注, 返回 {sample_id: label}。"""
    labels = {}
    if not path:
        return labels
    try:
        with io.open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                sid = rec.get("sample_id")
                if sid is not None:
                    labels[str(sid)] = rec.get("label")
    except (OSError, ValueError) as err:
        print(f"[warn] 标注文件读取失败({err}), 不统计检出率", file=sys.stderr)
    return labels


def detection_rate(records, labels):
    """按标注口径计算检出率; 无可用标注时返回 None。"""
    if not labels:
        return None
    per_sample = {}
    for r in records:
        if r["status"] != "ok":
            continue
        per_sample[r["sample"]] = r["vulns"] or 0
    pos = neg = tp = tn = 0
    for name, vulns in per_sample.items():
        stem = Path(name).stem
        if stem not in labels:
            continue
        if labels[stem] == 1:
            pos += 1
            tp += 1 if vulns > 0 else 0
        elif labels[stem] == 0:
            neg += 1
            tn += 1 if vulns == 0 else 0
    if pos == 0:
        return None
    return round(100.0 * tp / pos, 1)


# ---------------------------------------------------------------- 环境固化

def _try(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        first = (p.stdout or p.stderr or "").strip().splitlines()
        return first[0] if first else "unknown"
    except Exception:
        return "unavailable"


def collect_environment(args):
    """记录复现所需的环境信息。"""
    env = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "timezone": time.strftime("%Z"),
        "host": platform.node(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "command": " ".join(sys.argv),
        "cwd": os.getcwd(),
        "parameters": {
            "decompiler": args.decompiler,
            "ai": args.ai,
            "parallel": args.parallel,
            "max_funcs": args.max_funcs,
            "repeats": args.repeats,
            "warmup": args.warmup,
            "timeout": args.timeout,
        },
        "tools": {
            "radare2": _try(["r2", "-v"]),
            "R2_PATH_env": os.environ.get("R2_PATH", "(unset)"),
            "r2_effective": _try([os.environ.get("R2_PATH", "radare2"), "-v"])
            if os.environ.get("R2_PATH") else "unset (falls back to 'radare2')",
            "ghidra": (os.environ.get("GHIDRA_HOME")
                       or shutil.which("ghidraRun") or "unavailable"),
        },
    }
    try:
        p = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(ROOT),
                           capture_output=True, text=True, timeout=15)
        env["git_commit"] = (p.stdout or "").strip() or "unknown"
    except Exception:
        env["git_commit"] = "unknown"
    return env


# ---------------------------------------------------------------- 输出

def write_outputs(out_dir, records, env, args, labels):
    out_dir.mkdir(parents=True, exist_ok=True)
    stats_records = [r for r in records if r["repeat"] >= args.warmup]
    valid = [r for r in stats_records if r["status"] == "ok"]

    detail = out_dir / "end_to_end_timing_samples.csv"
    with io.open(detail, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=[
            "sample", "repeat", "status", "wall_sec", "pipeline_sec",
            "functions", "vulns", "report_written", "returncode"])
        w.writeheader()
        w.writerows(records)

    overall = summarize([r["wall_sec"] for r in valid])
    pipeline = summarize([r["pipeline_sec"] for r in valid])
    per_sample = {}
    for r in valid:
        per_sample.setdefault(r["sample"], []).append(r["wall_sec"])
    per_sample_stats = {
        name: summarize(vals) for name, vals in sorted(per_sample.items())}

    invalid = {}
    for r in stats_records:
        if r["status"] != "ok":
            invalid[r["status"]] = invalid.get(r["status"], 0) + 1

    rate = detection_rate(stats_records, labels)

    summary = {
        "caliber": ("end-to-end per binary: process start -> analyze writes "
                    "report and exits; includes interpreter startup, module "
                    "import, parsing, decompilation, detection, reporting"),
        "sample_key": "path relative to the working directory; unique even "
                      "when different directories hold identically named files",
        "environment": env,
        "counts": {
            "samples_collected": len({r["sample"] for r in stats_records}),
            "runs_total": len(records),
            "runs_counted": len(valid),
            "invalid_runs": sum(invalid.values()),
            "invalid_by_status": invalid,
        },
        "wall_sec": overall,
        "pipeline_sec": pipeline,
        "detection_rate": rate,
        "per_sample_wall_sec": per_sample_stats,
    }

    js = out_dir / "end_to_end_timing_summary.json"
    with io.open(js, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)

    # 与 eval/comparison_summary.csv 互补的计时口径汇总(不覆盖原文件)
    comp = out_dir / "comparison_summary_timing.csv"
    with io.open(comp, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["tool", "samples", "valid_samples", "detection_rate",
                    "avg_time_sec", "median_time_sec", "p95_time_sec",
                    "avg_pipeline_sec"])
        w.writerow(["BinMind", len({r["sample"] for r in stats_records}),
                    overall.get("n", 0),
                    "" if rate is None else rate,
                    overall.get("mean", ""), overall.get("median", ""),
                    overall.get("p95", ""), pipeline.get("mean", "")])

    return summary, detail, js, comp


class IncrementalWriter(object):
    """逐条落盘: 基准可能跑上百分钟, 中途崩溃或 Ctrl-C 不应让已测数据丢失。"""

    FIELDS = ["sample", "repeat", "status", "wall_sec", "pipeline_sec",
              "functions", "vulns", "report_written", "returncode"]

    def __init__(self, path):
        self.path = path
        self.fh = None
        self.writer = None

    def __enter__(self):
        self.fh = io.open(self.path, "w", encoding="utf-8", newline="")
        self.writer = csv.DictWriter(self.fh, fieldnames=self.FIELDS)
        self.writer.writeheader()
        self.fh.flush()
        return self

    def write(self, record):
        self.writer.writerow(record)
        self.fh.flush()          # 保证进程被杀时磁盘上已有完整一行
        os.fsync(self.fh.fileno())

    def __exit__(self, *exc):
        try:
            self.fh.close()
        except Exception:
            pass
        return False


# ---------------------------------------------------------------- self-test

def selftest():
    """不依赖反编译器的自检: 校验解析、判定与统计三处逻辑。"""
    failures = []

    def check(name, got, want):
        if got != want:
            failures.append(f"{name}: got={got!r} want={want!r}")

    log = ("INFO | core.pipeline | Pipeline done in 8.3s | 5 functions | 2 vulns\n"
           "some other line")
    check("parse.ok", parse_pipeline_log(log), (8.3, 5, 2))
    check("parse.miss", parse_pipeline_log("nothing here"), (None, None, None))

    check("classify.ok", classify(0, 5, False), "ok")
    check("classify.zero", classify(0, 0, False), "zero_functions")
    check("classify.unparsed", classify(0, None, False), "log_unparsed")
    check("classify.error", classify(1, 5, False), "error")
    check("classify.timeout", classify(0, 5, True), "timeout")

    # 回归防护: 超时分支曾因 bytes/str 拼接抛 TypeError 中断整轮基准
    check("as_text.bytes", _as_text(b"abc"), "abc")
    check("as_text.str", _as_text("abc"), "abc")
    check("as_text.none", _as_text(None), "")

    check("stats.mean", summarize([1.0, 2.0, 3.0])["mean"], 2.0)
    check("stats.median", summarize([1.0, 2.0, 3.0])["median"], 2.0)
    check("stats.empty", summarize([]), {"n": 0})

    with tempfile.TemporaryDirectory() as tmp:
        elf = Path(tmp) / "fake.elf"
        elf.write_bytes(b"\x7fELF\x02\x01\x01\x00")
        pe = Path(tmp) / "fake.exe"
        pe.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00")
        txt = Path(tmp) / "fake.txt"
        txt.write_bytes(b"hello world")
        check("detect.elf", detect_binary_format(str(elf)), "ELF")
        check("detect.pe", detect_binary_format(str(pe)), "PE")
        check("detect.other", detect_binary_format(str(txt)), None)
    check("detect.missing", detect_binary_format("no_such_file_xyz"), None)

    # 回归防护: 同名不同目录的样本必须得到不同的键, 否则统计会混算
    k1 = _sample_key("a/b/vuln.exe")
    k2 = _sample_key("c/d/vuln.exe")
    check("sample_key.unique", k1 != k2, True)

    class _A(object):
        warmup = 0
        repeats = 1
    with tempfile.TemporaryDirectory() as tmp:
        records = [
            {"sample": "a.exe", "repeat": 0, "status": "ok", "wall_sec": 4.0,
             "pipeline_sec": 3.9, "functions": 5, "vulns": 1,
             "report_written": True, "returncode": 0},
            {"sample": "b.exe", "repeat": 0, "status": "zero_functions",
             "wall_sec": 8.0, "pipeline_sec": 8.0, "functions": 0, "vulns": 0,
             "report_written": True, "returncode": 0},
        ]
        summary, _d, _j, _c = write_outputs(Path(tmp), records, {}, _A(), {})
        check("summary.counted", summary["counts"]["runs_counted"], 1)
        check("summary.excluded", summary["counts"]["invalid_runs"], 1)
        check("summary.mean", summary["wall_sec"]["mean"], 4.0)

    if failures:
        print("SELFTEST FAILED")
        for f in failures:
            print("  -", f)
        return 1
    print("SELFTEST PASSED (parse / classify / stats / detect / output)")
    return 0


# ---------------------------------------------------------------- 主流程

def main():
    ap = argparse.ArgumentParser(
        description="BinMind 端到端单样本计时基准 (可复现 eval/comparison_summary.csv 口径)")
    ap.add_argument("--samples", nargs="*", default=None,
                    help="样本文件或目录, 目录递归展开")
    ap.add_argument("--limit", type=int, default=None, help="最多取多少个样本")
    ap.add_argument("--repeats", type=int, default=1, help="每个样本重复次数")
    ap.add_argument("--warmup", type=int, default=0,
                    help="前 N 次作预热, 不计入统计")
    ap.add_argument("--timeout", type=int, default=600, help="单次运行超时(秒)")
    ap.add_argument("--max-funcs", type=int, default=20, help="每个目标分析的函数上限")
    ap.add_argument("--decompiler", choices=["auto", "r2", "ghidra"], default="auto")
    ap.add_argument("--ai", action="store_true",
                    help="启用 LLM 研判(默认关闭, 保证离线可复现)")
    ap.add_argument("--parallel", action="store_true", help="并行分析函数")
    ap.add_argument("--symbolic", action="store_true",
                    help="启用符号执行阶段(默认关闭, 保持计时口径稳定)")
    ap.add_argument("--labels", default=None,
                    help="可选 jsonl 标注(sample_id/label), 用于计算检出率")
    ap.add_argument("--out-dir", default=str(ROOT / "eval" / "timing_results"))
    ap.add_argument("--json", action="store_true", help="把汇总 JSON 打到 stdout")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if not args.samples:
        ap.error("需要 --samples (文件或目录), 或用 --selftest 做自检")

    samples = collect_samples(args.samples, args.limit)
    if not samples:
        print("[error] 未在给定路径下找到受支持的二进制(ELF/PE/Mach-O)", file=sys.stderr)
        return 2

    env = collect_environment(args)
    print("BinMind 端到端计时基准")
    print(f"  样本        : {len(samples)}")
    print(f"  重复/预热   : {args.repeats}/{args.warmup}")
    print(f"  反编译后端  : {args.decompiler}   AI: {'on' if args.ai else 'off'}")
    print(f"  radare2     : {env['tools']['radare2']}")
    print()

    records = []
    total = len(samples) * (args.repeats + args.warmup)
    done = 0
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    partial = out_dir / "end_to_end_timing_samples.csv"
    try:
        with IncrementalWriter(partial) as sink:
            for sample in samples:
                for i in range(args.repeats + args.warmup):
                    rec = run_once(sample, args, i)
                    records.append(rec)
                    sink.write(rec)
                    done += 1
                    mark = "OK " if rec["status"] == "ok" else "-- "
                    _parts = rec["sample"].split("/")
                    _short = "/".join(_parts[-2:]) if len(_parts) > 2 else rec["sample"]
                    print(f"  [{done}/{total}] {mark}{_short} "
                          f"{rec['wall_sec']:.2f}s funcs={rec['functions']} "
                          f"vulns={rec['vulns']}")
    except KeyboardInterrupt:
        print("\n[interrupted] 已完成的 %d 次运行已写入 %s"
              % (len(records), partial), file=sys.stderr)
        return 130

    labels = load_labels(args.labels)
    summary, detail, js, comp = write_outputs(
        out_dir, records, env, args, labels)

    counts = summary["counts"]
    print()
    print(f"  计入统计    : {counts['runs_counted']} / {counts['runs_total']} 次运行")
    if counts["invalid_by_status"]:
        print(f"  排除原因    : {counts['invalid_by_status']}")
    if summary["wall_sec"].get("n"):
        w = summary["wall_sec"]
        print(f"  端到端耗时  : 均值 {w['mean']}s  中位数 {w['median']}s  "
              f"P95 {w['p95']}s  (n={w['n']})")
    if summary["detection_rate"] is not None:
        print(f"  检出率      : {summary['detection_rate']}%")
    print(f"  明细        : {detail}")
    print(f"  汇总        : {js}")
    print(f"  计时对照表  : {comp}")

    if counts["runs_counted"] == 0:
        print()
        print("[error] 没有任何样本产生有效计时。最常见原因是反编译器不可用:",
              file=sys.stderr)
        print("        未检测到 radare2 或 Ghidra, 流水线会以 0 函数\"成功\"结束,",
              file=sys.stderr)
        print("        该耗时只反映空转开销, 不能作为端到端耗时使用。",
              file=sys.stderr)
        print("        请在装有 radare2 (或 Ghidra) 的环境中重跑本脚本。",
              file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
