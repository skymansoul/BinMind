"""
静态演示/验证脚本 — 不启动服务、不运行 pipeline 真实分析。

检查内容:
  1. 六个核心模块的导入状态与关键属性
  2. 上述模块文件的 ast.parse 语法状态

仅标准库, 无网络/外部服务/API key 依赖。

用法: python demo_verification.py
"""

import ast
import inspect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_CHECK_MODULES = [
    'core.pipeline',
    'cli.commands',
    'core.taint_crossfunc',
    'core.llm_finding_triage',
    'modules.output.web_api',
    'modules.project.web_api',
]


def _check_module(mod_name: str) -> bool:
    try:
        __import__(mod_name)
        return True
    except Exception as err:
        print(f"  [FAIL] {mod_name}: {type(err).__name__}: {err}")
        return False


def _print_attrs() -> None:
    import core.pipeline
    import modules.output.web_api as out_api
    import modules.project.web_api as proj_api
    import core.taint_crossfunc
    import core.llm_finding_triage

    sig = inspect.signature(core.pipeline.run_pipeline)
    print(f"  run_pipeline 参数: {list(sig.parameters)[:8]}...")
    print(f"  start_server 存在: {hasattr(out_api, 'start_server')}")
    print(f"  _gen_request_id 存在: {hasattr(proj_api, '_gen_request_id')}")
    print(f"  verify_crossfunc_taint 存在: "
          f"{hasattr(core.taint_crossfunc, 'verify_crossfunc_taint')}")
    print(f"  triage_findings 存在: "
          f"{hasattr(core.llm_finding_triage, 'triage_findings')}")


def _check_syntax() -> None:
    root = os.path.dirname(os.path.abspath(__file__))
    errors = []
    total = 0
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (
            '.git', '__pycache__', 'node_modules', '.venv', 'venv',
            '_trash', 'dist', 'build', '.temp')]
        for f in files:
            if not f.endswith('.py'):
                continue
            p = os.path.join(dirpath, f)
            total += 1
            try:
                # utf-8-sig: 兼容部分文件带 BOM 的情况
                ast.parse(open(p, encoding='utf-8-sig', errors='replace').read())
            except SyntaxError as e:
                errors.append(f"{p}:{e.lineno}")
    print(f"  语法检查: {total} 文件, 错误 {len(errors)}")
    for e in errors[:5]:
        print(f"    {e}")


def main() -> int:
    print("BinMind 静态验证")
    print("=" * 60)
    print("[1/3] 模块导入")
    ok = all(_check_module(m) for m in _CHECK_MODULES)
    print("[2/3] 关键属性")
    if ok:
        _print_attrs()
    else:
        print("  导入失败, 跳过属性检查")
    print("[3/3] 全树语法")
    _check_syntax()
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
