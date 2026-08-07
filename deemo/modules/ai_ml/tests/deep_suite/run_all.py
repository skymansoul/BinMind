# 深度样本回归测试一键入口——编译→扫描→收集对比
# 用法: python tests/deep_suite/run_all.py [--only-scan]

from __future__ import annotations

import sys
from pathlib import Path

BASE = Path(__file__).parent.parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

SUITE = Path(__file__).parent


def main() -> int:
    only_scan = "--only-scan" in sys.argv
    if not only_scan:
        import tests.deep_suite.compile_samples as compile_mod
        rc = compile_mod.main()
        if rc != 0:
            print("[run_all] 编译失败, 终止")
            return rc
    import tests.deep_suite.scan_scheduler as scan_mod
    rc = scan_mod.main()
    if rc != 0:
        print("[run_all] 扫描失败, 终止")
        return rc
    import tests.deep_suite.collect_results as collect_mod
    collect_mod.collect()
    print("\n[run_all] 深度回归测试完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
