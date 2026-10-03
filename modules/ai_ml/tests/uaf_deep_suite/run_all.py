# UAF深度套件——一键入口: 编译→扫描→收集
import sys
from pathlib import Path

BASE = Path(__file__).parent.parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))


def main() -> int:
    import tests.uaf_deep_suite.compile_samples as c
    import tests.uaf_deep_suite.scan_scheduler as s
    import tests.uaf_deep_suite.collect_results as col
    rc = c.main()
    if rc != 0:
        print("[uaf run_all] 编译失败")
        return rc
    rc = s.main()
    if rc != 0:
        print("[uaf run_all] 扫描失败")
        return rc
    col.main()
    print("[uaf run_all] UAF深度回归完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
