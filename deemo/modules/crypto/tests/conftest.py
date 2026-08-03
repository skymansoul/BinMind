# 测试目录下 `from crypto.src.X import Y` 的路径修正
# 有意为之的临时方案；生产环境用 _FlatFinder 解析
import sys
import os

_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# 确保 crypto 包可导入
_crypto_root = os.path.dirname(_project_root)
if _crypto_root not in sys.path:
    sys.path.insert(0, _crypto_root)
