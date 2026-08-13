# pytest收集钩子——确保ai_ml根目录优先于Desktop pyproject可编辑安装包
import sys
from pathlib import Path

_ROOT = Path(__file__).parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

