"""支持 `python -m parallel_deep_dev` 调用。"""

import sys
from .run import main

if __name__ == "__main__":
    sys.exit(main())
