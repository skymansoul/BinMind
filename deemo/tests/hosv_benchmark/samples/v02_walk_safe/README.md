# SAFE-ctr — walk_write

# CVE
SAFE-ctr

# 判定
SAFE

# 为什么有效
malloc(2l+2) 覆盖最长输出 2l+1 → 安全
