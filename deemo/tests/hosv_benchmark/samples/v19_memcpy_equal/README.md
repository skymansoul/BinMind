# SAFE-mceq — memcpy_corr

# CVE
SAFE-mceq

# 判定
SAFE

# 为什么有效
malloc(n+1) + memcpy(n) 共享系数相等 → 安全
