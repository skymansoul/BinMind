# SAFE-nt — null_terminator

# CVE
SAFE-nt

# 判定
SAFE

# 为什么有效
malloc(l+1) 预留终止符 → 安全
