# GENERIC-mcd — memcpy_corr

# CVE
GENERIC-mcd

# 判定
VULN

# 为什么有效
malloc(n) + memcpy(n*2) 写入系数大于分配 → 溢出
