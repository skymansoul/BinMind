# GENERIC-nt2 — null_terminator

# CVE
GENERIC-nt2

# 判定
VULN

# 为什么有效
fgets 读满 buf[15]=0 时 l-1=15 写越界 (边界情形)
