# CVE-2017-1000405 — null_terminator

# CVE
CVE-2017-1000405

# 判定
VULN

# 为什么有效
malloc(l) 缺终止符空间, d[l]=0 越界 1 字节
