# GENERIC-ob1 — struct_idx

# CVE
GENERIC-ob1

# 判定
VULN

# 为什么有效
i<=n 写入 n+1 个元素, 分配 n 个 → 结构越界
