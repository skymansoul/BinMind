# CVE-2021-3609 — struct_idx

# CVE
CVE-2021-3609

# 判定
VULN

# 为什么有效
p=arr+3, p[5]=arr[8], 分配 8 元素 → 越界
