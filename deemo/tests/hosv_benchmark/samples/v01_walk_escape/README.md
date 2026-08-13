# CVE-2021-3156 — walk_write

# CVE
CVE-2021-3156

# 判定
VULN

# 为什么有效
malloc(l+1) 但游走写每字符最多 2 步 (反斜杠转义), 最长输出 2l+1 > l+1 → 溢出
