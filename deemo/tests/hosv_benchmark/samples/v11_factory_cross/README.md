# GENERIC-fac — factory_bind

# CVE
GENERIC-fac

# 判定
VULN

# 为什么有效
make_buf(16) 返回 16 字节, strcpy 拷贝 >16 → 跨函数溢出
