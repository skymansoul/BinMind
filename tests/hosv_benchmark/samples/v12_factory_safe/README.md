# SAFE-fac — factory_bind

# CVE
SAFE-fac

# 判定
SAFE

# 为什么有效
make_buf(128) + strncpy 63 字节 → 安全
