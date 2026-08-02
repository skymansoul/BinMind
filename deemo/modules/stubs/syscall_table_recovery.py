# re-export from compat/ — 系统调用表恢复桩
# 参考: BofAEG (Xu & Wang, 2022) — 系统调用在栈溢出利用中的角色 &
#   RetSpill (CCS 2023) — 通过系统调用接口的内核提权
from modules.core.compat.syscall_table_recovery import *
