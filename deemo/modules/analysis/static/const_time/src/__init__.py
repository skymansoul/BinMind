#
# 二进制级常量时间验证 —— 在反汇编层面检测秘密依赖的分支/访存/循环违规
#
# 背景: 大多数常量时间验证工具（ctverif, SideTrail, ctgrind）工作在源码
# 或 LLVM IR 层。对于无源码的第三方二进制（闭源密码库、固件中的 crypto 实现）
# 这些工具无法使用。本模块在反汇编输出上做启发式分析——不需要源码
#
# 三大违规类型（对应专利交底书 4.4 节）：
#   (a) 秘密依赖分支 —— 秘密数据流到达条件跳转指令
#   (b) 秘密依赖访存 —— 秘密数据用作内存访问的偏移或索引
#   (c) 秘密依赖循环 —— 秘密数据控制循环的迭代次数
#
# 工作流程：
#   1. 识别秘密输入源（密钥参数、敏感缓冲区）——通过函数签名和导入表推断
#   2. 后向数据流追踪——从秘密源出发，追踪数据在指令间的流动
#   3. 违规检测——当秘密数据到达分支/访存/循环控制指令时报警
#
# 局限（在注释中显式声明，不做夸大）：
#   - 数据流追踪是过程内的（不跨函数边界）——调用点处截断
#   - 间接跳转/间接调用的目标解析不完备
#   - 假阳性率偏高：标记所有"可能"的违规，需人工审查确认
#
# ref: ctverif (Almeida et al., PLDI 2016) — LLVM 层的常量时间验证框架；
#      "Verifying Constant-Time Implementations" (Almeida et al., USENIX 2016);
# 本项目将其概念推广到二进制分析层面

from .secret_tracker import (
    SecretSource, SecretClass, SecretTaint,
    identify_secret_sources, propagate_taint_intraprocedural,
)
from .branch_checker import (
    check_secret_dependent_branches, BranchViolation,
)
from .mem_checker import (
    check_secret_dependent_memory, MemoryViolation,
)
from .loop_checker import (
    check_secret_dependent_loops, LoopViolation,
)
from .const_time_pipeline import (
    verify_constant_time, ConstTimeReport, ViolationSeverity,
)
