"""ACPE 多工具对比实验包入口.

创建: 2024-09-02
子模块:
  angr_explorer    angr CFG 危险调用点探索
  qemu_tracer      QEMU user-mode 追踪 + Python 具体值回退
  ghidra_headless  Ghidra 无头审计模拟
  run_benchmark    主实验 (统一 CSV)
  plot_comparison  可视化
  gen_result_table LaTeX 对比表
"""
