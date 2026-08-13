"""对比可视化数据 — 颜色方案 + MIMO 多类型基准结果.

创建: 2025-05-12

数据来源:
  - heap_overflow: 18 samples, F1=1.000
  - uaf: 20 samples, F1=1.000
  - format_string: 12 samples, F1=1.000
  - integer_overflow: 15 samples, F1=1.000
"""

COLORS = {
    'AVHO-G': '#2196F3',
    'UAF-Verifier': '#00BCD4',
    'Fmt-Verifier': '#7CB342',
    'Int-Interval': '#FF7043',
    'Angr': '#FF9800',
    'QEMU': '#4CAF50',
    'Ghidra': '#9C27B0',
    'PatternMatch': '#F44336',
}

MIMO_DEFAULTS = {
    # VERIFIED: 18-sample, 2026-08-09 regression
    'heap_overflow': [
        {'tool': 'AVHO-G', 'recall': 100.0, 'precision': 100.0,
         'f1': 100.0, 'avg_time_ms': 27.0, 'mode': 'VERIFIED',
         'tp': 14, 'tn': 4, 'fp': 0, 'fn': 0},
        {'tool': 'Angr', 'recall': 85.0, 'precision': 35.0,
         'f1': 49.6, 'avg_time_ms': 3200.0, 'mode': 'ESTIMATED'},
        {'tool': 'QEMU', 'recall': 70.0, 'precision': 90.0,
         'f1': 78.8, 'avg_time_ms': 500.0, 'mode': 'ESTIMATED'},
        {'tool': 'Ghidra', 'recall': 75.0, 'precision': 25.0,
         'f1': 37.5, 'avg_time_ms': 4500.0, 'mode': 'ESTIMATED'},
    ],
    # VERIFIED: 20-sample, 2026-08-09 regression_uaf_ensemble
    'uaf': [
        {'tool': 'UAF-Verifier', 'recall': 100.0, 'precision': 100.0,
         'f1': 100.0, 'avg_time_ms': 0.5, 'mode': 'VERIFIED',
         'tp': 17, 'tn': 3, 'fp': 0, 'fn': 0},
        {'tool': 'Angr', 'recall': 60.0, 'precision': 45.0,
         'f1': 51.4, 'avg_time_ms': 4200.0, 'mode': 'ESTIMATED'},
        {'tool': 'Ghidra', 'recall': 50.0, 'precision': 30.0,
         'f1': 37.5, 'avg_time_ms': 5500.0, 'mode': 'ESTIMATED'},
    ],
    # VERIFIED: 12-sample, 2026-08-09 regression_format_string
    'format_string': [
        {'tool': 'Fmt-Verifier', 'recall': 100.0, 'precision': 100.0,
         'f1': 100.0, 'avg_time_ms': 0.3, 'mode': 'VERIFIED',
         'tp': 8, 'tn': 4, 'fp': 0, 'fn': 0},
        {'tool': 'Angr', 'recall': 80.0, 'precision': 60.0,
         'f1': 68.6, 'avg_time_ms': 3800.0, 'mode': 'ESTIMATED'},
        {'tool': 'Ghidra', 'recall': 70.0, 'precision': 40.0,
         'f1': 50.9, 'avg_time_ms': 5000.0, 'mode': 'ESTIMATED'},
    ],
    # VERIFIED: 15-sample, 2026-08-09 regression_int_overflow
    'integer_overflow': [
        {'tool': 'Int-Interval', 'recall': 100.0, 'precision': 100.0,
         'f1': 100.0, 'avg_time_ms': 0.7, 'mode': 'VERIFIED',
         'tp': 11, 'tn': 4, 'fp': 0, 'fn': 0},
        {'tool': 'Angr', 'recall': 73.7, 'precision': 87.5,
         'f1': 80.0, 'avg_time_ms': 5000.0, 'mode': 'ESTIMATED'},
        {'tool': 'Ghidra', 'recall': 84.2, 'precision': 94.1,
         'f1': 88.9, 'avg_time_ms': 30000.0, 'mode': 'ESTIMATED'},
    ],
}
