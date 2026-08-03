# Entry-point: BehaviorTracer string-level pattern matching typed 报告 输出

import os
import logging

__log = logging.getLogger(__name__)


class BehaviorTracer:
    """Binary feature scanner — 匹配 API import strings against a behavior taxonomy"""

    def __init__(self):
        """Seed pattern library categorized /O, 网络, process, registry 签名s"""
        self.patterns = [
            {'pattern': 'socket',       'type': 'Network',  'description': 'Network socket operation'},
            {'pattern': 'connect',      'type': 'Network',  'description': 'Network connection attempt'},
            {'pattern': 'bind',         'type': 'Network',  'description': 'Bind to network port'},
            {'pattern': 'listen',       'type': 'Network',  'description': 'Listen for connections'},
            {'pattern': 'send',         'type': 'Network',  'description': 'Send data over network'},
            {'pattern': 'recv',         'type': 'Network',  'description': 'Receive data from network'},
            {'pattern': 'open',         'type': 'File',     'description': 'File open operation'},
            {'pattern': 'read',         'type': 'File',     'description': 'File read operation'},
            {'pattern': 'write',        'type': 'File',     'description': 'File write operation'},
            {'pattern': 'close',        'type': 'File',     'description': 'File close operation'},
            {'pattern': 'CreateFile',   'type': 'File',     'description': 'Windows file creation'},
            {'pattern': 'DeleteFile',   'type': 'File',     'description': 'File deletion'},
            {'pattern': 'RegOpenKey',   'type': 'Registry', 'description': 'Registry access'},
            {'pattern': 'CreateProcess','type': 'Process',  'description': 'Process creation'},
            {'pattern': 'ExitProcess',  'type': 'Process',  'description': 'Process termination'},
            {'pattern': 'system',       'type': 'Process',  'description': 'System command execution'},
            {'pattern': 'fork',         'type': 'Process',  'description': 'Process fork'},
            {'pattern': 'execve',       'type': 'Process',  'description': 'Execute program'},
            # 新增: 反分析/反调试模式 — 检测虚拟机、调试器和沙箱环境检查
            {'pattern': 'IsDebuggerPresent',  'type': 'AntiAnalysis', 'description': 'Debugger presence check'},
            {'pattern': 'CheckRemoteDebuggerPresent', 'type': 'AntiAnalysis', 'description': 'Remote debug check'},
            {'pattern': 'NtQuerySystemInformation', 'type': 'AntiAnalysis', 'description': 'System info enumeration (VM detection)'},
            {'pattern': 'GetTickCount',     'type': 'AntiAnalysis', 'description': 'Timing-based sandbox detection'},
            {'pattern': 'rdtsc',            'type': 'AntiAnalysis', 'description': 'RDTSC timing check'},
            # 新增: 持久化机制检测
            {'pattern': 'RegCreateKey',     'type': 'Persistence', 'description': 'Registry key creation (persistence)'},
            {'pattern': 'CreateService',    'type': 'Persistence', 'description': 'Windows service creation'},
            {'pattern': 'schtasks',         'type': 'Persistence', 'description': 'Scheduled task manipulation'},
            {'pattern': 'crontab',          'type': 'Persistence', 'description': 'Cron job manipulation'},
        ]
        self.behaviors = []

    def trace(self, binary_path, output_dir=None):
        """Scan binary for pattern 匹配; optionally emit a grouped 报告 disk"""
        try:
            self.behaviors = []

            # Latin-1: safe superset for arbitrary byte sequences binaries
            with open(binary_path, 'rb') as f:
                content = f.read().decode('latin-1', errors='ignore')

            for pattern in self.patterns:
                if pattern['pattern'] in content:
                    self.behaviors.append(pattern)

            hit_count = min(max(len(self.behaviors), 0), len(self.patterns))
            logger.debug("Matched %d / %d behavior patterns", hit_count, len(self.patterns))

            report_path = None
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                report_path = os.path.join(output_dir, 'behavior_report.txt')
                with open(report_path, 'w') as f:
                    f.write("Behavioral Analysis Report\n")
                    f.write("=" * 50 + "\n")
                    f.write(f"Binary: {binary_path}\n")
                    f.write(f"Behaviors Detected: {hit_count}\n\n")

                    # Partition matched behaviors category for structured 输出
                    by_type = {}
                    for behavior in self.behaviors:
                        behavior_type = behavior['type']
                        if behavior_type not in by_type:
                            by_type[behavior_type] = []
                        by_type[behavior_type].append(behavior)

                    for behavior_type, items in by_type.items():
                        f.write(f"--- {behavior_type} ---\n")
                        for item in items:
                            f.write(f"- {item['pattern']}: {item['description']}\n")
                        f.write("\n")

                    # 新增: 风险摘要区块 — 按类别统计并评估整体风险
                    f.write("=" * 50 + "\n")
                    f.write("Risk Summary\n")
                    f.write("=" * 50 + "\n")
                    risk_categories = {'AntiAnalysis': 0, 'Persistence': 0, 'Process': 0, 'Network': 0, 'File': 0, 'Registry': 0}
                    for b in self.behaviors:
                        risk_categories[b['type']] = risk_categories.get(b['type'], 0) + 1

                    for cat_name, cnt in risk_categories.items():
                        if cnt > 0:
                            f.write(f"- {cat_name}: {cnt}\n")

                    risk_score = min(100, (
                        risk_categories['AntiAnalysis'] * 20 +
                        risk_categories['Persistence'] * 25 +
                        risk_categories['Process'] * 15 +
                        risk_categories['Network'] * 10
                    ))
                    f.write(f"\nOverall Risk Score: {risk_score}/100\n")

            return {
                'success': True,
                'behaviors': self.behaviors,
                'report_path': report_path,
            }

        except Exception as e:
            logger.error("Trace error: %s", str(e))
            return {
                'success': False,
                'error': str(e),
            }


def trace_behavior(binary_path, output_dir=None):
    """Backward-compatible entry: instantiate tracer delegate"""
    tracer = BehaviorTracer()
    return tracer.trace(binary_path, output_dir)
