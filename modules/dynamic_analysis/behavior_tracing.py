# BehaviorTracer 入口：字符串级模式匹配与结构化报告输出
import os
import logging

logger = logging.getLogger(__name__)


class BehaviorTracer:
    # 二进制特征扫描器，将 API 导入字符串与行为分类法匹配

    def __init__(self):
        # 用分类好的 I/O、网络、进程、注册表签名填充模式库
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
        ]
        self.behaviors = []

    def trace(self, binary_path, output_dir=None):
        # 扫描二进制文件中的模式匹配，可选输出分组报告到磁盘
        try:
            self.behaviors = []

            # Latin-1 编码：二进制中任意字节序列的安全超集
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

                    # 按类别分组匹配到的行为用于结构化输出
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
    # 向后兼容入口，实例化 tracer 后委托执行
    tracer = BehaviorTracer()
    return tracer.trace(binary_path, output_dir)
