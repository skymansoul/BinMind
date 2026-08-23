# 入口：BehaviorTracer 字符串级模式匹配，输出分类报告

import os
import logging

__log = logging.getLogger(__name__)


class BehaviorTracer:
    """二进制特征扫描器 — 将 API 导入字符串与行为分类法匹配"""

    def __init__(self):
        """初始化模式库：I/O、网络、进程、注册表等分类签名"""
        self.patterns = [
            {'pattern': 'socket',       'type': 'Network',  'description': '网络套接字操作'},
            {'pattern': 'connect',      'type': 'Network',  'description': '发起网络连接'},
            {'pattern': 'bind',         'type': 'Network',  'description': '绑定网络端口'},
            {'pattern': 'listen',       'type': 'Network',  'description': '监听连接请求'},
            {'pattern': 'send',         'type': 'Network',  'description': '发送网络数据'},
            {'pattern': 'recv',         'type': 'Network',  'description': '接收网络数据'},
            {'pattern': 'open',         'type': 'File',     'description': '文件打开操作'},
            {'pattern': 'read',         'type': 'File',     'description': '文件读取操作'},
            {'pattern': 'write',        'type': 'File',     'description': '文件写入操作'},
            {'pattern': 'close',        'type': 'File',     'description': '文件关闭操作'},
            {'pattern': 'CreateFile',   'type': 'File',     'description': 'Windows 文件创建'},
            {'pattern': 'DeleteFile',   'type': 'File',     'description': '文件删除'},
            {'pattern': 'RegOpenKey',   'type': 'Registry', 'description': '注册表访问'},
            {'pattern': 'CreateProcess','type': 'Process',  'description': '进程创建'},
            {'pattern': 'ExitProcess',  'type': 'Process',  'description': '进程终止'},
            {'pattern': 'system',       'type': 'Process',  'description': '系统命令执行'},
            {'pattern': 'fork',         'type': 'Process',  'description': '进程派生'},
            {'pattern': 'execve',       'type': 'Process',  'description': '执行新程序'},
            # 反分析/反调试模式：检测虚拟机、调试器和沙箱环境
            {'pattern': 'IsDebuggerPresent',  'type': 'AntiAnalysis', 'description': '调试器存在检测'},
            {'pattern': 'CheckRemoteDebuggerPresent', 'type': 'AntiAnalysis', 'description': '远程调试器检测'},
            {'pattern': 'NtQuerySystemInformation', 'type': 'AntiAnalysis', 'description': '系统信息枚举（虚拟机检测）'},
            {'pattern': 'GetTickCount',     'type': 'AntiAnalysis', 'description': '基于时序的沙箱检测'},
            {'pattern': 'rdtsc',            'type': 'AntiAnalysis', 'description': 'RDTSC 时序检测'},
            # 持久化机制检测
            {'pattern': 'RegCreateKey',     'type': 'Persistence', 'description': '注册表键创建（持久化）'},
            {'pattern': 'CreateService',    'type': 'Persistence', 'description': 'Windows 服务创建'},
            {'pattern': 'schtasks',         'type': 'Persistence', 'description': '计划任务操作'},
            {'pattern': 'crontab',          'type': 'Persistence', 'description': 'Cron 任务操作'},
        ]
        self.behaviors = []

    def trace(self, binary_path, output_dir=None):
        """扫描二进制中的模式匹配，可选输出分组报告到磁盘"""
        try:
            self.behaviors = []

            # Latin-1：任意字节序列的安全超集
            with open(binary_path, 'rb') as f:
                content = f.read().decode('latin-1', errors='ignore')

            for pattern in self.patterns:
                if pattern['pattern'] in content:
                    self.behaviors.append(pattern)

            hit_count = min(max(len(self.behaviors), 0), len(self.patterns))
            __log.debug("匹配 %d / %d 个行为模式", hit_count, len(self.patterns))

            report_path = None
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                report_path = os.path.join(output_dir, 'behavior_report.txt')
                with open(report_path, 'w') as f:
                    f.write("行为分析报告\n")
                    f.write("=" * 50 + "\n")
                    f.write(f"二进制: {binary_path}\n")
                    f.write(f"检测到的行为数: {hit_count}\n\n")

                    # 按类别分组输出
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

                    # 风险摘要区块：按类别统计并评估整体风险
                    f.write("=" * 50 + "\n")
                    f.write("风险摘要\n")
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
                    f.write(f"\n整体风险评分: {risk_score}/100\n")

            return {
                'success': True,
                'behaviors': self.behaviors,
                'report_path': report_path,
            }

        except Exception as e:
            __log.error("追踪错误: %s", str(e))
            return {
                'success': False,
                'error': str(e),
            }


def trace_behavior(binary_path, output_dir=None):
    """向后兼容入口：实例化追踪器并委托执行"""
    tracer = BehaviorTracer()
    return tracer.trace(binary_path, output_dir)
