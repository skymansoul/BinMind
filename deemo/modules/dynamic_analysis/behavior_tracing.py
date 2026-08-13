# Entry-point: BehaviorTracer with string-level pattern matching and typed report output.

import os
import logging

__log = logging.getLogger(__name__)


class BehaviorTracer:
    """Binary feature scanner — matches API import strings against a behavior taxonomy."""

    def __init__(self):
        """Seed the pattern library with categorized I/O, network, process, and registry signatures."""
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
        """Scan binary for pattern matches; optionally emit a grouped report to disk."""
        try:
            self.behaviors = []

            # Latin-1: safe superset for arbitrary byte sequences in binaries.
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

                    # Partition matched behaviors by category for structured output.
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
    """Backward-compatible entry: instantiate tracer and delegate."""
    tracer = BehaviorTracer()
    return tracer.trace(binary_path, output_dir)
