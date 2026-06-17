import os

def trace_behavior(binary_path, output_dir=None):
    try:
        behaviors = []
        
        behavior_patterns = [
            {'pattern': 'socket', 'type': 'Network', 'description': 'Network socket operation'},
            {'pattern': 'connect', 'type': 'Network', 'description': 'Network connection attempt'},
            {'pattern': 'bind', 'type': 'Network', 'description': 'Bind to network port'},
            {'pattern': 'listen', 'type': 'Network', 'description': 'Listen for connections'},
            {'pattern': 'send', 'type': 'Network', 'description': 'Send data over network'},
            {'pattern': 'recv', 'type': 'Network', 'description': 'Receive data from network'},
            {'pattern': 'open', 'type': 'File', 'description': 'File open operation'},
            {'pattern': 'read', 'type': 'File', 'description': 'File read operation'},
            {'pattern': 'write', 'type': 'File', 'description': 'File write operation'},
            {'pattern': 'close', 'type': 'File', 'description': 'File close operation'},
            {'pattern': 'CreateFile', 'type': 'File', 'description': 'Windows file creation'},
            {'pattern': 'DeleteFile', 'type': 'File', 'description': 'File deletion'},
            {'pattern': 'RegOpenKey', 'type': 'Registry', 'description': 'Registry access'},
            {'pattern': 'CreateProcess', 'type': 'Process', 'description': 'Process creation'},
            {'pattern': 'ExitProcess', 'type': 'Process', 'description': 'Process termination'},
            {'pattern': 'system', 'type': 'Process', 'description': 'System command execution'},
            {'pattern': 'fork', 'type': 'Process', 'description': 'Process fork'},
            {'pattern': 'execve', 'type': 'Process', 'description': 'Execute program'},
        ]
        
        with open(binary_path, 'rb') as f:
            content = f.read().decode('latin-1', errors='ignore')
        
        for pattern in behavior_patterns:
            if pattern['pattern'] in content:
                behaviors.append(pattern)
        
        report_path = None,
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            report_path = os.path.join(output_dir, 'behavior_report.txt')
            with open(report_path, 'w') as f:
                f.write("Behavioral Analysis Report\n")
                f.write("=" * 50 + "\n")
                f.write(f"Binary: {binary_path}\n")
                f.write(f"Behaviors Detected: {len(behaviors)}\n\n")
                
                by_type = {}
                for behavior in behaviors:
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
            'behaviors': behaviors,
            'report_path': report_path
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }