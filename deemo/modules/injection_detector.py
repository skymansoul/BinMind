import os

def detect_injection(binary_path, output_dir=None):
    try:
        injection_points = []
        
        injection_patterns = [
            {'pattern': 'VirtualAlloc', 'type': 'Code Injection'},
            {'pattern': 'WriteProcessMemory', 'type': 'Process Injection'},
            {'pattern': 'CreateRemoteThread', 'type': 'Thread Injection'},
            {'pattern': 'VirtualProtect', 'type': 'Memory Protection Modification'},
            {'pattern': 'LoadLibrary', 'type': 'DLL Injection'},
            {'pattern': 'GetProcAddress', 'type': 'API Resolution'},
            {'pattern': 'ShellExecute', 'type': 'Command Execution'},
            {'pattern': 'system\\(', 'type': 'System Command'},
            {'pattern': 'execvp', 'type': 'Process Execution'},
            {'pattern': 'WinExec', 'type': 'Windows Execution'},
        ]
        
        with open(binary_path, 'rb') as f:
            content = f.read().decode('latin-1', errors='ignore')
        
        for pattern in injection_patterns:
            if pattern['pattern'] in content:
                injection_points.append({
                    'location': f"Contains {pattern['pattern']}",
                    'type': pattern['type'],
                    'risk': 'Medium'
                })
        
        report_path = None
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            report_path = os.path.join(output_dir, 'injection_report.txt')
            with open(report_path, 'w') as f:
                f.write("Memory Injection Detection Report\n")
                f.write("=" * 50 + "\n")
                f.write(f"Binary: {binary_path}\n")
                f.write(f"Injection Points Found: {len(injection_points)}\n\n")
                for point in injection_points:
                    f.write(f"- Location: {point['location']}\n")
                    f.write(f"  Type: {point['type']}\n")
                    f.write(f"  Risk: {point['risk']}\n\n")
        
        return {
            'success': True,
            'injection_points': injection_points,
            'report_path': report_path
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }