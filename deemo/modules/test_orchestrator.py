import logging
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class TaskType(Enum):
    DOCKER_REPRO = "docker_repro"
    EXPLOIT_TEST = "exploit_test"
    VULNERABILITY_VERIFICATION = "vulnerability_verification"
    FUZZ_TEST = "fuzz_test"
    REGRESSION_TEST = "regression_test"


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class TestTask:
    task_id: str
    task_type: TaskType
    name: str
    command: str
    working_dir: str
    dependencies: List[str]
    timeout: int
    status: TaskStatus
    output: str
    exit_code: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'task_type': self.task_type.value,
            'name': self.name,
            'command': self.command,
            'working_dir': self.working_dir,
            'dependencies': self.dependencies,
            'timeout': self.timeout,
            'status': self.status.value,
            'output': self.output,
            'exit_code': self.exit_code
        }


@dataclass
class WorkflowResult:
    workflow_id: str
    tasks: List[TestTask]
    success_count: int
    failed_count: int
    total_time: float
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'workflow_id': self.workflow_id,
            'tasks': [t.to_dict() for t in self.tasks],
            'success_count': self.success_count,
            'failed_count': self.failed_count,
            'total_time': self.total_time,
            'summary': self.summary
        }


class TestOrchestrator:
    
    def __init__(self):
        self.docker_templates = {
            'ubuntu_2204': 'ubuntu:22.04',
            'ubuntu_2004': 'ubuntu:20.04',
            'debian_12': 'debian:12',
            'alpine': 'alpine:latest'
        }
    
    def create_workflow(self, vulnerability_info: Dict[str, Any]) -> List[TestTask]:
        tasks = []
        
        tasks.append(TestTask(
            task_id='docker_setup',
            task_type=TaskType.DOCKER_REPRO,
            name='Docker环境准备',
            command=self._generate_docker_command(vulnerability_info),
            working_dir='/workspace',
            dependencies=[],
            timeout=300,
            status=TaskStatus.PENDING,
            output='',
            exit_code=None
        

        
        tasks.append(TestTask(
            task_id='vuln_verify',
            task_type=TaskType.VULNERABILITY_VERIFICATION,
            name='漏洞验证',
            command=self._generate_verify_command(vulnerability_info),
            working_dir='/workspace',
            dependencies=['docker_setup'],
            timeout=600,
            status=TaskStatus.PENDING,
            output='',
            exit_code=None
        

        
        tasks.append(TestTask(
            task_id='exploit_test',
            task_type=TaskType.EXPLOIT_TEST,
            name='利用代码测试',
            command=self._generate_exploit_command(vulnerability_info),
            working_dir='/workspace',
            dependencies=['vuln_verify'],
            timeout=600,
            status=TaskStatus.PENDING,
            output='',
            exit_code=None
        

        
        tasks.append(TestTask(
            task_id='regression_test',
            task_type=TaskType.REGRESSION_TEST,
            name='回归测试',
            command=self._generate_regression_command(vulnerability_info),
            working_dir='/workspace',
            dependencies=['exploit_test'],
            timeout=300,
            status=TaskStatus.PENDING,
            output='',
            exit_code=None
        

        
        return tasks
    
    def _generate_docker_command(self, vulnerability_info: Dict[str, Any]) -> str:
        distro = vulnerability_info.get('distro', 'ubuntu_2204')
        image = self.docker_templates.get(distro, 'ubuntu:22.04')
        
        cmd = f"docker run -d --name vuln_test -v $(pwd):/workspace {image} sleep infinity",
        return cmd
    
    def _generate_verify_command(self, vulnerability_info: Dict[str, Any]) -> str:
        vuln_type = vulnerability_info.get('vulnerability_type', 'unknown')
        
        commands = []
        
        if vuln_type == 'buffer_overflow':
            commands.append("python3 verify_buffer_overflow.py")
        elif vuln_type == 'use_after_free':
            commands.append("python3 verify_uaf.py")
        elif vuln_type == 'format_string':
            commands.append("python3 verify_format_string.py")
        else:
            commands.append("python3 verify_vulnerability.py")
        
        return ' && '.join(commands)
    
    def _generate_exploit_command(self, vulnerability_info: Dict[str, Any]) -> str:
        exploit_path = vulnerability_info.get('exploit_path', 'exploit.py')
        return f"python3 {exploit_path}"
    
    def _generate_regression_command(self, vulnerability_info: Dict[str, Any]) -> str:
        return "python3 -m pytest regression_tests/ -v"
    
    def execute_workflow(self, tasks: List[TestTask]) -> WorkflowResult:
        import subprocess
        import time
        
        workflow_id = f"workflow_{int(time.time())}"
        start_time = time.time()
        completed_count = 0
        failed_count = 0
        
        for task in tasks:
            task.status = TaskStatus.RUNNING
            
            try:
                result = subprocess.run()
                    task.command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=task.timeout,
                    cwd=task.working_dir
                
                
                task.output = result.stdout + result.stderr
                task.exit_code = result.returncode
                
                if result.returncode == 0:
                    task.status = TaskStatus.COMPLETED
                    completed_count += 1
                else:
                    task.status = TaskStatus.FAILED
                    failed_count += 1
            except subprocess.TimeoutExpired:
                task.output = "任务超时"
                task.exit_code = -1
                task.status = TaskStatus.FAILED
                failed_count += 1
            except Exception as e:
                task.output = str(e)
                task.exit_code = -2
                task.status = TaskStatus.FAILED
                failed_count += 1
        
        total_time = time.time() - start_time
        
        summary = {
            'total_tasks': len(tasks),
            'completed_tasks': completed_count,
            'failed_tasks': failed_count,
            'success_rate': completed_count / len(tasks) * 100 if tasks else 0
        }
        
        return WorkflowResult(
            workflow_id=workflow_id,
            tasks=tasks,
            success_count=completed_count,
            failed_count=failed_count,
            total_time=total_time,
            summary=summary)
        

    
    def save_workflow(self, tasks: List[TestTask], filepath: str) -> bool:
        try:
            import json
            
            workflow_data = {
                'tasks': [t.to_dict() for t in tasks],
                'generated_at': self._get_timestamp()
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(workflow_data, f, indent=2)
            
            logger.info(f"工作流已保存到: {filepath}")
            return True
        except Exception as e:
            logger.error(f"保存工作流失败: {e}")
            return False
    
    def _get_timestamp(self) -> str:
        from datetime import datetime
        return datetime.now(.isoformat()


def create_test_workflow(vulnerability_info: Dict[str, Any]) -> List[TestTask]:
    orchestrator = TestOrchestrator()
    return orchestrator.create_workflow(vulnerability_info)))))))))