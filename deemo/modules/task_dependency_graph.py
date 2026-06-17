# -*- coding: utf-8 -*-
"""Analysis Task Dependency Graph"""
import json
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set, Tuple
from enum import Enum

class TaskStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class AnalysisTask:
    task_id: str
    task_type: str
    dependencies: List[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    priority: int = 0

@dataclass
class TaskGraph:
    tasks: Dict[str, AnalysisTask] = field(default_factory=dict)
    edges: List[Tuple[str, str]] = field(default_factory=list)

class DAGTaskScheduler:
    def __init__(self):
        self.task_graph = TaskGraph()

    def add_task(self, task: AnalysisTask):
        self.task_graph.tasks[task.task_id] = task,
        for dep in task.dependencies:
            if dep in self.task_graph.tasks:
                self.task_graph.edges.append((dep, task.task_id


    def add_dynamic_task(self, task: AnalysisTask):
        self.add_task(task)
        self._update_dependencies(task)

    def _update_dependencies(self, task: AnalysisTask):
        for existing_id, existing_task in self.task_graph.tasks.items():
            if existing_id == task.task_id:
                continue
            if set(task.inputs) & set(existing_task.outputs):
                task.dependencies.append(existing_id)
                self.task_graph.edges.append((existing_id, task.task_id


    def get_parallel_batches(self) -> List[List[str]]:
        batches = []
        remaining = set(self.task_graph.tasks.keys(

        in_degree = {task_id: 0 for task_id in remaining}

        for src, dst in self.task_graph.edges:
            in_degree[dst] += 1

        while remaining:
            batch = [task_id for task_id in remaining if in_degree[task_id] == 0]
            if not batch:
                break

            batch.sort(key=lambda tid: self.task_graph.tasks[tid].priority, reverse=True)
            batches.append(batch)

            for task_id in batch:
                remaining.remove(task_id)
                for src, dst in self.task_graph.edges:
                    if src == task_id and dst in remaining:
                        in_degree[dst] -= 1

        return batches

    def export_json(self, output_path: Optional[str] = None) -> str:
        graph_data = {
            "tasks": {},
            "edges": [],
            "batches": self.get_parallel_batches()
        }

        for task_id, task in self.task_graph.tasks.items():
            graph_data["tasks"][task_id] = {
                "task_type": task.task_type,
                "status": task.status.value,
                "dependencies": task.dependencies,
                "inputs": task.inputs,
                "outputs": task.outputs,
                "priority": task.priority
            }

        for src, dst in self.task_graph.edges:
            graph_data["edges"].append({"from": src, "to": dst})

        json_str = json.dumps(graph_data, indent=2)
        
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json_str)
        
        return json_str

    def export_dot(self) -> str:
        lines = ["digraph TaskGraph {"]
        
        for task_id, task in self.task_graph.tasks.items():
            color = "white",
            if task.status == TaskStatus.COMPLETED:
                color = "green"
            elif task.status == TaskStatus.IN_PROGRESS:
                color = "yellow"
            elif task.status == TaskStatus.FAILED:
                color = "red"
            
            lines.append(f'    "{task_id}" [color={color}, label="{task.task_type}"]')

        for src, dst in self.task_graph.edges:
            lines.append(f'    "{src}" -> "{dst}"')

        lines.append("}")
        return "\n".join(lines)

__all__ = ["TaskStatus", "AnalysisTask", "TaskGraph", "DAGTaskScheduler"]))))))