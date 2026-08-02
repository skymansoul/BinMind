# tests for binary_analysis pipeline infrastructure

import pytest
from modules.analysis.static.binary_analysis.pipeline_infra import TaskQueue, BatchRunner


class TestTaskQueue:
    """Task queue for batch processing."""

    def test_enqueue_dequeue(self):
        """Basic enqueue and dequeue operations."""
        q = TaskQueue()
        q.enqueue({"id": 1, "action": "analyze"})
        q.enqueue({"id": 2, "action": "audit"})
        assert q.size() == 2
        item = q.dequeue()
        assert item["id"] == 1
        assert q.size() == 1

    def test_empty_dequeue(self):
        """Dequeue from empty queue returns None."""
        q = TaskQueue()
        assert q.dequeue() is None

    def test_queue_order(self):
        """FIFO order is preserved."""
        q = TaskQueue()
        for i in range(10):
            q.enqueue({"seq": i})
        results = []
        while q.size() > 0:
            results.append(q.dequeue()["seq"])
        assert results == list(range(10))


class TestBatchRunner:
    """Batch runner for parallel analysis."""

    def test_runner_creation(self):
        """BatchRunner can be created with default settings."""
        runner = BatchRunner(max_workers=2)
        assert runner.max_workers == 2

    def test_dispatch_tasks(self):
        """Dispatch empty task list doesn't crash."""
        runner = BatchRunner()
        results = runner.dispatch_tasks([])
        assert results == []


class TestPipelineIntegration:
    """End-to-end pipeline flow tests."""

    def test_config_loading(self):
        """Verify config can be loaded."""
        # import config if available
        try:
            from modules.analysis.static.binary_analysis.pipeline_infra import dispatch_tasks
            assert callable(dispatch_tasks)
        except ImportError:
            pytest.skip("pipeline_infra module not available")
