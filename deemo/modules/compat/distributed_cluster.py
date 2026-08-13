# Stub — refactored out; distributed config lives in config.py (DISTRIBUTED_MODE, REDIS_HOST).
# Tests resolve this module via importlib.util.
class DistributedCluster:
    def __init__(self, config=None): self.config = config or {}
    def connect(self): return True
    def submit_task(self, task): return {'task_id': 'mock-001'}
    def get_result(self, task_id): return {'status': 'completed'}
    def disconnect(self): return True

class ClusterNode:
    def __init__(self, host='localhost', port=6379): self.host = host; self.port = port
    def is_alive(self): return True
