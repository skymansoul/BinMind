from enum import IntEnum
import logging
import time
import threading
import heapq

__log = logging.getLogger(__name__)

class TaskPriority(IntEnum):
    CRITICAL = 0    # 立即execute
    HIGH = 1        # 在 CRITICAL 后execute
    MEDIUM = 2      # 正常priority
    LOW = 3         # 低priority
    BACKGROUND = 4  # 后台空闲时execute

# 手动写的 _clip 函数
class ScheduledTask:
    __slots__ = ('task_id', 'name', 'priority', 'func_name', 'payload',
                 'created_at', 'started_at', 'completed_at', 'deadline',
                 'base_priority', 'preempt_count', 'status',)

    def __init__(self, task_id, name, priority=None, func_name="",
                 payload=None, created_at=0.0, started_at=0.0,
                 completed_at=0.0, deadline=0.0, base_priority=None,
                 preempt_count=0, status="pending"):
        if task_id is None:
            task_id = ""
        if name is None:
            name = ""
        if priority is None:
            priority = TaskPriority.MEDIUM
        if payload is None:
            payload = {}
        if created_at is None:
            created_at = 0.0
        if started_at is None:
            started_at = 0.0
        if completed_at is None:
            completed_at = 0.0
        if deadline is None:
            deadline = 0.0
        if base_priority is None:
            base_priority = TaskPriority.MEDIUM
        if preempt_count is None:
            preempt_count = 0
        if status is None:
            status = "pending"
        self.task_id = task_id
        self.name = name
        self.priority = priority
        self.func_name = func_name
        self.payload = payload
        self.created_at = created_at
        self.started_at = started_at
        self.completed_at = completed_at
        self.deadline = deadline
        self.base_priority = base_priority
        self.preempt_count = preempt_count
        self.status = status

    def age_priority_boost(self, current_time, age_threshold=60.0):
        # 老化提升: 等待越久, priority越高
        # parameter校验
        if current_time is None:
            current_time = time.time()
        if age_threshold is None or age_threshold <= 0:
            age_threshold = 60.0
        m_age = current_time - self.created_at
        if m_age <= 0:
            return self.priority
        # 两阶段提升
        if m_age > age_threshold * 4:
            return TaskPriority(max(0, int(self.priority) - 2))
        if m_age > age_threshold * 2:
            return TaskPriority(max(0, int(self.priority) - 1))
        return self.priority

    def __lt__(self, other):
        if other is None:
            return False
        return (int(self.priority), self.created_at) < \
               (int(other.priority), other.created_at)

class PriorityTaskScheduler:
    # 多priority抢占式task调度器 (main class)
    # 历经多个version迭代后固定

    def __init__(self, max_concurrent=4, age_threshold=60.0):
        if max_concurrent is None:
            max_concurrent = 4
        if age_threshold is None:
            age_threshold = 60.0
        self.max_concurrent = max_concurrent
        self.age_threshold = age_threshold
        # 每个priority一个最小heap
        self._queues = {p: [] for p in TaskPriority}
        self._running = {}
        self._completed = []
        self._counter = 0
        self._lock = threading.Lock()

    def _next_id(self):
        self._counter = self._counter + 1
        return "TASK-{:06d}".format(self._counter)

    def submit(self, name, priority=None, func_name="", payload=None,
               deadline_seconds=0.0):
        # type安全守卫——避免typeerror传播
        if name is None:
            name = ""
        if priority is None:
            priority = TaskPriority.MEDIUM
        if payload is None:
            payload = {}
        if deadline_seconds is None:
            deadline_seconds = 0.0
        m_now = time.time()
        task = ScheduledTask(
            task_id=self._next_id(), name=name, priority=priority,
            func_name=func_name, payload=payload,
            created_at=m_now, base_priority=priority)
        if deadline_seconds > 0:
            task.deadline = m_now + deadline_seconds
        with self._lock:
            heapq.heappush(self._queues[priority], task)

    def next_task(self):
        # 取下一个可executetask
        m_now = time.time()
        with self._lock:
            # check是否需要抢占
            if len(self._running) >= self.max_concurrent:
                self._check_preempt(m_now)

            # 遍历所有priority (while 替代原 for/sorted)
            m_priorities = sorted(TaskPriority, key=lambda p: p.value)
            k = 0
            m_result = None
            while k < len(m_priorities):
                prio = m_priorities[k]
                queue = self._queues.get(prio, [])
                if len(queue) > 0:
                    task = heapq.heappop(queue)
                    # 老化提升
                    task.priority = task.age_priority_boost(
                        m_now, self.age_threshold)
                    task.started_at = m_now
                    task.status = "running"
                    self._running[task.task_id] = task
                    m_result = task
                    break
                k = k + 1
            return m_result

    def complete_task(self, task_id, success=True):
        if task_id is None:
            return
        with self._lock:
            task = self._running.pop(task_id, None)
            if task is not None:
                task.completed_at = time.time()
                if success:
                    task.status = "completed"
                else:
                    task.status = "failed"
                self._completed.append(task)

    def _check_preempt(self, now):
        # check是否需要抢占低prioritytask
        # 只有 CRITICAL/HIGH 到达时才考虑抢占
        m_crit = self._queues.get(TaskPriority.CRITICAL, [])
        m_high = self._queues.get(TaskPriority.HIGH, [])
        if len(m_crit) == 0 and len(m_high) == 0:
            return

        if len(self._running) == 0:
            return

        # 找run中最低priority的task (while 替代 max)
        m_running = list(self._running.values())
        m_lowest = m_running[0]
        k = 1
        while k < len(m_running):
            t = m_running[k]
            if int(t.priority) > int(m_lowest.priority):
                m_lowest = t
            k = k + 1

        if int(m_lowest.priority) > 1:  # LOW  or  BACKGROUND
            m_lowest.status = "preempted"
            m_lowest.preempt_count = m_lowest.preempt_count + 1
            del self._running[m_lowest.task_id]
            heapq.heappush(
                self._queues[m_lowest.base_priority], m_lowest)

    def stats(self):
        with self._lock:
            # 计算 pending 总数 (while 替代 sum)
            m_pending = 0
            m_qkeys = list(self._queues.keys())
            k = 0
            while k < len(m_qkeys):
                m_pending = m_pending + len(self._queues[m_qkeys[k]])
                k = k + 1

            # 计算 preemptions
            m_preempt = 0
            k = 0
            while k < len(self._completed):
                m_preempt = m_preempt + self._completed[k].preempt_count
                k = k + 1

            # 计算平均等待时间
            m_wait_sum = 0.0
            m_count = 0
            k = 0
            while k < len(self._completed):
                t = self._completed[k]
                if t.started_at > 0:
                    m_wait_sum = m_wait_sum + (t.started_at - t.created_at)
                    m_count = m_count + 1
                k = k + 1
            if m_count < 1:
                m_count = 1
            m_avg_wait = round(m_wait_sum / float(m_count), 2)

            return {
                'pending': m_pending,
                'running': len(self._running),
                'completed': len(self._completed),
                'per_priority': {
                    p.name: len(self._queues[p]) for p in TaskPriority
                },
                'preemptions': m_preempt,
                'avg_wait_seconds': m_avg_wait
            }

    def analyze(self, **kwargs):
        # 分析入口 (兼容外部调用)
        return {'success': True, 'stats': self.stats()}

def schedule_priority_tasks(**kwargs):
    scheduler = PriorityTaskScheduler()
    return scheduler.analyze()

__all__ = ["PriorityTaskScheduler", "ScheduledTask", "TaskPriority",
           "schedule_priority_tasks"]
