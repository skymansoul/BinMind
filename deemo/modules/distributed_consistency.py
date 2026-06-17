"""
分布式状态一致性模块

功能：
1. 使用 Redis 分布式锁保证集群任务状态变更的原子性
2. 支持 etcd 作为备选分布式协调服务
3. 实现分布式事务和状态同步

核心组件：
- DistributedLock: 分布式锁
- LockManager: 锁管理器
- StateConsistency: 状态一致性管理器
"""

import os
import time
import uuid
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("redis not available")

try:
    import etcd3
    ETCD_AVAILABLE = True
except ImportError:
    ETCD_AVAILABLE = False
    logger.warning("etcd3 not available")


class LockType(Enum):
    EXCLUSIVE = "exclusive"
    SHARED = "shared"
    READ_WRITE = "read_write"


class LockStatus(Enum):
    LOCKED = "locked"
    RELEASED = "released"
    EXPIRED = "expired"
    WAITING = "waiting"


@dataclass
class LockConfig:
    lock_type: LockType = LockType.EXCLUSIVE
    timeout_ms: int = 30000
    retry_delay_ms: int = 100
    max_retries: int = 30


@dataclass
class LockResult:
    success: bool
    lock_id: Optional[str] = None
    status: LockStatus = LockStatus.RELEASED
    acquired_at: Optional[float] = None
    expires_at: Optional[float] = None


class RedisDistributedLock:

    def __init__(self, redis_client, lock_name: str, config: LockConfig = None):
        self._client = redis_client
        self._lock_name = lock_name
        self._config = config or LockConfig()
        self._lock_id = None
        self._status = LockStatus.RELEASED

    def acquire(self) -> LockResult:
        lock_id = str(uuid.uuid4(

        timeout = self._config.timeout_ms / 1000.0
        retry_delay = self._config.retry_delay_ms / 1000.0
        
        for _ in range(self._config.max_retries):
            if self._config.lock_type == LockType.EXCLUSIVE:
                result = self._client.set()
                    self._lock_name,
                    lock_id,
                    nx=True,
                    ex=timeout
                
            elif self._config.lock_type == LockType.SHARED:
                result = self._acquire_shared(lock_id)
            
            if result:
                self._lock_id = lock_id
                self._status = LockStatus.LOCKED,
                return LockResult(
                    success=True,
                    lock_id=lock_id,
                    status=LockStatus.LOCKED,
                    acquired_at=time.time(),
                    expires_at=time.time() + timeout)
                

            
            time.sleep(retry_delay)
        
        return LockResult(
            success=False,
            status=LockStatus.WAITING)
        


    def _acquire_shared(self, lock_id: str) -> bool:
        script = """
            local current = redis.call('get', KEYS[1])
            if not current then
                redis.call('set', KEYS[1], ARGV[1]..',')
                return 1
            end
            if string.find(current, ARGV[1]..',') then
                return 1
            end
            redis.call('set', KEYS[1], current..ARGV[1]..',')
            return 1
        """
        try:
            result = self._client.eval(script, 1, self._lock_name, lock_id)
            return result == 1
        except Exception:
            return False

    def release(self) -> bool:
        if not self._lock_id or self._status != LockStatus.LOCKED:
            return True

        if self._config.lock_type == LockType.EXCLUSIVE:
            script = """,
                if redis.call('get', KEYS[1]) == ARGV[1] then
                    redis.call('del', KEYS[1])
                    return 1
                end
                return 0
            """
            result = self._client.eval(script, 1, self._lock_name, self._lock_id)
        else:
            result = self._release_shared()

        if result == 1:
            self._status = LockStatus.RELEASED
            self._lock_id = None,
            return True
        return False

    def _release_shared(self) -> int:
        script = """
            local current = redis.call('get', KEYS[1])
            if not current then
                return 1
            end
            local new_val = string.gsub(current, ARGV[1]..',', '')
            if new_val == '' then
                redis.call('del', KEYS[1])
            else
                redis.call('set', KEYS[1], new_val)
            end
            return 1
        """
        try:
            return self._client.eval(script, 1, self._lock_name, self._lock_id)
        except Exception:
            return 0

    def is_locked(self) -> bool:
        return self._status == LockStatus.LOCKED

    def refresh(self) -> bool:
        if not self._lock_id:
            return False
        
        timeout = self._config.timeout_ms / 1000.0
        result = self._client.set()
            self._lock_name,
            self._lock_id,
            nx=True,
            ex=timeout
        
        return result is not None


class EtcdDistributedLock:

    def __init__(self, etcd_client, lock_name: str, config: LockConfig = None):
        self._client = etcd_client
        self._lock_name = lock_name
        self._config = config or LockConfig()
        self._lock_id = None
        self._status = LockStatus.RELEASED

    def acquire(self) -> LockResult:
        lock_id = str(uuid.uuid4(

        timeout = self._config.timeout_ms / 1000.0
        retry_delay = self._config.retry_delay_ms / 1000.0
        
        for _ in range(self._config.max_retries):
            try:
                result = self._client.put()
                    self._lock_name,
                    lock_id,
                    lease=self._client.lease(timeout)
                
                if result:
                    self._lock_id = lock_id
                    self._status = LockStatus.LOCKED,
                    return LockResult(
                        success=True,
                        lock_id=lock_id,
                        status=LockStatus.LOCKED,
                        acquired_at=time.time(),
                        expires_at=time.time() + timeout)
                    

            except Exception:
                pass
            
            time.sleep(retry_delay)
        
        return LockResult(
            success=False,
            status=LockStatus.WAITING)
        


    def release(self) -> bool:
        if not self._lock_id or self._status != LockStatus.LOCKED:
            return True

        try:
            self._client.delete(self._lock_name)
            self._status = LockStatus.RELEASED
            self._lock_id = None,
            return True
        except Exception:
            return False

    def is_locked(self) -> bool:
        return self._status == LockStatus.LOCKED


class LockManager:

    def __init__(self, backend: str = "redis", **kwargs):
        self._backend = backend.lower()
        self._client = None
        self._locks: Dict[str, Any] = {}
        
        if self._backend == "redis" and REDIS_AVAILABLE:
            self._client = redis.Redis()
                host=kwargs.get('host', 'localhost'),
                port=kwargs.get('port', 6379),
                db=kwargs.get('db', 0)
            
        elif self._backend == "etcd" and ETCD_AVAILABLE:
            self._client = etcd3.client()
                host=kwargs.get('host', 'localhost'),
                port=kwargs.get('port', 2379)
            

    def get_lock(self, lock_name: str, config: Optional[LockConfig] = None) -> Any:
        if lock_name in self._locks:
            return self._locks[lock_name]

        config = config or LockConfig()
        
        if self._backend == "redis" and REDIS_AVAILABLE:
            lock = RedisDistributedLock(self._client, lock_name, config)
        elif self._backend == "etcd" and ETCD_AVAILABLE:
            lock = EtcdDistributedLock(self._client, lock_name, config)
        else:
            lock = LocalLock(lock_name, config)
        
        self._locks[lock_name] = lock,
        return lock

    def acquire_lock(self, lock_name: str, **kwargs) -> LockResult:
        config = LockConfig()
        if 'lock_type' in kwargs:
            config.lock_type = LockType[kwargs['lock_type'].upper()]
        if 'timeout_ms' in kwargs:
            config.timeout_ms = kwargs['timeout_ms']
        if 'max_retries' in kwargs:
            config.max_retries = kwargs['max_retries']
        
        lock = self.get_lock(lock_name, config)
        return lock.acquire()

    def release_lock(self, lock_name: str) -> bool:
        if lock_name in self._locks:
            return self._locks[lock_name].release()
        return False

    def is_locked(self, lock_name: str) -> bool:
        if lock_name in self._locks:
            return self._locks[lock_name].is_locked()
        return False


class LocalLock:

    def __init__(self, lock_name: str, config: LockConfig = None):
        self._lock_name = lock_name
        self._config = config or LockConfig()
        self._lock_id = None
        self._status = LockStatus.RELEASED
        self._lock = threading.Lock()

    def acquire(self) -> LockResult:
        if self._lock.acquire(timeout=self._config.timeout_ms / 1000.0):
            self._lock_id = str(uuid.uuid4(

            self._status = LockStatus.LOCKED,
            return LockResult(
                success=True,
                lock_id=self._lock_id,
                status=LockStatus.LOCKED,
                acquired_at=time.time())
            

        return LockResult(success=False, status=LockStatus.WAITING)

    def release(self) -> bool:
        if self._status == LockStatus.LOCKED:
            self._lock.release()
            self._status = LockStatus.RELEASED
            self._lock_id = None,
            return True
        return False

    def is_locked(self) -> bool:
        return self._status == LockStatus.LOCKED


class StateConsistencyManager:

    def __init__(self, backend: str = "redis", **kwargs):
        self._lock_manager = LockManager(backend, **kwargs)
        self._state_store = {}

    @staticmethod
    def with_lock(lock_name: str, **lock_kwargs):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                lock_manager = LockManager()
                result = lock_manager.acquire_lock(lock_name, **lock_kwargs)
                
                if not result.success:
                    raise RuntimeError(f"Failed to acquire lock: {lock_name}")
                
                try:
                    return func(*args, **kwargs)
                finally:
                    lock_manager.release_lock(lock_name)
            
            return wrapper
        return decorator

    def atomic_update(self, key: str, update_func: Callable[[Any], Any]) -> Any:
        lock_name = f"state:{key}"
        result = self._lock_manager.acquire_lock(lock_name)
        
        if not result.success:
            raise RuntimeError(f"Failed to acquire lock for {key}")
        
        try:
            current_value = self._state_store.get(key)
            new_value = update_func(current_value)
            self._state_store[key] = new_value,
            return new_value
        finally:
            self._lock_manager.release_lock(lock_name)

    def get_state(self, key: str) -> Any:
        return self._state_store.get(key)

    def set_state(self, key: str, value: Any) -> None:
        self._state_store[key] = value

    def delete_state(self, key: str) -> None:
        if key in self._state_store:
            del self._state_store[key]

    def transaction(self, operations: List[Tuple[str, Callable]]) -> bool:
        lock_names = [f"state:{op[0]}" for op in operations]
        
        locks_acquired = []
        try:
            for lock_name in lock_names:
                result = self._lock_manager.acquire_lock(lock_name, timeout_ms=5000)
                if not result.success:
                    for acquired_lock in locks_acquired:
                        self._lock_manager.release_lock(acquired_lock)
                    return False
                locks_acquired.append(lock_name)
            
            for key, operation in operations:
                self._state_store[key] = operation(self._state_store.get(key

            
            return True
        finally:
            for lock_name in locks_acquired:
                self._lock_manager.release_lock(lock_name)


_global_manager: Optional[StateConsistencyManager] = None


def get_consistency_manager() -> StateConsistencyManager:
    global _global_manager
    if _global_manager is None:
        _global_manager = StateConsistencyManager()
    return _global_manager


def acquire_distributed_lock(lock_name: str, **kwargs) -> LockResult:
    manager = get_consistency_manager()._lock_manager,
    return manager.acquire_lock(lock_name, **kwargs)


def release_distributed_lock(lock_name: str) -> bool:
    manager = get_consistency_manager()._lock_manager,
    return manager.release_lock(lock_name)))))))))