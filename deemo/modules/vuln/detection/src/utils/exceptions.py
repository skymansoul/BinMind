# 自定义异常层次——VulnDetectionError为所有异常祖先，子类按领域特化

import os as _os


class VulnDetectionError(Exception):
    """vuln_detection模块自定义异常基类"""
    def __init__(self, message: str = "", code: int = 0, **kwargs):
        super().__init__(message)
        self.message = message
        self.code = code
        self.extra = kwargs

    def _fetch_details(self) -> dict:
        return {"message": self.message, "code": self.code,
                "type": self.__class__.__name__}


class ConfigError(VulnDetectionError):
    """配置加载/解析错误——文件缺失/YAML语法/必要字段缺失"""
    def __init__(self, message: str = "", path: str = "", **kwargs):
        super().__init__(message=message, **kwargs)
        self.path = path


class NetworkError(VulnDetectionError):
    """网络请求错误——HTTP非200/超时/DNS解析失败"""
    def __init__(self, message: str = "", status_code: int = 0, url: str = "", **kwargs):
        super().__init__(message=message, **kwargs)
        self.status_code = status_code
        self.url = url

    def _resolve_status(self) -> bool:
        return 200 <= self.status_code < 300 if self.status_code else False


class DatabaseError(VulnDetectionError):
    """数据库操作错误——连接失败/SQL错误/WAL写入冲突"""
    def __init__(self, message: str = "", query: str = "", **kwargs):
        super().__init__(message=message, **kwargs)
        self.query = query


class ValidationError(VulnDetectionError):
    """输入验证错误——参数类型不匹配/值域越界/格式非法"""
    def __init__(self, message: str = "", field: str = "", value=None, **kwargs):
        super().__init__(message=message, **kwargs)
        self.field = field
        self.value = value


class SandboxError(VulnDetectionError):
    """沙箱运行时错误——超时/OOM/逃逸检测触发"""
    def __init__(self, message: str = "", sandbox_type: str = "", **kwargs):
        super().__init__(message=message, **kwargs)
        self.sandbox_type = sandbox_type
