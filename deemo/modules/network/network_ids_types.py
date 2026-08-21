"""IDS规则引擎——数据结构与常量定义。"""
import logging
from dataclasses import dataclass, field
from typing import List, Dict

_log = logging.getLogger(__name__)


@dataclass
class SuricataRule:
    sid: int = 0
    msg: str = ""
    action: str = "alert"
    proto: str = "any"
    src_ip: str = "any"
    src_port: str = "any"
    direction: str = "->"
    dst_ip: str = "any"
    dst_port: str = "any"
    content_patterns: List[str] = field(default_factory=list)
    pcre_patterns: List[str] = field(default_factory=list)
    flow_direction: str = ""  # to_server, to_client, established
    dsize_min: int = 0
    dsize_max: int = 0
    threshold_count: int = 0
    threshold_seconds: int = 0
    reference_urls: List[str] = field(default_factory=list)
    classtype: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)
    raw: str = ""
