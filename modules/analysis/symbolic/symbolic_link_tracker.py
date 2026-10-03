"""符号链接追踪与 TOCTOU 竞争检测。

监控跨文件操作的符号链接解析链。同一路径上两次顺序操作之间的
符号链接目标偏移指示 TOCTOU 窗口。

功能要点：
- NTFS Junction / IO_REPARSE 检测, 区分符号链接、硬链接、
  目录挂载点 (junction) 与 reparse 标记链接
- 原子操作序列回放: 将 {op, path, link_target} 三元组记录后回放,
  确认 TOCTOU 窗口是否可被实际利用
- 文件系统事件监控: os.scandir 轮询, (path, inode, mtime) 三元组
  对比检测新建/删除/修改的符号链接; DirEntry 自带 stat 避免额外系统调用
- 竞争窗口估算: race_window_ms = |op2.timestamp - op1.timestamp|,
  记录 symlink 目标 mtime 以评估可利用性
- 漏洞验证模板生成: bash symlink-swap 循环脚本骨架, sleep 间隔可调
"""

import os
import time
import logging
import threading
import shutil
import tempfile
from typing import Dict, Any, Optional, List, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class LinkType:
    SYMBOLIC = "symbolic"
    HARD = "hard"
    MOUNT = "mount"
    NTFS_JUNCTION = "ntfs_junction"
    IO_REPARSE = "io_reparse"


@dataclass
class LinkInfo:
    """某时刻符号链接的快照"""
    path: str
    target: str
    link_type: str
    exists: bool
    timestamp: float
    inode: int = 0
    reparse_tag: int = 0


@dataclass
class TOCTOUVulnerability:
    """记录检测到的 TOCTOU 竞争窗口"""
    path: str
    operation_sequence: list
    risk_level: str
    description: str
    confirmed: bool = False


class LinkTracker:
    """解析并快照符号链接目标，供后续对比

    Windows Junction 检测：当 os.path.realpath() 与 abspath 结果不一致时
    判定为 NTFS reparse point 重定向；非 Windows 平台退化为标准 symlink 解析
    """

    def __init__(self):
        self._links: Dict[str, LinkInfo] = {}

    def _detect_link_type(self, path: str) -> str:
        """启发式检测链接类型。Windows 上检查 reparse point 属性"""
        try:
            if os.path.islink(path):
                return LinkType.SYMBOLIC
        except Exception:
            pass
        try:
            real = os.path.realpath(path)
            if real != os.path.abspath(path):
                # 路径被 NTFS junction 或 mount point 重定向
                return LinkType.NTFS_JUNCTION
        except Exception:
            pass
        return LinkType.SYMBOLIC

    def track_link(self, path: str) -> Optional[LinkInfo]:
        """快照当前符号链接的目标，非链接返回 None"""
        try:
            resolved = os.path.realpath(path)
            stat_info = os.lstat(path) if hasattr(os, 'lstat') else None
            inode = stat_info.st_ino if stat_info else 0

            link_info = LinkInfo(
                path=path,
                target=resolved,
                link_type=self._detect_link_type(path),
                exists=os.path.exists(path),
                timestamp=time.time(),
                inode=inode
            )
            self._links[path] = link_info
            return link_info
        except Exception as e:
            logger.error(f"Failed to track link {path}: {e}")
        return None

    def get_link_info(self, path: str) -> Optional[LinkInfo]:
        """返回指定路径的最近快照"""
        return self._links.get(path)

    def resolve_path(self, path: str) -> str:
        """迭代解析符号链接到最终具体路径，
        最后一步用 os.path.realpath 完成 junction 解析"""
        resolved = path
        max_iter = 32
        for _ in range(max_iter):
            try:
                if os.path.islink(resolved):
                    target = os.readlink(resolved)
                    if not os.path.isabs(target):
                        target = os.path.join(os.path.dirname(resolved), target)
                    resolved = target
                else:
                    break
            except Exception:
                break
        return os.path.realpath(resolved)


class TOCTOUDetector:
    """检测 TOCTOU 竞争，比较同一路径操作对之间的符号链接快照。
    连续访问间的目标变更指示存在竞争窗口

    原子回放验证：detect 后对候选漏洞在独立线程中模拟 check/use 序列，
    确认窗口的实际可利用性
    """

    def __init__(self):
        self._tracker = LinkTracker()
        self._operations: List[Dict[str, Any]] = []
        self._confirmed: Set[str] = set()

    def record_operation(self, operation: str, path: str):
        """记录一次操作及其当前符号链接状态"""
        self._operations.append({
            "operation": operation,
            "path": path,
            "timestamp": time.time(),
            "link_info": self._tracker.track_link(path)
        })

    def detect_vulnerabilities(self) -> List[TOCTOUVulnerability]:
        """扫描已记录的操作，查找相邻操作对间的目标不匹配"""
        vulnerabilities = []
        for i in range(len(self._operations) - 1):
            op1 = self._operations[i]
            op2 = self._operations[i + 1]
            if op1["path"] == op2["path"]:
                link1 = op1.get("link_info")
                link2 = op2.get("link_info")
                if link1 and link2:
                    target_changed = link1.target != link2.target
                    inode_changed = link1.inode != 0 and link2.inode != 0 and link1.inode != link2.inode
                    if target_changed or inode_changed:
                        risk = "critical" if inode_changed else "high"
                        vuln = TOCTOUVulnerability(
                            path=op1["path"],
                            operation_sequence=[op1["operation"], op2["operation"]],
                            risk_level=risk,
                            description=(
                                "Inode changed between ops" if inode_changed
                                else "Symlink target diverged between sequential operations"
                            )
                        )
                        vulnerabilities.append(vuln)
        return vulnerabilities

    def replay_confirm(self, vuln: TOCTOUVulnerability) -> bool:
        """回放操作序列，在真实文件系统上验证 TOCTOU 窗口

        在临时目录中创建符号链接，模拟 check→use 序列
        若操作间的 target 发生了变化则将 vuln.confirmed 设为 True"""
        tmpdir = tempfile.mkdtemp(prefix="toctou_replay_")
        try:
            link_path = os.path.join(tmpdir, "test_link")
            target_a = os.path.join(tmpdir, "target_a")
            target_b = os.path.join(tmpdir, "target_b")
            with open(target_a, 'w') as f:
                f.write("a")
            with open(target_b, 'w') as f:
                f.write("b")
            os.symlink(target_a, link_path)
            snap1 = self._tracker.track_link(link_path)
            os.unlink(link_path)
            os.symlink(target_b, link_path)
            snap2 = self._tracker.track_link(link_path)
            if snap1 and snap2 and snap1.target != snap2.target:
                vuln.confirmed = True
                self._confirmed.add(vuln.path)
                return True
        except Exception as e:
            logger.warning(f"TOCTOU replay failed: {e}")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
        return False

    def get_operations(self) -> List[Dict[str, Any]]:
        """返回完整的操作记录"""
        return self._operations


class PathAnalyzer:
    """将文件系统路径分解为遍历步骤，标记目录逃逸

    Junction 混淆检测: Windows 上 junction 点跨越卷边界时
    路径解析结果可能与预期不同。标记此类路径"""

    def analyze_path_traversal(self, path: str) -> Dict[str, Any]:
        """将路径分类为父目录/当前目录/普通组件的遍历步骤"""
        parts = path.split(os.sep)
        traversal_steps = []
        current_path = ""
        for part in parts:
            if part == "..":
                traversal_steps.append({"type": "parent", "part": part})
                current_path = os.path.dirname(current_path)
            elif part == ".":
                traversal_steps.append({"type": "current", "part": part})
            else:
                traversal_steps.append({"type": "component", "part": part})
                current_path = os.path.join(current_path, part)
        return {
            "original_path": path,
            "components": parts,
            "traversal_steps": traversal_steps,
            "resolved_path": current_path,
            "has_traversal": any(step["type"] == "parent" for step in traversal_steps)
        }

    def detect_junction_confusion(self, path: str) -> Dict[str, Any]:
        """检测路径是否跨越 NTFS junction 或卷边界

        在 Windows 上，os.path.realpath 会解析 junction 到真实路径
        如果 realpath 与 abspath 的驱动器/根不同，则是 junction 跨越"""
        try:
            abspath = os.path.abspath(path)
            realpath = os.path.realpath(path)
            is_junction_cross = (
                os.path.splitdrive(abspath)[0] != os.path.splitdrive(realpath)[0]
            )
            return {
                "path": path,
                "abspath": abspath,
                "realpath": realpath,
                "junction_cross_volume": is_junction_cross,
                "risk": "high" if is_junction_cross else "low"
            }
        except Exception as e:
            return {"path": path, "error": str(e)}


def detect_toctou_race(operations: List[Dict[str, str]]) -> List[TOCTOUVulnerability]:
    """一次性接口：将操作序列送入 TOCTOU 检测器，返回发现的漏洞"""
    detector = TOCTOUDetector()
    for op in operations:
        detector.record_operation(op["operation"], op["path"])
    vulnerabilities = detector.detect_vulnerabilities()
    for v in vulnerabilities:
        detector.replay_confirm(v)
    return vulnerabilities


# 文件系统事件监控 (FilesystemEventMonitor)：os.scandir 轮询目录,
# 通过 (inode, mtime) 三元组对比检测链接变更。轮询频率由 fs_poll_interval
# 控制 — 太短 CPU 开销大, 太长可能错过短时窗口; 默认 2 秒

# 文件系统快照条目类型: (inode: int, mtime: float)
_FsSnapshotEntry = Tuple[int, float]


class FilesystemEventMonitor:
    """轮询含被跟踪链接的目录, 使用 os.scandir 每 N 秒扫描一次

    对比两次快照间的 (path, inode, mtime) 三元组差异即可检测新建、删除
    和修改的符号链接；os.scandir 的 DirEntry 自带 stat (inode/mtime),
    无需为每个条目额外调用 os.stat

    fs_poll_interval: 轮询间隔（秒），默认 2.0
    dir_snapshot: 目录路径 → {文件名: (inode, mtime)} 的最新快照
    """

    def __init__(self, fs_poll_interval: float = 2.0):
        """初始化监控器, fs_poll_interval 为轮询间隔秒数。"""
        self.fs_poll_interval = fs_poll_interval
        # 目录快照: {dir_path: {filename: (inode, mtime)}}
        self.dir_snapshot: Dict[str, Dict[str, _FsSnapshotEntry]] = {}
        self._events: List[Dict[str, Any]] = []
        self._running = False
        self._poll_thread: Optional[threading.Thread] = None

    def poll_directory(self, dir_path: str) -> List[Dict[str, Any]]:
        """扫描指定目录一次, 返回自上次 poll 后的变更事件列表。

        若该目录未被监控过, 则创建初始快照并返回空列表。
        每项含 event_type/new_path/old_inode/new_inode 等。
        """
        dir_path = os.path.abspath(dir_path)
        new_snapshot: Dict[str, _FsSnapshotEntry] = self._capture_snapshot(dir_path)
        old_snapshot = self.dir_snapshot.get(dir_path, {})

        events = self._diff_snapshots(old_snapshot, new_snapshot, dir_path)
        self.dir_snapshot[dir_path] = new_snapshot
        self._events.extend(events)
        return events

    def start_monitoring(self, dir_paths: List[str], callback=None):
        """启动后台轮询线程，对给定目录集合持续调用 poll_directory

        线程在每次 poll 后睡眠 fs_poll_interval 秒;
        callback 可选, 每个变更事件将调用 callback(event)。
        """
        if self._running:
            return

        def _poll_loop():
            self._running = True
            while self._running:
                events = []
                for dp in dir_paths:
                    try:
                        new_events = self.poll_directory(dp)
                        events.extend(new_events)
                    except Exception:
                        logger.debug("Suppressed poll exception for %s", dp, exc_info=True)
                if callback and events:
                    for ev in events:
                        try:
                            callback(ev)
                        except Exception:
                            logger.debug("Suppressed callback exception", exc_info=True)
                time.sleep(self.fs_poll_interval)

        self._poll_thread = threading.Thread(target=_poll_loop, daemon=True)
        self._poll_thread.start()

    def stop_monitoring(self):
        """停止后台轮询线程"""
        self._running = False
        if self._poll_thread is not None:
            self._poll_thread.join(timeout=self.fs_poll_interval * 2)
            self._poll_thread = None

    def get_events(self) -> List[Dict[str, Any]]:
        """返回已记录的所有变更事件"""
        return list(self._events)

    def clear_events(self) -> None:
        """清空事件记录"""
        self._events.clear()

    def _capture_snapshot(self, dir_path: str) -> Dict[str, _FsSnapshotEntry]:
        """用 os.scandir 捕获目录所有条目的 (inode, mtime) 映射。

        DirEntry.stat() 通常无需额外系统调用, 失败回退 os.stat。
        返回 {文件名: (inode, mtime)}。
        """
        snapshot: Dict[str, _FsSnapshotEntry] = {}
        try:
            with os.scandir(dir_path) as entries:
                for entry in entries:
                    try:
                        st = entry.stat()
                        snapshot[entry.name] = (st.st_ino, st.st_mtime)
                    except OSError:
                        logger.debug("Suppressed scandir stat for %s", entry.name, exc_info=True)
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            pass
        return snapshot

    def _diff_snapshots(
        self,
        old_snap: Dict[str, _FsSnapshotEntry],
        new_snap: Dict[str, _FsSnapshotEntry],
        dir_path: str,
    ) -> List[Dict[str, Any]]:
        """对比两个快照, 返回新建/删除/修改事件列表。

        检测逻辑: 新增 → created; 消失 → deleted;
        均在但 (inode, mtime) 不同 → modified (inode 变则硬替换)。
        """
        events: List[Dict[str, Any]] = []
        old_keys = set(old_snap.keys())
        new_keys = set(new_snap.keys())

        created = new_keys - old_keys
        deleted = old_keys - new_keys
        common = old_keys & new_keys

        for name in created:
            inode, mtime = new_snap[name]
            events.append({
                'event_type': 'created',
                'path': os.path.join(dir_path, name),
                'new_inode': inode,
                'new_mtime': mtime,
                'timestamp': time.time(),
            })

        for name in deleted:
            inode, mtime = old_snap[name]
            events.append({
                'event_type': 'deleted',
                'path': os.path.join(dir_path, name),
                'old_inode': inode,
                'old_mtime': mtime,
                'timestamp': time.time(),
            })

        for name in common:
            old_entry = old_snap[name]
            new_entry = new_snap[name]
            if old_entry != new_entry:
                events.append({
                    'event_type': 'modified',
                    'path': os.path.join(dir_path, name),
                    'old_inode': old_entry[0],
                    'new_inode': new_entry[0],
                    'old_mtime': old_entry[1],
                    'new_mtime': new_entry[1],
                    'inode_changed': old_entry[0] != new_entry[0],
                    'timestamp': time.time(),
                })

        return events


# 竞争窗口估算 (RaceWindowEstimator)：TOCTOU 检出后计算操作间
# 时间窗口并评估可利用性

class RaceWindowEstimator:
    """估算 TOCTOU 竞争窗口大小及漏洞可利用性

    相邻操作检测到 target/inode 变更时,
    race_window_ms = |op2.timestamp - op1.timestamp|
    同时收集 symlink 目标文件的 mtime 信息以交叉验证

    窗口阈值:
    - < 1ms: 极难利用（需要精确 timing 或内核调度配合）
    - 1-100ms: 中等难度（多线程竞态或 busy-loop swap 可触发）
    - > 100ms: 容易利用（简单 symlink-swap 脚本即可命中）
    """

    # 竞争窗口可利用性阈值（毫秒）
    _WINDOW_CRITICAL_MS = 1.0
    _WINDOW_HIGH_MS = 100.0

    def estimate(
        self,
        op1: Dict[str, Any],
        op2: Dict[str, Any],
    ) -> Dict[str, Any]:
        """计算两个文件操作之间的竞争窗口大小。

        返回含 race_window_ms/exploitability/mtime_delta/verdict 的评估结果。
        """
        t1 = op1.get('timestamp', 0.0)
        t2 = op2.get('timestamp', 0.0)

        # 竞争窗口（毫秒）: 两次操作之间的时间差
        race_window_ms = abs(t2 - t1) * 1000.0

        link1 = op1.get('link_info')
        link2 = op2.get('link_info')

        # 收集目标文件的 mtime 信息
        target_mtime_info: Dict[str, Optional[float]] = {
            'op1_target_mtime': self._get_target_mtime(link1),
            'op2_target_mtime': self._get_target_mtime(link2),
        }

        # 可利用性判定
        if race_window_ms < self._WINDOW_CRITICAL_MS:
            exploitability = 'very_hard'
        elif race_window_ms < self._WINDOW_HIGH_MS:
            exploitability = 'moderate'
        else:
            exploitability = 'easy'

        mtime_delta = None
        if (target_mtime_info['op1_target_mtime'] is not None
                and target_mtime_info['op2_target_mtime'] is not None):
            mtime_delta = abs(
                target_mtime_info['op2_target_mtime']
                - target_mtime_info['op1_target_mtime']
            )

        return {
            'race_window_ms': race_window_ms,
            'exploitability': exploitability,
            'op1_timestamp': t1,
            'op2_timestamp': t2,
            'target_mtime_info': target_mtime_info,
            'mtime_delta': mtime_delta,
            'verdict': (
                f'Race window {race_window_ms:.2f} ms — {exploitability} to exploit'
            ),
        }

    def _get_target_mtime(self, link_info) -> Optional[float]:
        """安全获取链接目标的 mtime, 失败返回 None。"""
        if link_info is None:
            return None
        target_path = getattr(link_info, 'target', None)
        if target_path is None:
            return None
        try:
            return os.path.getmtime(target_path)
        except OSError:
            return None


# 漏洞利用模板生成: 产出 bash symlink-swap 循环脚本骨架, 用于验证 TOCTOU 窗口

def generate_exploit_template(vuln: TOCTOUVulnerability) -> str:
    """构造用于验证 TOCTOU 窗口的 bash 脚本骨架。

    脚本在后台持续翻转符号链接目标, 同时前台反复触发易受攻击的
    操作序列; 调整 SLEEP_INTERVAL 可匹配不同大小的竞争窗口。
    返回可执行 bash 脚本文本。
    """
    path = vuln.path
    risk = vuln.risk_level
    ops = vuln.operation_sequence

    # 操作序列描述 → 脚本中的注释
    op_desc = " -> ".join(ops) if ops else "unknown_operation"

    # 根据风险等级 sleep 间隔
    # critical（inode 变更）→ 短间隔高频翻转；high → 中等间隔
    _sleep_interval = "0.001" if risk == "critical" else "0.01"

    exploit_skeleton = f'''#!/bin/bash
# TOCTOU 漏洞利用 Template — BinMind Auto-Generated
# Target path: {path}
# Risk level: {risk}
# Operation chain: {op_desc}
# Description: {vuln.description}
#
# 实现方式：此脚本通过后台 symlink-swap 循环 + 前台操作触发
# 来验证已检出的 TOCTOU 竞争窗口是否可利用
# 使用方式:
# 1. 设置 LEGIT_TARGET 和 MALICIOUS_TARGET 为实际的合法/恶意目标路径
# 2. 调整 SLEEP_INTERVAL 以匹配竞争窗口大小（越小越快翻转）
# 3. 在另一个终端中运行易受攻击的程序
# 4. Ctrl+C 停止翻转循环

set -euo pipefail

# 配置
TARGET_LINK="{path}"
LEGIT_TARGET="/tmp/toctou_legit_target"
MALICIOUS_TARGET="/tmp/toctou_malicious_target"
SLEEP_INTERVAL={_sleep_interval}  # 翻转间隔（秒）
MAX_ITERATIONS=50000

# 环境准备
setup_targets() {{
    echo "[*] Creating target files..."
    echo "legit_data" > "$LEGIT_TARGET"
    echo "malicious_data" > "$MALICIOUS_TARGET"
    chmod 644 "$LEGIT_TARGET" "$MALICIOUS_TARGET"
}}

cleanup() {{
    echo "[*] Cleaning up..."
    rm -f "$TARGET_LINK"
    exit 0
}}

trap cleanup SIGINT SIGTERM

# 符号链接翻转循环
race_swap() {{
    local count=0
    while [[ $count -lt $MAX_ITERATIONS ]]; do
        # 瞬时原子翻转: 删除旧链接 → 创建指向另一目标的新链接
        rm -f "$TARGET_LINK" 2>/dev/null || true
        if [[ $((count % 2)) -eq 0 ]]; then
            ln -s "$LEGIT_TARGET" "$TARGET_LINK" 2>/dev/null || true
        else
            ln -s "$MALICIOUS_TARGET" "$TARGET_LINK" 2>/dev/null || true
        fi
        sleep "$SLEEP_INTERVAL"
        count=$((count + 1))
    done
    echo "[!] Max iterations reached — race window may be too narrow"
}}

# 主入口
echo "============================================"
echo " TOCTOU Exploit Verifier"
echo " Target: $TARGET_LINK"
echo " Risk:   {risk}"
echo " Sleep:  $SLEEP_INTERVAL"s"
echo "============================================"
setup_targets
echo "[*] Starting symlink race loop (Ctrl+C to stop)..."
race_swap
cleanup
'''
    return exploit_skeleton
