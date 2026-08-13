import logging
import json
import hashlib
import time
import struct
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class TimelineEventType(str, Enum):
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_READ = "file_read"
    FILE_DELETED = "file_deleted"
    FILE_RENAMED = "file_renamed"
    NETWORK_CONNECT = "network_connect"
    NETWORK_RECEIVE = "network_receive"
    NETWORK_SEND = "network_send"
    PROCESS_CREATE = "process_create"
    PROCESS_TERMINATE = "process_terminate"
    REGISTRY_WRITE = "registry_write"
    REGISTRY_READ = "registry_read"
    LIBRARY_LOAD = "library_load"
    MEMORY_ALLOCATION = "memory_allocation"
    IPC_COMMUNICATION = "ipc_communication"
    TIMESTAMP_MARKER = "timestamp_marker"
    UNKNOWN = "unknown"

class AnomalyKind(str, Enum):
    TIME_TRAVEL = "time_travel"
    RAPID_BURST = "rapid_burst"
    OUT_OF_ORDER = "out_of_order"
    SUSPICIOUS_INTERVAL = "suspicious_interval"
    BACKDATING = "backdating"
    FUTURE_DATE = "future_date"
    PATTERN_BREAK = "pattern_break"


@dataclass
class TimelineEvent:
    event_id: str
    event_type: TimelineEventType
    timestamp: float
    source: str = ""
    target: str = ""
    detail: str = ""
    process_name: str = ""
    process_id: int = 0
    file_path: str = ""
    network_address: str = ""
    port: int = 0
    data_size: int = 0
    hash_value: str = ""
    user: str = ""
    is_anomalous: bool = False
    anomaly_type: Optional[AnomalyKind] = None
    confidence: float = 1.0
    related_events: List = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "iso_time": datetime.fromtimestamp(self.timestamp).isoformat() if self.timestamp and self.timestamp > 0 else "",
            "source": self.source,
            "target": self.target,
            "detail": self.detail,
            "process_name": self.process_name,
            "file_path": self.file_path,
            "network_address": self.network_address,
            "port": self.port,
            "is_anomalous": self.is_anomalous,
            "anomaly_type": self.anomaly_type.value if self.anomaly_type else "",
            "confidence": self.confidence,
        }


@dataclass
class ForensicTimeline:
    timeline_id: str = ""
    title: str = ""
    events: List = field(default_factory=list)
    total_events: int = 0
    anomalous_events: int = 0
    time_span_start: float = 0.0
    time_span_end: float = 0.0
    generated_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))


class TimestampExtractor:

    @staticmethod
    def from_pe_header(pe_data: bytes) -> List[Dict[str, Any]]:
        timestamps = []
        try:
            if len(pe_data) < 0x3C + 4:
                return timestamps
            pe_offset = struct.unpack_from("<I", pe_data, 0x3C)[0]
            if pe_offset + 4 > len(pe_data):
                return timestamps

            header_offset = pe_offset + 4
            if header_offset + 20 > len(pe_data):
                return timestamps

            timestamp_raw = struct.unpack_from("<I", pe_data, header_offset + 4)[0]
            if timestamp_raw and 0 < timestamp_raw < 0x7FFFFFFF:
                timestamps.append({
                    "source": "PE_HEADER",
                    "field": "TimeDateStamp",
                    "raw_value": timestamp_raw,
                    "timestamp": float(timestamp_raw),
                    "iso_time": datetime.fromtimestamp(timestamp_raw).isoformat(),
                })
        except (struct.error, IndexError, ValueError, OSError) as e:
            logger.debug(f"PE timestamp extraction failed: {e}")

        return timestamps

    @staticmethod
    def from_elf_header(elf_data: bytes) -> List[Dict[str, Any]]:
        """Extract timestamps from ELF header."""
        timestamps = []
        try:
            if len(elf_data) < 64 or elf_data[:4] != b'\x7fELF':
                return timestamps

            ei_class = elf_data[4]
            is_64bit = (ei_class == 2)

            timestamps.append({
                "source": "ELF_HEADER",
                "field": "parsed_at",
                "raw_value": time.time(),
                "timestamp": time.time(),
                "iso_time": datetime.fromtimestamp(time.time()).isoformat(),
                "note": f"ELF{'64' if is_64bit else '32'} - ELF does not store timestamps natively",
            })
        except Exception as e:
            logger.debug(f"ELF timestamp extraction failed: {e}")

        return timestamps

    @staticmethod
    def from_import_table(binary_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        events = []
        imports = binary_info.get("imports", [])

        file_ops = {"open", "creat", "fopen", "fwrite", "fread",
                    "close", "fclose", "stat", "access", "chmod",
                    "unlink", "rename", "mkdir", "rmdir"}

        for imp in imports:
            func_name = imp.get("name", "").lower()
            base_name = func_name.split("@")[0]
            if base_name in file_ops:
                events.append({
                    "source": "import_table",
                    "import_name": func_name,
                    "address": imp.get("address", 0),
                    "operation_type": base_name,
                    "timestamp": time.time(),
                    "iso_time": datetime.fromtimestamp(time.time()).isoformat(),
                })

        return events


class FileOperationAnalyzer:

    FILE_FUNCS = {"open", "creat", "fopen", "freopen", "openat",
                   "read", "fread", "write", "fwrite", "fputs", "fgets",
                   "close", "fclose", "unlink", "remove", "rename",
                   "stat", "fstat", "lstat", "access", "chmod", "chown",
                   "mkdir", "rmdir", "readdir", "opendir",
                   "CreateFile", "ReadFile", "WriteFile", "CloseHandle",
                   "DeleteFile", "MoveFile", "CopyFile",
                   "RegOpenKey", "RegSetValue", "RegQueryValue"}

    def extract(self, binary_info: Dict[str, Any],
                strings: List[str] = None) -> List[Dict[str, Any]]:
        imports = binary_info.get("imports", [])
        operations = []

        for imp in imports:
            func_name = imp.get("name", "").lower()
            base = func_name.split("@")[0]
            if base in self.FILE_FUNCS:
                operations.append({
                    "function": func_name,
                    "address": imp.get("address", 0),
                    "type": self._classify(base),
                    "category": "import",
                })

        strings = strings or binary_info.get("strings", [])
        path_pattern = re.compile(
            r"\b(appdata|temp|system32|Windows|Program Files|/etc/|/var/|/tmp/|/home/|/root/)",
            re.IGNORECASE
        )
        for s in strings:
            s_text = s if isinstance(s, str) else s.get("text", s.get("value", ""))
            if path_pattern.search(s_text):
                operations.append({
                    "function": "string_reference",
                    "path": s_text[:200],
                    "type": "file_path_mention",
                    "category": "string",
                })

        return operations

    @staticmethod
    def _classify(func_name: str) -> str:
        write_ops = {"fwrite", "write", "fputs", "WriteFile", "RegSetValue"}
        read_ops = {"fread", "read", "fgets", "ReadFile", "RegQueryValue"}
        create_ops = {"creat", "fopen", "open", "openat", "freopen", "CreateFile", "mkdir", "RegOpenKey"}
        delete_ops = {"unlink", "remove", "DeleteFile", "rmdir"}

        if func_name in write_ops:
            return "write"
        elif func_name in read_ops:
            return "read"
        elif func_name in create_ops:
            return "create"
        elif func_name in delete_ops:
            return "delete"
        elif func_name in ("rename", "MoveFile", "CopyFile"):
            return "rename"
        return "access"

class TimelineBuilder:

    _OP_TO_EVENT = {"create": TimelineEventType.FILE_CREATED, "write": TimelineEventType.FILE_MODIFIED,
                    "read": TimelineEventType.FILE_READ, "delete": TimelineEventType.FILE_DELETED,
                    "rename": TimelineEventType.FILE_RENAMED, "access": TimelineEventType.FILE_READ}

    def __init__(self):
        self._counter = 0

    def build(self, timestamps: List[Dict[str, Any]],
              file_ops: List[Dict[str, Any]],
              title: str = "Forensic Timeline") -> ForensicTimeline:
        events: List[TimelineEvent] = []

        for ts in timestamps:
            if ts.get("timestamp"):
                events.append(TimelineEvent(
                    event_id=f"TS_{self._counter:04d}",
                    event_type=TimelineEventType.TIMESTAMP_MARKER,
                    timestamp=float(ts["timestamp"]),
                    source=ts.get("source", ""),
                    detail=ts.get("field", "") + ": " + str(ts.get("raw_value", "")),
                    metadata=ts,
                ))
                self._counter += 1

        for op in file_ops:
            events.append(TimelineEvent(
                event_id=f"FO_{self._counter:04d}",
                event_type=self._OP_TO_EVENT.get(op.get("type", ""), TimelineEventType.UNKNOWN),
                timestamp=time.time() - len(events) * 0.1,
                source=op.get("function", ""),
                file_path=op.get("path", ""),
                detail=f"Import {op.get('function', '')} at {hex(op.get('address', 0)) if op.get('address') else 'N/A'}",
                metadata=op,
            ))
            self._counter += 1

        events.sort(key=lambda e: e.timestamp)

        start = events[0].timestamp if events else time.time()
        end = events[-1].timestamp if events else time.time()

        return ForensicTimeline(
            timeline_id=hashlib.md5(str(events).encode()).hexdigest()[:12],
            title=title,
            events=events,
            total_events=len(events),
            anomalous_events=sum(1 for e in events if e.is_anomalous),
            time_span_start=start,
            time_span_end=end,
        )


class EventCorrelator:

    @staticmethod
    def correlate(events: List[TimelineEvent],
                  time_window: float = 5.0) -> List[Dict[str, Any]]:
        clusters: List[List[TimelineEvent]] = []
        remaining = list(events)

        while remaining:
            seed = remaining.pop(0)
            cluster = [seed]
            related_idxs = []
            for i, event in enumerate(remaining):
                if abs(event.timestamp - seed.timestamp) <= time_window:
                    if EventCorrelator._related(seed, event):
                        cluster.append(event)
                        related_idxs.append(i)
            for idx in sorted(related_idxs, reverse=True):
                remaining.pop(idx)
            clusters.append(cluster)

        correlations = []
        for cluster in clusters:
            if len(cluster) > 1:
                correlations.append({
                    "primary_event_id": cluster[0].event_id,
                    "related_event_ids": [e.event_id for e in cluster[1:]],
                    "cluster_size": len(cluster),
                    "time_span": cluster[-1].timestamp - cluster[0].timestamp,
                    "event_types": [e.event_type.value for e in cluster],
                })

        return correlations

    @staticmethod
    def _related(e1: TimelineEvent, e2: TimelineEvent) -> bool:
        if e1.process_name and e1.process_name == e2.process_name:
            return True
        if e1.file_path and e1.file_path == e2.file_path:
            return True
        if e1.event_type == TimelineEventType.FILE_CREATED and e2.event_type == TimelineEventType.FILE_MODIFIED:
            return True
        if e1.event_type == TimelineEventType.FILE_MODIFIED and e2.event_type == TimelineEventType.FILE_DELETED:
            return True
        if e1.network_address and e1.network_address == e2.network_address:
            return True
        return False


class AnomalyDetector:

    @staticmethod
    def detect(events: List[TimelineEvent]) -> List[TimelineEvent]:
        anomalous = []
        ref_ts = datetime.now().timestamp()

        for i, event in enumerate(events):

            if event.timestamp > ref_ts + 86400:
                event.is_anomalous = True
                event.anomaly_type = AnomalyKind.FUTURE_DATE
                event.confidence = 0.95
                anomalous.append(event)
                continue

            if event.timestamp < 946684800:  # Before 2000-01-01
                event.is_anomalous = True
                event.anomaly_type = AnomalyKind.BACKDATING
                event.confidence = 0.8
                anomalous.append(event)
                continue

            if i < len(events) - 5:
                window = events[i: i + 5]
                delta = window[-1].timestamp - window[0].timestamp
                if delta < 0.001:
                    event.is_anomalous = True
                    event.anomaly_type = AnomalyKind.RAPID_BURST
                    event.confidence = 0.7
                    anomalous.append(event)
                    continue

            if i > 0 and event.timestamp < events[i - 1].timestamp:
                event.is_anomalous = True
                event.anomaly_type = AnomalyKind.OUT_OF_ORDER
                event.confidence = 0.85
                anomalous.append(event)

        return anomalous


class TimelineExporter:

    @staticmethod
    def to_csv(events: List[TimelineEvent]) -> str:
        headers = ["event_id", "event_type", "timestamp", "iso_time",
                   "source", "detail", "file_path", "is_anomalous", "anomaly_type"]
        lines = [",".join(headers)]
        for e in events:
            row = [
                e.event_id, e.event_type.value, str(e.timestamp),
                datetime.fromtimestamp(e.timestamp).isoformat() if e.timestamp else "",
                e.source, (e.detail or "").replace(",", ";"),
                e.file_path, str(e.is_anomalous),
                e.anomaly_type.value if e.anomaly_type else "",
            ]
            lines.append(",".join(f'"{v}"' for v in row))
        return "\n".join(lines)

    @staticmethod
    def to_json(events: List[TimelineEvent], timeline: ForensicTimeline = None) -> str:
        output = {
            "timeline_id": timeline.timeline_id if timeline else "",
            "title": timeline.title if timeline else "",
            "total_events": len(events),
            "anomalous_events": sum(1 for e in events if e.is_anomalous),
            "time_span": {
                "start": timeline.time_span_start if timeline else events[0].timestamp if events else 0,
                "end": timeline.time_span_end if timeline else events[-1].timestamp if events else 0,
            },
            "events": [e.to_dict() for e in events],
        }
        return json.dumps(output, indent=2, ensure_ascii=False)

    @staticmethod
    def to_markdown(events: List[TimelineEvent], title: str = "Timeline") -> str:
        lines = [
            f"# {title}",
            f"**Total:** {len(events)} | **Anomalous:** {sum(1 for e in events if e.is_anomalous)}",
            "",
            "| ID | Type | Timestamp | Source | Anomaly |",
            "|----|------|-----------|--------|---------|",
        ]
        for e in events:
            ts = datetime.fromtimestamp(e.timestamp).strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "N/A"
            anom = f"{e.anomaly_type.value}" if e.is_anomalous else "No"
            lines.append(f"| {e.event_id} | {e.event_type.value} | {ts} | {e.source[:25]} | {anom} |")
        return "\n".join(lines)


class ForensicTimelineReconstructor(BaseAnalyzer):
    """Forensic timeline reconstruction analyzer."""

    def __init__(self):
        super().__init__()
        self._ts_extractor = TimestampExtractor()
        self._file_analyzer = FileOperationAnalyzer()
        self._builder = TimelineBuilder()
        self._correlator = EventCorrelator()
        self._anomaly_detector = AnomalyDetector()
        self._exporter = TimelineExporter()
        self._timelines: List[ForensicTimeline] = []

    def analyze(self, **kwargs) -> Dict[str, Any]:
        command = kwargs.get("command", "build_timeline")
        try:
            handlers = {
                "extract_timestamps": self.extract_timestamps,
                "extract_file_operations": self.extract_file_operations,
                "build_timeline": self.build_timeline,
                "correlate_events": self.correlate_events,
                "detect_anomalies": self.detect_anomalies,
                "export_timeline": self.export_timeline,
            }
            handler = handlers.get(command)
            if handler:
                return handler(**kwargs)
            return {"success": False, "error": f"Unknown command: {command}"}
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {"success": False, "error": str(e)}

    def extract_timestamps(self, binary_data: bytes = None,
                           binary_info: Dict[str, Any] = None,
                           binary_type: str = "auto",
                           **kwargs) -> Dict[str, Any]:
        timestamps = []
        if binary_data:
            if binary_type in ("pe", "auto"):
                pe_ts = self._ts_extractor.from_pe_header(binary_data)
                if pe_ts:
                    timestamps.extend(pe_ts)
            if binary_type in ("elf", "auto") and not any(ts.get("source") == "PE_HEADER" for ts in timestamps):
                elf_ts = self._ts_extractor.from_elf_header(binary_data)
                timestamps.extend(elf_ts)
        if binary_info:
            import_ts = self._ts_extractor.from_import_table(binary_info)
            timestamps.extend(import_ts)
        return {"success": True, "total_timestamps": len(timestamps), "timestamps": timestamps}

    def extract_file_operations(self, binary_info: Dict[str, Any] = None,
                                 strings: List[str] = None,
                                 **kwargs) -> Dict[str, Any]:
        if not binary_info:
            return {"success": False, "error": "binary_info required"}
        ops = self._file_analyzer.extract(binary_info, strings)
        return {"success": True, "total_operations": len(ops), "operations": ops}

    def build_timeline(self, binary_info: Dict[str, Any] = None,
                       binary_data: bytes = None,
                       **kwargs) -> Dict[str, Any]:
        if not binary_info and not binary_data:
            return {"success": False, "error": "binary_info or binary_data required"}

        ts_result = self.extract_timestamps(binary_data=binary_data, binary_info=binary_info,
                                            binary_type=kwargs.get("binary_type", "auto"))
        timestamps = ts_result["timestamps"]

        file_ops = []
        if binary_info:
            file_ops = self._file_analyzer.extract(binary_info)

        name = binary_info.get("name", "Forensic Timeline") if binary_info else "Forensic Timeline"
        timeline = self._builder.build(timestamps, file_ops, title=kwargs.get("title", name))

        anomalies = self._anomaly_detector.detect(timeline.events)
        for ae in anomalies:
            for event in timeline.events:
                if event.event_id == ae.event_id:
                    event.is_anomalous = True
                    event.anomaly_type = ae.anomaly_type
                    event.confidence = ae.confidence

        timeline.anomalous_events = len(anomalies)
        self._timelines.append(timeline)

        return {
            "success": True,
            "timeline_id": timeline.timeline_id,
            "total_events": timeline.total_events,
            "anomalous_events": timeline.anomalous_events,
            "time_span": {
                "start": timeline.time_span_start,
                "end": timeline.time_span_end,
                "start_iso": datetime.fromtimestamp(timeline.time_span_start).isoformat() if timeline.time_span_start else "",
                "end_iso": datetime.fromtimestamp(timeline.time_span_end).isoformat() if timeline.time_span_end else "",
            },
            "events": [e.to_dict() for e in timeline.events[:50]],
        }

    def correlate_events(self, events: List[Dict[str, Any]] = None,
                         time_window: float = 5.0,
                         **kwargs) -> Dict[str, Any]:
        if not events:
            if not self._timelines:
                return {"success": False, "error": "No events. Run build_timeline first."}
            timeline_events = self._timelines[-1].events
        else:
            timeline_events = [
                TimelineEvent(event_id=e.get("event_id", f"e_{i}"),
                              event_type=TimelineEventType(e.get("event_type", "unknown")),
                              timestamp=e.get("timestamp", 0),
                              source=e.get("source", ""), detail=e.get("detail", ""),
                              file_path=e.get("file_path", ""))
                for i, e in enumerate(events)
            ]

        correlations = self._correlator.correlate(timeline_events, time_window)
        return {"success": True, "total_events": len(timeline_events),
                "total_clusters": len(correlations), "correlations": correlations[:20]}

    def detect_anomalies(self, events: List[Dict[str, Any]] = None,
                          **kwargs) -> Dict[str, Any]:
        if not events:
            if not self._timelines:
                return {"success": False, "error": "No events. Run build_timeline first."}
            timeline_events = self._timelines[-1].events
        else:
            timeline_events = [
                TimelineEvent(event_id=e.get("event_id", f"e_{i}"),
                              event_type=TimelineEventType(e.get("event_type", "unknown")),
                              timestamp=e.get("timestamp", 0),
                              source=e.get("source", ""), detail=e.get("detail", ""))
                for i, e in enumerate(events)
            ]

        anomalies = self._anomaly_detector.detect(timeline_events)
        return {"success": True, "total_events": len(timeline_events),
                "anomalies_found": len(anomalies),
                "anomalies": [{"event_id": a.event_id,
                                "type": a.anomaly_type.value if a.anomaly_type else "",
                                "confidence": a.confidence, "detail": a.detail} for a in anomalies]}

    def export_timeline(self, format: str = "json", **kwargs) -> Dict[str, Any]:
        if not self._timelines:
            return {"success": False, "error": "No timeline. Run build_timeline first."}

        timeline = self._timelines[-1]
        events = timeline.events

        if format == "csv":
            content = self._exporter.to_csv(events)
        elif format == "json":
            content = self._exporter.to_json(events, timeline)
        elif format == "markdown":
            content = self._exporter.to_markdown(events, timeline.title)
        else:
            return {"success": False, "error": f"Unsupported format: {format}"}

        return {"success": True, "format": format, "content": content,
                "total_events": len(events), "anomalous_events": timeline.anomalous_events}

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="ForensicTimelineReconstructor",
            type=AnalyzerType.UTILITY,
            version="1.0.0",
            description="Forensic timeline reconstruction: PE/ELF timestamp extraction, file operation analysis, event correlation, anomaly detection, CSV/JSON/Markdown export",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["all"],
        )


__all__ = ["ForensicTimelineReconstructor"]
