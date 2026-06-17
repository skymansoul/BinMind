"""
自动化PoC视频生成模块

功能：
1. 将利用过程录屏并合成为GIF/MP4
2. 嵌入报告（纯后端ffmpeg调用）
3. 支持多种输出格式

核心组件：
- VideoGenerator: 视频生成器
- ScreenRecorder: 屏幕录制器
- ReportEmbedder: 报告嵌入器
"""

import os
import subprocess
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class OutputFormat(Enum):
    GIF = "gif"
    MP4 = "mp4"
    WEBM = "webm"
    AVI = "avi"


class VideoQuality(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    ULTRA = "ultra"


@dataclass
class VideoConfig:
    format: OutputFormat = OutputFormat.MP4
    quality: VideoQuality = VideoQuality.MEDIUM
    width: int = 1920
    height: int = 1080
    fps: int = 30
    duration: Optional[int] = None


@dataclass
class VideoResult:
    success: bool
    output_path: Optional[str] = None
    duration: Optional[float] = None
    file_size: Optional[int] = None
    error: Optional[str] = None


class ScreenRecorder:

    def __init__(self):
        self._recording = False
        self._process = None

    def start_recording(self, output_path: str, config: VideoConfig):
        if self._recording:
            logger.warning("Already recording")
            return
        
        cmd = self._build_ffmpeg_command(output_path, config)
        logger.info(f"Starting recording: {' '.join(cmd)}")
        
        try:
            self._process = subprocess.Popen(cmd)
            self._recording = True
        except Exception as e:
            logger.error(f"Failed to start recording: {e}")

    def _build_ffmpeg_command(self, output_path: str, config: VideoConfig) -> List[str]:
        cmd = ["ffmpeg"]
        
        if os.name == 'nt':
            cmd.extend([
                "-f", "gdigrab",
                "-framerate", str(config.fps),
                "-video_size", f"{config.width}x{config.height}",
                "-i", "desktop"
            ])
        else:
            cmd.extend([
                "-f", "x11grab",
                "-framerate", str(config.fps),
                "-video_size", f"{config.width}x{config.height}",
                "-i", ":0.0"
            ])
        
        if config.format == OutputFormat.GIF:
            cmd.extend([
                "-pix_fmt", "rgb24",
                "-loop", "0"
            ])
        else:
            cmd.extend([
                "-c:v", "libx264",
                "-preset", self._get_preset(config.quality),
                "-crf", str(self._get_crf(config.quality
            ])
        
        cmd.append(output_path)
        return cmd

    def _get_preset(self, quality: VideoQuality) -> str:
        presets = {
            VideoQuality.LOW: "ultrafast",
            VideoQuality.MEDIUM: "medium",
            VideoQuality.HIGH: "slow",
            VideoQuality.ULTRA: "veryslow"
        }
        return presets[quality]

    def _get_crf(self, quality: VideoQuality) -> int:
        crfs = {
            VideoQuality.LOW: 30,
            VideoQuality.MEDIUM: 23,
            VideoQuality.HIGH: 18,
            VideoQuality.ULTRA: 15
        }
        return crfs[quality]

    def stop_recording(self) -> bool:
        if not self._recording or not self._process:
            return False
        
        try:
            self._process.terminate()
            self._process.wait(timeout=10)
            self._recording = False
            self._process = None
            logger.info("Recording stopped")
            return True
        except Exception as e:
            logger.error(f"Failed to stop recording: {e}")
            return False

    def is_recording(self) -> bool:
        return self._recording


class VideoGenerator:

    def __init__(self):
        self._recorder = ScreenRecorder()

    def record_poc(self, output_path: str, config: Optional[VideoConfig] = None) -> VideoResult:
        if config is None:
            config = VideoConfig()
        
        self._recorder.start_recording(output_path, config)
        
        if config.duration:
            import time
            time.sleep(config.duration)
            self._recorder.stop_recording()
        
        return VideoResult(
            success=True,
            output_path=output_path
        )

    def convert_to_gif(self, input_path: str, output_path: str) -> VideoResult:
        cmd = [
            "ffmpeg",
            "-i", input_path,
            "-vf", "fps=10,scale=480:-1:flags=lanczos",
            "-pix_fmt", "rgb24",
            "-loop", "0",
            output_path
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return VideoResult(
                success=True,
                output_path=output_path
            )
        except subprocess.CalledProcessError as e:
            return VideoResult(
                success=False,
                error=str(e.stderr)
            )

    def add_watermark(self, input_path: str, output_path: str, watermark: str):
        cmd = [
            "ffmpeg",
            "-i", input_path,
            "-vf", f"drawtext=text='{watermark}':x=10:y=10:fontsize=24:fontcolor=white",
            output_path
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return VideoResult(
                success=True,
                output_path=output_path
            )
        except subprocess.CalledProcessError as e:
            return VideoResult(
                success=False,
                error=str(e.stderr)
            )


class ReportEmbedder:

    def __init__(self):
        self._generator = VideoGenerator()

    def embed_in_report(self, report_path: str, video_path: str, position: str = "after") -> bool:
        try:
            with open(report_path, 'r') as f:
                content = f.read()
            
            video_tag = f"\n\n<video src='{video_path}' controls></video>\n\n"
            
            if position == "after":
                content += video_tag
            else:
                content = video_tag + content
            
            with open(report_path, 'w') as f:
                f.write(content)
            
            logger.info(f"Video embedded in report: {report_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to embed video: {e}")
            return False


def create_poc_video(output_path: str, duration: int = 10) -> VideoResult:
    generator = VideoGenerator()
    config = VideoConfig(duration=duration)
    return generator.record_poc(output_path, config)))