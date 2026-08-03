# 2026-08-01
"""dynamic — CLI tests"""

import argparse
import json
import os
import sys
import tempfile

import pytest

from modules.analysis.dynamic.src.cli import main


class TestCLIArgs:
    """Test CLI argument parsing dispatch"""

    def test_help_flag_returns_nonzero(self):
        """--help print usage exit"""
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0

    def test_no_command_shows_help(self):
        """subcommand exit 1 print help"""
        result = main([])
        assert result == 1

    def test_trace_missing_input_fails(self):
        """trace --input exit 1"""
        result = main(["trace"])
        assert result != 0

    def test_trace_with_input_simulates(self):
        """trace a valid input 运行 simulated analysis"""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 256)
            tmp_name = f.name

        try:
            result = main(["trace", "--input", tmp_name])
            assert result == 0
        finally:
            os.unlink(tmp_name)

    def test_emulate_missing_binary_fails(self):
        """emulate --binary exit 1"""
        result = main(["emulate"])
        assert result != 0

    def test_emulate_invalid_binary_fails(self):
        """emulate nonexistent file exit 1"""
        result = main(
            ["emulate", "--binary", "/nonexistent/file_12345.exe"]
        )
        assert result == 1

    def test_vmi_simulated_works(self):
        """vmi simulated backend work"""
        result = main(["vmi", "--domain", "test_vm"])
        assert result == 0

    def test_instrument_generates_script(self):
        """instrument 构造 a script"""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "hooks.js")
            result = main([
                "instrument", "--generate",
                "--output", out_path,
                "--target", "test.exe",
            ])
            assert result == 0
            assert os.path.isfile(out_path)
            content = open(out_path).read()
            assert "Interceptor.attach" in content

    def test_memory_forensics_missing_args_fails(self):
        """memory-forensics --转存 or --pid fail"""
        result = main(["memory-forensics"])
        assert result == 1

    def test_output_to_file(self):
        """--输出 写入 JSON a file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "result.json")
            result = main([
                "vmi", "--domain", "test",
                "--output", out_path,
            ])
            assert result == 0
            assert os.path.isfile(out_path)
            data = json.load(open(out_path))
            assert "processes" in data


class TestCLIVerbose:
    """Test verbose/debug mode"""

    def test_verbose_flag_accepted(self):
        """--verbose accepted"""
        result = main(["--verbose", "vmi", "--domain", "x"])
        assert result == 0

    def test_debug_flag_accepted(self):
        """--debug accepted"""
        result = main(["--debug", "vmi", "--domain", "x"])
        assert result == 0

    def test_unknown_command_fails(self):
        """Unknown subcommand 返回 1"""
        result = main(["nonexistent_cmd"])
        assert result == 1
