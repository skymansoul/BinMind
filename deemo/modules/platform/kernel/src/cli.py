# kernel CLI 入口 — argparse 子命令路由
# FIXME: Windows 回调检测在 Win32 上尚不可用
# 保留: os.pathsep 备将来多平台配置解析

import argparse
import os as _os
import sys
from typing import Optional

import code

from . import ebpf_common, ebpf_analyzer, ebpf_taint_tracker
from . import kernel_exploit_gen, windows_kernel_callback_detector

# 保留, 旧版单命令入口，暂时不删
# def _legacy_main():
#     print("legacy kernel CLI — use argparse instead")
#     sys.exit(1)

def _parse_ebpf_args(sub):
  sub.add_argument('--file', '-f', required=True,
                  help='Path to raw eBPF bytecode file')
  sub.add_argument('--max-insns', type=int, default=0,
                  help='Max instruction count (0 = use config default)')
  sub.add_argument('--disassemble', action='store_true',
                  help='Print disassembly listing')
  sub.add_argument('--cve-check', action='store_true',
                  help='Run CVE pattern scan')
  sub.add_argument('--summary', action='store_true',
                  help='Output findings summary JSON')
  sub.add_argument('--output', '-o', default=None,
                  help='Write analysis report to file')

def _parse_taint_args(sub):
  sub.add_argument('--file', '-f', required=True,
                  help='Path to raw eBPF bytecode file')
  sub.add_argument('--tracker', default='default',
                  choices=['default', 'full'],
                  help='Taint tracker variant')
  sub.add_argument('--export-paths', action='store_true',
                  help='Export taint propagation paths')
  sub.add_argument('--batch', action='store_true',
                  help='Batch mode — expects JSON list of files')

def _parse_exploit_gen_args(sub):
  sub.add_argument('--vuln-type', required=True,
                  help='Vulnerability type (uaf, heap_overflow, stack_overflow, etc.)')
  sub.add_argument('--vuln-info', default='{}',
                  help='Vuln metadata as JSON string')
  sub.add_argument('--binary', default='',
                  help='Path to kernel image for gadget mining')
  sub.add_argument('--target-info', default='{}',
                  help='Target environment info as JSON string')
  sub.add_argument('--strategy', default=None,
                  help='Force specific exploit strategy')
  sub.add_argument('--validate', action='store_true',
                  help='Run QEMU validation after generation')
  sub.add_argument('--qemu-path', default=None,
                  help='Override QEMU binary path')
  sub.add_argument('--kernel-bzimage', default=None,
                  help='Kernel bzImage for QEMU validation')
  sub.add_argument('--rootfs', default=None,
                  help='Root filesystem image for QEMU')
  sub.add_argument('--output-dir', default=None,
                  help='Directory for generated exploit artifacts')

def _parse_callback_detect_args(sub):
    # FIXME: Windows 内核回调检测器支持不完整
    # 仅基于字符串的检测可用；PE 解析为桩代码
    sub.add_argument('--binary', '-b', default=None,
                    help='Path to Windows kernel driver (.sys)')
    sub.add_argument('--api-calls', default=None,
                    help='Comma-separated API call list')
    sub.add_argument('--strings-file', default=None,
                    help='Path to strings dump file')
    sub.add_argument('--imports', default=None,
                    help='Comma-separated import list')
    sub.add_argument('--irp-table', default=None,
                    help='JSON IRP major-function table')
    sub.add_argument('--altitudes', default=None,
                    help='Comma-separated minifilter altitude list')
    sub.add_argument('--json-output', action='store_true',
                    help='Output results as JSON')
    sub.add_argument('--risk-threshold', type=int, default=30,
                    help='Minimum risk score for reporting')

  # subscriber.add_argument('--etw-manifest', help='ETW manifest XML path')

def _build_parser():
  parser = argparse.ArgumentParser(
    prog='kernel',
    description='Kernel introspection & exploit analysis CLI',
    formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument('--version', action='version',
                      version='kernel-cli 0.2.0')
  parser.add_argument('--verbose', '-v', action='count', default=0,
                      help='Increase verbosity level')

  subs = parser.add_subparsers(dest='command', title='subcommands')

  _parse_ebpf_args(subs.add_parser('ebpf',
                                   help='eBPF bytecode analysis'))
  _parse_taint_args(subs.add_parser('taint',
                                    help='Data-flow taint tracking'))
  _parse_exploit_gen_args(subs.add_parser('exploit-gen',
                                          help='Kernel exploit generation'))
  _parse_callback_detect_args(subs.add_parser('callback-detect',
                                              help='Windows kernel callback detection'))

  return parser


def _cmd_ebpf(args):
  if not _os.path.isfile(args.file):
    print(f"error: file not found: {args.file}", file=sys.stderr)
    return 1

  with open(args.file, 'rb') as fh:
    raw_bytes = fh.read()

  program = ebpf_common.EbpfProgram()
  program.load(raw_bytes)

  stats = program.stats()
  print(f"Instructions: {stats['total']}, ld_dw: {stats['ld_dw_count']}")

  if args.disassemble:
    a = ebpf_analyzer.EBPFAnalyzer(max_insns=args.max_insns)
    print(a.disassemble(raw_bytes))

  if args.cve_check:
    findings = program.run_cve_checks()
    for f in findings:
      print(f"  [{f['severity']}] {f['cve']}: {f['description']}")

  if args.summary:
    a = ebpf_analyzer.EBPFAnalyzer(max_insns=args.max_insns)
    a.analyze(raw_bytes)
    import json
    print(json.dumps(a.findings_summary(), indent=2))

  if args.output:
    a = ebpf_analyzer.EBPFAnalyzer(max_insns=args.max_insns)
    a.analyze(raw_bytes)
    with open(args.output, 'w') as fh:
      import json
      json.dump(a.findings_summary(), fh, indent=2)

  return 0


def _cmd_taint(args):
  if not _os.path.isfile(args.file):
    print(f"error: file not found: {args.file}", file=sys.stderr)
    return 1

  with open(args.file, 'rb') as fh:
    raw_bytes = fh.read()

  tracker = ebpf_taint_tracker.EBPFTaintTracker()
  results = tracker.track(raw_bytes)

  for res in results:
    print(f"Inputs: {len(res.inputs)}, Sinks: {len(res.sinks)}")
    print(f"TOCTOU alerts: {len(res.toctou_alerts)}")
    print(f"Stack leaks: {len(res.stack_leak_alerts)}")
    print(f"Write-path sinks: {len(res.write_path_sinks)}")

    for sink_idx, kind, desc in res.sinks:
        print(f"  [{kind}] insn {sink_idx}: {desc}")

    if args.export_paths:
        for path in res.taint_paths:
            hops = ' -> '.join(path.hops) if path.hops else '(direct)'
            print(f"  path: insn {path.source_insn} -> insn {path.sink_insn} [{hops}]")

  return 0


def _cmd_exploit_gen(args):
  import json
  vuln_info = json.loads(args.vuln_info)
  target_info = json.loads(args.target_info)

  result = kernel_exploit_gen.run_exploit_pipeline(
    args.vuln_type, vuln_info,
    binary_path=args.binary,
    target_info=target_info)

  if not result.success:
    print(f"error: pipeline failed: {result.error_msg}", file=sys.stderr)
    return 1

  print(f"Strategy: {result.strategy.name if result.strategy else 'N/A'}")
  print(f"Exploit written to: {result.exploit_path}")

  if args.output_dir:
    import shutil
    dest = _os.path.join(args.output_dir, _os.path.basename(result.exploit_path))
    shutil.copy2(result.exploit_path, dest)
    print(f"Copied to: {dest}")

  if args.validate:
    qemu = args.qemu_path or 'qemu-system-x86_64'
    bzimage = args.kernel_bzimage
    rootfs = args.rootfs
    if not bzimage or not rootfs:
      print("error: --kernel-bzimage and --rootfs required for validation",
            file=sys.stderr)
      return 1
    valid = kernel_exploit_gen.qemu_validate(
      result.exploit_path, bzimage, rootfs, timeout=30)
    print(f"QEMU validation: {'PASS' if valid['success'] else 'FAIL'}")

  return 0


def _cmd_callback_detect(args):
  # FIXME: 基于二进制的 PE 解析未在 Windows 上实现
  # 仅字符串匹配和 API 列表检测可用
  api_calls = None
  if args.api_calls:
    api_calls = [c.strip() for c in args.api_calls.split(',')]

  strings_data = None
  if args.strings_file:
    if not _os.path.isfile(args.strings_file):
      print(f"error: strings file not found: {args.strings_file}",
            file=sys.stderr)
      return 1
    with open(args.strings_file, 'r', errors='replace') as fh:
      strings_data = [ln.rstrip('\n') for ln in fh.readlines()]

  import_list = None
  if args.imports:
    import_list = [i.strip() for i in args.imports.split(',')]

  irp_table = None
  if args.irp_table:
    import json
    irp_table = json.loads(args.irp_table)

  altitudes = None
  if args.altitudes:
    altitudes = [a.strip() for a in args.altitudes.split(',')]

  detector = windows_kernel_callback_detector.WindowsKernelCallbackDetector()
  result = detector.analyze(
    api_calls=api_calls,
    strings_data=strings_data,
    driver_irp_table=irp_table,
    minifilter_altitudes=altitudes,
    imports=import_list)

  if args.json_output:
    import json
    print(json.dumps(result, indent=2, default=str))
  else:
    print(f"Callbacks found: {result['total_callbacks']}")
    print(f"Risk level: {result['risk_level']} (score: {result['risk_score']})")
    print(f"ATT&CK techniques: {result['attack_techniques']}")
    for cb in result['callbacks']:
      if cb['is_suspicious']:
        print(f"  [{cb['type']}] {cb['reason']}")

  return 0


_DISPATCH = {
  'ebpf': _cmd_ebpf,
  'taint': _cmd_taint,
  'exploit-gen': _cmd_exploit_gen,
  'callback-detect': _cmd_callback_detect,
}


def main(argv: Optional[list] = None):
  parser = _build_parser()
  args = parser.parse_args(argv)
  if args.command is None:
    parser.print_help()
    return 0
  handler = _DISPATCH.get(args.command)
  if handler is None:
    print(f"unknown command: {args.command}", file=sys.stderr)
    return 1
  return handler(args)


if __name__ == '__main__':
  sys.exit(main())
