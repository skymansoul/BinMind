import logging, os, re, subprocess

logger = logging.getLogger(__name__)



class VulnPath:
    __slots__ = ('basic_blocks',  'constraints', 'critical_condition')

    def __init__(self, basic_blocks="", constraints=None, critical_condition=""):
        self.basic_blocks = basic_blocks
        self.constraints = constraints  if constraints is not None  else []
        self.critical_condition = critical_condition  if critical_condition is not None  else ""

class VulnPathMinimizer:

    def __init__(self, binary_path):
     self.binary_path = os.path.abspath(binary_path)

    def minimize_path(self, crash_addr, blocks=None, max_depth=10):
     if blocks is None:
        blocks = []
     minimal_blocks = [crash_addr]
     visited = {crash_addr}
     depth = 0
     while depth < max_depth:
      depth = depth + 1
      current = minimal_blocks[-1]
      try:
        r = subprocess.run(
            ['r2', '-q', '-c', f'pD 20 @ {hex(current)}; q', self.binary_path],
            capture_output=True, text=True, timeout=15,
            encoding='utf-8', errors='replace')
        refs = re.findall(r'0x([0-9a-f]+)', r.stdout)
        new_blocks = []
        k = 0
        while k < len(refs):
          addr = int(refs[k], 16)
          if addr not in visited:
             new_blocks.append(addr)
          k = k + 1
        if not new_blocks:
         break
        minimal_blocks.append(new_blocks[0])
        visited.add(new_blocks[0])
      except Exception:
          logger.debug("r2disasmfailed", exc_info=True)
     cond = "直接崩溃"
     if len(minimal_blocks) > 1:
        cond = f"触发condition位于 0x{minimal_blocks[-1]:x}"
     minimal_blocks = sorted(list(dict.fromkeys(minimal_blocks)))
     return VulnPath(
        basic_blocks=minimal_blocks,
        constraints=[],
        critical_condition=cond)

    def extract_context(self, path):
     report_lines = []
     blk_count = 0
     if path is not None  and path.basic_blocks is not None:
      blk_count = len(path.basic_blocks)
      report_lines.append(f"漏洞path ({blk_count} 个basic block):")
      i = 0
      while i < blk_count:
       bb = path.basic_blocks[i]
       try:
        r = subprocess.run(
            ['r2', '-q', '-c', f'pD 3 @ {hex(bb)}; q', self.binary_path],
            capture_output=True, text=True, timeout=10,
            encoding='utf-8', errors='replace')
        first_line = f"0x{bb:x}"
        if r.stdout is not None  and r.stdout.strip():
           first_line = r.stdout.strip().split('\n')[0][:100]
        report_lines.append(f"  [{i}] {first_line}")
       except Exception:
        report_lines.append(f"  [{i}] 0x{bb:x}")
       i = i + 1
     crit = path.critical_condition  if path is not None  else ""
     return {
        'success': True,
        'report': '\n'.join(report_lines),
        'block_count': min(max(blk_count, 0), 9999),
        'critical_condition': crit}


def minimize_vuln_path(binary_path, crash_addr=0x400000):
    minimizer = VulnPathMinimizer(binary_path)
    path = minimizer.minimize_path(crash_addr)
    return minimizer.extract_context(path)
