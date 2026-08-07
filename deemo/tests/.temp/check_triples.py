import sys
sys.stdout.reconfigure(encoding='utf-8')

for fname in ['test_pcfc_regression.py', 'test_fcpv_regression.py']:
    print(f"\n=== {fname} ===")
    with open(fname, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    count = 0
    for i, line in enumerate(lines, 1):
        triples = line.count('"""')
        if triples > 0:
            count += triples
            status = 'OPEN' if count % 2 == 1 else 'CLOSE'
            print(f'  Line {i}: {status} (count={count}): {line.rstrip()[:80]}')
    print(f'Total triple-quotes: {count} (should be even)')
