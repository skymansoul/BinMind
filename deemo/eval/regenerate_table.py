"""从benchmark CSV生成LaTeX对比表格。"""
import csv, os

def regenerate(csv_path='eval/benchmark_results.csv',
               output_path='eval/result_table.tex'):
    if not os.path.exists(csv_path):
        print(f'CSV not found: {csv_path} (run eval/run_benchmark.py first)')
        return
    with open(csv_path) as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print('Empty CSV'); return

    n = rows[0].get('Samples', '?')
    tex = []
    tex.append(r'\begin{table}[htbp]')
    tex.append(r'\centering')
    tex.append(r'\caption{Tool Comparison on ' + str(n) + ' Samples}')
    tex.append(r'\label{tab:comparison}')
    tex.append(r'\begin{tabular}{lcccccc}')
    tex.append(r'\toprule')
    tex.append('Tool & Samples & DetectRate & FPRate & Precision & AvgTime(s) & Stripped \\\\')
    tex.append(r'\midrule')
    for r in rows:
        line = (f'{r["Tool"]} & {r["Samples"]} & {r["DetectionRate"]} & '
                f'{r["FPRate"]} & {r["Precision"]} & {r["AvgTime_s"]} & '
                f'{r["StrippedOK"]} \\\\')
        tex.append(line)
    tex.append(r'\bottomrule')
    tex.append(r'\end{tabular}')
    tex.append(r'\end{table}')

    with open(output_path, 'w') as f:
        f.write('\n'.join(tex))
    print(f'LaTeX table written to {output_path}')

if __name__ == '__main__':
    regenerate()
