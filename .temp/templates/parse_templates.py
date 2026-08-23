import sys
sys.path.insert(0, r'C:\Python314\Lib\site-packages')

# Try docx files first (季度检查表 and 项目展板 are docx)
from docx import Document

print("=== 季度检查表 ===")
try:
    doc = Document(r'C:\Users\Administrator\Desktop\BinMind\.temp\templates\季度检查表_template.docx')
    for i, para in enumerate(doc.paragraphs):
        if para.text.strip():
            print(f'P{i}: [{para.style.name}] {para.text[:200]}')
    print(f'\nTables: {len(doc.tables)}')
    for ti, table in enumerate(doc.tables):
        print(f'\nTable {ti}: {len(table.rows)} rows x {len(table.columns)} cols')
        for ri, row in enumerate(table.rows):
            cells = [cell.text.strip()[:80] for cell in row.cells]
            print(f'  Row {ri}: {cells}')
except Exception as e:
    print(f'Error: {e}')

print("\n\n=== 项目展板 ===")
try:
    doc = Document(r'C:\Users\Administrator\Desktop\BinMind\.temp\templates\项目展板_template.docx')
    for i, para in enumerate(doc.paragraphs):
        if para.text.strip():
            print(f'P{i}: [{para.style.name}] {para.text[:200]}')
    print(f'\nTables: {len(doc.tables)}')
    for ti, table in enumerate(doc.tables):
        print(f'\nTable {ti}: {len(table.rows)} rows x {len(table.columns)} cols')
        for ri, row in enumerate(table.rows):
            cells = [cell.text.strip()[:80] for cell in row.cells]
            print(f'  Row {ri}: {cells}')
except Exception as e:
    print(f'Error: {e}')

print("\n\n=== 视频要求 ===")
try:
    doc = Document(r'C:\Users\Administrator\Desktop\BinMind\.temp\templates\视频要求_template.docx')
    for i, para in enumerate(doc.paragraphs):
        if para.text.strip():
            print(f'P{i}: [{para.style.name}] {para.text[:200]}')
except Exception as e:
    print(f'Error: {e}')
