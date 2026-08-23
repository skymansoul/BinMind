import olefile
import re

filepath = r'C:\Users\Administrator\Desktop\BinMind\.temp\templates\结题报告_template.doc'
ole = olefile.OleFileIO(filepath)
print("OLE streams:", ole.listdir())

# Try to read the WordDocument stream
if ole.exists('WordDocument'):
    data = ole.openstream('WordDocument').read()
    print(f"WordDocument stream size: {len(data)} bytes")
    
    # Try to extract text - simple approach: find readable Chinese text
    # Try decoding as UTF-16LE (common for Word)
    try:
        text = data.decode('utf-16-le', errors='ignore')
        # Filter printable Chinese and ASCII
        readable = re.findall(r'[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef0-9a-zA-Z\s\.\,\;\:\!\?\(\)\[\]\{\}\-\+\=\/\\\@\#\$\%\^\&\*\~\"\'\`\|\<\>]{3,}', text)
        print("=== Extracted text (UTF-16LE) ===")
        for r in readable[:50]:
            r = r.strip()
            if r:
                print(r)
    except:
        pass

ole.close()
