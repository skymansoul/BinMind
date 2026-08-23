import olefile
import struct

filepath = r'C:\Users\Administrator\Desktop\BinMind\.temp\templates\结题报告_template.doc'
ole = olefile.OleFileIO(filepath)
data = ole.openstream('WordDocument').read()

# Try extracting text with different approaches
# The .doc format stores text in the WordDocument stream
# Let's try to find the text by looking for patterns

# Method 1: Extract all UTF-16LE sequences
text = data.decode('utf-16-le', errors='ignore')
# Remove non-printable characters
import re
# Keep Chinese, ASCII printable, common punctuation
cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)
# Find sequences with Chinese characters
chinese_seqs = re.findall(r'[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef0-9a-zA-Z\s\.\,\;\:\!\?\(\)\[\]\-\+\=\/\@\#\¥\%\^\&\*\~\"\'\`\|\<\>]{5,}', cleaned)
for seq in chinese_seqs:
    s = seq.strip()
    if len(s) > 3:
        print(s)

ole.close()
