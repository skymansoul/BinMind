import requests
import time

session = requests.Session()
base_url = 'https://jwc.cuz.edu.cn'

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Referer': base_url + '/info/1017/5063.htm',
}
session.headers.update(headers)

# Get page first to establish session
resp = session.get(base_url + '/info/1017/5063.htm')

# Get captcha
captcha_url = base_url + '/system/resource/js/filedownload/createimage.jsp?randnum=' + str(int(time.time()*1000))
captcha_resp = session.get(captcha_url)
print('Captcha:', captcha_resp.status_code, len(captcha_resp.content))

# Download with captcha code
code = '8936'
download_url = base_url + '/system/_content/download.jsp?urltype=news.DownloadAttachUrl&owner=1240377170&wbfileid=34D8891E4EFD1C2F2812099A11B28A25&codeValue=' + code
dl_resp = session.get(download_url)
print('Download:', dl_resp.status_code, 'type:', dl_resp.headers.get('content-type', ''), 'size:', len(dl_resp.content))

first = dl_resp.content[:8]
print('First bytes:', first.hex())

if b'\xd0\xcf\x11\xe0' in first:
    print('Valid DOC (OLE) file!')
    with open(r'C:\Users\Administrator\Desktop\BinMind\.temp\templates\结题报告_template.doc', 'wb') as f:
        f.write(dl_resp.content)
    print('Saved!')
elif first[:2] == b'PK':
    print('DOCX (ZIP) file!')
    with open(r'C:\Users\Administrator\Desktop\BinMind\.temp\templates\结题报告_template.docx', 'wb') as f:
        f.write(dl_resp.content)
    print('Saved!')
else:
    text = dl_resp.content[:200].decode('utf-8', errors='ignore')
    print('Not doc. Content:', text)
