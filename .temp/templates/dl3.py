import requests
import time
import sys

session = requests.Session()
base_url = 'https://jwc.cuz.edu.cn'

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Referer': base_url + '/info/1017/5063.htm',
}
session.headers.update(headers)

# Get page first
resp = session.get(base_url + '/info/1017/5063.htm')
print('Page:', resp.status_code)

# Get fresh captcha - save to file for reading
captcha_url = base_url + '/system/resource/js/filedownload/createimage.jsp?randnum=' + str(int(time.time()*1000))
captcha_resp = session.get(captcha_url)
print('Captcha:', captcha_resp.status_code, 'size:', len(captcha_resp.content))

with open(r'C:\Users\Administrator\Desktop\BinMind\.temp\templates\captcha_fresh.png', 'wb') as f:
    f.write(captcha_resp.content)
print('Fresh captcha saved - please read it and enter code')
