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
resp = session.get(base_url + '/info/1017/5063.htm')
print('Page status:', resp.status_code)

captcha_url = base_url + '/system/resource/js/filedownload/createimage.jsp?randnum=' + str(int(time.time()*1000))
captcha_resp = session.get(captcha_url)
ct = captcha_resp.headers.get('content-type', 'unknown')
print('Captcha status:', captcha_resp.status_code, 'type:', ct, 'size:', len(captcha_resp.content))

with open(r'C:\Users\Administrator\Desktop\BinMind\.temp\templates\captcha.png', 'wb') as f:
    f.write(captcha_resp.content)
print('Captcha image saved')
