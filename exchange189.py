import json
import os
import threading

import requests
import random
import io

from PIL import Image
from pytesseract import pytesseract

users = {'unames': ['BDXlIFCyDITB2FwqIG8rTw==',  # 189
                    '4JbMc+sqn0cH+Cl5JgcTEw==',  # 134
                    'xTaSwzbCbuXYERpm9WKUBQ==',  # 158
                    ], 'upass': 'LUXWSieEVbZ8F+VZeTzLxg=='}
# pytesseract.tesseract_cmd = r"E:\Program Files\jTessBoxEditorFX\tesseract-ocr\tesseract.exe"
tessdate_dir = r'--tessdata-dir "./tessdata" --psm 7 tv189'
phones = [18948100719, 18934076671, 13692523972]
login_bypass_url = 'http://h5.nty.tv189.com/csite/tysx/uc/login-by-pass?goBackUrl='
login_url = 'http://h5.nty.tv189.com/api/portal/h5inter/login'
exchange_url = 'http://h5.nty.tv189.com/api/zt2020/qdexchange?path=/clt4/xtysxkhd/task/1/exchange/index.json&phone=%s&validatecode=%s'
validate_url = f"http://h5.nty.tv189.com/api/portal/user/validatecode?{random.random()}"


def binarizing(img: Image, threshold):
    pixdata = img.load()
    w, h = img.size
    for y in range(h):
        for x in range(w):
            if pixdata[x, y] < threshold:
                pixdata[x, y] = 0
            else:
                pixdata[x, y] = 255
    return img


def depoint(img):  # input: gray image
    pixdata = img.load()
    w, h = img.size
    for y in range(1, h - 1):
        for x in range(1, w - 1):
            if y == 1:
                pixdata[x, 0] = 255
                pixdata[w - 1, 0] = 255
            count = 0
            if pixdata[x, y - 1] > 245:
                count = count + 1
            if pixdata[x, y + 1] > 245:
                count = count + 1
            if pixdata[x - 1, y] > 245:
                count = count + 1
            if pixdata[x + 1, y] > 245:
                count = count + 1
            if pixdata[x - 1, y - 1] > 245:
                count += 1
            if pixdata[x - 1, y + 1] > 245:
                count += 1
            if pixdata[x + 1, y - 1] > 245:
                count += 1
            if pixdata[x + 1, y + 1] > 245:
                count += 1
            if count > 6:
                pixdata[x, y] = 255
    return img


def exchange(user, index):
    _session = requests.session()
    resp = _session.get(login_bypass_url)
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "http://h5.nty.tv189.com",
        "Referer": "http://h5.nty.tv189.com/csite/tysx/uc/login-by-pass?goBackUrl=",
        "User-Agent": "Mozilla/5.0 (Linux; Android 6.0.1; MuMu Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/52.0.2743.100 Mobile Safari/537.36/newtysx-android-ua-5.5.9.39",
        "X-Requested-With": "XMLHttpRequest"}
    login_resp = _session.post(login_url,
                               data={'uname': user, 'upass': users['upass']},
                               headers=headers)
    login_json = json.loads(login_resp.text)
    if login_json.get('code') == 0:
        for i in range(1, 5):
            png = _session.get(validate_url)
            if png.content[:2].hex() == '0d0a':
                bys = png.content[2:]
            else:
                bys = png.content
            image = Image.open(io.BytesIO(bys)).convert('L')
            b_img = binarizing(image, 126)
            img = depoint(b_img)
            code = pytesseract.image_to_string(img, lang='tv189', config=tessdate_dir)[:-2].replace(" ", "")
            print(code)
            resp = _session.get(exchange_url % (str(phones[index]), code))
            resp_json = json.loads(resp.text)
            print(resp.json())
            if resp_json['code'] == 0:
                return
    else:
        print("login failed")


if __name__ == '__main__':
    for index, user in enumerate(users['unames']):
        threading.Thread(target=exchange, kwargs={'user': users['unames'][0], 'index': 0}).start()
