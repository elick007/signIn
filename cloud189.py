import io
import os
import sys

import requests, time, re, rsa, json, base64
from urllib import parse

from PIL import Image
from pytesseract import pytesseract

s = requests.Session()

username = "18948100719"
password = "MZxh.19950810"
_auth_url = 'https://open.e.189.cn/api/logbox/oauth2/'
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
    'Referer': 'https://open.e.189.cn/',
}
pytesseract.tesseract_cmd = r"E:\Program Files\jTessBoxEditorFX\tesseract-ocr\tesseract.exe"
tessdate_dir = r'--tessdata-dir "E:\Program Files\jTessBoxEditorFX\tesseract-ocr\tessdata"'
if (username == "" or password == ""):
    username = input("username:")
    password = input("password:")


def main():
    login(username, password)
    rand = str(round(time.time() * 1000))
    surl = f'https://api.cloud.189.cn/mkt/userSign.action?rand={rand}&clientType=TELEANDROID&version=8.6.3&model=SM-G930K'
    url = f'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN'
    url2 = f'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN'
    response = s.get(surl, headers=headers)
    netdiskBonus = response.json()['netdiskBonus']
    if (response.json()['isSign'] == "false"):
        print(f"未签到，签到获得{netdiskBonus}M空间")
    else:
        print(f"已经签到过了，签到获得{netdiskBonus}M空间")
    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
        "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
        "Host": "m.cloud.189.cn",
        "Accept-Encoding": "gzip, deflate",
    }
    response = s.get(url, headers=headers)
    if ("errorCode" in response.text):
        print(response.text)
    else:
        description = response.json()['description']
        print(f"抽奖获得{description}")
    response = s.get(url2, headers=headers)
    if ("errorCode" in response.text):
        print(response.text)
    else:
        description = response.json()['description']
        print(f"抽奖获得{description}")


BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")


def int2char(a):
    return BI_RM[a]


b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b64tohex(a):
    d = ""
    e = 0
    c = 0
    for i in range(len(a)):
        if list(a)[i] != "=":
            v = b64map.index(list(a)[i])
            if 0 == e:
                e = 1
                d += int2char(v >> 2)
                c = 3 & v
            elif 1 == e:
                e = 2
                d += int2char(c << 2 | v >> 4)
                c = 15 & v
            elif 2 == e:
                e = 3
                d += int2char(c)
                d += int2char(v >> 2)
                c = 3 & v
            else:
                e = 0
                d += int2char(c << 2 | v >> 4)
                d += int2char(15 & v)
    if e == 1:
        d += int2char(c << 2)
    return d


def rsa_encode(j_rsakey, string):
    rsa_key = f"-----BEGIN PUBLIC KEY-----\n{j_rsakey}\n-----END PUBLIC KEY-----"
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
    result = b64tohex((base64.b64encode(rsa.encrypt(f'{string}'.encode(), pubkey))).decode())
    return result


def calculate_md5_sign(params):
    return hashlib.md5('&'.join(sorted(params.split('&'))).encode('utf-8')).hexdigest()


def login(username, password):
    url = "https://cloud.189.cn/udb/udb_login.jsp?pageId=1&redirectURL=/main.action"
    r = s.get(url)
    captchaToken = re.findall(r"captchaToken' value='(.+?)'", r.text)[0]
    lt = re.findall(r'lt = "(.+?)"', r.text)[0]
    returnUrl = re.findall(r"returnUrl = '(.+?)'", r.text)[0]
    paramId = re.findall(r'paramId = "(.+?)"', r.text)[0]
    j_rsakey = re.findall(r'j_rsaKey" value="(\S+)"', r.text, re.M)[0]
    s.headers.update({"lt": lt})

    username = rsa_encode(j_rsakey, username)
    password = rsa_encode(j_rsakey, password)
    captcha = _needcaptcha(captchaToken, username)
    url = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
        'Referer': 'https://open.e.189.cn/',
    }
    data = {
        "appKey": "cloud",
        "accountType": '01',
        "userName": f"{{RSA}}{username}",
        "password": f"{{RSA}}{password}",
        "validateCode": f"{captcha}",
        "captchaToken": captchaToken,
        "returnUrl": returnUrl,
        "mailSuffix": "@189.cn",
        "paramId": paramId
    }
    r = s.post(url, data=data, headers=headers, timeout=5)
    if (r.json()['result'] == 0):
        print(r.json()['msg'])
    else:
        print(r.json()['msg'])
    redirect_url = r.json()['toUrl']
    r = s.get(redirect_url)
    return s


def _needcaptcha(captchaToken, username):
    """登录验证码处理函数"""
    url = _auth_url + "needcaptcha.do"
    post_data = {
        "accountType": "01",
        "userName": f"{{RSA}}{username}",
        "appKey": "cloud"
    }
    r = s.post(url, data=post_data, headers=headers)
    captcha = ""
    if r.text != "0":  # 需要验证码
        pic_url = _auth_url + "picCaptcha.do"
        img_data = s.get(
            pic_url, params={"token": captchaToken}, headers=headers).content
        with open("E:\\image.png", "wb") as f:
            f.write(img_data)
        image=Image.open(io.BytesIO(img_data)).convert("L")
        b_image=binarizing(image,126)
        b_image.save("E:\\b_image.png")
        d_image=depoint(b_image)
        d_image.save("E:\\d_image.png")
        captcha =pytesseract.image_to_string(d_image,lang="eng",config=tessdate_dir)
        print(captcha)
    else:
        print("No verification code processing function!")
    return captcha

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


if __name__ == "__main__":
    main()
