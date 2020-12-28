"""
天翼云盘 API，封装了对天翼云的各种操作
"""
import hashlib
import io
import logging
import os
import re
from base64 import b64encode

from pytesseract import pytesseract

import utils
import requests
import rsa
from PIL import Image
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

__all__ = ['Cloud189']
logger = logging.getLogger('cloud189')
API = 'https://api.cloud.189.cn'
UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) ????/1.0.0 ' \
     'Chrome/69.0.3497.128 Electron/4.2.12 Safari/537.36 '
# UA = 'Mozilla/5.0'
SUFFIX_PARAM = 'clientType=TELEMAC&version=1.0.0&channelId=web_cloud.189.cn'


class Cloud189(object):
    SUCCESS = 0
    FAILED = -1

    def __init__(self):
        self._session = requests.Session()
        self._captcha_handler = None
        self._timeout = 15  # 每个请求的超时(不包含下载响应体的用时)
        self._host_url = 'https://cloud.189.cn'
        self._auth_url = 'https://open.e.189.cn/api/logbox/oauth2/'
        self._cookies = None
        self._sessionKey = ""
        self._sessionSecret = ""
        self._accessToken = ""
        self._headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
            'Referer': 'https://open.e.189.cn/',
        }
        disable_warnings(InsecureRequestWarning)  # 全局禁用 SSL 警告

    def _get(self, url, **kwargs):
        try:
            kwargs.setdefault('timeout', self._timeout)
            kwargs.setdefault('headers', self._headers)
            return self._session.get(url, verify=False, **kwargs)
        except requests.Timeout:
            logger.warning(
                "Encountered timeout error while requesting network!")
            raise TimeoutError
        except (requests.RequestException, Exception) as e:
            logger.error(f"Unexpected error: {e=}")

    def _post(self, url, data, **kwargs):
        try:
            kwargs.setdefault('timeout', self._timeout)
            kwargs.setdefault('headers', self._headers)
            return self._session.post(url, data, verify=False, **kwargs)
        except requests.Timeout:
            logger.warning(
                "Encountered timeout error while requesting network!")
            raise TimeoutError
        except (requests.RequestException, Exception) as e:
            logger.error(f"Unexpected error: {e=}")

    def set_session(self, key, secret, token):
        self._sessionKey = key
        self._sessionSecret = secret
        self._accessToken = token

    def set_captcha_handler(self, captcha_handler):
        """设置下载验证码处理函数
        :param captcha_handler (img_data) -> str 参数为图片二进制数据,需返回验证码字符
        """
        self._captcha_handler = captcha_handler

    def get_cookie(self):
        return self._session.cookies.get_dict()

    def _redirect(self):
        r = self._get(self._host_url
                      + "/udb/udb_login.jsp?pageId=1&redirectURL=/main.action")
        captchaToken = re.findall(r"captchaToken' value='(.+?)'", r.text)[0]
        lt = re.findall(r'lt = "(.+?)"', r.text)[0]
        returnUrl = re.findall(r"returnUrl = '(.+?)'", r.text)[0]
        paramId = re.findall(r'paramId = "(.+?)"', r.text)[0]
        self._session.headers.update({"lt": lt})
        return captchaToken, returnUrl, paramId

    def _needcaptcha(self, captchaToken, username):
        """登录验证码处理函数"""
        url = self._auth_url + "needcaptcha.do"
        post_data = {
            "accountType": "01",
            "userName": "{RSA}" + b64tohex(encrypt(username)),
            "appKey": "cloud"
        }
        r = self._post(url, data=post_data)
        captcha = ""
        if r.text != "0":  # 需要验证码
            if self._captcha_handler:
                pic_url = self._auth_url + "picCaptcha.do"
                img_data = self._get(
                    pic_url, params={"token": captchaToken}).content
                captcha = self._captcha_handler(img_data)  # 用户手动识别验证码
            else:
                logger.error("No verification code processing function!")
        return captcha

    def login_by_cookie(self, config):
        """使用 cookie 登录"""
        cookies = config if isinstance(config, dict) else config.cookie
        try:
            for k, v in cookies.items():
                self._session.cookies.set(k, v, domain=".cloud.189.cn")
            resp = self._get(self._host_url + "/v2/getUserLevelInfo.action")
            if "InvalidSessionKey" not in resp.text:
                try:
                    self.set_session(config.key, config.secret, config.token)
                except:
                    pass
                return Cloud189.SUCCESS
        except:
            pass
        return Cloud189.FAILED

    def login(self, username, password):
        """使用 用户名+密码 登录"""
        captchaToken, returnUrl, paramId = self._redirect()
        validateCode = self._needcaptcha(captchaToken, username)
        url = self._auth_url + "loginSubmit.do"
        data = {
            "appKey": "cloud",
            "accountType": '01',
            "userName": "{RSA}" + b64tohex(encrypt(username)),
            "password": "{RSA}" + b64tohex(encrypt(password)),
            "validateCode": validateCode,
            "captchaToken": captchaToken,
            "returnUrl": returnUrl,
            "mailSuffix": "@189.cn",
            "paramId": paramId
        }
        r = self._post(url, data=data)
        msg = r.json()["msg"]
        if msg == "登录成功":
            self._get(r.json()["toUrl"])
            return Cloud189.SUCCESS
        print(msg)
        self.login(username, password)
        return Cloud189.FAILED

    def user_sign(self):
        """签到 + 抽奖"""
        sign_url = API + '//mkt/userSign.action'
        headers = {
            'SessionKey': self._sessionKey
        }
        resp = requests.get(sign_url, headers=headers, verify=False)
        if not resp:
            logger.error("Sign: network error!")
        if resp.status_code != requests.codes.ok:
            print(f"签到失败 {resp=}, {headers=}")
        else:
            msg = re.search(r'获得.+?空间', resp.text)
            msg = msg.group() if msg else ""
            print(f"签到成功！{msg}。每天签到可领取更多福利哟，记得常来！")

        url = 'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action'
        params = {
            'taskId': 'TASK_SIGNIN',
            'activityId': 'ACT_SIGNIN'
        }
        for i in range(1, 3):
            resp = self._get(url, params=params)
            if not resp:
                logger.error("Sign: network error!")
            resp = resp.json()
            if 'errorCode' in resp:
                print(f"今日抽奖({i})次数已用完： {resp['errorCode']}")
            else:
                print(f"今日抽奖({i})次：{resp['prizeName']}")
            params.update({'taskId': 'TASK_SIGNIN_PHOTOS'})


RSA_KEY = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDY7mpaUysvgQkbp0iIn2ezoUyh
i1zPFn0HCXloLFWT7uoNkqtrphpQ/63LEcPz1VYzmDuDIf3iGxQKzeoHTiVMSmW6
FlhDeqVOG094hFJvZeK4OzA6HVwzwnEW5vIZ7d+u61RV1bsFxmB68+8JXs3ycGcE
4anY+YzZJcyOcEGKVQIDAQAB
-----END PUBLIC KEY-----
"""
b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")


def int2char(a):
    return BI_RM[a]


def b64tohex(a):
    d = ""
    e = 0
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


def encrypt(password: str) -> str:
    return b64encode(
        rsa.encrypt(
            (password).encode('utf-8'),
            rsa.PublicKey.load_pkcs1_openssl_pem(RSA_KEY.encode())
        )
    ).decode()


def captcah_handler(img_data) -> str:
    tessdate_dir = r'--tessdata-dir "./tessdata" --psm 7 cloud189'
    image = Image.open(io.BytesIO(img_data)).convert("L")
    b_image = utils.binarizing(image, 126)
    d_image = utils.depoint(b_image)
    return pytesseract.image_to_string(d_image, lang="cloud189", config=tessdate_dir)[:-2].replace(" ", "")


username = ""
password = ""

if (username == "" or password == ""):
    username = input("账号：")
    password = input("密码：")
cloud = Cloud189()
cloud.set_captcha_handler(captcah_handler)
cloud.login(username, password)
cloud.user_sign()
