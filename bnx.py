# -*- coding: utf-8 -*-
# @File     :bnx.py
# @Software :PyCharm
import base64
import hashlib
import time

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from eth_account import Account
from eth_account.messages import encode_defunct
from loguru import logger

# TODO 版本号
cv = 217

Rules = ["uDx.UvmhMXyOE4QG5Le1b6Zip7YR&kAcdJKj@Snt2lP3N+aqfH9r=FoIswzW8CBg0VT",
         "A1M8E3F7KtUHcv@J&N+LopDqS25QIOZYuVhRlzknjTebgrdyw9.x6CWsa=GB0mPif4X",
         "O&FPGp+on=vX.V@Nc17dsat85TWwgSzfyZLIuq4AYJK6r2kmC3lhbBR9HiEeUDj0MxQ",
         "&u95ehs1H8LWI2ZFlvNpm7xgUS.ErbqiM6JcY+PXdD3=ojQRkKTB4wnzVtOaC0@yGfA",
         "sSHmxX=iTn1bL3jB8K0Ww6e4UJRDh2yV&ZAdOMrIN7+apEPzvCFfuG.ql9cYgkt5o@Q",
         "W7pxPGoa.6MibguTvweUd@n3m2qSkHsLRVXKfl+&YFyErD94CA1BOhI=z5tjJ0N8ZcQ",
         "xqWYNwCLAQkiEPUfdT8tFO.lbmV+=u@6Rvy52coHDr37jeBS40M9Gap1szK&JZXngIh",
         "61tw+.YVJhWZL@R23obMrD=l9dOnNcEAk04HUupQSXFsG&ByjaxCg8i7PI5mKfqzveT",
         "Har3jpB.KO1btnXWv+U9LYidofQ7q4lCAFMeE6uJSmZTxcszk&P@w=hI0GyN58VRg2D",
         "eEP6vhCdTHnGxXO=qlouNkKwBJ+mbcF7@Za4L3jRYtU&VI1AW.9M5Q8rgp2DszSf0iy"]

s = Rules[cv % 10]


def get_uk(account_address):
    _o = account_address[2:]
    key = b"d36704ca8f0daf9f1d0be610cef86d87"
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(_o.encode(), AES.block_size))
    r = base64.b64encode(ciphertext).decode()
    return r


def get_key():
    f = ['x', '7', 'p', 'y', 's', '2', 'i', '9', 'c', 'k', '3', 'm', 'd', 'z', 'l', 't', '5', 'j', 'u', '4', 'v', 'f',
         'r', 'n', 'h', 'q', 'w', 'e', '8', 'a', '6', 'b', 'g']
    e = int(time.time() * 1000)
    a = 4096 * (e - 1668096000000) + (0 << 11) + (0 << 10) + 0
    d, c, u = 33, '', a
    while u / d > 0:
        p = u % d
        c = f[int(p)] + c
        u = (u - p) / d
    c = '_p' + c
    return c, a


def get_sign(e, t, n):
    i, l = "", ""
    if isinstance(e, dict):
        for s in e:
            i += s + "=" + str(e[s]) + "&"
    elif isinstance(e, str) and e != "":
        i += e + "&"
    i += "tk=" + str(t)

    c = [0] * len(n)
    for f in range(len(i)):
        h = n.find(i[f])
        if h >= 0:
            c[h] += 1
    for d in range(len(n)):
        if c[d] > 0:
            for p in range(c[d]):
                l += n[d]

    return hashlib.md5(l.encode()).hexdigest()


def login(private_key):
    """
    登录
    :param private_key: 私钥
    :return:
    """
    account = Account.privateKeyToAccount(private_key)
    msg = 'You are better than you know!'
    signature = Account.sign_message(encode_defunct(text=msg), account.key.hex()).signature.hex()
    uk = get_uk(account.address.lower())
    key, _tk = get_key()
    value = get_sign({
        "account": account.address.lower(), "uk": uk, "ukSign": signature, "shareCode": "", "w": 1, "cv": 217
    }, _tk, s)
    params = {
        'account': account.address.lower(), 'uk': uk, 'ukSign': signature, 'shareCode': '', 'w': 1, 'cv': 217,
        key: value, '_tk': _tk, '_cv': '217'}
    response = requests.get(url='https://raid.binaryx.pro/chess/login/doChainLogin', params=params).json()
    logger.debug(response)
    if response.get('uid', False):
        return response['token'], response['uid']
    else:
        raise ValueError('登录失败')


def attack(_token, _uid, _consume=200):
    """
    打怪
    :param _token: 账户token
    :param _uid: 账户uid
    :param _consume: 攻击数量
    :return:
    """
    headers = {
        'Accept': '*/*', 'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7', 'Cache-Control': 'no-cache',
        'Connection': 'keep-alive', 'Pragma': 'no-cache',
        'Referer': 'https://raid.binaryx.pro/217/web-desktop/index.html?v=14287257',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
        'language': 'en', 'token': _token}
    key, _tk = get_key()
    value = get_sign({"_consume": _consume}, _tk, s)
    params = {'consume': str(_consume), key: value, '_tk': _tk, '_cv': '217', '_uid': _uid}
    response = requests.get('https://raid.binaryx.pro/chess/demonKing/attack', params=params, headers=headers)
    logger.debug(response.text)


def enter_demon_king(_token, _uid):
    key, _tk = get_key()
    value = get_sign({}, _tk, s)
    headers = {
        'Accept': '*/*', 'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7', 'Cache-Control': 'no-cache',
        'Connection': 'keep-alive', 'Pragma': 'no-cache',
        'Referer': 'https://raid.binaryx.pro/217/web-desktop/index.html?v=14287257',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
        'language': 'en', 'token': _token}
    params = {key: value, '_tk': _tk, '_cv': '217', '_uid': _uid}

    response = requests.get('https://raid.binaryx.pro/chess/demonKing/enterDemonKing', params=params,
                            headers=headers).json()
    logger.debug(response)


if __name__ == '__main__':
    _account = Account().create()
    logger.debug(_account.address)
    logger.debug(_account.key.hex())
    # TODO 登录
    token, uid = login(_account.key.hex())
    # TODO 打怪
    # attack(token, uid)
    # TODO 查询数据
    # enter_demon_king(token, uid)
