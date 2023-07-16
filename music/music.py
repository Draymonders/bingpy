import math
import random
import requests
import execjs

from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import Crypto.Util.number as CUN

byte_encode = "utf-8"

def js_call(file_name, method_name, *args):
    # 创建一个JavaScript运行环境
    runtime = execjs.get().name
    code = ""
    # 编写要执行的JavaScript代码
    with open(file_name, "r") as f:
        code = f.read()
        # 在JavaScript运行环境中执行代码
        ctx = execjs.compile(code)
        result = ctx.call(method_name, *args)

        return result

# rsa 非对称加密
def _rsa(a, b, c):
    # encrypted_string(rsa_key_pair(b, "", c), a)
    return js_call("./music.js", "c", a, b, c)
    pass

# aes 对称加密
def aes(a, b):
    key = b.encode(byte_encode)
    iv_str = "0102030405060708"
    # 生成随机的 16 字节密钥和 16 字节初始化向量
    iv = iv_str.encode(byte_encode)

    # 初始化 AES 加密器和解密器，使用 CBC 模式和随机初始化向量
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # 加密数据
    data = a.encode(byte_encode)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    encry_str = b64encode(ciphertext).decode(byte_encode)

    # print("ciphertext: type ", type(ciphertext))

    cipher2 = AES.new(key, AES.MODE_CBC, iv)
    decry_bytes = unpad(cipher2.decrypt(ciphertext), AES.block_size)
    # print("decode:", str(decry_bytes))

    return encry_str

def random_str(l): 
    seeds = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    res = ""
    for i in range(l):
        p = math.floor(random.random() * l) 
        res += seeds[p]
    return res

# 获取加密token
def get_token(json_text: str):
    e = "010001"
    f = "00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7"
    g = "0CoJUm6Qyw8W8jud"

    i = random_str(16)
    # i = "Rb6ZdQXeJ2ZroQQO"
    enc_text = aes(aes(json_text, g), i)
    # print(enc_text)
    enc_sec_text = _rsa(i, e, f)
    return {
        "params":enc_text, 
        "encSecKey": enc_sec_text
    }

def get_music_url(id: str):

    req_str = '{"ids":"[' + id + ']","level":"standard","encodeType":"aac","csrf_token":""}'
    data = get_token(req_str)

    cookies = {
        '_ntes_nuid': 'c2c3fca0e04f049156e18cd84f9a44ba',
        'NMTID': '00OS9K6I-C9ouDwN0raprVADN-9ig4AAAF40NYPOg',
        'WEVNSM': '1.0.0',
        'ntes_kaola_ad': '1',
        'WNMCID': 'orafdr.1656901301966.01.0',
        '__bid_n': '1848960528522ba8bf4207',
        '__snaker__id': 'puXvzOjesNYAwdkB',
        'WM_TID': 'sbuXW1olwRtAERQBQEPAfkooMKkzpwcE',
        'YD00000558929251%3AWM_NI': 'tDndmk12j%2FiJtDDMoNNG222UlAABUM0F8XsSTe1ejeD9P44kRltL3DiWwlAY0ybIzz79c3TLnDAEH73KZ7hObS37LzfXm6z0XcUcCINZXIh%2F3YIZKPGqqU1Tei7Xr%2BFUT28%3D',
        'YD00000558929251%3AWM_NIKE': '9ca17ae2e6ffcda170e2e6ee88b47397f0a285d05a92868bb3d15e978b9b83d148bcebbdaae46df79f9c90e42af0fea7c3b92ab89ca285f061f3eea6d0ec42b89c8caeee468e99fed3b15fb09f8fa3d847f49af8b9f25998bbff86e96f88e7a0d5b76192b4bcadb250ab89b98dc453f4a7aeaaf972f5e7add4d748ae9c8fa6cb3df19596d8eb45a28dfdd8cf72a688a3d7f93c9cbd9b84c2438e8698aaeb25f18787bbca5c85afbfb6b460a7b7f9b9f121868b9cd3bb37e2a3',
        'YD00000558929251%3AWM_TID': '3%2Fns24%2BVCJdEVVVEBQeVe059cPx9AStL',
        'P_INFO': '19833001203|1680243342|1|music|00&99|null&null&null#bej&null#10#0|&0||19833001203',
        '_iuqxldmzr_': '32',
        '_ntes_nnid': 'c2c3fca0e04f049156e18cd84f9a44ba,1689406397897',
        'ntes_utid': 'tid._.67wL6UbJw5RERgURAEPRkWVe%252FD%252BORscs._.0',
        'sDeviceId': 'YD-MGPnFqEy8zxBV0FVFBORbDbRzqJ2SKXM',
        'playerid': '74101990',
        'JSESSIONID-WYYY': '4RtWhAs8UJt%2BgsveCZoNmbdr%2FC7ijEPsBPINh4QdQccoXP5uyMw9Zica702PBvRp%2B%2Fv4h%2F08z0ZrOW4KXM%2FxroH%2FRIlzqA76HMqzfnJkGVo8mdNTNmkxKfkiACOMQ0OSHi7SzOD6AQg4Nj2zv2wNJrvQKfnCnOR0Wa2fNcS06EEkY0O6%3A1689482868845',
        'WM_NI': 'UK5BPxSh0yVt00XGM4n%2FJ6InvxbD8BmaImOxTP%2BvLUcHI8mZfpD0suE%2Fs8LL1deE05seePa9RsKkjyWD8q3EG4q0089xVRnVdqfoPFppmtRvONrEQQBx9JompWohVA7LbGo%3D',
        'WM_NIKE': '9ca17ae2e6ffcda170e2e6ee92c84ef68ffc89e472fbeb8aa3d14f838e9eadd53bae90ffd0cd34f490a9dacd2af0fea7c3b92a9795fba3d37491b8009ad580f4f098a8d040aef186d7cc66b6a8aea5bb4aafbf878ece749890e597cf5fa19887d9f052a6b08cd1f27f87f1bdd9cf48f3bcaba6b33fb1bbabb1e43392ad858ce973959cf892b24f85ecbfd1b334fba89ab3ed5ea8afaa90d34eb4b0a395d17e8d92bea6d45b82a8f7abee67b489a189d54bf594aea8ee37e2a3',
    }

    headers = {
        'authority': 'music.163.com',
        'accept': '*/*',
        'accept-language': 'zh-CN,zh;q=0.9',
        # Requests sorts cookies= alphabetically
        # 'cookie': '_ntes_nuid=c2c3fca0e04f049156e18cd84f9a44ba; NMTID=00OS9K6I-C9ouDwN0raprVADN-9ig4AAAF40NYPOg; WEVNSM=1.0.0; ntes_kaola_ad=1; WNMCID=orafdr.1656901301966.01.0; __bid_n=1848960528522ba8bf4207; __snaker__id=puXvzOjesNYAwdkB; WM_TID=sbuXW1olwRtAERQBQEPAfkooMKkzpwcE; YD00000558929251%3AWM_NI=tDndmk12j%2FiJtDDMoNNG222UlAABUM0F8XsSTe1ejeD9P44kRltL3DiWwlAY0ybIzz79c3TLnDAEH73KZ7hObS37LzfXm6z0XcUcCINZXIh%2F3YIZKPGqqU1Tei7Xr%2BFUT28%3D; YD00000558929251%3AWM_NIKE=9ca17ae2e6ffcda170e2e6ee88b47397f0a285d05a92868bb3d15e978b9b83d148bcebbdaae46df79f9c90e42af0fea7c3b92ab89ca285f061f3eea6d0ec42b89c8caeee468e99fed3b15fb09f8fa3d847f49af8b9f25998bbff86e96f88e7a0d5b76192b4bcadb250ab89b98dc453f4a7aeaaf972f5e7add4d748ae9c8fa6cb3df19596d8eb45a28dfdd8cf72a688a3d7f93c9cbd9b84c2438e8698aaeb25f18787bbca5c85afbfb6b460a7b7f9b9f121868b9cd3bb37e2a3; YD00000558929251%3AWM_TID=3%2Fns24%2BVCJdEVVVEBQeVe059cPx9AStL; P_INFO=19833001203|1680243342|1|music|00&99|null&null&null#bej&null#10#0|&0||19833001203; _iuqxldmzr_=32; _ntes_nnid=c2c3fca0e04f049156e18cd84f9a44ba,1689406397897; ntes_utid=tid._.67wL6UbJw5RERgURAEPRkWVe%252FD%252BORscs._.0; sDeviceId=YD-MGPnFqEy8zxBV0FVFBORbDbRzqJ2SKXM; playerid=74101990; JSESSIONID-WYYY=4RtWhAs8UJt%2BgsveCZoNmbdr%2FC7ijEPsBPINh4QdQccoXP5uyMw9Zica702PBvRp%2B%2Fv4h%2F08z0ZrOW4KXM%2FxroH%2FRIlzqA76HMqzfnJkGVo8mdNTNmkxKfkiACOMQ0OSHi7SzOD6AQg4Nj2zv2wNJrvQKfnCnOR0Wa2fNcS06EEkY0O6%3A1689482868845; WM_NI=UK5BPxSh0yVt00XGM4n%2FJ6InvxbD8BmaImOxTP%2BvLUcHI8mZfpD0suE%2Fs8LL1deE05seePa9RsKkjyWD8q3EG4q0089xVRnVdqfoPFppmtRvONrEQQBx9JompWohVA7LbGo%3D; WM_NIKE=9ca17ae2e6ffcda170e2e6ee92c84ef68ffc89e472fbeb8aa3d14f838e9eadd53bae90ffd0cd34f490a9dacd2af0fea7c3b92a9795fba3d37491b8009ad580f4f098a8d040aef186d7cc66b6a8aea5bb4aafbf878ece749890e597cf5fa19887d9f052a6b08cd1f27f87f1bdd9cf48f3bcaba6b33fb1bbabb1e43392ad858ce973959cf892b24f85ecbfd1b334fba89ab3ed5ea8afaa90d34eb4b0a395d17e8d92bea6d45b82a8f7abee67b489a189d54bf594aea8ee37e2a3',
        'origin': 'https://music.163.com',
        'referer': 'https://music.163.com/',
        'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    }

    params = {
        'csrf_token': '',
    }

    response = requests.post('https://music.163.com/weapi/song/enhance/player/url/v1', params=params, cookies=cookies, headers=headers, data=data)
    return response.text



if __name__ == "__main__":
    # 找到网易云音乐的id，即可得到url；（付费音乐获取不到~）
    id = "28987656"
    
    print(get_music_url(id))