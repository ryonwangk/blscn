#!/usr/bin/env python3
"""
模拟 POST 请求到 spain.blscn.cn/SendRegisterUserVerificationCode
支持快代理自动切换

使用方法:
    python blscn_send_code.py
"""

import sys
import os
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import urllib.request
import urllib.parse
import urllib.error
import json

# 添加项目根目录到路径
_parent = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from tools.proxies.kuaidaili import get_proxy, KuaidailiProxy


def send_register_code():
    url = "https://spain.blscn.cn/CHN/account/SendRegisterUserVerificationCode"

    params = {
        "email": "dfasjkd@gg.com",
        "mobile": "13800138000",
        "isMobileVerify": "False",
        "data": "Kwnq6/CVr0TWWF4d6/o/jeK308yqQppbwDHyynp8xHMITL5/iGjAoLYtSxrRg84HRKXbwpCIYqMj7Gk3aSV+ry1r64GgAqYd9GCtLkTtc8Upt81bXEJlKBi9FqfL0YH86YkniBLU3wboEC93WW+yvw==",
        "captchaData": "QmBScbP8kTQaj5YbgRreYbj7OSB3dXmFMCUHDfbOEArJe4JkK4hQ9C+6hJ+CFF8x+1exiPu2RSKgMKheAz/GcGwjyTFnV6uM5XhdVB3x+qncozfNnf78IhDibCXczM/Ts5XF3OFr6/FcjHBn47qWsUkriNvUzgAkgxGJbccrGmAfYWAU43Qti8iHkXQsJoA8tWZPcIMLfI3+Na7hKZt9/ugFz7rwjSQ4x7RpmHwYMuCXIjM04PxhgozxvedPGNRAiDEN4knAyDJkvCsQtFpZPY9OvryowO/5Lo/t/OhzlE0zjwiUe5KqwLhM58xbOrzJmiTulwslIZJc5g1BIc2Y089z8yV+4SORS3mK6Fr2PoAIM5mBHAORLj8TovMeSX+xl6SA2aPrzHvdeZZz0r6oVLAZ5e9FNs3Ur3kBblJoJBpAxJ6bXV0dI9C33S0rhSdgdulTsVFXpa1wp+cc3YOeDQ==",
        "captchaId": "480d211b-7add-492c-8b4a-a9235dd9b0d8"
    }

    query_string = urllib.parse.urlencode(params)
    full_url = f"{url}?{query_string}"

    headers = {
        "Host": "spain.blscn.cn",
        "Content-Length": "0",
        "RequestVerificationToken": "CfDJ8JdeSWGIgchBpI-EMX3QVqPvcFCdgHd8Agu371rtKrP5gGA_TilikQjgS_AiJOrUkw5WXUllS2HxFa-CdqtWIl5RJd1qwdnu_keXHwBT6WC74yTKoVx65EQIaAYPbZE1ABtzA4HTeermhHHl4YtIV_4",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Sec-Ch-Ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Origin": "https://spain.blscn.cn",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://spain.blscn.cn/CHN/account/RegisterUser",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Cookie": ".AspNetCore.Antiforgery.BDmv0qjjHrI=CfDJ8JdeSWGIgchBpI-EMX3QVqOGW7l6lATJIqTbdp2Qsng7HrODto2qlOvD_3UoEvoQ47yXyOK6vRkVjaCoKxVxUOOiSQdxV63xNmcBys951Hc9gOOJUQAjDo-tVaHUkyPxv0_1RAVzYQ58xKo7COHNE4o",
        "Priority": "u=1, i"
    }

    req = urllib.request.Request(full_url, method="POST")
    for key, value in headers.items():
        req.add_header(key, value)

    print(f"URL: {full_url}")
    print(f"Headers: {json.dumps(headers, indent=2, ensure_ascii=False)}")
    print("-" * 50)

    # 使用快代理
    print("\n[1] 从快代理获取 IP...")
    proxy = get_proxy()
    if not proxy:
        print("  FAIL: 无法获取代理，退出")
        return None

    proxy_url = proxy.get("http", "")
    import re
    m = re.match(r'http://([^:@]+):([^@]+)@(.+)', proxy_url)
    if m:
        proxy_host_port = m.group(3)
    else:
        proxy_host_port = proxy_url
    print(f"  使用代理: {proxy_host_port}")

    # 构建代理处理器
    proxy_handler = urllib.request.ProxyHandler({
        "http": proxy_url,
        "https": proxy_url,
    })

    # 如果有认证，创建密码管理器
    if m:
        password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(None, proxy_url, m.group(1), m.group(2))
        auth_handler = urllib.request.ProxyBasicAuthHandler(password_mgr)
        opener = urllib.request.build_opener(proxy_handler, auth_handler)
    else:
        opener = urllib.request.build_opener(proxy_handler)

    try:
        with opener.open(req, timeout=30) as response:
            status = response.status
            body = response.read().decode("utf-8")
            print(f"\n[2] 响应结果:")
            print(f"Status: {status}")
            print(f"Response length: {len(body)}")
            print(f"Response: {body[:2000]}{'...' if len(body) > 2000 else ''}")
            return body
    except urllib.error.HTTPError as e:
        print(f"\n[2] HTTP Error: {e.code} {e.reason}")
        try:
            body = e.read().decode('utf-8')
            print(f"Response: {body[:1000]}")
        except:
            print(f"Response (raw): {e.read()}")
        return None
    except urllib.error.URLError as e:
        print(f"\n[2] URL Error: {e.reason}")
        return None


if __name__ == "__main__":
    send_register_code()
