#!/usr/bin/python3
# Copyright (C) iBug 2022

import base64
import datetime
import json
import random
import requests
import string
import subprocess


def genstring(k):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))


def genkey():
    return subprocess.run(['wg', 'genkey'], capture_output=True).stdout.decode().strip()


def pubkey(privkey):
    return subprocess.run(['wg', 'pubkey'], input=privkey.encode(), capture_output=True).stdout.decode().strip()


def reg(key):
    url = 'https://api.cloudflareclient.com/v0a977/reg'
    headers = {
        'User-Agent': 'okhttp/3.12.1',
        'Content-Type': 'application/json; charset=UTF-8',
    }
    install_id = genstring(11)
    payload = {
        'key': key,
        'install_id': install_id,
        'fcm_token': f'{install_id}:APA91b{genstring(134)}',
        'referer': '1.1.1.1',
        'warp_enabled': True,
        'tos': datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S+08:00'),
        'model': 'Xiaomi POCO X2',
        'type': 'Android',
        'locale': 'en_US',
    }
    r = requests.post(url, headers=headers, data=json.dumps(payload))
    return r.json()


def main():
    k = genkey()
    pk = pubkey(k)
    r = reg(pk)
    c = r['config']

    print('[Interface]')
    print('PrivateKey =', k)
    print('# PublicKey =', pk)
    print('Address =', c['interface']['addresses']['v4'])
    print('Address =', c['interface']['addresses']['v6'])
    print('# ClientID =', list(base64.b64decode(c['client_id'])))
    print('# Table = off')
    print('''
[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
# Endpoint = engage.cloudflareclient.com:2408
Endpoint = 162.159.192.1:2408
# Endpoint = [2606:4700:d0::a29f:c005]:2408
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0''')


if __name__ == '__main__':
    main()
