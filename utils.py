# coding=utf-8
from pyasn1.type.univ import Null
import requests
import json
import hmac
import hashlib
import rsa
import base64
from hashlib import sha256

from rsa import key

def httpPost(url,params):
    
    headers = {}
    headers['Content-Type'] = 'application/json'
    resp = requests.post(url, data=json.dumps(params),headers=headers)
    respBody = {}
    respBody['code'] = 200
    respBody['msg'] = 'ok'
    respBody['success'] = True
    respBody['data'] = None
    if resp.status_code != 200:
        respBody['code'] = resp.status_code
        respBody['msg'] = resp.text
    else:
        return resp.text

def getBaseString(params):

    keys = sorted(params)
    size = len(params)
    i = 0;
    baseString = ''
    for key in keys:
        i=i+1;
        if i == size:
            baseString=baseString+key+"="+str(params[key])
        else:
            baseString=baseString+key+"="+str(params[key])+"&"
    return baseString

def md5(data):
    m = hashlib.md5()
    m.update(data.encode('utf-8'))
    return m.hexdigest()

def hmacSha256(data,secretKey):
   return hmac.new(secretKey.encode('utf-8'), data.encode('utf-8'), digestmod=sha256).hexdigest()

def rsaSign(data,privateKey):
    privKey = rsa.PrivateKey.load_pkcs1(base64.b64decode(privateKey),format='DER')
    return base64.b64encode(rsa.sign(data.encode('utf-8'),privKey,'SHA-256')).decode()

def rsaVerify(data,publicKey,sign):
    pubKey = rsa.PublicKey.load_pkcs1(base64.b64decode(publicKey),format='DER')
    return rsa.verify(data.encode('utf-8'),base64.b64decode(sign),pubKey)

def genKey():
    (pubkey, privkey) = rsa.newkeys(1024)
    pubkey = base64.b64encode(pubkey.save_pkcs1(format='DER')).decode()
    privkey = base64.b64encode(privkey.save_pkcs1(format="DER")).decode()
    # pubkey = pubkey.save_pkcs1(format='PEM').decode().replace("-----BEGIN RSA PUBLIC KEY-----","").replace("-----END RSA PUBLIC KEY-----","").replace("\n","")
    # privkey = privkey.save_pkcs1(format="PEM").decode().replace("-----BEGIN RSA PRIVATE KEY-----","").replace("-----END RSA PRIVATE KEY-----","").replace("\n","")

    keys = {}
    keys['pubKey'] = pubkey
    keys['privKey'] = privkey
    return keys

if __name__ == '__main__':

    params = {}
    params['d'] = 20
    params['c'] = '111'
    params['a'] = '2222'
    params['m'] = 100
    baseString = getBaseString(params)
    print(baseString)
    print(md5(baseString))
    print(hmacSha256(baseString,'xxxxxxxxxxxxxxxx'))

    keys = genKey()
    privKey = keys['privKey']
    pubKey = keys['pubKey']

    print(len(privKey))
    sign = rsaSign(baseString,privKey)
    
    print(sign)

    print(rsaVerify(baseString,pubKey,sign))


