import requests
import random
import struct
from google.protobuf.json_format import MessageToDict,ParseDict
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from proto.majorlogin_pb2 import LoginReq, LoginRes
from proto.likeprofile_pb2 import likeprofile
from proto.AccountPersonalShow_pb2 import AccountPersonalShowInfo
RELEASEVERSION = "OB50"

def aes_cbc_encrypt(plaintext):
    aes = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%')
    padded_plaintext = pad(plaintext, AES.block_size)
    return aes.encrypt(padded_plaintext)

def create_like_payload(uid):
    data = likeprofile()
    data.uid = int(uid)
    data.region = 'bd'
    data = data.SerializeToString()
    encrypted_data = aes_cbc_encrypt(data)
    return encrypted_data

def make_info_payload(a: int) -> bytes:
    def encode_varint(value: int) -> bytes:
        out = b''
        while value > 0x7F:
            out += struct.pack('B', (value & 0x7F) | 0x80)
            value >>= 7
        out += struct.pack('B', value)
        return out

    return b'\x08' + encode_varint(a) + b'\x10' + encode_varint(7)


def get_access_token(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    payload = {
        "uid" : uid,
        "password" : password,
        "response_type" : "token",
        "client_type" : "2",
        "client_secret":"2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id" : "100067",
    }
    headers = {
        'User-Agent': f"Dalvik/2.1.0 (Linux; U; Android {random.randint(5,13)}.{random.randint(0,9)}.{random.randint(0,9)}; CPH{random.randint(0,1000)} Build/RKQ1.{random.randint(0,1000)}.{random.randint(0,1000)})",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }

    response = requests.post(url, data=payload, headers=headers)
    data = response.json()
    auth_data = (data["access_token"],data["open_id"])
    return auth_data

def create_jwt_token(uid, password):
    access_token, open_id = get_access_token(uid, password)

    data = {
      "open_id": open_id,
      "open_id_type": "4",
      "login_token": access_token,
      "orign_platform_type": "4"
    }
    proto = LoginReq()
    ParseDict(data,proto)
    payload = aes_cbc_encrypt(proto.SerializeToString())

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': f"Dalvik/2.1.0 (Linux; U; Android {random.randint(5,13)}.{random.randint(0,9)}.{random.randint(0,9)}; CPH{random.randint(0,1000)} Build/RKQ1.{random.randint(0,1000)}.{random.randint(0,1000)})",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }

    response = requests.post(url, data=payload, headers=headers)
    proto = LoginRes()
    proto.ParseFromString(response.content)
    return proto.jwt_token

def like(target_uid,jwt):
    payload = create_like_payload(target_uid)
    headers = {
        "User-Agent": f"Dalvik/2.1.0 (Linux; U; Android {random.randint(5,13)}.{random.randint(0,9)}.{random.randint(0,9)}; CPH{random.randint(0,1000)} Build/RKQ1.{random.randint(0,1000)}.{random.randint(0,1000)})",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "Authorization": f"Bearer {jwt}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB50",
    }

    response = requests.post("https://clientbp.ggblueshark.com/LikeProfile", data=payload, headers=headers, timeout=30)
    response.raise_for_status()

def get_account_info(uid, JWT):
    payload = make_info_payload(uid)
    data_enc = aes_cbc_encrypt(payload)

    headers = {
        'User-Agent': f"Dalvik/2.1.0 (Linux; U; Android {random.randint(5,13)}.{random.randint(0,9)}.{random.randint(0,9)}; CPH{random.randint(0,1000)} Build/RKQ1.{random.randint(0,1000)}.{random.randint(0,1000)})",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': f"Bearer {JWT}",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }

    resp = requests.post("https://clientbp.ggblueshark.com/GetPlayerPersonalShow", data=data_enc, headers=headers)
    msg = AccountPersonalShowInfo()
    msg.ParseFromString(resp.content)
    return msg
