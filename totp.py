from hashlib import sha1
from struct import pack, unpack
from time import time

blocksize = sha1().block_size
def hmac_sha1(key, msg):
    if len(key) > blocksize:
        key = sha1(key).digest()
    key += b"\0" * (blocksize - len(key))
    msg = sha1(bytes(x^0x36 for x in key) + msg).digest() 
    return sha1(bytes(x^0x5c for x in key) + msg)


def dt(h):
    offset = h[19] & 0xf
    return unpack(">L", h[offset:offset+4])[0] & 0x7fffffff


def hotp(key, counter):
    hmac = hmac_sha1(key, pack(">Q", counter))
    return "{:0>6}".format(dt(hmac.digest()) % 10**6)


def totp(key):
    return hotp(key, int(time() // 30))


def check_totp(key, pin, window=0):
    t = int(time() // 30)
    for n in range(t-window, t+window+1):
        if pin == hotp(key, n):
            return True
    return False
