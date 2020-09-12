from hashlib import pbkdf2_hmac
import hashlib
import hmac
import base64
import math
import operator

### 모듈 이용 ###
K = pbkdf2_hmac('sha1', password='password'.encode(), salt='salt'.encode(), iterations=1000, dklen=32)
print('[ 모듈 이용 ] DK =', base64.b64encode(K).decode())

### 동작원리 이용 ###
def pbkdf2(password, salt, iteration, dklen):
    hlen = hmac.new(password, msg=None, digestmod=hashlib.sha1).digest_size  
    len = math.ceil(dklen/hlen)
    r = dklen-(len-1)*hlen
    DK = b''
    for i in range(1, len+1):
        T = bytes(hlen)
        INT = i.to_bytes(4, byteorder='big')
        U_0 = salt + INT
        for j in range(iteration):
            U_N = hmac.new(password, U_0, hashlib.sha1).digest()
            T = bytes(map(operator.xor, T, U_N))
            U_0 = U_N
        if (i == len):
            DK += T[:r]
            return DK
        DK += T
    return DK
    
DK = pbkdf2('password'.encode(), 'salt'.encode(), 1000, 32)
print('[ 동작원리 이용 ] DK =', base64.b64encode(DK).decode())

