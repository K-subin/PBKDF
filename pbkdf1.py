import hashlib
import base64

def pbkdf1(password, salt, iteration, dklen):
    T_0 = password + salt
    for i in range(iteration):
        T_N = hashlib.sha1(T_0).digest()
        T_0 = T_N
    return T_0[:dklen]

DK = pbkdf1('password'.encode(), 'salt'.encode(), 1000, 20)
print(base64.b64encode(DK).decode('utf-8'))
