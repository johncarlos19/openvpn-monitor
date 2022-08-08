import base64
import codecs
import hashlib
import sys

from cryptography.fernet import Fernet
import jwt





class AESCipher(object):

    def __init__(self, key):
        self.fernet = Fernet(key)
        self.secret_key = key

    def encrypt(self, raw):
        enctex = jwt.encode(raw, self.secret_key, algorithm='HS256')
        return enctex

    def decrypt(self, enc):
        print(type(enc))
        dectex = jwt.decode(enc, self.secret_key, algorithms=['HS256'])
        return dectex

