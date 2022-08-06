import base64
import codecs
import hashlib
import sys

from cryptography.fernet import Fernet





class AESCipher(object):

    def __init__(self, key):
        self.fernet = Fernet(key)

    def encrypt(self, raw):
        enctex = self.fernet.encrypt(raw.encode("utf8"))
        return enctex.decode("utf8")

    def decrypt(self, enc):
        print(type(enc))
        dectex = self.fernet.decrypt(str.encode(enc)).decode()
        return dectex

