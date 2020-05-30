# -*- coding: utf-8 -*-
"""
Created on Mon Sep 30 19:28:12 2019

@author: eduar
"""

import os
import getpass
import base64
from cryptography.fernet import Fernet

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

a=getpass.getpass(prompt='Password: ', stream=None)
bytes3 = a.encode()


backend = default_backend()
# Salts should be randomly generated
salt = os.urandom(16)
# derive
kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
        )
key = kdf.derive(bytes3)
jj=base64.urlsafe_b64encode(key)
f = Fernet(jj)


#cifrar
with open('mensagem.txt', 'rb') as g:
    data = g.read()
token = f.encrypt(data)
encrip=open("mensagem_cifrada.txt", "wb")
encrip.write(token)
encrip.close()

with open('mensagem_cifrada.txt', 'ab') as file:
    file.write(salt)




