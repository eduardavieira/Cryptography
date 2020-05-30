# -*- coding: utf-8 -*-
"""
Created on Mon Oct  7 18:44:48 2019

@author: eduar
"""
import os
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac

#gerar key1 e key2
a=getpass.getpass(prompt='Password: ', stream=None)
bytes3 = a.encode()
backend = default_backend()
# Salts should be randomly generated
salt = os.urandom(16)
# derive
kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=100000,
        backend=backend
        )
key = kdf.derive(bytes3)
key1=key[:32]
key2=key[32:]


#chacha20
nonce = os.urandom(16)
algorithm = algorithms.ChaCha20(key1, nonce)
cipher = Cipher(algorithm, mode=None, backend=default_backend())
encryptor = cipher.encryptor()
with open('mensagem.txt', 'rb') as g:
    data = g.read()
ct = encryptor.update(data)
encrip=open("mensagem_cifrada.txt", "wb")
encrip.write(ct)

#mac
h = hmac.HMAC(key2, hashes.SHA256(), backend=default_backend())
h.update(ct)
tag=h.finalize()
encrip.write(tag)

#fechar mensagem_cifrada.txt
encrip.close()




