# -*- coding: utf-8 -*-
"""
Created on Wed Sep 25 12:45:20 2019

@author: eduar
"""

from cryptography.fernet import Fernet

with open('mensagem.txt', 'rb') as g:
    data = g.read()
key = Fernet.generate_key()
f = Fernet(key)


#ficheiro com key
dkey=open("key.txt", "wb")
dkey.write(key)
dkey.close()


#ficheiro com mensagem cifrada
token = f.encrypt(data)
encrip=open("mensagem_cifrada.txt", "wb")
encrip.write(token)
encrip.close()

