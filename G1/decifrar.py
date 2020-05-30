# -*- coding: utf-8 -*-
"""
Created on Mon Sep 30 19:16:27 2019

@author: eduar
"""

with open('key.txt', 'rb') as g:
    data = g.read()
f = Fernet(data)

with open('mensagem_cifrada.txt', 'rb') as h:
    mensagem=h.read()

r=f.decrypt(mensagem)
dkey=open("mensagem_recuperada.txt", "wb")
dkey.write(r)
dkey.close()
