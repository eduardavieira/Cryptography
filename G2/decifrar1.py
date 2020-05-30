# -*- coding: utf-8 -*-
"""
Created on Sun Oct  6 21:42:25 2019

@author: eduar
"""




import getpass
import base64
from cryptography.fernet import Fernet

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend



def decifrar():
    with open('mensagem_cifrada.txt', 'rb') as r:
        data=r.read()
        salt=data[-16:]
        data=data[:-16]
        
    #pedir a passphrase ao user
    
    backend = default_backend()
    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            #verificar salt
            salt=salt,
            iterations=100000,
            backend=backend
            )
    
    a=getpass.getpass(prompt='Password: ', stream=None)
    bytes3 = a.encode()
    key = kdf.derive(bytes3)
    jj=base64.urlsafe_b64encode(key)
    f = Fernet(jj)

    
   
    r=f.decrypt(data)
    dkey=open("mensagem_recuperada.txt", "wb")
    dkey.write(r)
    dkey.close()
    
    
    
decifrar()

        

