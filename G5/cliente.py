# -*- coding: utf-8 -*-
"""
Created on Mon Oct 28 18:20:54 2019

@author: eduar
"""
from cryptography.exceptions import InvalidSignature

'''

'''

import asyncio
import socket

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives import hashes, hmac

conn_port = 8801
max_msg_size = 9999

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.key = b"1234567890123456"
        self.key2 = b"12345678901234567890123456789012"
    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt +=1



        if msg: #1-só decifra se chegou algo do servidor
            criptoIV, tag = msg[:-32], msg[-32:]#separamos msg recebido em criptograma e tag
            iv, cripto = criptoIV[:16], criptoIV[16:]
            h = hmac.HMAC(self.key2, hashes.SHA256(), default_backend())
            h.update(cripto)
            #2-decifrar msg só se a tag verificar
            try:
                h.verify(tag)
                cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), default_backend())
                decryptor = cipher.decryptor()
                msg = decryptor.update(cripto) + decryptor.finalize()
                print('Received (%d): %r' % (self.msg_cnt , msg.decode()))
            except (InvalidSignature):
                print ("Oops!  Não se verificou a integridade do criptograma.")
        
        print('Input message to send (empty to finish)')
        new_msg = input().encode()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(new_msg) + encryptor.finalize()
        #mac
        h = hmac.HMAC(self.key2, hashes.SHA256(), default_backend())
        h.update(ct)
        tag=h.finalize() #como mandar tag para o outro lado??
        new_msg2 = (iv+ct)+tag

        # cifrar new_msg
        return new_msg2 if len(new_msg)>0 else None



#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


@asyncio.coroutine
def tcp_echo_client(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader, writer = yield from asyncio.open_connection('127.0.0.1',
                                                        conn_port, loop=loop)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = yield from reader.read(max_msg_size)
        if msg :
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()
