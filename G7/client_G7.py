# -*- coding: utf-8 -*-
"""
Created on Mon Oct 28 18:20:54 2019
@author: grupo6
"""
from cryptography.exceptions import InvalidSignature

import asyncio
import socket

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives import hashes, hmac

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives import serialization


from cryptography.hazmat.primitives.asymmetric import padding



conn_port = 8801
max_msg_size = 9999


class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """

    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
        self.x_client_private_key = None
        self.gx = None
        self.gy = None
        self.derived_key = b""
        self.key1= None
        self.key2= None
        self.cliente_private_key_assinatura=None
        self.cliente_private_key_assinatura_serializable=None
        self.cliente_public_key_assinatura=None
        self.cliente_public_key_assinatura_serializable=None
        self.signature=None
        self.gxb=None
        self.serverPK=None
        self.assinatura=None
        self.gyb=None
        self.sigb=None
        self.shared_key=None




    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1


        p = 99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583
        g = 44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675
        pn = dh.DHParameterNumbers(p, g)
        parameters = pn.parameters(default_backend())
        



        if self.msg_cnt == 1: #envia chave publica gx serializada:gxb
            self.x_client_private_key = parameters.generate_private_key()
            self.gx = self.x_client_private_key.public_key()
            self.gxb = self.gx.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            return self.gxb


        elif self.msg_cnt == 2:

            #Cliente recebe msg. Que contém gyb e Sigb
            self.gyb, self.sigb = msg[:-256], msg[-256:]

            #desserializar chave gyb para gy
            self.gy = serialization.load_der_public_key(data=self.gyb, backend=default_backend())


            '''
            :::::::::::::::::::::SIGa(gx,gy)::::::::::::::::::::::::::::::::::::
            '''
            with open("client_private_key.txt", "rb") as file2:
                self.cliente_private_key_assinatura = serialization.load_der_private_key(file2.read(), password=None, backend=default_backend())


            self.assinatura=self.gxb+self.gyb #gxb é a chave da alice enviada, gyb é a chave do bob recebida
            #vamos fazer a assinatura da chave publica serializada Diffi-Helman da Alice
            self.signature = self.cliente_private_key_assinatura.sign(
                    self.assinatura,
                    padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()
                    ),
                    salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                    )
                    
            

            '''
            VERIFICAR ASSINATURA
            '''
            with open("server_public_key_assinatura.txt", "rb") as file1:
                self.serverPK = serialization.load_der_public_key(file1.read(), backend=default_backend())


            #self.sigb é a assinatura do servidor, recebida na msg
          
            try:
                self.serverPK.verify(  #
                    self.sigb,
                    self.assinatura,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                self.shared_key = self.x_client_private_key.exchange(self.gy)
            except (InvalidSignature):
                print("Oops!  Não se verificou a assinatura.")


            self.derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(self.shared_key)
            self.key1=self.derived_key[:16]
            self.key2=self.derived_key[16:]

            print('Input message to send (empty to finish)')
            new_msg = input().encode()

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.key1), modes.CTR(iv), default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(new_msg) + encryptor.finalize()
            # mac
            h = hmac.HMAC(self.key2, hashes.SHA256(), default_backend())
            h.update(ct)
            tag = h.finalize()
            new_msg2 = (iv + ct) + tag +self.signature
            return new_msg2 if len(new_msg) > 0 else None


        elif self.msg_cnt >=3:
            if msg: 
                criptoIV, tag = msg[:-32], msg[-32:]
                iv, cripto = criptoIV[:16], criptoIV[16:]
                h = hmac.HMAC(self.key2, hashes.SHA256(), default_backend())
                h.update(cripto)

                try:
                    h.verify(tag)
                    cipher = Cipher(algorithms.AES(self.key1), modes.CTR(iv), default_backend())
                    decryptor = cipher.decryptor()
                    msg = decryptor.update(cripto) + decryptor.finalize()
                    print('Received (%d): %r' % (self.msg_cnt, msg.decode()))
                except (InvalidSignature):
                    print("Oops!  Não se verificou a integridade do criptograma.")




            print('Input message to send (empty to finish)')
            new_msg = input().encode()

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.key1), modes.CTR(iv), default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(new_msg) + encryptor.finalize()
            # mac
            h = hmac.HMAC(self.key2, hashes.SHA256(), default_backend())
            h.update(ct)
            tag = h.finalize()  # como mandar tag para o outro lado??
            new_msg2 = (iv + ct) + tag
            return new_msg2 if len(new_msg) > 0 else None


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
        if msg:
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