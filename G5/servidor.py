# -*- coding: utf-8 -*-
"""
Created on Mon Oct 28 18:22:22 2019

@author: eduar
"""

import asyncio
import os


from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives import hashes, hmac

conn_cnt = 0
conn_port = 8801
max_msg_size = 9999


class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """

    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.key = b"1234567890123456"
        self.key2 = b"12345678901234567890123456789012"

    def process(self, msg):  # este msg é new_msg2 = ct+tag
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1

        if msg:  # 1-só decifra se chegou algo do servidor
            criptoIV, tag = msg[:-32], msg[-32:]#separamos msg recebido em criptograma e tag
            iv, cripto = criptoIV[:16], criptoIV[16:]

            h = hmac.HMAC(self.key2, hashes.SHA256(), default_backend())
            h.update(cripto)
            # 2-decifrar msg só se a tag verificar
            try:
                h.verify(tag)
                cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), default_backend())
                decryptor = cipher.decryptor()
                msg = decryptor.update(cripto) + decryptor.finalize()

                print('Received (%d): %r' % (self.msg_cnt, msg.decode()))
            except (InvalidSignature):
                print("Oops!  Não se verificou a integridade do criptograma.")



        print('%d : %r' % (self.id, msg.decode()))
        new_msg = msg.decode().upper().encode()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(new_msg) + encryptor.finalize()
        # mac
        h = hmac.HMAC(self.key2, hashes.SHA256(), default_backend())
        h.update(ct)
        tag = h.finalize()  # como mandar tag para o outro lado??
        new_msg2 = (iv+ct)+tag

        return new_msg2 if len(new_msg) > 0 else None


#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt += 1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)
    data = yield from reader.read(max_msg_size)
    while True:
        if not data: continue
        if data[:1] == b'\n': break
        data = srvwrk.process(data)
        if not data: break
        writer.write(data)
        yield from writer.drain()
        data = yield from reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port, loop=loop)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')


run_server()
