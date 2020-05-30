"""
Created on Tue Oct 22 23:10:01 2019

@author: grupo6
"""
import os
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#class que cifra, deve ter 2 métodos: keygen e enc.
class C:
    def __init__(self, d, e):
        self.d = d
        self.e = e
        pass
    def keygen(): #nao tem argumento porque é c.keygen()
        key=os.urandom(32) #gera a chave de 32bits do chacha20
        return key
    def enc(d, e): #d=k e=mensagem
        nonce = b"0" * 16 #os.urandom(16)
        algorithm = algorithms.ChaCha20(d, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        data = e.encode() #Mensagem é string. Passamos para byte
        ct = encryptor.update(data) #este é o criptograma
        return ct


#class adversario, deve ter 2 métodos: choose e guess.
class A:
    def __init__(self, a, b, c):
        self.a = a
        self.b = b
        self.c = c
    #deve escolher 2 mensagens para nós cifrarmos da lista m de mensagens inseridas pelo adversário
    def choose(a): #a=me
        f= random.choice(a)
        return f
        
    def guess(b, c): #b=lista de criptogramas c=criptograma
        if b[0]==c: #se o criptograma dado ao adversario for igual ao criptograma da mensagem[0] retornamos o crip de m[0]
            r=0
            return (r)
        elif b[1]==c:  #se o criptograma dado ao adversario for igual ao criptograma da mensagem[1] retornamos o crip de m[1]
            r=1
            return (r)
        for i in range(2, len(b), 1):  #se por acaso nas mensagens q o adversario testou (que começam no b[2]) ele encontrar o criptograma certo, retornamos esse crip
            if b[i]==c:
                return (b[i])
                break
        else: #quando tudo o resto falha, escolhe a mensagem 1 ou a mensagem 2 aleatoriamente
            bit=[0,1]
            r=random.choice(bit)
            return (r)


def IND_CPA():
    k = C.keygen()
    
    #vamos inserir as duas mensagens, para cifrar 1 delas
    me=[]
    me0="mensagem0"
    me.append(me0)
    me1="mensagem1"
    me.append(me1)
    me2="mensagem2"
    me.append(me2)
    m=[]
    m0 = A.choose(me)
    m.append(m0)
    m1 = A.choose(me)
    m.append(m1)
    bit=[0,1]
    b=random.choice(bit) #permite, aleatoriamente, cifrar a mensagem m[0] ou m[1]
    c = C.enc(k,m[b]) #c é o nosso criptograma, resulta de m[0] ou m[1]
    
    #lista é uma lista com todos os criptogramas gerados pelo adversario
    lista=[]
    #as entradas 0 e 1 desta lista sao as mensagens que nos foram dadas, desta feita cifradas. Estas entradas permitem ao A.guess() testar cifras determinísticas
    lista0=C.enc(k,m[0])
    lista.append(lista0)
    lista1=C.enc(k,m[1])
    lista.append(lista1)
    
    #m2 e m3 são as mensagens que o adversario decidiu testar e acrescentar à lista de criptogramas (na prática, o enc_oracle)
    m2="mensagem0"
    lista2=C.enc(k,m2)
    lista.append(lista2)
    m3="mensagem7"
    lista3=C.enc(k,m3)
    lista.append(lista3)
    m4="mensagem9"
    lista4=C.enc(k,m4)
    lista.append(lista4)
    # variavel 'lista' é uma lista de criptogramas: os criptogramas de m0, m1, m2="mensagem0" m3="mensagem1" e m4="mensagem2"
    c2 = A.guess(lista, c)
    if c==c2:
        print('Descobrimos o criptograma, estava na lista das mensagens extra geradas')
    elif b==c2:
        print('Descobrimos, a mensagem cifrada foi  m [',b,"]")
    else:
        print('Não descobrimos')


IND_CPA()
