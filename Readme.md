## Cryptography

This repository contains the resolution to exercises of a Cryptography class. This exercises were solved using python v3 environment.

## G1: Using Fernent to cipher a .txt file.

The goal was to cipher the message in the file "mensagem.txt" using the cipher _Fernet_ and thus ensuring data confidentiality and integrity.
The result of ciphering this file resulted in the file "mensagem_cifrada.txt". The key generated can be consulted in the file "key.txt" and using this file it is possible to recover the original message from the "mensagem_cifrada.txt" file.

---

## G2: Protection of cryptographic secrets

To cipher, "cifrar1.py" prompts the user for a passphrase that is used to generate a cryptographic key using PBKDF and salt. This key ciphers the message in the file "mensagem.txt."
To decipher, "decifrar1.py" prompts the user for the passphrase that should be equal to the one used
to cipher. Only if the resulting cryptographic key matches the "mensagem_cifrada.txt" is deciphered.


---

## G3: Encrypt then MAC

Using the cipher _ChaCha20_ it was possible to cipher the message in the "mensagem.txt" file. This was done
by prompting the user for a passphrase that using PBKDF2 generated the cryptographic keys key1 and key2.
key1 was used to cipher the message and key2 was used in the MAC and thus ensuring data confidentiality and integrity. This resulted in the cryptogram "mensagem_cifrada.txt"


---


## G4: Definitions of security - IND-CPA

ChaCha20 is a deterministic cipher and IND-CPA proves it.

---


## G5: Safe Client-Server communication

Both the client and server cipher their messages before sending them, resulting in a cryptogram. The receiver
of this cryptogram uses a tag to verify its integrity and thus ensuring that it has not been tempered with.
Only them, the receiver proceeds to decipher it.

---

## G6: Public-key cryptography in a Client-Server application

With the intent of using Public-key cryptography, both the server and the client generate private and public keys.
After sharing their public keys and generating the master key, communication may begin. The messages sent consist in
the concatenation of the cryptogram, initialization vector (iv) and the message authentication code (tag).

---

## G7: Update of G6 - using Digital signatures

The private and public keys used in G6 are used to generate the private and public digital signatures.
To exemplify: the server uses its private key to generate its signature and uses the client's public key to verify the signature that the client sent.

---


## G8: Update of G7 - using Public key certificate

To improve G7 public key certificates are now used in G8 to communicate the public keys, instead of saving them in .txt files.

---


## The repository

```
+-- Readme.md: file containing a description of the repository.
+-- G1
|    +-- cifrar.py: code to cipher the "mensagem.txt" file.
|    +-- decifrar.py: code to decipher the "mensagem_cifrada.txt" file.
|    +-- key.txt: file containing the key.
|    +-- mensagem.txt: message we want to cipher.
|    +-- mensagem_cifrada.txt: cryptogram.
|    +-- mensagem_recuperada.txt: result of deciphering.
|    
+-- G2
|    +-- cifrar1.py: code to cipher the "mensagem.txt" file.
|    +-- decifrar1.py: code to decipher the "mensagem_cifrada.txt" file.
|    +-- mensagem.txt: message we want to cipher.
|    +-- mensagem_cifrada.txt: cryptogram.
|    +-- mensagem_recuperada.txt: result of deciphering.
|
+-- G3
|    +-- E_MAC.py: code to implement the Encrypt then MAC.
|    +-- mensagem.txt: message we want to cipher.
|    +-- mensagem_cifrada.txt: cryptogram.
|
+-- G4
|    +-- IND_CPA.py: code to implement IND-CPA.
|
+-- G5
|    +-- cliente.py
|    +-- servidor.py
|
+-- G6
|    +-- cliente_G6.py
|    +-- servidor_G6.py
|
+-- G7
|    +-- Chaves_Assinatura_Servidor.py: code to generate the 
|        server's public key and private key, stored in files.
|    +-- Chaves_Assinatura_Cliente.py: code to generate the 
|        client's public key and private key, stored in files.
|    +-- client_G7.py
|    +-- client_private_key.txt: client's private key.
|    +-- client_public_key.txt: client's public key.
|    +-- server_G7.py
|    +-- server_private_key_assinatura.txt: server's private key.
|    +-- server_public_key_assinatura.txt: server's public key.
|
+-- G8
|    +-- CA.crt: root certificate.
|    +-- client.py
|    +-- Client1.p12: client's certificate
|    +-- server.py
|    +-- Servidor.p12: server's certificate

```

---

### Authors:
[Eduarda Vieira](https://github.com/eduardavieira)

[Cláudia Abreu](https://github.com/claudiarmabreu)

[José Alexandre Ferreira](https://github.com/jose-alexandre98)