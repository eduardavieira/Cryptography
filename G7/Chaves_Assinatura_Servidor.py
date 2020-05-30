
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization



def gera():
    server_private_key_assinatura = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # serializar chave privada do cliente
    server_private_key_assinatura_serializable = server_private_key_assinatura.private_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    # gerar chave publica do cliente
    server_public_key_assinatura = server_private_key_assinatura.public_key()
    # serializar chave publica do cliente
    server_public_key_assinatura_serializable = server_public_key_assinatura.public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    serverSK = open("server_private_key_assinatura.txt", "wb")
    serverSK.write(server_private_key_assinatura_serializable)
    serverSK.close()
    serverPK = open("server_public_key_assinatura.txt", "wb")
    serverPK.write(server_public_key_assinatura_serializable)
    serverPK.close()


gera()