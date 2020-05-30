
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def process():
            cliente_private_key_assinatura = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            # serializar chave privada do cliente
            cliente_private_key_assinatura_serializable = cliente_private_key_assinatura.private_bytes(
                encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption())
            # gerar chave publica do cliente
            cliente_public_key_assinatura = cliente_private_key_assinatura.public_key()
            # serializar chave publica do cliente
            cliente_public_key_assinatura_serializable = cliente_public_key_assinatura.public_bytes(
                encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)

            clientSK = open("client_private_key.txt", "wb")
            clientSK.write(cliente_private_key_assinatura_serializable)
            clientSK.close()
            clientPK = open("client_public_key.txt", "wb")
            clientPK.write(cliente_public_key_assinatura_serializable)
            clientPK.close()


######################
process()
