from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_user_keys(user_name):
    # 1. Generar la llave privada RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # 2. Guardar Privada
    priv_file = f"{user_name}_private.pem"
    with open(priv_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 3. Guardar Pública
    pub_file = f"{user_name}_public.pem"
    public_key = private_key.public_key()
    with open(pub_file, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"✅ Identidad generada con éxito para '{user_name}'")
    print(f"   - Creado: {priv_file}")
    print(f"   - Creado: {pub_file}")