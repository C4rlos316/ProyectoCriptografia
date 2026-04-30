import re

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# ── Validación de entrada ──────────────────────────────────
_VALID_USERNAME = re.compile(r"^[a-zA-Z0-9_-]+$")


def _validate_username(user_name: str) -> None:
    """
    Valida que el nombre de usuario solo contenga caracteres seguros.
    Rechaza entradas vacías y caracteres que podrían causar path traversal
    (e.g. '../', '/', '\\', '.').
    """
    if not user_name or not _VALID_USERNAME.match(user_name):
        raise ValueError(
            f"Nombre de usuario inválido: '{user_name}'. "
            "Solo se permiten letras, números, guiones y guiones bajos."
        )


def generate_user_keys(user_name):
    _validate_username(user_name)
    # 1. Generar la llave privada RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    priv_file = f"{user_name}_private.pem"
    pub_file  = f"{user_name}_public.pem"

    with open(priv_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(pub_file, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    print(f"[OK] Identidad RSA generada para '{user_name}'")
    print(f"   - Creado: {priv_file}")
    print(f"   - Creado: {pub_file}")


def generate_signing_keys(user_name: str):
    """
    Genera un par de llaves Ed25519 para firma digital.
    Guarda: {user_name}_signing_private.pem  y  {user_name}_signing_public.pem
    """
    _validate_username(user_name)
    private_key = Ed25519PrivateKey.generate()

    priv_file = f"{user_name}_signing_private.pem"
    pub_file  = f"{user_name}_signing_public.pem"

    with open(priv_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(pub_file, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    print(f"[OK] Llaves de firma Ed25519 generadas para '{user_name}'")
    print(f"   - Creado: {priv_file}")
    print(f"   - Creado: {pub_file}")