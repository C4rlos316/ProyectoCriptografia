import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag

# ══════════════════════════════════════════════════════════
# Funciones usadas por los tests 
# ══════════════════════════════════════════════════════════

def generate_key() -> bytes:
    """Genera una clave AES-256 aleatoria (32 bytes)."""
    return AESGCM.generate_key(bit_length=256)


def generate_nonce() -> bytes:
    """Genera un nonce de 96 bits (12 bytes) — tamaño estándar para AES-GCM."""
    return os.urandom(12)


def build_aad(filename: str) -> bytes:
    """
    Construye el Additional Authenticated Data (AAD) a partir del nombre de archivo.
    El AAD se autentica pero NO se cifra: si alguien lo modifica, el descifrado falla.
    """
    aad_dict = {
        "filename":  filename,
        "algorithm": "AES-GCM-256",
        "version":   "1.0",
    }
    return json.dumps(aad_dict, sort_keys=True).encode()


def encrypt_file(input_path: str, output_path: str) -> bytes:
    """
    Cifra un archivo con AES-GCM-256 y guarda el contenedor .vault.
    Retorna la clave utilizada.
    """
    key   = generate_key()
    nonce = generate_nonce()
    aad   = build_aad(os.path.basename(input_path))

    with open(input_path, "rb") as f:
        plaintext = f.read()

    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    container = {
        "nonce":      nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "aad":        aad.decode(),
    }
    with open(output_path, "w") as f:
        json.dump(container, f, indent=2)

    return key


def decrypt_file(vault_path: str, output_path: str, key: bytes) -> None:
    """
    Descifra un contenedor .vault con la clave provista.
    Lanza InvalidTag si el archivo fue modificado o la clave es incorrecta.
    """
    with open(vault_path, "r") as f:
        container = json.load(f)

    nonce      = bytes.fromhex(container["nonce"])
    ciphertext = bytes.fromhex(container["ciphertext"])
    aad        = container["aad"].encode()

    aesgcm    = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad) 

    with open(output_path, "wb") as f:
        f.write(plaintext)

def encrypt_file_hybrid(input_path, output_path, public_key_paths):
    """
    Cifra un archivo usando AES-GCM y envuelve la llave con RSA para N destinatarios.
    """
    # 1. Preparar datos simétricos (D2)
    file_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    with open(input_path, "rb") as f:
        plaintext = f.read()
    
    aad = json.dumps({"filename": os.path.basename(input_path), "version": "2.0"}, sort_keys=True).encode()
    aesgcm = AESGCM(file_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # 2. Cifrar la 'file_key' para cada destinatario 
    recipients_list = []
    for pub_path in public_key_paths:
        with open(pub_path, "rb") as f:
            pub_key = serialization.load_pem_public_key(f.read())
        
        # Envolver la llave de archivo con la pública del usuario
        enc_key = pub_key.encrypt(
            file_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        recipients_list.append({
            "recipient_id": os.path.basename(pub_path),
            "encrypted_key": enc_key.hex()
        })

    # 3. Guardar contenedor final
    container = {
        "header": json.loads(aad.decode()),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "recipients": recipients_list
    }

    with open(output_path, "w") as f:
        json.dump(container, f, indent=2)
    print(f"[+] Archivo protegido para {len(public_key_paths)} destinatarios.")

def decrypt_file_hybrid(vault_path, output_path, private_key_path):
    """
    Busca la llave cifrada correspondiente a la privada del usuario y descifra.
    """
    with open(vault_path, "r") as f:
        container = json.load(f)
    
    with open(private_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)

    # 1. Intentar descifrar alguna de las llaves en la lista 'recipients'
    file_key = None
    for entry in container["recipients"]:
        try:
            encrypted_key_bytes = bytes.fromhex(entry["encrypted_key"])
            file_key = priv_key.decrypt(
                encrypted_key_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            break # Si logramos descifrar una, ya tenemos la file_key
        except Exception:
            continue

    if not file_key:
        raise ValueError("No se encontró una llave para este usuario o la privada es incorrecta.")

    # 2. Descifrar el contenido con AES-GCM
    nonce = bytes.fromhex(container["nonce"])
    ciphertext = bytes.fromhex(container["ciphertext"])
    aad = json.dumps(container["header"], sort_keys=True).encode()
    
    aesgcm = AESGCM(file_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise InvalidTag(
            "El archivo fue modificado o está corrupto (la autenticación AES-GCM falló)."
        )
    
    with open(output_path, "wb") as f:
        f.write(plaintext)
    print(f"[+] Archivo recuperado exitosamente.")