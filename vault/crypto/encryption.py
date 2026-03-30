"""
encryption.py - Cifrado hibrido para multiples destinatarios

Librerias utilizadas:
  - cryptography (PyCA): AES-GCM-256 + RSA-OAEP con SHA-256.
"""

import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization


# ----------------------------------------------------------------
#  FINGERPRINT - Identificador unico de cada clave publica
# ----------------------------------------------------------------

def get_key_fingerprint(public_key) -> str:
    """
    Genera un ID unico a partir de una clave publica.

      - Convierte la clave publica a bytes.
      - Le aplica SHA-256.
      - Toma los primeros 32 caracteres hex como identificador.
    """
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pub_bytes).hexdigest()[:32]


# ----------------------------------------------------------------
#  CIFRADO 
# ----------------------------------------------------------------

def encrypt_file_hybrid(input_path, output_path, public_key_paths):
    """
    Cifra un archivo para multiples destinatarios usando cifrado hibrido.

    Parametros:
      - input_path:       ruta del archivo
      - output_path:      ruta donde se guardara el .vault
      - public_key_paths: lista de rutas a las claves publicas de los destinatarios

    El archivo resultante (.vault) contiene:
      - header:      metadatos autenticados (nombre, version, lista de destinatarios)
      - recipients:  la file_key cifrada para cada destinatario
      - nonce:       valor aleatorio usado en AES-GCM
      - ciphertext:  el archivo cifrado
    """

    # 1. Leer el archivo original
    with open(input_path, "rb") as f:
        plaintext = f.read()

    # 2. Generar la clave simetrica (file_key) y un nonce aleatorio
    file_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    # 3. Para cada destinatario: calcular su ID y cifrar la file_key con su clave publica
    recipients_list = []
    recipient_ids = []

    for pub_path in public_key_paths:
        # Cargar la clave publica del destinatario
        with open(pub_path, "rb") as f:
            pub_key = serialization.load_pem_public_key(f.read())

        # Calcular el ID unico del destinatario
        recipient_id = get_key_fingerprint(pub_key)
        recipient_ids.append(recipient_id)

        # Cifrar la llave con RSA-OAEP (solo cifra 32 bytes, no el archivo completo)
        enc_key = pub_key.encrypt(
            file_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        recipients_list.append({
            "recipient_id": recipient_id,
            "encrypted_key": enc_key.hex()
        })

    # 4. Construir el AAD

    aad = json.dumps(
        {
            "filename": os.path.basename(input_path),
            "recipients": sorted(recipient_ids),
            "version": "2.0"
        },
        separators=(",", ":"),
        sort_keys=True
    ).encode()

    # 5. Cifrar el archivo con AES-GCM usando la file_key
    aesgcm = AESGCM(file_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # 6. Guardar el contenedor .vault
    container = {
        "header": json.loads(aad.decode()),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "recipients": recipients_list
    }

    with open(output_path, "w") as f:
        json.dump(container, f, indent=2)

    print(f"[+] Archivo protegido para {len(public_key_paths)} destinatarios.")


# ----------------------------------------------------------------
#  DESCIFRADO
# ----------------------------------------------------------------

def decrypt_file_hybrid(vault_path, output_path, private_key_path):
    """
    Descifra un archivo .vault usando la clave privada del destinatario.

    Parametros:
      - vault_path:       ruta del archivo .vault cifrado
      - output_path:      ruta donde se guardara el archivo recuperado
      - private_key_path: ruta a la clave privada del usuario (.pem)
    """

    # 1. Leer el contenedor .vault
    with open(vault_path, "r") as f:
        container = json.load(f)

    # 2. Cargar la clave privada del usuario
    with open(private_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)

    # 3. Calcular mi ID el fingerprint y buscar la entrada en la lista de destinatarios
    my_id = get_key_fingerprint(priv_key.public_key())
    recipients_index = {entry["recipient_id"]: entry for entry in container["recipients"]}

    if my_id not in recipients_index:
        raise ValueError("No se encontro una llave para este usuario o la privada es incorrecta.")

    # 4. Descifrar la file_key usando mi clave privada (RSA-OAEP)
    encrypted_key_bytes = bytes.fromhex(recipients_index[my_id]["encrypted_key"])
    try:
        file_key = priv_key.decrypt(
            encrypted_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception:
        raise ValueError("No se encontro una llave para este usuario o la privada es incorrecta.")

    # 5. Reconstruir el AAD exactamente como se hizo al cifrar
    #    (mismos separadores y orden de claves para que los bytes coincidan)
    aad = json.dumps(container["header"], separators=(",", ":"), sort_keys=True).encode()

    # 6. Descifrar el archivo con AES-GCM
    nonce = bytes.fromhex(container["nonce"])
    ciphertext = bytes.fromhex(container["ciphertext"])

    aesgcm = AESGCM(file_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

    # 7. Guardar el archivo recuperado
    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"[+] Archivo recuperado exitosamente.")