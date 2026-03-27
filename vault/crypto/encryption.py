import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# ... (Mantén tus funciones generate_key, generate_nonce y build_aad igual) ...

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

    # 2. Cifrar la 'file_key' para cada destinatario (D3 - Híbrido)
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
    print(f"[✓] Archivo protegido para {len(public_key_paths)} destinatarios.")

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
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    
    with open(output_path, "wb") as f:
        f.write(plaintext)
    print(f"[✓] Archivo recuperado exitosamente.")