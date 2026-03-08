"""
Módulo de cifrado autenticado - Secure Digital Document Vault
Algoritmo : AES-GCM-256 (AEAD)
Librería  : cryptography (PyCA)
"""

import os
import json
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─────────────────────────────────────────────────────────────
# GENERACIÓN DE CLAVE Y NONCE
# ─────────────────────────────────────────────────────────────

def generate_key() -> bytes:
    """
    Genera una clave simétrica de 256 bits usando el CSPRNG del OS.
    Una clave nueva por cada archivo → RS-7 (Separación de claves).
    """
    return AESGCM.generate_key(bit_length=256)


def generate_nonce() -> bytes:
    """
    Genera un nonce de 96 bits.
    Se genera con os.urandom → nunca predecible.

    ¿Por qué no reutilizar el nonce?
    Si el mismo nonce se usa dos veces con la misma clave en AES-GCM:
      1. XOR(C1, C2) = XOR(P1, P2) → el atacante deduce contenido
      2. El auth_tag puede forjarse → autenticación completamente rota
    """
    return os.urandom(12)


# ─────────────────────────────────────────────────────────────
# METADATA (AAD — Associated Authenticated Data)
# ─────────────────────────────────────────────────────────────

def build_aad(filename: str) -> bytes:
    """
    Construye el AAD a partir de los metadatos del archivo.

    El AAD NO se cifra (es legible en el contenedor),
    pero SÍ está autenticado criptográficamente por el auth_tag de AES-GCM.
    Si alguien modifica filename, algorithm, version o timestamp → InvalidTag.

    sort_keys=True garantiza orden determinista → mismo bytes al descifrar.
    """
    metadata = {
        "algorithm": "AES-GCM-256",
        "filename": filename,
        "timestamp": int(time.time()),
        "version": "1.0",
    }
    # sort_keys=True garantiza que el JSON sea idéntico
    # al momento de cifrar y al momento de descifrar.
    # Sin esto, el orden de las llaves puede cambiar y el AAD no coincide.
    return json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")


# ─────────────────────────────────────────────────────────────
# CIFRADO — escribe archivo .vault
# ─────────────────────────────────────────────────────────────

def encrypt_file(input_path: str, output_path: str) -> bytes:
    """
    Lee un archivo, lo cifra con AES-GCM y guarda el contenedor .vault.

    Estructura del contenedor (JSON):
    {
        "header"    : { filename, algorithm, version, timestamp },
        "nonce"     : "hex...",
        "ciphertext": "hex..."   ← incluye los 16 bytes del auth_tag al final
    }

    Args:
        input_path  : Ruta del archivo a cifrar
        output_path : Ruta donde se guarda el .vault

    Returns:
        key (bytes): Clave usada. En D2 se retorna para uso inmediato.
                     En D3+ se protegerá con la clave pública del destinatario.
    """
    # 1. Leer archivo original
    with open(input_path, "rb") as f:
        plaintext = f.read()

    # 2. Generar clave y nonce únicos para este archivo
    key   = generate_key()
    nonce = generate_nonce()

    # 3. Construir AAD con los metadatos
    filename = os.path.basename(input_path)
    aad      = build_aad(filename)

    # 4. Cifrar con AES-GCM
    #    aesgcm.encrypt(nonce, plaintext, aad) → ciphertext
    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # 5. Ensamblar contenedor y guardar como JSON
    container = {
        "header":     json.loads(aad.decode("utf-8")),   # legible en el archivo
        "nonce":      nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }

    with open(output_path, "w") as f:
        json.dump(container, f, indent=2)

    print(f"\n[✓] Archivo cifrado: {output_path}")
    print(f"    Nonce      : {nonce.hex()}")
    print(f"    Ciphertext : {len(ciphertext)} bytes (plaintext + 16 bytes auth_tag)")
    print(f"    Metadata   : {json.loads(aad)}")

    return key


# ─────────────────────────────────────────────────────────────
# DESCIFRADO — lee archivo .vault y escribe plaintext
# ─────────────────────────────────────────────────────────────

def decrypt_file(vault_path: str, output_path: str, key: bytes) -> bool:
    """
    Lee un contenedor .vault, verifica el auth_tag y descifra el archivo.

    AES-GCM verifica la autenticación ANTES de retornar el plaintext.
    Si el ciphertext O el AAD fueron modificados → falla con InvalidTag.

    Args:
        vault_path  : Ruta al archivo .vault
        output_path : Ruta donde se escribe el archivo descifrado
        key         : Clave simétrica de 32 bytes

    Returns:
        True si el descifrado fue exitoso, False si hubo manipulación.
    """
    # 1. Cargar contenedor
    with open(vault_path, "r") as f:
        container = json.load(f)

    # 2. Reconstruir AAD exactamente igual que al cifrar
    #    sort_keys=True asegura el mismo orden de llaves → mismo bytes
    aad        = json.dumps(container["header"], separators=(",", ":"), sort_keys=True).encode("utf-8")
    nonce      = bytes.fromhex(container["nonce"])
    ciphertext = bytes.fromhex(container["ciphertext"])

    # 3. Descifrar y verificar auth_tag
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        with open(output_path, "wb") as f:
            f.write(plaintext)
        print(f"\n[✓] Descifrado exitoso: {output_path}")
        print(f"    Contenido: {plaintext[:80]}{'...' if len(plaintext) > 80 else ''}")
        return True
    except Exception:
        print("\n[✗] ERROR: autenticación fallida — el archivo fue manipulado o la clave es incorrecta.")
        return False


# ─────────────────────────────────────────────────────────────
# DEMO — simula el flujo completo con un archivo de prueba
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":

    print("=" * 55)
    print("   SECURE DIGITAL DOCUMENT VAULT — Demo D2")
    print("=" * 55)

    # ── Crear archivo de prueba ──────────────────────────────
    with open("test.txt", "w") as f:
        f.write("Este es el contenido secreto del documento de prueba.\n")
        f.write("Solo el destinatario autorizado puede leer esto.")

    print("\n[i] Archivo original creado: test.txt")

    # ── Cifrar ───────────────────────────────────────────────
    print("\n--- CIFRANDO ---")
    key = encrypt_file("test.txt", "test.vault")
    print(f"    Clave (hex): {key.hex()[:32]}...  ← guardar esto")

    # ── Descifrar con clave correcta ─────────────────────────
    print("\n--- DESCIFRANDO (clave correcta) ---")
    decrypt_file("test.vault", "test_decrypted.txt", key)

    # ── Simular clave incorrecta ─────────────────────────────
    print("\n--- DESCIFRANDO (clave incorrecta) ---")
    wrong_key = AESGCM.generate_key(bit_length=256)
    decrypt_file("test.vault", "test_wrong.txt", wrong_key)

    # ── Simular manipulación del ciphertext ──────────────────
    print("\n--- SIMULANDO MANIPULACIÓN DEL CIPHERTEXT ---")
    with open("test.vault", "r") as f:
        tampered = json.load(f)

    original_ct = tampered["ciphertext"]
    ct_bytes    = bytearray(bytes.fromhex(original_ct))
    ct_bytes[0] ^= 0xFF                                    # modificar primer byte
    tampered["ciphertext"] = ct_bytes.hex()

    with open("test_tampered.vault", "w") as f:
        json.dump(tampered, f)

    decrypt_file("test_tampered.vault", "test_tampered_out.txt", key)

    # ── Simular manipulación del metadata ────────────────────
    print("\n--- SIMULANDO MANIPULACIÓN DE METADATA (AAD) ---")
    with open("test.vault", "r") as f:
        meta_tampered = json.load(f)

    meta_tampered["header"]["filename"] = "archivo_falso.txt"  # cambiar nombre

    with open("test_meta_tampered.vault", "w") as f:
        json.dump(meta_tampered, f)

    decrypt_file("test_meta_tampered.vault", "test_meta_out.txt", key)

    print("\n" + "=" * 55)
    print("   Archivos generados:")
    print("   test.txt              ← original")
    print("   test.vault            ← contenedor cifrado")
    print("   test_decrypted.txt    ← descifrado correctamente")
    print("=" * 55)