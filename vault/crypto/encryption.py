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