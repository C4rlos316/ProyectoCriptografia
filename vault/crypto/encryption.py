import hashlib
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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
        "algorithm": "AES-GCM-256",
        "filename":  filename,
        "version":   "1.0",
    }
    return json.dumps(aad_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")


def encrypt_file(input_path: str, output_path: str) -> bytes:
    """
    Cifra un archivo con AES-GCM-256 y guarda el contenedor .vault.
    Retorna la clave utilizada (el usuario debe guardarla para descifrar).
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
        "aad":        aad.decode("utf-8"),
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
    aad        = container["aad"].encode("utf-8")

    aesgcm    = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

    with open(output_path, "wb") as f:
        f.write(plaintext)


# ══════════════════════════════════════════════════════════════════════════════
# FIRMAS DIGITALES
# ══════════════════════════════════════════════════════════════════════════════

def _get_signing_fingerprint(public_key) -> str:
    """
    Calcula el fingerprint SHA-256 de una llave pública Ed25519.
    Retorna los primeros 32 caracteres hex.
    """
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pub_bytes).hexdigest()[:32]


def _build_signable(header: dict, ciphertext_hex: str) -> bytes:
    """
    Construye el mensaje que se firma:
        SHA-256( ciphertext_hex_bytes || header_json_bytes )

      - ciphertext_hex : el archivo cifrado; cualquier modificación invalida la firma.
      - header (AAD)   : filename, recipients, version; impide manipular metadatos.

    """
    header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    material = ciphertext_hex.encode("utf-8") + header_bytes
    return hashlib.sha256(material).digest()


def sign_container(header: dict, ciphertext_hex: str, signing_priv_path: str) -> tuple:
    """
    Firma el contenedor usando la llave privada Ed25519 del remitente.

    El signer_id permite al destinatario identificar qué llave pública usar
    para verificar, sin necesidad de probar cada llave disponible.
    """
    with open(signing_priv_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)

    signable  = _build_signable(header, ciphertext_hex)
    signature = priv_key.sign(signable)

    signer_id = _get_signing_fingerprint(priv_key.public_key())
    return signature.hex(), signer_id


def verify_signature(container: dict, signing_pub_path: str) -> None:
    """
    Verifica la firma digital del contenedor ANTES de cualquier descifrado.

    """
    if "signature" not in container or "signer_id" not in container:
        raise ValueError(
            "El contenedor no contiene firma digital. "
            "Archivo rechazado por falta de autenticación de origen."
        )

    with open(signing_pub_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())

    signable       = _build_signable(container["header"], container["ciphertext"])
    signature_bytes = bytes.fromhex(container["signature"])

    try:
        pub_key.verify(signature_bytes, signable)
    except Exception:
        raise ValueError(
            "Firma inválida: el archivo fue modificado o el remitente no coincide. "
            "Archivo rechazado."
        )


# ══════════════════════════════════════════════════════════════════════════════
# CIFRADO / DESCIFRADO HÍBRIDO
# ══════════════════════════════════════════════════════════════════════════════

def _get_key_fingerprint(public_key) -> str:
    """
    Calcula el fingerprint SHA-256 de una llave pública RSA (formato DER).
    Primeros 32 caracteres hex → 128 bits de entropía → identificador de destinatario.
    """
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pub_bytes).hexdigest()[:32]


def encrypt_file_hybrid(
    input_path: str,
    output_path: str,
    public_key_paths: list,
    signing_priv_path: str = None,
) -> None:
    """
    Cifra un archivo usando cifrado híbrido AES-GCM + RSA-OAEP para N destinatarios.
    Si se proporciona signing_priv_path, firma el contenedor con Ed25519.
    """
    # ── 1. Generar datos simétricos───
    file_key = AESGCM.generate_key(bit_length=256)
    nonce    = os.urandom(12)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    # ── 2. Cifrar con AES-GCM-256 ──
    # Primera pasada: calcular fingerprints.
    recipients_list = []
    recipient_ids   = []
    for pub_path in public_key_paths:
        with open(pub_path, "rb") as f:
            pub_key = serialization.load_pem_public_key(f.read())

        rid = _get_key_fingerprint(pub_key)
        recipient_ids.append(rid)

        enc_key = pub_key.encrypt(
            file_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        recipients_list.append({
            "recipient_id":  rid,
            "encrypted_key": enc_key.hex(),
        })

    # ── 3. Construir AAD con lista ordenada de IDs ──
    header = {
        "filename":   os.path.basename(input_path),
        "recipients": sorted(recipient_ids),
        "version":    "2.0",
    }
    aad = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")

    # ── 4. Cifrar datos ──
    aesgcm     = AESGCM(file_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # ── 5. Guardar contenedor ──
    container = {
        "header":     header,
        "nonce":      nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "recipients": recipients_list,
    }

    # ── 6. Firma digital ─────
    if signing_priv_path:
        sig_hex, signer_id = sign_container(
            container["header"],
            container["ciphertext"],
            signing_priv_path,
        )
        container["signature"] = sig_hex
        container["signer_id"] = signer_id

    with open(output_path, "w") as f:
        json.dump(container, f, indent=2)

    signed_msg = " y firmado digitalmente" if signing_priv_path else ""
    print(f"[+] Archivo cifrado{signed_msg} para {len(public_key_paths)} destinatario(s).")


def decrypt_file_hybrid(
    vault_path: str,
    output_path: str,
    private_key_path: str,
    signing_pub_path: str = None,
) -> None:
    """
    Descifra un contenedor .vault con la llave privada RSA del destinatario.
    Si se proporciona signing_pub_path, verifica la firma Ed25519 PRIMERO.

    """
    with open(vault_path, "r") as f:
        container = json.load(f)

    # ── Verificar firma ANTES de cualquier descifrado ───
    if signing_pub_path:
        verify_signature(container, signing_pub_path)
    elif "signature" in container:
        # Contenedor firmado pero no se proporcionó llave de verificación: rechazar.
        raise ValueError(
            "El contenedor contiene una firma digital pero no se proporcionó "
            "la llave pública del remitente para verificarla. "
            "Use --firma-publica para verificar el origen del archivo."
        )

    # ── Cargar llave privada RSA del destinatario ───
    with open(private_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)

    # ── Buscar la entrada del destinatario por fingerprint  ───
    my_id = _get_key_fingerprint(priv_key.public_key())
    recipients_index = {
        entry["recipient_id"]: entry
        for entry in container["recipients"]
    }

    if my_id not in recipients_index:
        raise ValueError(
            "Este usuario no está en la lista de destinatarios autorizados."
        )

    # ── Desenvolver la file_key con RSA-OAEP ────
    encrypted_key_bytes = bytes.fromhex(recipients_index[my_id]["encrypted_key"])
    try:
        file_key = priv_key.decrypt(
            encrypted_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception:
        raise ValueError(
            "No se pudo desenvolver la llave de archivo. "
            "La llave privada no corresponde a este contenedor."
        )

    # ── Reconstruir AAD y descifrar con AES-GCM ────
    nonce      = bytes.fromhex(container["nonce"])
    ciphertext = bytes.fromhex(container["ciphertext"])
    aad        = json.dumps(
        container["header"], separators=(",", ":"), sort_keys=True
    ).encode("utf-8")

    aesgcm = AESGCM(file_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise ValueError(
            "Autenticación AES-GCM fallida: el archivo fue modificado o está corrupto."
        )

    with open(output_path, "wb") as f:
        f.write(plaintext)

    verified_msg = " Firma verificada:  OK" if signing_pub_path else ""
    print(f"[+] Archivo recuperado exitosamente{verified_msg}.")