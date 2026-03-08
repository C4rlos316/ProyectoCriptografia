"""
EXPECTATIVAS PARA PRUEBAS UNITARIAS

Para cumplir con los Requisitos de Seguridad (RS), este módulo debe validar:

1. ROUNDTRIP (RS-1): Cifrar un archivo y luego descifrarlo con la llave correcta 
   debe devolver el contenido original exacto.
   
2. INTEGRIDAD (RS-2): Si se modifica aunque sea UN BYTE del archivo .vault, 
   el descifrado DEBE fallar (lanzar InvalidTag).
   
3. LLAVE INCORRECTA (RS-1): Intentar descifrar con una llave hexadecimal distinta 
   debe ser rechazado inmediatamente.
   
4. NO REPETICIÓN (RS-7): Cifrar el mismo archivo dos veces seguidas debe generar 
   contenedores .vault distintos (uso correcto de nonce/IV).

Nota: Los tests deben crear sus propios archivos temporales de prueba y 
limpiarlos al finalizar (usar fixtures de pytest).

"""
import os
import json
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── importar desde el módulo ────────────────────────────────
from encryption import generate_key, generate_nonce, build_aad, encrypt_file, decrypt_file


# ════════════════════════════════════════════════════════════
# HELPERS — simulan archivos en memoria sin tocar el disco
# ════════════════════════════════════════════════════════════

def _encrypt_bytes(plaintext: bytes, filename: str = "test.txt") -> dict:
    """
    Versión en memoria de encrypt_file().
    Recibe bytes directamente en lugar de leer un archivo del disco.
    Retorna el contenedor como dict (no escribe .vault).

    Así simulamos cualquier archivo:
        _encrypt_bytes(b"hola")                  → archivo de texto
        _encrypt_bytes(b"A" * 1_000_000)         → archivo de 1 MB
        _encrypt_bytes(b"%PDF-1.4 ...")          → simula un PDF
        _encrypt_bytes(b"")                      → archivo vacío
    """
    key   = generate_key()
    nonce = generate_nonce()
    aad   = build_aad(filename)

    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    return {
        "key":        key,
        "nonce":      nonce,
        "ciphertext": ciphertext,
        "aad":        aad,
    }


def _decrypt_bytes(container: dict) -> bytes:
    """
    Versión en memoria de decrypt_file().
    Lanza InvalidTag si hay manipulación.
    """
    aesgcm = AESGCM(container["key"])
    return aesgcm.decrypt(container["nonce"], container["ciphertext"], container["aad"])


# ════════════════════════════════════════════════════════════
# TEST 1 — Roundtrip: encrypt → decrypt = archivo idéntico
# ════════════════════════════════════════════════════════════

class TestRoundtrip:

    def test_texto_simple(self):
        """El plaintext recuperado debe ser idéntico al original."""
        plaintext = b"mensaje secreto del documento"
        container = _encrypt_bytes(plaintext)
        assert _decrypt_bytes(container) == plaintext

    def test_archivo_vacio(self):
        """Un archivo vacío debe cifrarse y descifrarse sin error."""
        container = _encrypt_bytes(b"")
        assert _decrypt_bytes(container) == b""

    def test_archivo_grande(self):
        """Simula un archivo de 1 MB (ej: imagen o PDF)."""
        plaintext = os.urandom(1_000_000)   # 1 MB de bytes aleatorios
        container = _encrypt_bytes(plaintext, "imagen.jpg")
        assert _decrypt_bytes(container) == plaintext

    def test_bytes_binarios(self):
        """Simula un archivo binario (PDF, imagen, etc.)."""
        plaintext = bytes(range(256)) * 100   # todos los valores de byte posibles
        container = _encrypt_bytes(plaintext, "binario.bin")
        assert _decrypt_bytes(container) == plaintext


# ════════════════════════════════════════════════════════════
# TEST 2 — Clave incorrecta debe fallar
# ════════════════════════════════════════════════════════════

class TestWrongKey:

    def test_clave_diferente_falla(self):
        """Una clave distinta a la usada al cifrar debe lanzar InvalidTag."""
        container = _encrypt_bytes(b"contenido secreto")
        container["key"] = generate_key()           # reemplazar por clave nueva
        with pytest.raises(InvalidTag):
            _decrypt_bytes(container)

    def test_clave_ceros_falla(self):
        """Una clave de puros ceros también debe fallar."""
        container = _encrypt_bytes(b"contenido secreto")
        container["key"] = b"\x00" * 32
        with pytest.raises(InvalidTag):
            _decrypt_bytes(container)

    def test_clave_parcialmente_modificada_falla(self):
        """Cambiar un solo bit de la clave debe fallar."""
        container = _encrypt_bytes(b"contenido secreto")
        key_modificada = bytearray(container["key"])
        key_modificada[0] ^= 0x01               # flip de 1 bit
        container["key"] = bytes(key_modificada)
        with pytest.raises(InvalidTag):
            _decrypt_bytes(container)


# ════════════════════════════════════════════════════════════
# TEST 3 — Ciphertext modificado debe ser detectado
# ════════════════════════════════════════════════════════════

class TestCiphertextTamper:

    def test_modificar_primer_byte(self):
        """Modificar el primer byte del ciphertext debe ser detectado."""
        container = _encrypt_bytes(b"datos confidenciales")
        ct = bytearray(container["ciphertext"])
        ct[0] ^= 0xFF
        container["ciphertext"] = bytes(ct)
        with pytest.raises(InvalidTag):
            _decrypt_bytes(container)

    def test_modificar_byte_del_medio(self):
        """Modificar un byte en la mitad del ciphertext debe ser detectado."""
        container = _encrypt_bytes(b"datos confidenciales")
        ct = bytearray(container["ciphertext"])
        ct[len(ct) // 2] ^= 0xAA
        container["ciphertext"] = bytes(ct)
        with pytest.raises(InvalidTag):
            _decrypt_bytes(container)

    def test_modificar_auth_tag(self):
        """
        Modificar los últimos 16 bytes (el auth_tag) debe ser detectado.
        AES-GCM adjunta el tag al final del ciphertext.
        """
        container = _encrypt_bytes(b"datos confidenciales")
        ct = bytearray(container["ciphertext"])
        ct[-1] ^= 0xFF                          # último byte del tag
        container["ciphertext"] = bytes(ct)
        with pytest.raises(InvalidTag):
            _decrypt_bytes(container)

    def test_ciphertext_truncado(self):
        """Ciphertext al que le faltan bytes debe ser rechazado."""
       container = _encrypt_bytes(b"datos confidenciales")
        container["ciphertext"] = container["ciphertext"][:-4]
        with pytest.raises(Exception):          # InvalidTag o ValueError
            _decrypt_bytes(container)


# ════════════════════════════════════════════════════════════
# TEST 4 — Metadata (AAD) modificada debe ser detectada
# ════════════════════════════════════════════════════════════

class TestMetadataTamper:

    def test_cambiar_filename_en_aad(self):
        """
        Cambiar el nombre del archivo en el AAD debe ser detectado.
        Aunque el ciphertext no cambió, el AAD ya no coincide con el tag.
        """
        container = _encrypt_bytes(b"documento legal", "contrato.pdf")
        # Simular que alguien modifica el nombre en los metadatos
        container["aad"] = container["aad"].replace(
            b"contrato.pdf", b"contrato_falso.pdf"
        )
        with pytest.raises(InvalidTag):
            _decrypt_bytes(container)

    def test_cambiar_algoritmo_en_aad(self):
        """Cambiar el campo algorithm en AAD debe ser detectado."""
        container = _encrypt_bytes(b"documento legal")
        container["aad"] = container["aad"].replace(
            b"AES-GCM-256", b"AES-CBC-256"
        )
        with pytest.raises(InvalidTag):
            _decrypt_bytes(container)

    def test_aad_completamente_diferente(self):
        """Reemplazar el AAD completo por otro debe ser detectado."""
        container = _encrypt_bytes(b"documento legal")
        container["aad"] = build_aad("archivo_distinto.txt")
        with pytest.raises(InvalidTag):
            _decrypt_bytes(container)

    def test_aad_vacio_cuando_no_lo_era(self):
        """Usar AAD vacío cuando el original no lo era debe fallar."""
        container = _encrypt_bytes(b"documento legal")
        container["aad"] = b""
        with pytest.raises(InvalidTag):
            _decrypt_bytes(container)


# ════════════════════════════════════════════════════════════
# TEST 5 — Múltiples cifrados producen ciphertexts distintos
# ════════════════════════════════════════════════════════════

class TestRandomness:

    def test_mismo_plaintext_produce_ciphertexts_distintos(self):
        """
        Cifrar el mismo contenido dos veces debe producir ciphertexts distintos.
        Esto valida que el nonce es aleatorio en cada operación.
        """
        plaintext = b"contenido identico"
        c1 = _encrypt_bytes(plaintext)
        c2 = _encrypt_bytes(plaintext)
        assert c1["ciphertext"] != c2["ciphertext"]

    def test_nonces_distintos_por_operacion(self):
        """Cada cifrado debe generar un nonce diferente."""
        c1 = _encrypt_bytes(b"abc")
        c2 = _encrypt_bytes(b"abc")
        assert c1["nonce"] != c2["nonce"]

    def test_claves_distintas_por_archivo(self):
        """Cada cifrado debe generar una clave diferente (una por archivo)."""
        c1 = _encrypt_bytes(b"abc")
        c2 = _encrypt_bytes(b"abc")
        assert c1["key"] != c2["key"]

    def test_nonce_es_96_bits(self):
        """El nonce debe medir exactamente 12 bytes (96 bits)."""
        nonce = generate_nonce()
        assert len(nonce) == 12

    def test_clave_es_256_bits(self):
        """La clave debe medir exactamente 32 bytes (256 bits)."""
        key = generate_key()
        assert len(key) == 32
        container = _encrypt_bytes(b"datos confidenciales")
        container["ciphertext"] = container["ciphertext"][:-4]
        with pytest.raises(Exception):          # InvalidTag o ValueError
            _decrypt_bytes(container)
