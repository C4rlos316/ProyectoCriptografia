import os
import json
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.asymmetric import rsa
from vault.crypto.encryption import encrypt_file_hybrid, decrypt_file_hybrid
from cryptography.hazmat.primitives import serialization


# ════════════════════════════════════════════════════════════
# HELPERS — funciones auxiliares para los tests
# ════════════════════════════════════════════════════════════

def _generate_key() -> bytes:
    """Genera una clave AES-256 (32 bytes)."""
    return AESGCM.generate_key(bit_length=256)


def _generate_nonce() -> bytes:
    """Genera un nonce de 96 bits (12 bytes)."""
    return os.urandom(12)


def _build_aad(filename: str) -> bytes:
    """Construye un AAD simple para los tests de D2."""
    import time
    metadata = {
        "algorithm": "AES-GCM-256",
        "filename": filename,
        "timestamp": int(time.time()),
        "version": "1.0",
    }
    return json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _encrypt_bytes(plaintext: bytes, filename: str = "test.txt") -> dict:
    """Cifra bytes en memoria y retorna el contenedor como dict."""
    key   = _generate_key()
    nonce = _generate_nonce()
    aad   = _build_aad(filename)

    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    return {
        "key":        key,
        "nonce":      nonce,
        "ciphertext": ciphertext,
        "aad":        aad,
    }


def _decrypt_bytes(container: dict) -> bytes:
    """Descifra un contenedor en memoria. Lanza InvalidTag si hay manipulacion."""
    aesgcm = AESGCM(container["key"])
    return aesgcm.decrypt(container["nonce"], container["ciphertext"], container["aad"])

def _generate_rsa_pair(tmp_dir, username):
    """
    Genera un par de llaves RSA y las guarda como archivos .pem
    en el directorio temporal. Retorna (ruta_publica, ruta_privada).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    priv_path = os.path.join(tmp_dir, f"{username}_private.pem")
    pub_path = os.path.join(tmp_dir, f"{username}_public.pem")

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(pub_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return pub_path, priv_path


# ════════════════════════════════════════════════════════════
# TEST 1 — encrypt → decrypt = archivo idéntico
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
        container["key"] = _generate_key()          # reemplazar por clave nueva
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
        container["aad"] = _build_aad("archivo_distinto.txt")
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
        nonce = _generate_nonce()
        assert len(nonce) == 12

    def test_clave_es_256_bits(self):
        """La clave debe medir exactamente 32 bytes (256 bits)."""
        key = _generate_key()
        assert len(key) == 32


# ════════════════════════════════════════════════════════════════
# TESTS — Cifrado hibrido
# ════════════════════════════════════════════════════════════════
# Pruebas requeridas:
#   1. Dos usuarios autorizados pueden descifrar
#   2. Usuario no autorizado NO puede descifrar
#   3. Lista de destinatarios manipulada -> falla
#   4. Clave privada incorrecta -> falla
#   5. Eliminar entrada de destinatario -> falla

# ════════════════════════════════════════════════════════════
# TEST 6 — Ambos destinatarios pueden descifrar
# ════════════════════════════════════════════════════════════

class TestHybridBothUsersDecrypt:

    def test_alice_y_bob_descifran_mismo_archivo(self, tmp_path):
        """
        Si ciframos un archivo para Alice y Bob,
        ambos deben poder descifrarlo y obtener el mismo contenido.
        """
        tmp_dir = str(tmp_path)

        # Crear archivo de prueba
        original = b"Documento compartido entre Alice y Bob"
        input_file = os.path.join(tmp_dir, "documento.txt")
        with open(input_file, "wb") as f:
            f.write(original)

        # Generar llaves para Alice y Bob
        alice_pub, alice_priv = _generate_rsa_pair(tmp_dir, "alice")
        bob_pub, bob_priv = _generate_rsa_pair(tmp_dir, "bob")

        # Cifrar para ambos
        vault_file = os.path.join(tmp_dir, "documento.vault")
        encrypt_file_hybrid(input_file, vault_file, [alice_pub, bob_pub])

        # Alice descifra
        alice_output = os.path.join(tmp_dir, "alice_resultado.txt")
        decrypt_file_hybrid(vault_file, alice_output, alice_priv)
        with open(alice_output, "rb") as f:
            assert f.read() == original

        # Bob descifra
        bob_output = os.path.join(tmp_dir, "bob_resultado.txt")
        decrypt_file_hybrid(vault_file, bob_output, bob_priv)
        with open(bob_output, "rb") as f:
            assert f.read() == original


# ════════════════════════════════════════════════════════════
# TEST 7 — Usuario NO autorizado no puede descifrar
# ════════════════════════════════════════════════════════════

class TestHybridUnauthorizedUser:

    def test_intruso_no_puede_descifrar(self, tmp_path):
        """
        Si ciframos solo para Alice y Bob,
        un tercer usuario (intruso) NO debe poder descifrar.
        """
        tmp_dir = str(tmp_path)

        # Crear archivo
        input_file = os.path.join(tmp_dir, "secreto.txt")
        with open(input_file, "wb") as f:
            f.write(b"Solo para Alice y Bob")

        # Llaves de los autorizados
        alice_pub, _ = _generate_rsa_pair(tmp_dir, "alice")
        bob_pub, _ = _generate_rsa_pair(tmp_dir, "bob")

        # Llaves del intruso
        _, intruso_priv = _generate_rsa_pair(tmp_dir, "intruso")

        # Cifrar solo para Alice y Bob
        vault_file = os.path.join(tmp_dir, "secreto.vault")
        encrypt_file_hybrid(input_file, vault_file, [alice_pub, bob_pub])

        # El intruso intenta descifrar -> debe fallar
        intruso_output = os.path.join(tmp_dir, "intruso_resultado.txt")
        with pytest.raises(ValueError):
            decrypt_file_hybrid(vault_file, intruso_output, intruso_priv)


# ════════════════════════════════════════════════════════════
# TEST 8 — Manipulacion de la lista de destinatarios falla
# ════════════════════════════════════════════════════════════

class TestHybridTamperedRecipientList:

    def test_agregar_destinatario_al_header_falla(self, tmp_path):
        """
        Si un atacante agrega un ID a la lista de destinatarios en el header,
        el AAD cambia y el descifrado falla por auth tag invalido.
        """
        tmp_dir = str(tmp_path)

        input_file = os.path.join(tmp_dir, "archivo.txt")
        with open(input_file, "wb") as f:
            f.write(b"Contenido protegido")

        alice_pub, alice_priv = _generate_rsa_pair(tmp_dir, "alice")
        bob_pub, _ = _generate_rsa_pair(tmp_dir, "bob")

        vault_file = os.path.join(tmp_dir, "archivo.vault")
        encrypt_file_hybrid(input_file, vault_file, [alice_pub, bob_pub])

        # Manipular: agregar un ID falso a la lista de destinatarios en el header
        with open(vault_file, "r") as f:
            container = json.load(f)

        container["header"]["recipients"].append("id_falso_del_atacante")

        with open(vault_file, "w") as f:
            json.dump(container, f, indent=2)

        # Alice intenta descifrar -> falla porque el AAD fue modificado
        alice_output = os.path.join(tmp_dir, "alice_resultado.txt")
        with pytest.raises(Exception):
            decrypt_file_hybrid(vault_file, alice_output, alice_priv)

    def test_quitar_destinatario_del_header_falla(self, tmp_path):
        """
        Si un atacante elimina un ID de la lista en el header,
        el descifrado tambien falla.
        """
        tmp_dir = str(tmp_path)

        input_file = os.path.join(tmp_dir, "archivo.txt")
        with open(input_file, "wb") as f:
            f.write(b"Contenido protegido")

        alice_pub, alice_priv = _generate_rsa_pair(tmp_dir, "alice")
        bob_pub, _ = _generate_rsa_pair(tmp_dir, "bob")

        vault_file = os.path.join(tmp_dir, "archivo.vault")
        encrypt_file_hybrid(input_file, vault_file, [alice_pub, bob_pub])

        # Manipular: quitar el ultimo destinatario del header
        with open(vault_file, "r") as f:
            container = json.load(f)

        container["header"]["recipients"].pop()

        with open(vault_file, "w") as f:
            json.dump(container, f, indent=2)

        alice_output = os.path.join(tmp_dir, "alice_resultado.txt")
        with pytest.raises(Exception):
            decrypt_file_hybrid(vault_file, alice_output, alice_priv)


# ════════════════════════════════════════════════════════════
# TEST 9 — Clave privada incorrecta falla
# ════════════════════════════════════════════════════════════

class TestHybridWrongPrivateKey:

    def test_privada_de_otro_usuario_falla(self, tmp_path):
        """
        Si Alice intenta descifrar con la clave privada de Carol
        (que no es destinataria), debe fallar.
        """
        tmp_dir = str(tmp_path)

        input_file = os.path.join(tmp_dir, "archivo.txt")
        with open(input_file, "wb") as f:
            f.write(b"Solo para Alice")

        alice_pub, _ = _generate_rsa_pair(tmp_dir, "alice")
        _, carol_priv = _generate_rsa_pair(tmp_dir, "carol")

        vault_file = os.path.join(tmp_dir, "archivo.vault")
        encrypt_file_hybrid(input_file, vault_file, [alice_pub])

        # Carol intenta descifrar con SU clave privada -> falla
        carol_output = os.path.join(tmp_dir, "carol_resultado.txt")
        with pytest.raises(ValueError):
            decrypt_file_hybrid(vault_file, carol_output, carol_priv)


# ════════════════════════════════════════════════════════════
# TEST 10 — Eliminar entrada de destinatario rompe el acceso
# ════════════════════════════════════════════════════════════

class TestHybridRemovedRecipientEntry:

    def test_eliminar_entrada_de_bob_impide_descifrado(self, tmp_path):
        """
        Si alguien elimina la entrada de Bob de la lista recipients
        del contenedor, Bob ya no puede descifrar.
        """
        tmp_dir = str(tmp_path)

        input_file = os.path.join(tmp_dir, "archivo.txt")
        with open(input_file, "wb") as f:
            f.write(b"Para Alice y Bob")

        alice_pub, _ = _generate_rsa_pair(tmp_dir, "alice")
        bob_pub, bob_priv = _generate_rsa_pair(tmp_dir, "bob")

        vault_file = os.path.join(tmp_dir, "archivo.vault")
        encrypt_file_hybrid(input_file, vault_file, [alice_pub, bob_pub])

        # Manipular: eliminar la entrada de Bob del contenedor
        with open(vault_file, "r") as f:
            container = json.load(f)

        # Quedarse solo con el primer destinatario (Alice)
        container["recipients"] = [container["recipients"][0]]

        with open(vault_file, "w") as f:
            json.dump(container, f, indent=2)

        # Bob intenta descifrar -> falla porque su entrada ya no existe
        bob_output = os.path.join(tmp_dir, "bob_resultado.txt")
        with pytest.raises(ValueError):
            decrypt_file_hybrid(vault_file, bob_output, bob_priv)
