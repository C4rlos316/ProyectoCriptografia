import os
import json
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.asymmetric import rsa
from vault.crypto.encryption import encrypt_file_hybrid, decrypt_file_hybrid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


from vault.crypto.encryption import (
    decrypt_file_hybrid,
    encrypt_file_hybrid,
    verify_signature,
)

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


def _gen_rsa_pair(tmp_dir: str, username: str):
    """Genera par RSA y guarda PEMs. Retorna (pub_path, priv_path)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
 
    priv_path = os.path.join(tmp_dir, f"{username}_private.pem")
    pub_path  = os.path.join(tmp_dir, f"{username}_public.pem")
 
    with open(priv_path, "wb") as f:
        f.write(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with open(pub_path, "wb") as f:
        f.write(priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    return pub_path, priv_path
 
 
def _gen_ed25519_pair(tmp_dir: str, username: str):
    """Genera par Ed25519 y guarda PEMs. Retorna (pub_path, priv_path)."""
    priv = Ed25519PrivateKey.generate()
 
    priv_path = os.path.join(tmp_dir, f"{username}_signing_private.pem")
    pub_path  = os.path.join(tmp_dir, f"{username}_signing_public.pem")
 
    with open(priv_path, "wb") as f:
        f.write(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with open(pub_path, "wb") as f:
        f.write(priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    return pub_path, priv_path
 
 
def _make_signed_vault(tmp_path, content: bytes = b"Contenido confidencial de prueba"):
    """
    Crea un .vault firmado listo para usar en tests.
    Retorna un dict con todas las rutas relevantes.
    """
    tmp_dir = str(tmp_path)
 
    # Archivo de entrada
    input_file = os.path.join(tmp_dir, "original.txt")
    with open(input_file, "wb") as f:
        f.write(content)
 
    # Llaves del destinatario (RSA)
    alice_pub, alice_priv = _gen_rsa_pair(tmp_dir, "alice")
 
    # Llaves del remitente (Ed25519)
    sender_sign_pub, sender_sign_priv = _gen_ed25519_pair(tmp_dir, "sender")
 
    # Cifrar + firmar
    vault_file = os.path.join(tmp_dir, "archivo.vault")
    encrypt_file_hybrid(
        input_file,
        vault_file,
        [alice_pub],
        signing_priv_path=sender_sign_priv,
    )
 
    return {
        "input_file":      input_file,
        "vault_file":      vault_file,
        "alice_pub":       alice_pub,
        "alice_priv":      alice_priv,
        "sender_sign_pub": sender_sign_pub,
        "sender_sign_priv": sender_sign_priv,
        "original":        content,
        "tmp_dir":         tmp_dir,
    }
 

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
        alice_pub, alice_priv = _gen_rsa_pair(tmp_dir, "alice")
        bob_pub, bob_priv = _gen_rsa_pair(tmp_dir, "bob")

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
        alice_pub, _ = _gen_rsa_pair(tmp_dir, "alice")
        bob_pub, _ = _gen_rsa_pair(tmp_dir, "bob")

        # Llaves del intruso
        _, intruso_priv = _gen_rsa_pair(tmp_dir, "intruso")

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

    def test_agregar_campo_al_header_falla(self, tmp_path):
        """
        Si un atacante agrega un campo extra al header (que forma parte del AAD),
        el AAD reconstruido cambia y el descifrado falla por auth tag invalido.
        """
        tmp_dir = str(tmp_path)

        input_file = os.path.join(tmp_dir, "archivo.txt")
        with open(input_file, "wb") as f:
            f.write(b"Contenido protegido")

        alice_pub, alice_priv = _gen_rsa_pair(tmp_dir, "alice")
        bob_pub, _ = _gen_rsa_pair(tmp_dir, "bob")

        vault_file = os.path.join(tmp_dir, "archivo.vault")
        encrypt_file_hybrid(input_file, vault_file, [alice_pub, bob_pub])

        # Manipular: agregar un campo extra al header (modifica el AAD real)
        with open(vault_file, "r") as f:
            container = json.load(f)

        container["header"]["atacante"] = "id_falso"  # el header ES el AAD

        with open(vault_file, "w") as f:
            json.dump(container, f, indent=2)

        # Alice intenta descifrar -> falla porque el AAD fue modificado
        alice_output = os.path.join(tmp_dir, "alice_resultado.txt")
        with pytest.raises(Exception):
            decrypt_file_hybrid(vault_file, alice_output, alice_priv)

    def test_modificar_filename_en_header_falla(self, tmp_path):
        """
        Si un atacante modifica el filename en el header (que forma parte del AAD),
        el AAD reconstruido ya no coincide con el tag y el descifrado falla.
        """
        tmp_dir = str(tmp_path)

        input_file = os.path.join(tmp_dir, "archivo.txt")
        with open(input_file, "wb") as f:
            f.write(b"Contenido protegido")

        alice_pub, alice_priv = _gen_rsa_pair(tmp_dir, "alice")
        bob_pub, _ = _gen_rsa_pair(tmp_dir, "bob")

        vault_file = os.path.join(tmp_dir, "archivo.vault")
        encrypt_file_hybrid(input_file, vault_file, [alice_pub, bob_pub])

        # Manipular: cambiar el filename en el header (modifica el AAD real)
        with open(vault_file, "r") as f:
            container = json.load(f)

        container["header"]["filename"] = "archivo_diferente.txt"  # el header ES el AAD

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

        alice_pub, _ = _gen_rsa_pair(tmp_dir, "alice")
        _, carol_priv = _gen_rsa_pair(tmp_dir, "carol")

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

        alice_pub, _ = _gen_rsa_pair(tmp_dir, "alice")
        bob_pub, bob_priv = _gen_rsa_pair(tmp_dir, "bob")

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




# ══════════════════════════════════════════════════════════════════════════════
# TEST 11 — Firma válida: archivo aceptado y descifrado correctamente
# ══════════════════════════════════════════════════════════════════════════════
 
class TestValidSignatureAccepted:
 
    def test_firma_valida_descifra_correctamente(self, tmp_path):
        """
        Un contenedor firmado con una llave Ed25519 válida debe:
        1. Pasar la verificación de firma.
        2. Descifrar el contenido correctamente.
        """
        ctx = _make_signed_vault(tmp_path, b"Documento secreto firmado y cifrado")
 
        output_file = os.path.join(ctx["tmp_dir"], "recuperado.txt")
        decrypt_file_hybrid(
            ctx["vault_file"],
            output_file,
            ctx["alice_priv"],
            signing_pub_path=ctx["sender_sign_pub"],
        )
 
        with open(output_file, "rb") as f:
            resultado = f.read()
 
        assert resultado == ctx["original"], (
            "El contenido descifrado no coincide con el original."
        )
 
    def test_contenedor_contiene_campos_de_firma(self, tmp_path):
        """
        El .vault generado con firma debe contener los campos 'signature' y 'signer_id'.
        """
        ctx = _make_signed_vault(tmp_path)
 
        with open(ctx["vault_file"], "r") as f:
            container = json.load(f)
 
        assert "signature"  in container, "Falta el campo 'signature' en el contenedor."
        assert "signer_id"  in container, "Falta el campo 'signer_id' en el contenedor."
 
        # La firma Ed25519 es 64 bytes = 128 chars hex
        assert len(container["signature"]) == 128, (
            f"Longitud de firma inesperada: {len(container['signature'])} chars."
        )
 
    def test_verify_signature_no_lanza_en_firma_valida(self, tmp_path):
        """
        verify_signature() NO debe lanzar excepción cuando la firma es válida.
        """
        ctx = _make_signed_vault(tmp_path)
 
        with open(ctx["vault_file"], "r") as f:
            container = json.load(f)
 
        # No debe lanzar nada
        verify_signature(container, ctx["sender_sign_pub"])
 
 
# ══════════════════════════════════════════════════════════════════════════════
# TEST 12 — Ciphertext modificado → firma rechazada
# ══════════════════════════════════════════════════════════════════════════════
 
class TestTamperedCiphertextRejected:
 
    def test_ciphertext_modificado_invalida_firma(self, tmp_path):
        """
        Si un atacante modifica el ciphertext en el contenedor,
        la verificación de firma debe fallar con ValueError.
        El descifrado NO debe ejecutarse.
        """
        ctx = _make_signed_vault(tmp_path)
 
        # Manipular: cambiar el último byte del ciphertext hex
        with open(ctx["vault_file"], "r") as f:
            container = json.load(f)
 
        ct = container["ciphertext"]
        # Flip del último byte (siempre hay al menos 2 chars)
        last_byte = int(ct[-2:], 16) ^ 0xFF
        container["ciphertext"] = ct[:-2] + f"{last_byte:02x}"
 
        tampered_vault = os.path.join(ctx["tmp_dir"], "tampered.vault")
        with open(tampered_vault, "w") as f:
            json.dump(container, f, indent=2)
 
        output_file = os.path.join(ctx["tmp_dir"], "recuperado.txt")
        with pytest.raises(ValueError, match="[Ff]irma|[Mm]odificado|[Rr]echazado"):
            decrypt_file_hybrid(
                tampered_vault,
                output_file,
                ctx["alice_priv"],
                signing_pub_path=ctx["sender_sign_pub"],
            )
 
    def test_ciphertext_modificado_verify_signature_lanza(self, tmp_path):
        """
        verify_signature() directamente debe lanzar ValueError
        cuando el ciphertext fue modificado.
        """
        ctx = _make_signed_vault(tmp_path)
 
        with open(ctx["vault_file"], "r") as f:
            container = json.load(f)
 
        # Sustituir todo el ciphertext por basura
        container["ciphertext"] = "deadbeef" * 20
 
        with pytest.raises(ValueError):
            verify_signature(container, ctx["sender_sign_pub"])
 
 
# ══════════════════════════════════════════════════════════════════════════════
# TEST 13 — Metadatos header modificado → firma rechazada
# ══════════════════════════════════════════════════════════════════════════════
 
class TestTamperedMetadataRejected:
 
    def test_modificar_filename_invalida_firma(self, tmp_path):
        """
        Cambiar el filename en el header debe invalidar la firma,
        porque el header forma parte del material firmado.
        """
        ctx = _make_signed_vault(tmp_path)
 
        with open(ctx["vault_file"], "r") as f:
            container = json.load(f)
 
        container["header"]["filename"] = "archivo_malicioso.exe"
 
        tampered_vault = os.path.join(ctx["tmp_dir"], "tampered.vault")
        with open(tampered_vault, "w") as f:
            json.dump(container, f, indent=2)
 
        output_file = os.path.join(ctx["tmp_dir"], "recuperado.txt")
        with pytest.raises(ValueError):
            decrypt_file_hybrid(
                tampered_vault,
                output_file,
                ctx["alice_priv"],
                signing_pub_path=ctx["sender_sign_pub"],
            )
 
    def test_agregar_campo_al_header_invalida_firma(self, tmp_path):
        """
        Agregar un campo nuevo al header (ej. campo 'atacante') modifica
        el material firmado y debe invalidar la firma.
        """
        ctx = _make_signed_vault(tmp_path)
 
        with open(ctx["vault_file"], "r") as f:
            container = json.load(f)
 
        container["header"]["campo_extra"] = "inyeccion_de_metadato"
 
        tampered_vault = os.path.join(ctx["tmp_dir"], "tampered_header.vault")
        with open(tampered_vault, "w") as f:
            json.dump(container, f, indent=2)
 
        output_file = os.path.join(ctx["tmp_dir"], "recuperado.txt")
        with pytest.raises(ValueError):
            decrypt_file_hybrid(
                tampered_vault,
                output_file,
                ctx["alice_priv"],
                signing_pub_path=ctx["sender_sign_pub"],
            )
 

 
 
# ══════════════════════════════════════════════════════════════════════════════
# TEST 14 — Llave pública incorrecta → verificación rechazada
# ══════════════════════════════════════════════════════════════════════════════
 
class TestWrongPublicKeyRejected:
 
    def test_llave_publica_de_otro_usuario_rechazada(self, tmp_path):
        """
        Si se intenta verificar la firma con la llave pública de otro usuario
        (que no firmó el archivo), debe fallar con ValueError.
        """
        ctx = _make_signed_vault(tmp_path)
 
        # Generar un par Ed25519 completamente distinto (impostor)
        impostor_pub, _ = _gen_ed25519_pair(ctx["tmp_dir"], "impostor")
 
        output_file = os.path.join(ctx["tmp_dir"], "recuperado.txt")
        with pytest.raises(ValueError, match="[Ff]irma|[Ii]nválid|[Rr]echazado"):
            decrypt_file_hybrid(
                ctx["vault_file"],
                output_file,
                ctx["alice_priv"],
                signing_pub_path=impostor_pub,
            )
 
    def test_llave_rsa_en_lugar_de_ed25519_rechazada(self, tmp_path):
        """
        Pasar una llave RSA donde se espera Ed25519 debe resultar en error.
        El sistema no debe descifrar si la verificación no puede completarse.
        """
        ctx = _make_signed_vault(tmp_path)
 
        # La llave pública RSA de Alice no es Ed25519 → no puede verificar la firma
        output_file = os.path.join(ctx["tmp_dir"], "recuperado.txt")
        with pytest.raises(Exception):
            decrypt_file_hybrid(
                ctx["vault_file"],
                output_file,
                ctx["alice_priv"],
                signing_pub_path=ctx["alice_pub"],  # llave RSA, no Ed25519
            )
 
    def test_verify_signature_con_llave_incorrecta(self, tmp_path):
        """
        verify_signature() directamente debe lanzar ValueError
        cuando la llave pública no corresponde al firmante.
        """
        ctx = _make_signed_vault(tmp_path)
        wrong_pub, _ = _gen_ed25519_pair(ctx["tmp_dir"], "wrong")
 
        with open(ctx["vault_file"], "r") as f:
            container = json.load(f)
 
        with pytest.raises(ValueError):
            verify_signature(container, wrong_pub)
 
 
# ══════════════════════════════════════════════════════════════════════════════
# TEST 15 — Firma eliminada del contenedor → rechazado
# ══════════════════════════════════════════════════════════════════════════════
 
class TestMissingSignatureRejected:
 
    def test_sin_campo_signature_rechazado(self, tmp_path):
        """
        Si se elimina el campo 'signature' del contenedor, la verificación
        debe rechazarlo con ValueError indicando ausencia de firma.
        """
        ctx = _make_signed_vault(tmp_path)
 
        with open(ctx["vault_file"], "r") as f:
            container = json.load(f)
 
        del container["signature"]
 
        no_sig_vault = os.path.join(ctx["tmp_dir"], "no_signature.vault")
        with open(no_sig_vault, "w") as f:
            json.dump(container, f, indent=2)
 
        output_file = os.path.join(ctx["tmp_dir"], "recuperado.txt")
        with pytest.raises(ValueError, match="[Ff]irma|[Ss]ignature|[Aa]utenticac"):
            decrypt_file_hybrid(
                no_sig_vault,
                output_file,
                ctx["alice_priv"],
                signing_pub_path=ctx["sender_sign_pub"],
            )
 
    def test_sin_campo_signer_id_rechazado(self, tmp_path):
        """
        Si se elimina el campo 'signer_id', la verificación también debe fallar.
        """
        ctx = _make_signed_vault(tmp_path)
 
        with open(ctx["vault_file"], "r") as f:
            container = json.load(f)
 
        del container["signer_id"]
 
        no_id_vault = os.path.join(ctx["tmp_dir"], "no_signer_id.vault")
        with open(no_id_vault, "w") as f:
            json.dump(container, f, indent=2)
 
        output_file = os.path.join(ctx["tmp_dir"], "recuperado.txt")
        with pytest.raises(ValueError):
            decrypt_file_hybrid(
                no_id_vault,
                output_file,
                ctx["alice_priv"],
                signing_pub_path=ctx["sender_sign_pub"],
            )
 
    def test_contenedor_firmado_sin_llave_verificacion_rechazado(self, tmp_path):
        """
        Si el contenedor tiene firma pero NO se proporciona llave de verificación,
        el sistema debe rechazarlo en lugar de ignorar la firma silenciosamente.
        Aceptar una firma sin verificarla anularía todas las garantías de D5.
        """
        ctx = _make_signed_vault(tmp_path)
 
        output_file = os.path.join(ctx["tmp_dir"], "recuperado.txt")
        with pytest.raises(ValueError, match="[Ff]irma|[Pp]ública|[Vv]erificar"):
            # Sin signing_pub_path → debe rechazarse porque el contenedor está firmado
            decrypt_file_hybrid(
                ctx["vault_file"],
                output_file,
                ctx["alice_priv"],
                signing_pub_path=None,
            )
 
    def test_firma_vacia_rechazada(self, tmp_path):
        """
        Una firma vacía (string vacío) debe ser rechazada.
        """
        ctx = _make_signed_vault(tmp_path)
 
        with open(ctx["vault_file"], "r") as f:
            container = json.load(f)
 
        container["signature"] = ""
 
        empty_sig_vault = os.path.join(ctx["tmp_dir"], "empty_sig.vault")
        with open(empty_sig_vault, "w") as f:
            json.dump(container, f, indent=2)
 
        output_file = os.path.join(ctx["tmp_dir"], "recuperado.txt")
        with pytest.raises(Exception):
            decrypt_file_hybrid(
                empty_sig_vault,
                output_file,
                ctx["alice_priv"],
                signing_pub_path=ctx["sender_sign_pub"],
            )
 