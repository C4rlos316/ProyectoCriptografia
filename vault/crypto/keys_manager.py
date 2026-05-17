import json
import os
import re
import shutil
import warnings
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# ── Derivación de clave (KDF) ─────


def _derive_key_argon2id(password: str, salt: bytes) -> bytes:
    """
    Deriva una clave de 32 bytes usando Argon2id.
    Parámetros: time_cost=3, memory_cost=65536 KiB (64 MiB), parallelism=1.
    """
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )


def _derive_key_scrypt(password: str, salt: bytes) -> bytes:
    """
    Deriva una clave de 32 bytes usando scrypt.
    Parámetros: n=131072 (2^17), r=8, p=1.
    """
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=131072,
        r=8,
        p=1,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def _derive_key(password: str, salt: bytes, kdf: str, kdf_params: dict) -> bytes:
    """
    Dispatcher de KDF. Selecciona argon2id o scrypt según el identificador `kdf`.
    Lanza ValueError para identificadores de KDF desconocidos.
    """
    if kdf == "argon2id":
        return _derive_key_argon2id(password, salt)
    elif kdf == "scrypt":
        return _derive_key_scrypt(password, salt)
    else:
        raise ValueError(
            f"KDF desconocido: '{kdf}'. Los valores válidos son 'argon2id' y 'scrypt'.")


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


def _validate_password(password: str) -> None:
    """
    Valida que la contraseña no esté vacía ni sea solo espacios en blanco.
    Emite una advertencia si la contraseña tiene menos de 5 caracteres.
    """
    if password.strip() == "":
        raise ValueError("La contraseña no puede estar vacía.")
    if len(password) < 5:
        warnings.warn(
            "ADVERTENCIA: La contraseña tiene menos de 5 caracteres. "
            "Se recomienda una contraseña más larga.",
            UserWarning,
        )


def generate_user_keys(user_name: str, password: str) -> None:
    """
    Genera un par de claves RSA-2048 con la clave privada cifrada.

    La clave privada se cifra usando una clave derivada de `password` mediante
    Argon2id y se almacena en formato JSON con extensión .keystore.

    Escribe:
        {user_name}_private.keystore  — clave privada cifrada (JSON)
        {user_name}_public.pem        — clave pública en texto claro
    """
    # 1. Validar entradas
    _validate_username(user_name)
    _validate_password(password)

    # 2. Verificar si ya existe el keystore y pedir confirmación
    keystore_file = f"{user_name}_private.keystore"
    if os.path.exists(keystore_file):
        respuesta = input(
            f"Ya existe una clave para '{user_name}'. ¿Desea sobreescribirla? [s/N] ")
        if respuesta not in ("s", "S"):
            print("Operación cancelada. No se sobreescribió la clave existente.")
            return

    # 3. Generar clave privada RSA-2048
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 4. Generar salt aleatorio de 16 bytes
    salt = os.urandom(16)

    # 5. Derivar clave de cifrado con Argon2id
    try:
        derived_key = _derive_key_argon2id(password, salt)
        kdf = "argon2id"
        kdf_params = {"time_cost": 3, "memory_cost": 65536, "parallelism": 1}
    except ImportError:
        derived_key = _derive_key_scrypt(password, salt)
        kdf = "scrypt"
        kdf_params = {"n": 131072, "r": 8, "p": 1}

    # 6. Serializar la clave privada con cifrado PKCS8
    encrypted_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            derived_key),
    )

    # 7. Construir el diccionario del keystore
    keystore_dict = _build_keystore_dict(
        encrypted_key_bytes, salt, kdf, kdf_params, "rsa")

    # 8. Escribir el keystore cifrado
    _write_keystore(keystore_file, keystore_dict)

    # 9. Escribir la clave pública en texto claro
    pub_file = f"{user_name}_public.pem"
    with open(pub_file, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    # 10. Confirmación
    print(f"[OK] Identidad RSA generada para '{user_name}'")


def generate_signing_keys(user_name: str, password: str) -> None:
    """
    Genera un par de llaves Ed25519 para firma digital con cifrado basado en contraseña.
    Guarda: {user_name}_signing_private.keystore  y  {user_name}_signing_public.pem
    """
    # 1. Validar entradas
    _validate_username(user_name)
    _validate_password(password)

    # 2. Verificar si ya existe el keystore y pedir confirmación
    keystore_file = f"{user_name}_signing_private.keystore"
    if os.path.exists(keystore_file):
        respuesta = input(
            f"Ya existe una clave para '{user_name}'. ¿Desea sobreescribirla? [s/N] ")
        if respuesta not in ("s", "S"):
            print("Operación cancelada. No se sobreescribió la clave existente.")
            return

    # 3. Generar clave privada Ed25519
    private_key = Ed25519PrivateKey.generate()

    # 4. Generar salt aleatorio
    salt = os.urandom(16)

    # 5. Derivar clave con Argon2id (fallback a scrypt)
    try:
        derived_key = _derive_key_argon2id(password, salt)
        kdf = "argon2id"
        kdf_params = {"time_cost": 3, "memory_cost": 65536, "parallelism": 1}
    except ImportError:
        derived_key = _derive_key_scrypt(password, salt)
        kdf = "scrypt"
        kdf_params = {"n": 131072, "r": 8, "p": 1}

    # 6. Serializar la clave privada con cifrado
    encrypted_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            derived_key),
    )

    # 7. Construir el diccionario del keystore
    keystore_dict = _build_keystore_dict(
        encrypted_key_bytes, salt, kdf, kdf_params, "ed25519")

    # 8. Escribir el keystore cifrado
    _write_keystore(keystore_file, keystore_dict)

    # 9. Escribir la clave pública en texto claro
    pub_file = f"{user_name}_signing_public.pem"
    with open(pub_file, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    # 10. Mensaje de éxito
    print(f"[OK] Llaves de firma Ed25519 generadas para '{user_name}'")


# ── Lectura y validación de keystore ──────────────────────

_REQUIRED_KEYSTORE_FIELDS = [
    "encrypted_key",
    "salt",
    "kdf",
    "kdf_params",
    "key_type",
    "version",
    "created_at",
    "status",
]


def _read_and_validate_keystore(keystore_path: str) -> dict:
    """
    Lee y valida un archivo keystore desde disco.

    - Si el archivo no existe, lanza ValueError con la ruta.
    - Parsea el contenido como JSON.
    - Verifica que todos los campos requeridos estén presentes;
      lanza ValueError por cada campo faltante.
    - Retorna el dict parseado si todos los campos están presentes.
    """
    if not os.path.exists(keystore_path):
        raise ValueError(
            f"No se encontró el archivo keystore: '{keystore_path}'.")

    with open(keystore_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for field in _REQUIRED_KEYSTORE_FIELDS:
        if field not in data:
            raise ValueError(
                f"Keystore inválido: falta el campo requerido '{field}'.")

    return data


# ── Serialización del keystore ─────────────────────────────

def _build_keystore_dict(
    encrypted_key_bytes: bytes,
    salt: bytes,
    kdf: str,
    kdf_params: dict,
    key_type: str,
) -> dict:
    """
    Construye y devuelve el diccionario completo del keystore con todos los
    campos requeridos por el formato

    Parámetros:
        encrypted_key_bytes: bytes PEM de la clave privada cifrada con PKCS8
                             BestAvailableEncryption.
        salt:                salt aleatorio (≥16 bytes) usado en la derivación.
        kdf:                 identificador del KDF ("argon2id" o "scrypt").
        kdf_params:          parámetros específicos del KDF.
        key_type:            tipo de clave ("rsa" o "ed25519").

    Retorna:
        dict con los campos: encrypted_key, salt, kdf, kdf_params, key_type,
        version, created_at, status.
    """
    return {
        "encrypted_key": encrypted_key_bytes.hex(),
        "salt": salt.hex(),
        "kdf": kdf,
        "kdf_params": kdf_params,
        "key_type": key_type,
        "version": "1.0",
        "created_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "activa",
    }


def _write_keystore(path: str, data: dict) -> None:
    """
    Serializa `data` a JSON  y lo escribe en `path`.

    Parámetros:
        path: ruta del archivo de destino.
        data: diccionario con los campos del keystore.
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ── Carga de clave privada ─────────────────────────────────

def load_private_key(keystore_path: str, password: str):
    """
    Carga y descifra una clave privada desde un archivo `.keystore`.

    Parámetros:
        keystore_path: ruta al archivo .keystore (JSON).
        password:      contraseña usada al generar la clave.

    Retorna:
        Objeto de clave privada en memoria (RSAPrivateKey o Ed25519PrivateKey).
        Nunca devuelve bytes serializados de la clave privada.

    Lanza:
        ValueError — si faltan campos requeridos en el keystore.
        ValueError — si la contraseña es incorrecta o el keystore está corrupto

    Emite:
        UserWarning — si la clave tiene un campo `expires_at` en el pasado.
    """
    # 1. Leer y validar el keystore; propaga ValueError si faltan campos
    data = _read_and_validate_keystore(keystore_path)

    # 2. Extraer campos necesarios para el descifrado
    salt = bytes.fromhex(data["salt"])
    kdf = data["kdf"]
    kdf_params = data["kdf_params"]
    encrypted_key_bytes = bytes.fromhex(data["encrypted_key"])

    # 3. Derivar la clave de descifrado a partir de la contraseña y el salt
    derived_key = _derive_key(password, salt, kdf, kdf_params)

    # 4. Intentar cargar la clave privada; cualquier excepción se convierte en
    #    un ValueError genérico para no revelar la causa exacta del fallo
    try:
        private_key = serialization.load_pem_private_key(
            encrypted_key_bytes,
            password=derived_key,
        )
    except Exception:
        raise ValueError(
            "Error al cargar la clave: contraseña incorrecta o keystore inválido."
        )

    # 5. Advertir si la clave ha expirado
    if "expires_at" in data:
        try:
            expires_at = datetime.strptime(
                data["expires_at"], "%Y-%m-%dT%H:%M:%SZ")
            if expires_at < datetime.utcnow():
                warnings.warn(
                    f"ADVERTENCIA: La clave expiró el {data['expires_at']}. "
                    "Continúe con precaución.",
                    UserWarning,
                )
        except ValueError:
            # Fecha con formato inesperado
            pass

    # 6. Retornar el objeto de clave en memoria
    return private_key


# ── Exportación / Importación de keystore ─────────────────

def export_keystore(keystore_path: str, destination_path: str) -> None:
    """
    Exporta un archivo `.keystore` al destino indicado.

    No requiere contraseña: la clave privada ya está cifrada en reposo dentro
    del keystore. La función valida que el archivo de origen exista y sea un
    keystore válido antes de copiarlo.

    Parámetros:
        keystore_path:    ruta al archivo .keystore de origen.
        destination_path: ruta de destino.

    Lanza:
        ValueError — si el archivo no existe o le faltan campos requeridos
    """
    # 1. Validar que el origen existe y es un keystore bien formado
    _read_and_validate_keystore(keystore_path)

    # 2. Copiar el archivo preservando metadatos
    shutil.copy2(keystore_path, destination_path)


# ── Importación de keystore ────────────────────────────────

def import_keystore(source_path: str, destination_path: str, password: str) -> None:
    """
    Importa un archivo `.keystore` de respaldo al destino indicado.

    Valida todos los campos requeridos del keystore de origen y verifica la
    contraseña antes de copiar el archivo, garantizando que solo keystores
    válidos y accesibles sean restaurados.

    Parámetros:
        source_path:      ruta al archivo .keystore de origen.
        destination_path: ruta de destino donde se copiará el keystore.
        password:         contraseña para verificar el acceso a la clave privada.

    Lanza:
        ValueError — si faltan campos requeridos en el keystore .
        ValueError — si la contraseña es incorrecta o el keystore está corrupto
    """
    # 1. Validar todos los campos requeridos del keystore de origen;
    #    propaga ValueError si el archivo no existe o faltan campos.
    _read_and_validate_keystore(source_path)

    # 2. Verificar la contraseña intentando cargar la clave privada;
    #    propaga ValueError si la contraseña es incorrecta o el keystore está corrupto.
    load_private_key(source_path, password)

    # 3. Copiar el archivo al destino preservando metadatos.
    shutil.copy2(source_path, destination_path)
