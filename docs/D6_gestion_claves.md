# Key Management Design — D6: Gestión de Claves

## 1. Objetivo de seguridad

Este módulo resuelve la vulnerabilidad crítica de D3: las claves privadas RSA-2048 y Ed25519
se almacenaban en disco en texto claro usando `serialization.NoEncryption()`. Cualquier
atacante con acceso al sistema de archivos podía leerlas y usarlas sin ninguna barrera.

**Objetivo de seguridad D6:**
> *"Las claves privadas permanecen confidenciales y utilizables únicamente por usuarios
> autorizados, incluso si el medio de almacenamiento es comprometido."*

| Propiedad | Significado | Cómo se logra |
|-----------|-------------|---------------|
| **Confidencialidad en reposo** | La clave privada no puede leerse del disco sin la contraseña | Cifrado PKCS8 con clave derivada de contraseña (KDF) |
| **Resistencia a diccionario offline** | Un atacante con el archivo no puede probar contraseñas rápidamente | Argon2id con 64 MiB de memoria requerida por intento |
| **Integridad del keystore** | Cualquier modificación al archivo es detectada al cargar | La clave derivada incorrecta produce fallo al deserializar PKCS8 |
| **Mensajes genéricos** | El sistema no revela si falló la contraseña o el archivo | Un solo mensaje de error para ambos casos |

---

## 2. ¿Por qué cifrar las claves privadas?

Cuando una clave privada se guarda sin cifrar, **poseer el archivo equivale a poseer la clave**.
Esto significa que:

- Un atacante que roba el disco, hace una copia de seguridad no autorizada, o accede
  brevemente al sistema de archivos obtiene acceso permanente a todos los archivos cifrados
  para ese usuario.
- No hay ninguna barrera adicional: basta con leer el archivo PEM y usarlo directamente.

### La solución: cifrado basado en contraseña

Al cifrar la clave privada con una contraseña, se introduce un segundo factor de seguridad:


Un atacante que roba el archivo `.keystore` obtiene datos cifrados que no puede usar sin
la contraseña. La seguridad del sistema ya no depende exclusivamente de la seguridad del
sistema de archivos.

### ¿Por qué no es suficiente con permisos de archivo?

Los permisos del sistema operativo son la primera línea de defensa,
pero tienen limitaciones:

| Escenario | Permisos de archivo | Cifrado con contraseña |
|-----------|--------------------|-----------------------|
| Acceso físico al disco (robo de laptop) |  No protege |  Protege |
| Copia de seguridad no cifrada |  No protege |  Protege |
| Acceso root/administrador comprometido |  No protege |  Protege |
| Malware con acceso al sistema de archivos |  No protege |  Protege |
| Acceso normal de usuario sin contraseña | ✅ Protege | ✅ Protege |

El cifrado con contraseña protege en todos los escenarios donde los permisos fallan.

---

## 3. Selección del KDF: Argon2id

### ¿Qué es un KDF?

Una **Función de Derivación de Claves** (KDF) transforma una contraseña de longitud variable
en una clave criptográfica de longitud fija. El objetivo no es solo hacer la transformación,
sino hacerla **deliberadamente lenta y costosa** para que los ataques de diccionario sean
inviables.

### ¿Por qué Argon2id y no SHA-256 o bcrypt?

| KDF | Velocidad | Memoria requerida | Resistencia GPU | ¿Lo usamos? |
|-----|-----------|-------------------|-----------------|-------------|
| SHA-256 (directo) | ~10⁹ intentos/seg en GPU | Ninguna |  Muy vulnerable | No |
| bcrypt | ~10⁴ intentos/seg | ~4 KB |  Moderada | No |
| scrypt | ~10² intentos/seg | Configurable |  Buena | Fallback |
| **Argon2id** | ~10¹ intentos/seg | **64 MiB** | ✅ Excelente | **Sí** |


### Parámetros implementados

```python
# Argon2id — parámetros en keys_manager.py
hash_secret_raw(
    secret=password.encode("utf-8"),
    salt=salt,
    time_cost=3,       # 3 iteraciones
    memory_cost=65536, # 64 MiB de RAM requeridos
    parallelism=1,     # 1 hilo
    hash_len=32,       # 32 bytes de salida (256 bits)
    type=Type.ID,
)
```

| Parámetro | Valor | Justificación |
|-----------|-------|---------------|
| `time_cost` | 3 | Mínimo recomendado por OWASP para Argon2id |
| `memory_cost` | 65536 KiB (64 MiB) | Hace que cada intento requiera 64 MiB de RAM; |
| `parallelism` | 1 | Un hilo; suficiente para uso interactivo |
| `hash_len` | 32 bytes | Clave de 256 bits para AES-256-CBC interno de PKCS8 |

Con estos parámetros, un atacante con hardware dedicado puede probar
aproximadamente **10–50 contraseñas por segundo** en lugar de los miles por
segundo que permitiría SHA-256 directo.

---

## 4. Formato del archivo Keystore

### Estructura

Cada clave privada se almacena en un archivo JSON con extensión `.keystore`. Este formato
fue elegido sobre alternativas por las mismas razones que el contenedor `.vault`:
legibilidad, portabilidad y facilidad de depuración. Los datos sensibles como la clave cifrada
no son legibles.

```json
{
  "encrypted_key": "2d2d2d2d2d424547494e20454e435259505445442050524956415445204b45592d2d2d2d2d...",
  "salt": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "kdf": "argon2id",
  "kdf_params": {
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 1
  },
  "key_type": "rsa",
  "version": "1.0",
  "created_at": "2026-05-14T10:00:00Z",
  "status": "activa"
}
```

### Descripción de campos

| Campo | Tipo | Requerido | Descripción |
|-------|------|-----------|-------------|
| `encrypted_key` | string (hex) | Sí | Bytes PEM de la clave privada cifrada con PKCS8 BestAvailableEncryption |
| `salt` | string (hex) | Sí | Salt aleatorio de 16 bytes, único por generación de clave |
| `kdf` | string | Sí | Identificador del KDF: `"argon2id"` o `"scrypt"` |
| `kdf_params` | object | Sí | Parámetros del KDF  |
| `key_type` | string | Sí | Tipo de clave: `"rsa"` o `"ed25519"` |
| `version` | string | Sí | Versión del formato: `"1.0"` |
| `created_at` | string  | Sí | Marca de tiempo de creación |
| `status` | string | Sí | Estado del ciclo de vida: `"activa"`, `"rotada"`, `"comprometida"`, `"expirada"` |
| `expires_at` | string | No | Fecha de expiración opcional |

### Nombres de archivos

| Tipo de clave | Archivo keystore | Archivo clave pública |
|---------------|------------------|-----------------------|
| RSA-2048 (cifrado) | `{usuario}_private.keystore` | `{usuario}_public.pem` |
| Ed25519 (firma) | `{usuario}_signing_private.keystore` | `{usuario}_signing_public.pem` |

Las claves públicas se siguen guardando en texto claro como archivos PEM.

### ¿Por qué el salt es único por clave?

El salt se genera con `os.urandom(16)` en cada operación de generación. Esto garantiza que:

- Dos usuarios con la misma contraseña producen keystores completamente distintos.
- Un atacante no puede precomputar tablas de hashes para contraseñas comunes.
- Si el mismo usuario regenera sus claves, el nuevo keystore es independiente del anterior.

---

## 5. Flujo de generación de clave

```
python main.py identidad alice
       │
       ▼
  CLI solicita contraseña 
       │
       ▼
  generate_user_keys("alice", password)
       │
       ├── Validar username (regex ^[a-zA-Z0-9_-]+$)
       ├── Validar password (no vacío; advertir si < 5 chars)
       ├── Verificar si ya existe alice_private.keystore
       │
       ▼
  Generar clave RSA-2048
  Generar salt = os.urandom(16)
       │
       ▼
  Derivar clave_cifrado = Argon2id(password, salt)  [64 MiB, 3 iteraciones]
       │
       ▼
  encrypted_key = private_key.private_bytes(PKCS8, BestAvailableEncryption(clave_cifrado))
       │
       ▼
  Escribir alice_private.keystore (JSON con todos los campos)
  Escribir alice_public.pem (texto claro)
       │
       ▼
  [OK] Identidad RSA generada para 'alice'
```
