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
## 6. Flujo de carga de clave (descifrado)

```
python main.py descifrar doc.vault out.txt --privada alice_private.keystore
       │
       ▼
  CLI solicita contraseña
       │
       ▼
  decrypt_file_hybrid(..., password=contraseña)
       │
       ▼
  load_private_key("alice_private.keystore", password)
       │
       ├── Leer y validar JSON
       ├── Extraer salt, kdf, kdf_params, encrypted_key
       ├── Derivar clave_cifrado = Argon2id(password, salt)
       │
       ▼
  serialization.load_pem_private_key(encrypted_key_bytes, password=clave_cifrado)
       │
       ├── OK → retornar objeto clave privada en memoria
       │
       └── FALLO → ValueError genérico
                   "Error al cargar la clave: contraseña incorrecta o keystore inválido."
```
---

## 7. Estrategia de respaldo y recuperación

### Principio de diseño

El archivo `.keystore` **ya es nuestro respaldo**. No se necesita ninguna
transformación adicional porque la clave privada ya está cifrada dentro de él.
Copiar el archivo es suficiente para hacer un respaldo seguro.

### Exportar (respaldar)

```bash
python main.py respaldar alice /ruta/segura/alice_private.keystore
python main.py respaldar alice /ruta/segura/alice_signing_private.keystore --tipo ed25519
```

La operación `export_keystore` valida que el archivo fuente sea un keystore bien formado
y lo copia preservando metadatos. **No requiere contraseña** porque
la clave ya está cifrada.

### Importar (restaurar)

```bash
python main.py restaurar /ruta/respaldo/alice_private.keystore
```

La operación `import_keystore` hace tres cosas antes de copiar:

1. Valida que todos los campos requeridos estén presentes.
2. Verifica la contraseña intentando descifrar la clave si la contraseña es incorrecta, falla aquí.
3. Solo si la verificación pasa, copia el archivo al directorio de trabajo.

Esto garantiza que no se restaure un keystore corrupto o con contraseña incorrecta.

**Comportamiento automático en mismo directorio:** si el archivo de respaldo y el destino
resolverían al mismo archivo (por ejemplo, al restaurar un `.keystore` que ya está en el
directorio de trabajo), el sistema agrega automáticamente el sufijo `_restaurado` al nombre
del archivo de destino:

```
# backup_alice.keystore está en el mismo directorio → se crea:
backup_alice_restaurado.keystore
```

Esto permite restaurar sin sobreescribir el respaldo original ni generar un error.

### ¿Qué pasa si se pierde el archivo keystore?

Si el archivo `.keystore` se pierde sin respaldo, **la clave privada se pierde permanentemente**.
Todos los archivos `.vault` cifrados para esa clave quedan inaccesibles. No hay mecanismo de
recuperación sin el archivo keystore y la contraseña.


---

## 8. Ciclo de vida de la clave

```
generate_user_keys()
       │
       ▼
   [activa]  ←── uso normal (cifrar/descifrar)
       │
       ├── generate_user_keys() con confirmación → [rotada]
       │
       ├── sospecha de compromiso → [comprometida]  (manual)
       │
       └── expires_at superado → [expirada]  (advertencia automática al cargar)
```

El campo `status` en el keystore registra el estado actual. Al cargar una clave con
`expires_at` en el pasado, el sistema emite una advertencia pero no bloquea la operación:

### Procedimiento ante compromiso de clave

Si se sospecha que una clave privada fue expuesta:

1. Generar un nuevo par de claves con `python main.py identidad <usuario>`.
2. Distribuir la nueva clave pública a los remitentes.
3. Re-cifrar todos los archivos importantes con la nueva clave pública.
4. Tratar todos los archivos cifrados con la clave antigua como potencialmente comprometidos.

No existe mecanismo de revocación automática en este sistema (está fuera del alcance).

---

## 9. Seguridad

### ¿Qué pasa si la contraseña es débil?

La seguridad del keystore depende directamente  de la contraseña. Argon2id
hace que cada intento sea costoso, pero no puede compensar una contraseña trivial:

| Contraseña | Entropía estimada | Tiempo para romper (GPU dedicada, ~10 intentos/seg) |
|------------|-------------------|-----------------------------------------------------|
| `123456` | ~20 bits | < 1 segundo |
| `password` | ~28 bits | ~3 segundos |
| `MiPerro2020` | ~40 bits | ~35 años |
| `xK9#mP2$vL7@` | ~78 bits | > edad del universo |

El sistema emite una advertencia cuando la contraseña tiene menos de **5 caracteres**, pero
**no bloquea la operación**. La decisión final es del usuario.


**Riesgo:** si el usuario elige una contraseña débil, la seguridad
del keystore se reduce a la entropía de esa contraseña. Argon2id con 64 MiB ralentiza
los ataques, pero no los hace imposibles contra contraseñas muy cortas.

### ¿Qué pasa si el dispositivo está comprometido?

Mientras la clave privada está cargada en memoria durante una operación de descifrado,
un atacante con acceso a nivel de proceso  podría extraerla. Este riesgo se acepta como **fuera del alcance de la mitigación solo por software**.

La mitigación disponible es sobrescribir el material de clave en memoria inmediatamente
tras su uso. Python no garantiza esto por su modelo de gestión de memoria, pero el objeto de clave no se almacena en caché .

### ¿Por qué mensajes de error genéricos?

Cuando `load_private_key` falla, siempre devuelve el mismo mensaje:

```
"Error al cargar la clave: contraseña incorrecta o keystore inválido."
```

Esto previene **ataques donde el atacante puede probar contraseñas**: si el sistema distinguiera entre "contraseña incorrecta" y "keystore corrupto", aqui se podría usar esa diferencia para obtener información sobre el estado del keystore o confirmar que tiene el archivo correcto.

### ¿Qué protege este sistema y qué no?

| Amenaza | ¿Protegido? | Mecanismo |
|---------|-------------|-----------|
| Robo del archivo `.keystore` sin contraseña |  Sí | Argon2id + AES-256-CBC |
| Ataque de diccionario offline sobre el keystore |  Sí | 64 MiB por intento limita velocidad |
| Keystore modificado (salt o clave alterados) |  Sí | Fallo al deserializar PKCS8 |
| Contraseña débil elegida por el usuario |  Parcial | Advertencia, pero no bloqueo |
| Clave en memoria durante operación activa |  No | Fuera del alcance  |
| Pérdida del archivo keystore sin respaldo |  No | Pérdida permanente de acceso |
| Keylogger capturando la contraseña |  No | Fuera del alcance |

---

## 10. Uso desde la CLI

### Generar identidad RSA (cifrado)

```bash
python main.py identidad alice
# Solicita: Contraseña maestra: [sin eco]
# Genera: alice_private.keystore  y  alice_public.pem
```

### Generar identidad Ed25519 (firma)

```bash
python main.py identidad-firma alice
# Solicita: Contraseña maestra: [sin eco]
# Genera: alice_signing_private.keystore  y  alice_signing_public.pem
```

### Cifrar un archivo con firma digital desde keystore

El argumento `--firma-privada` acepta tanto archivos `.pem`  como archivos `.keystore` cifrados. Cuando se pasa un `.keystore`, el CLI solicita la contraseña de firma antes de proceder:

```bash
# Con keystore cifrado
python main.py cifrar doc.txt doc.vault \
    --publicas alice_public.pem bob_public.pem \
    --firma-privada alice_signing_private.keystore
# Solicita: Contraseña de firma:  ← contraseña de identidad-firma
# Resultado: [+] Archivo cifrado y firmado digitalmente para 2 destinatario(s).

# Con PEM sin cifrar
python main.py cifrar doc.txt doc.vault \
    --publicas alice_public.pem \
    --firma-privada alice_signing_private.pem
# No solicita contraseña de firma
```

### Descifrar un archivo

Cuando el vault fue cifrado con firma digital, **todos los destinatarios** no solo el remitente deben pasar `--firma-publica` para verificar la autenticidad del origen.
El sistema rechaza descifrar un vault firmado si no se proporciona la llave de verificación.

```bash
# Descifrar con verificación de firma
python main.py descifrar doc.vault recuperado.txt \
    --privada alice_private.keystore \
    --firma-publica alice_signing_public.pem
# Solicita: Contraseña maestra:
# Resultado: [+] Archivo recuperado exitosamente. Firma verificada:  OK

# Descifrar sin verificación
python main.py descifrar doc.vault recuperado.txt --privada alice_private.keystore
# Solicita: Contraseña maestra:
```

### Respaldar un keystore

```bash
# Respaldar clave RSA
python main.py respaldar alice /ruta/segura/alice_private.keystore

# Respaldar clave de firma Ed25519
python main.py respaldar alice /ruta/segura/alice_signing_private.keystore --tipo ed25519
```

### Restaurar desde respaldo

```bash
python main.py restaurar /ruta/respaldo/alice_private.keystore
# Solicita: Contraseña maestra:
# Verifica la contraseña antes de restaurar
```