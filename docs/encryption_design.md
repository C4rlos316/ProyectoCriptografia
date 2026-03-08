# Encryption Design — D2: Cifrado Autenticado de Archivos

## 1. Objetivo de seguridad

Este módulo es el **nucleo criptografico** del Secure Digital Document Vault.
Su propósito es garantizar tres propiedades fundamentales para cada archivo cifrado:

| Propiedad | Significado | Cómo se logra |
|-----------|-------------|---------------|
| **Confidencialidad** | Nadie sin la clave puede leer el contenido | Cifrado AES-256 en modo GCM |
| **Integridad** | Cualquier modificación al contenido cifrado es detectada | Auth tag de 128 bits (GCM) |
| **Detección de manipulación** | Cualquier cambio en los metadatos también es detectado | Datos Autenticados Asociados (AAD) |

**Objetivo de seguridad D2:**
> *"Un atacante que obtenga el archivo cifrado no debe poder leer ni modificar su contenido sin ser detectado."*

En esta etapa el sistema cifra archivos **para un solo propietario** (aún no se comparten).
La clave simétrica se retorna al usuario directamente; en entregas futuras (D3+) se protegerá
con la clave pública del destinatario (cifrado híbrido).

---

## 2. Algoritmo AEAD seleccionado: AES-GCM-256

### ¿Qué es AEAD?

**AEAD** (Authenticated Encryption with Associated Data) es una clase de algoritmos criptográficos
que realizan **dos operaciones en una sola llamada**:

1. **Cifrado** — transforma el contenido legible (plaintext) en datos ilegibles (ciphertext).
2. **Autenticación** — genera una etiqueta (auth tag) que prueba que ni el ciphertext ni los
   datos asociados (metadatos) fueron modificados.

Esto significa que con una sola operación obtenemos confidencialidad + integridad + detección de
manipulación. No necesitamos implementar un MAC por separado.

### ¿Por qué elegimos AES-GCM?

**AES-GCM** = Advanced Encryption Standard en modo Galois/Counter Mode.

- Es el estándar de la industria (TLS 1.3, IPsec, almacenamiento en la nube).
- Tiene soporte nativo en hardware moderno (instrucciones AES-NI en procesadores Intel/AMD),
  lo que lo hace extremadamente rápido.
- Está estandarizado por NIST en la publicación **SP 800-38D**.
- La librería `cryptography` de Python (PyCA) proporciona una implementación auditada y
  respaldada por OpenSSL.

### Implementación

- **Librería:** `cryptography` (PyCA) — clase `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
- **Función de cifrado:** `aesgcm.encrypt(nonce, plaintext, aad)` → retorna `ciphertext || auth_tag`
- **Función de descifrado:** `aesgcm.decrypt(nonce, ciphertext, aad)` → retorna `plaintext`
  o lanza `InvalidTag` si hay cualquier manipulación.

---

## 3. Tamaño de clave y parámetros criptográficos

| Parámetro | Valor | Justificación |
|-----------|-------|---------------|
| **Clave AES** | 256 bits (32 bytes) | Máximo nivel de seguridad de AES. Resistente a ataques de fuerza bruta incluso con computación cuántica parcial (Grover reduce la seguridad efectiva a 128 bits, que sigue siendo seguro). |
| **Nonce (IV)** | 96 bits (12 bytes) | Tamaño recomendado por NIST SP 800-38D para AES-GCM. Con 96 bits, el nonce se usa directamente como IV del contador interno sin necesidad de una función hash adicional. |
| **Auth Tag** | 128 bits (16 bytes) | Tamaño máximo soportado por GCM. La probabilidad de falsificar un tag válido es de 1 en 2^128, lo que hace la falsificación computacionalmente imposible. |

### Generación de la clave

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=256)
```

- `AESGCM.generate_key()` internamente usa `os.urandom()`, que es el **CSPRNG**
  (Cryptographically Secure Pseudo-Random Number Generator) del sistema operativo.
- En Windows usa `CryptGenRandom` (BCryptGenRandom); en Linux usa `/dev/urandom`.
- **Se genera una clave nueva por cada archivo** que se cifra → si una clave se compromete,
  solo afecta a un archivo (principio de separación de claves, RS-7).

---

## 4. Estrategia de nonce

### Generación

```python
nonce = os.urandom(12)   # 96 bits aleatorios del CSPRNG del OS
```

- Se genera un **nonce nuevo** en cada operación de cifrado.
- Se usa `os.urandom()` que accede directamente a la API de aleatoriedad del sistema operativo.
- **Nunca** se siembra manualmente ni se usa `random.random()` (que es predecible).

### Unicidad

Con 96 bits de aleatoriedad, la probabilidad de colisión (repetir un nonce) sigue el
problema del cumpleaños:

- Después de **2^32 (~4 mil millones)** de cifrados con la misma clave, la probabilidad de
  colisión es de aproximadamente **2^-33** (1 en 8 mil millones).
- Como nuestro sistema genera una **clave nueva por cada archivo**, el nonce solo se usa
  **una vez por clave**, eliminando completamente el riesgo de reutilización.

### Almacenamiento

El nonce **no es secreto** — se almacena en el contenedor `.vault` como una cadena hexadecimal
junto al ciphertext. Lo que importa es que sea **único**, no que sea secreto.

### ¿Qué pasa si el nonce se repite con la misma clave?

Si un atacante obtiene dos ciphertexts `C1` y `C2` cifrados con la misma clave y el mismo nonce:

1. **Pérdida de confidencialidad:** `XOR(C1, C2) = XOR(P1, P2)`. El atacante obtiene el XOR
   de los dos plaintexts originales. Si conoce parcialmente uno de los textos (lo cual es
   común con formatos conocidos como PDF, HTML, JSON), puede deducir el otro completamente.

2. **Destrucción de la autenticación:** El polinomio de autenticación GHASH se vuelve
   resoluble. El atacante puede **forjar auth tags válidos** para cualquier ciphertext que
   desee, rompiendo completamente la integridad.

3. **Conclusión:** La reutilización de nonce en AES-GCM compromete **todas** las propiedades
   de seguridad simultáneamente (confidencialidad, integridad y autenticación). Por eso
   nuestro sistema genera un nonce aleatorio nuevo en cada cifrado y usa una clave distinta
   por archivo como doble protección.

---

## 5. Estrategia de autenticación de metadatos (AAD)

### ¿Qué es el AAD?

**AAD** (Associated Authenticated Data) son datos que se **autentican pero no se cifran**.
Esto significa que:

- Cualquiera puede **leer** los metadatos (son visibles en el contenedor `.vault`).
- **Nadie puede modificarlos** sin ser detectado, porque el auth tag de AES-GCM los protege.
- Si un atacante cambia cualquier byte del AAD, la operación de descifrado falla con `InvalidTag`.

### ¿Por qué usar AAD?

Los metadatos necesitan estar visibles (por ejemplo, para saber qué algoritmo se usó antes de
intentar descifrar), pero no deben ser manipulables. Un atacante podría intentar:

- Cambiar el nombre del archivo para confundir al receptor.
- Cambiar la versión del algoritmo para forzar una ruta de descifrado más débil.
- Alterar la marca de tiempo para falsificar cuándo se creó el documento.

El AAD previene todos estos ataques sin necesidad de cifrar los metadatos.

### Campos del AAD

Los metadatos se construyen con la función `build_aad(filename)` y se serializan como JSON:

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `algorithm` | string | Identificador del algoritmo: `"AES-GCM-256"` |
| `filename` | string | Nombre original del archivo cifrado |
| `timestamp` | int | Marca de tiempo Unix (epoch) del momento de cifrado |
| `version` | string | Versión del formato del contenedor: `"1.0"` |

### Serialización determinista

Para que el AAD sea idéntico al cifrar y al descifrar, se serializa con parámetros estrictos:

```python
json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
```

- `sort_keys=True` — ordena las claves del JSON alfabéticamente, garantizando el mismo orden siempre.
- `separators=(",", ":")` — elimina espacios en blanco, produciendo un JSON compacto e idéntico byte a byte.
- `.encode("utf-8")` — convierte a bytes para pasarlo como AAD a AES-GCM.

Sin estos parámetros, el orden de las llaves podría cambiar entre ejecuciones de Python,
causando que el AAD no coincida y el descifrado falle erróneamente.

---

## 6. Detección de manipulación

AES-GCM proporciona detección de manipulación automática a través del auth tag de 128 bits.
El sistema detecta y rechaza los siguientes ataques:

| Tipo de manipulación | Qué pasa al descifrar | Test que lo demuestra |
|----------------------|----------------------|----------------------|
| Ciphertext modificado (cualquier byte) | `InvalidTag` | `TestCiphertextTamper` (4 tests) |
| Auth tag modificado (últimos 16 bytes) | `InvalidTag` | `test_modificar_auth_tag` |
| Ciphertext truncado | `InvalidTag` / `Exception` | `test_ciphertext_truncado` |
| Metadata (AAD) modificada | `InvalidTag` | `TestMetadataTamper` (4 tests) |
| Clave incorrecta | `InvalidTag` | `TestWrongKey` (3 tests) |
| Nonce modificado | `InvalidTag` | El nonce es input del descifrado; si cambia, el tag no coincide |

### Fallo seguro

Cuando AES-GCM detecta manipulación:

1. **Nunca retorna datos parciales** — el plaintext no se revela si la verificación falla.
2. La librería lanza la excepción `cryptography.exceptions.InvalidTag`.
3. Nuestra función `decrypt_file()` captura la excepción, imprime un mensaje de error
   y retorna `False` sin escribir ningún archivo de salida.
4. No se revela información sobre *qué* fue lo que falló (ciphertext vs metadata vs clave),
   lo que evita dar pistas al atacante.

---
