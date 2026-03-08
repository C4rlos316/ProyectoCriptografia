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
## 7. Aleatoriedad segura


### Fuentes de aleatoriedad utilizadas


| Operación | Función | Fuente subyacente |
|-----------|---------|-------------------|
| Generación de clave (256 bits) | `AESGCM.generate_key(bit_length=256)` | `os.urandom()` → CSPRNG del OS |
| Generación de nonce (96 bits) | `os.urandom(12)` | CSPRNG del OS directamente |


### ¿Qué es un CSPRNG?


Un **CSPRNG** (Cryptographically Secure Pseudo-Random Number Generator) es un generador de
números aleatorios que cumple con propiedades de seguridad criptográfica:


- **Impredecible:** Conocer valores anteriores no permite predecir valores futuros.
- **Resistente a ataques de estado:** Incluso si un atacante obtiene el estado interno del
  generador, no puede reconstruir valores pasados.


`os.urandom()` en Python delega al sistema operativo:
- **Windows:** `BCryptGenRandom` (antes `CryptGenRandom`)
- **Linux:** `getrandom()` / `/dev/urandom`
- **macOS:** `getentropy()`


### Lo que NO hacemos (y por qué)


| Mala práctica | Riesgo | Nuestra decisión |
|---------------|--------|------------------|
| Usar `random.random()` | Es un PRNG predecible (Mersenne Twister), no criptográfico. Un atacante puede predecir la secuencia. | Usamos `os.urandom()` exclusivamente |
| Sembrar manualmente (`random.seed(42)`) | Produce la misma secuencia cada vez. Todas las claves y nonces serían predecibles. | Nunca sembramos; dejamos que el OS provea entropía |
| Usar el timestamp como semilla | Solo hay ~1 segundo de resolución; un atacante puede adivinar el valor. | El timestamp solo aparece en los metadatos, nunca como fuente de aleatoriedad |


---


## 8. Formato del contenedor `.vault`


Cada operación de cifrado produce un archivo `.vault` que contiene todo lo necesario para
descifrar el archivo (excepto la clave, que se gestiona por separado).


### Estructura


```
vault_container (.vault)
 ├── header        → metadatos autenticados (AAD), legibles
 ├── nonce         → valor único para este cifrado (hex)
 └── ciphertext    → contenido cifrado + auth_tag de 16 bytes (hex)
```


### Ejemplo real de un archivo `.vault`


```json
{
  "header": {
    "algorithm": "AES-GCM-256",
    "filename": "documento.txt",
    "timestamp": 1709836800,
    "version": "1.0"
  },
  "nonce": "a1b2c3d4e5f6a1b2c3d4e5f6",
  "ciphertext": "7f3a9c...e8b201"
}
```


| Campo | Formato | Tamaño | Descripción |
|-------|---------|--------|-------------|
| `header` | Objeto JSON | Variable | Metadatos del archivo. Se reconstruye como AAD al descifrar. |
| `nonce` | Hex string | 24 caracteres (12 bytes) | Nonce único usado en el cifrado. |
| `ciphertext` | Hex string | `(len(plaintext) + 16) * 2` chars | Contenido cifrado concatenado con el auth tag de 16 bytes. |


### ¿Por qué JSON y no binario?


- **Legibilidad:** Permite inspeccionar los metadatos sin herramientas especiales.
- **Portabilidad:** JSON es universal y se puede parsear en cualquier lenguaje.
- **Depuración:** Facilita el desarrollo y las pruebas durante esta etapa.
- **El ciphertext sigue siendo opaco:** Aunque el formato es JSON, los datos cifrados se
  almacenan como hex strings y son ilegibles sin la clave.


---


## 9. Flujo de cifrado y descifrado


### Cifrado (`encrypt_file`)


```
Archivo original
       │
       ▼
  1. Leer contenido (bytes)
       │
       ▼
  2. Generar clave AES-256    ← AESGCM.generate_key(256)  [CSPRNG]
  3. Generar nonce 96 bits     ← os.urandom(12)            [CSPRNG]
  4. Construir AAD             ← build_aad(filename)        [JSON determinista]
       │
       ▼
  5. aesgcm.encrypt(nonce, plaintext, aad)
       │
       ▼
  6. ciphertext || auth_tag   (el tag va al final, 16 bytes)
       │
       ▼
  7. Guardar contenedor .vault (JSON con header, nonce, ciphertext)
       │
       ▼
  8. Retornar la clave al usuario
```


### Descifrado (`decrypt_file`)


```
Archivo .vault + clave
       │
       ▼
  1. Leer contenedor JSON
       │
       ▼
  2. Reconstruir AAD desde header  ← json.dumps(header, sort_keys=True)
  3. Extraer nonce (hex → bytes)
  4. Extraer ciphertext (hex → bytes)
       │
       ▼
  5. aesgcm.decrypt(nonce, ciphertext, aad)
       │
       ├── OK → plaintext original → escribir archivo de salida
       │
       └── FALLO → InvalidTag → NO se escribe nada, retorna False
```


---


## 10. Pruebas implementadas


Se implementaron **20 tests** organizados en 5 clases que cubren todos los requisitos de D2:


| # | Clase | Tests | Qué valida |
|---|-------|-------|------------|
| 1 | `TestRoundtrip` | 4 | Cifrar y descifrar produce un archivo idéntico (texto, vacío, 1 MB, binario) |
| 2 | `TestWrongKey` | 3 | La clave incorrecta falla (clave diferente, ceros, 1 bit cambiado) |
| 3 | `TestCiphertextTamper` | 4 | Ciphertext modificado es detectado (primer byte, medio, tag, truncado) |
| 4 | `TestMetadataTamper` | 4 | Metadata modificada es detectada (filename, algorithm, AAD completo, AAD vacío) |
| 5 | `TestRandomness` | 5 | Cifrados múltiples producen diferentes ciphertexts, nonces y claves |


Ejecutar con: `pytest tests/test_encryption.py -v`


---


## 11. Decisiones de seguridad


### ¿Por qué AEAD en lugar de cifrado + hash separados?


| Aspecto | Cifrado + Hash manual | AEAD (AES-GCM) |
|---------|----------------------|-----------------|
| **Operaciones** | Dos separadas: cifrar con AES-CBC/CTR + calcular HMAC-SHA256 | Una sola llamada: `aesgcm.encrypt()` |
| **Riesgo de error** | Alto. El orden importa: Encrypt-then-MAC es seguro, pero MAC-then-Encrypt es vulnerable a padding oracles. Un error de implementación rompe todo. | Bajo. El algoritmo integra ambas operaciones internamente de forma inseparable. |
| **Claves necesarias** | Dos: una para cifrar, otra para el MAC. Si se reutiliza la misma clave para ambas, se debilita la seguridad. | Una sola clave para todo. |
| **Metadatos** | Hay que decidir explícitamente qué incluir en el MAC y cómo. Si se olvida incluir un campo, queda desprotegido. | El parámetro AAD protege automáticamente cualquier dato asociado que se pase. |
| **Estándar** | No hay un estándar único; cada implementación puede hacerlo diferente. | NIST SP 800-38D define exactamente cómo funciona AES-GCM. |


**Conclusión:** AEAD elimina una categoría completa de errores de implementación y ofrece
las mismas garantías de seguridad en un solo primitivo estandarizado.


### ¿Qué pasa si el nonce se repite?


(Ver sección 4 — Estrategia de nonce)


En resumen: la reutilización de nonce en AES-GCM es **catastrófica** porque:
- Rompe la confidencialidad (XOR de plaintexts queda expuesto).
- Rompe la autenticación (el atacante puede forjar tags válidos).
- **Nuestra mitigación:** nonce aleatorio de 96 bits por cifrado + clave única por archivo.


### ¿Contra qué atacante nos defendemos?


**Atacante A1 — Externo con acceso al almacenamiento:**


Este es el adversario principal en D2. Tiene las siguientes capacidades:
- Puede leer todos los archivos `.vault` almacenados en disco.
- Puede copiar, analizar y comparar contenedores cifrados.
- **No** tiene acceso a la clave simétrica ni a la memoria de la aplicación.


Nuestras defensas:
- **AES-256** hace que descifrar por fuerza bruta sea computacionalmente infactible
  (2^256 posibles claves; incluso con todos los computadores del mundo trabajando en
  paralelo, tomaría más tiempo que la edad del universo).
- **El auth tag** impide que modifique el ciphertext o los metadatos sin ser detectado.
- **Clave única por archivo** limita el impacto: comprometer una clave no afecta a otros archivos.


**Atacante A3 — Man-in-the-Middle:**


Puede interceptar y modificar el contenedor antes de que llegue al destinatario.
- Cualquier modificación al ciphertext, nonce o metadata causa `InvalidTag` al descifrar.
- No puede generar un contenedor válido sin poseer la clave simétrica.
- No puede modificar selectivamente los metadatos porque están protegidos por el AAD.
## 12. Manual de Uso y CLI (Command Line Interface)


Para facilitar la evaluación y uso del módulo criptográfico, se implementó una Interfaz de Línea de Comandos (CLI) interactiva. Esta herramienta abstrae la complejidad criptográfica y permite ejecutar el flujo de la Bóveda Segura directamente desde la terminal.


### 12.1. Configuración del Entorno (Prerrequisitos)


Para garantizar la reproducibilidad y evitar conflictos con dependencias del sistema operativo, el proyecto debe ejecutarse dentro de un entorno virtual de Python.


**Paso 1: Crear y activar el entorno virtual**
# Crear el entorno (ejecutar en la raíz del proyecto)
python -m venv .venv


# Activar el entorno en linea de comandos (en caso de que no aparezca ())
.\.venv\Scripts\activate


