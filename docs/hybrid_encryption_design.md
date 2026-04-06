# Hybrid Encryption Design — D3: Cifrado Híbrido

## 1. Objetivo de seguridad

Este módulo mejora el sistema de cifrado autenticado (D2) para permitir el **intercambio seguro de archivos entre múltiples usuarios** mediante cifrado híbrido.

El sistema garantizara:

| Propiedad | Significado | Cómo se logra |
|-----------|-------------|---------------|
| **Confidencialidad** | Solo los destinatarios autorizados pueden leer el archivo | Cifrado AES-GCM-256 + encapsulamiento RSA-OAEP por destinatario |
| **Integridad** | Cualquier modificación al contenido cifrado es detectada | Auth tag de 128 bits (GCM) |
| **Control de acceso** | Solo los destinatarios incluidos en la lista pueden descifrar | Cada destinatario recibe su propia copia cifrada de la clave |
| **Protección de metadatos** | La lista de destinatarios no puede ser alterada | La lista de IDs se incluye en el AAD |

**Objetivo de seguridad D3:**
> *"Solo los destinatarios previstos pueden acceder al archivo, incluso si el contenedor cifrado está expuesto públicamente."*

---

## 2. ¿Por qué cifrado híbrido?

### El problema

El cifrado simétrico (AES-GCM) es rápido y seguro para cifrar archivos, pero tiene un problema:
¿cómo compartir la clave de forma segura con varios destinatarios?

El cifrado asimétrico (RSA) permite enviar datos de forma segura sin compartir secretos previamente,
pero tiene una limitación importante: **solo puede cifrar datos pequeños** (cientos de bytes como máximo,
dependiendo del tamaño de la clave RSA).

### La solución: combinar ambos

El cifrado híbrido combina lo mejor de ambos:

| Componente | Algoritmo | Qué hace |
|------------|-----------|----------|
| **Cifrado del archivo** | AES-GCM-256 (simétrico) | Cifra el contenido completo del archivo de forma rápida y segura |
| **Protección de la clave** | RSA-OAEP con SHA-256 (asimétrico) | Cifra la clave AES con la clave pública de cada destinatario |

```
Archivo original
       │
       ▼
  AES-GCM-256 (file_key)  ──────►  Ciphertext
       │
       │  file_key (32 bytes)
       │
       ├──► RSA-OAEP con clave pública de Alice  ──►  encrypted_key_alice
       ├──► RSA-OAEP con clave pública de Bob    ──►  encrypted_key_bob
       └──► RSA-OAEP con clave pública de Carol  ──►  encrypted_key_carol
```

### ¿Por qué sigue siendo necesario el cifrado simétrico?

RSA-OAEP con una clave de 2048 bits solo puede cifrar un máximo de **190 bytes** por operación.
Un archivo de 10 MB tendría que dividirse en más de 50,000 bloques RSA, lo cual sería lento e impráctico. Además, RSA no proporciona autenticación de datos (AEAD).

AES-GCM cifra archivos de cualquier tamaño en una sola operación, con autenticación incluida.

| Operación | AES-GCM | RSA-OAEP |
|-----------|---------|----------|
| Cifrar 1 MB | ~1 ms | ~26 segundos (en bloques de 190 bytes) |
| Autenticación incluida | Sí (auth tag) | No |
| Tamaño máximo por operación | Sin límite práctico | ~190 bytes (RSA-2048) |

### ¿Por qué es necesario cifrar la clave por cada destinatario?

Cada destinatario tiene su propio par de claves RSA (pública + privada). Para que Alice y Bob
puedan descifrar el mismo archivo, cada uno necesita una copia de la `file_key` protegida con
**su propia** clave pública, porque:

- Solo Alice tiene la clave privada de Alice → solo ella puede desenvolver su copia.
- Solo Bob tiene la clave privada de Bob → solo él puede desenvolver su copia.
- Un intruso sin clave privada autorizada no puede recuperar la `file_key` de ninguna entrada.

El archivo se cifra **una sola vez** con AES-GCM. Lo que se duplica es solo el encapsulamiento
de la clave (32 bytes por destinatario), lo cual es eficiente.

---

## 3. Algoritmo de encapsulamiento de clave: RSA-OAEP

### ¿Qué es RSA-OAEP?

**RSA-OAEP** (RSA con Optimal Asymmetric Encryption Padding) es un esquema de cifrado de clave
pública que protege datos pequeños como claves simétricas de forma segura.

- **RSA:** algoritmo asimétrico basado en la dificultad de factorizar números grandes.
- **OAEP:** esquema de padding que protege contra ataques de texto cifrado elegido.

### Parámetros utilizados

| Parámetro | Valor | Justificación |
|-----------|-------|---------------|
| **Tamaño de clave RSA** | 2048 bits | Nivel de seguridad equivalente a ~112 bits simétricos. Recomendado por NIST hasta 2030. |
| **Padding** | OAEP | Seguro contra ataques CCA2 (Chosen Ciphertext Attack). |
| **Función hash** | SHA-256 | Se usa tanto para el hash del mensaje como para el MGF (Mask Generation Function). |
| **Dato cifrado** | 32 bytes (file_key AES-256) | Muy por debajo del límite de 190 bytes de RSA-2048 con OAEP-SHA256. |

### Implementación

```python
# Cifrar la file_key con la clave pública del destinatario
enc_key = pub_key.encrypt(
    file_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Descifrar la file_key con la clave privada
file_key = priv_key.decrypt(
    encrypted_key_bytes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

---

## 4. Mecanismo de identificación de destinatarios: Fingerprint

### El problema

Cuando un destinatario recibe un archivo `.vault`, necesita encontrar **su** entrada en la lista
de destinatarios. Esto debe hacerse de forma:

- **Determinista:** dado el mismo par de claves, siempre se obtiene el mismo ID.
- **Segura contra confusiones:** dos usuarios distintos nunca comparten el mismo ID.
- **Sin información externa:** no depende de nombres de usuario ni rutas de archivo.

### La solución: SHA-256 de la clave pública en formato DER

```python
def get_key_fingerprint(public_key) -> str:
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(pub_bytes).hexdigest()[:32]
```

| Paso | Qué hace | Por qué |
|------|----------|---------|
| Exportar en DER | Convierte la clave pública a bytes | DER es un formato binario estándar. La misma clave siempre produce los mismos bytes. |
| SHA-256 | Calcula el hash de los bytes | Produce un identificador de longitud fija (256 bits) independiente del tamaño de la clave. |
| Primeros 32 hex chars | Toma los primeros 16 bytes del hash | 16 bytes = 128 bits de entropía. |

### Búsqueda directa

Al descifrar, el destinatario calcula su propio fingerprint una vez y busca directamente
en un diccionario indexado por ID:

```python
# Calcular mi ID a partir de mi clave privada
my_id = get_key_fingerprint(priv_key.public_key())

# Crear índice de búsqueda directa — O(1), sin iterar
recipients_index = {entry["recipient_id"]: entry for entry in container["recipients"]}

if my_id not in recipients_index:
    raise ValueError("Este usuario no está en la lista de destinatarios.")
```

Esto es más seguro y eficiente que iterar intentando descifrar cada entrada con `try/except`,
porque:

- **Seguridad:** un usuario no autorizado recibe un error inmediato sin ejecutar ninguna
  operación criptográfica con las claves de otros destinatarios.

---

## 5. AAD actualizado: protección de la lista de destinatarios

### ¿Qué cambió respecto a D2?

En D2, el AAD solo contenía el nombre del archivo, timestamp, algoritmo y versión.
En D3, el AAD **incluye la lista ordenada de IDs de destinatarios**:

```python
aad = json.dumps(
    {
        "filename": os.path.basename(input_path),
        "recipients": sorted(recipient_ids),
        "version": "2.0"
    },
    separators=(",", ":"),
    sort_keys=True
).encode()
```

### ¿Por qué incluir los destinatarios en el AAD?

Porque el AAD queda como "asegurado" al auth tag de AES-GCM. Si un atacante modifica la lista
de destinatarios en el header, el auth tag ya no coincide y el descifrado falla:

| Ataque | Qué intenta el atacante | Resultado |
|--------|------------------------|-----------|
| **Agregar destinatario** | Añade un ID falso a la lista en el header | Auth tag inválido → descifrado falla |
| **Quitar destinatario** | Elimina un ID de la lista en el header | Auth tag inválido → descifrado falla |
| **Intercambiar identidades** | Cambia un ID por otro en la lista | Auth tag inválido → descifrado falla |

### Serialización determinista

La lista se ordena con `sorted()` antes de incluirla en el AAD. Esto garantiza que
independientemente del orden en que se pasen las claves públicas al cifrar, el AAD
siempre produce los mismos bytes → el descifrado funciona correctamente.

---
