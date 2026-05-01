# Signature Design — D5: Autenticación de Origen e Integridad

## 1. Diseño de la Firma (Signature Design)

### Algoritmo elegido: Ed25519
Para la implementación de firmas digitales se seleccionó **Ed25519**. 
- **¿Por qué?** Es el estándar moderno preferido por su alta velocidad, firmas pequeñas de 64 bytes y su resistencia contra ataques de canal lateral.

### ¿Qué datos se firman?
La firma digital amarra todo el contexto del archivo mediante la función `_build_signable()`, que concatena:
1. El **Ciphertext** (el archivo cifrado en hexadecimal).
2. El **Header / Metadatos** (que incluye el nombre del archivo y la lista de destinatarios).

### ¿Por qué es necesario aplicar un Hash antes de firmar?
Firmar archivos grandes directamente es ineficiente. Al aplicar **SHA-256** sobre la concatenación del ciphertext y los metadatos, reducimos el volumen de datos a un resumen único de 32 bytes. Firmar este hash es matemáticamente equivalente a firmar el documento entero, garantizando que el proceso sea rápido sin importar el tamaño del archivo.

---

## 2. Decisiones de Seguridad (Security Decisions)

### ¿Por qué firmar el Ciphertext y no el Plaintext?
Implementamos el paradigma **"Encrypt-then-Sign"**:
1. Permite al destinatario verificar la autenticidad del paquete **antes** de intentar descifrarlo.
2. Protege el contenedor exterior (`.vault`), impidiendo que un atacante manipule la estructura antes de que llegue al usuario.

### ¿Qué sucede si la firma NO se verifica primero?
Si el sistema descifrara antes de verificar, estaría procesando datos potencialmente maliciosos. Al verificar la firma como el **paso número 1**, el sistema descarta archivos manipulados instantáneamente, ahorrando ciclos de CPU y protegiendo el motor de descifrado.

### ¿Qué sucede si se excluyen los metadatos de la firma?
Si solo se firmara el ciphertext, un atacante podría interceptar el archivo y cambiar el `header` (por ejemplo, alterando la lista de `recipients` para agregar su propia llave). Al incluir el `header` en el hash de la firma, cualquier cambio en los metadatos invalida la firma por completo.