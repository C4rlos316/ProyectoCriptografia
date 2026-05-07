# 1- Almacenamiento Inseguro de Identidades

### Título: Persistencia de claves privadas en texto claro (Falta de cifrado en reposo)

### Descripción
El sistema de bóveda segura permite la generación de identidades mediante el comando `python main.py identidad <nombre>`, produciendo archivos `.pem` para las llaves pública y privada. Se ha identificado que la función de serialización en el código fuente utiliza `serialization.NoEncryption()`, lo que provoca que la clave privada se almacene sin ninguna capa de protección criptográfica en el disco duro

Esta implementación contradice directamente el modelo de seguridad del proyecto, el cual exige que las claves privadas estén protegidas por una Función de Derivación de Claves (KDF) y cifrado simétrico para evitar el acceso no autorizado por parte de adversarios con acceso al sistema de archivos

### Impacto
El impacto de este hallazgo es **Crítico**, afectando los pilares de Confidencialidad y Autenticidad del sistema:
* **Acceso No Autorizado:** Cualquier usuario o proceso con permisos de lectura sobre el archivo `.pem` puede extraer la clave privada directamente.
* **Suplantación de Identidad:** Un atacante puede cargar la llave sin conocer una contraseña, permitiéndole descifrar archivos dirigidos al usuario y generar firmas digitales falsas a su nombre.
* **Nulidad de Protección:** Se invalida el factor de conocimiento, dejando la seguridad del sistema dependiente exclusivamente de la seguridad física del dispositivo.

### Pasos para reproducir el fenómeno
1. **Generación:** Ejecutar el comando `python main.py identidad alice` para crear una nueva identidad.
2. **Inspección:** Abrir el archivo generado `alice_private.pem` con un editor de texto plano o mediante el comando `type` en consola.
3. **Verificación visual:** Confirmar que el encabezado del archivo es `-----BEGIN PRIVATE KEY-----`La ausencia de la etiqueta `ENCRYPTED` confirma que la llave no posee cifrado.
4. **Validación técnica:** Ejecutar un script que utilice `load_pem_private_key(data, password=None)`. Si la llave se carga exitosamente, la vulnerabilidad es positiva.

### Gravedad
**CRÍTICA**

### Arreglar
Se debe modificar la lógica de persistencia de llaves para solicitar obligatoriamente una contraseña al usuario y aplicar el estándar de cifrado **PKCS8** con **AES-256**.

