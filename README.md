# 🔐 Proyecto Criptografía


### Integrantes del equipo y roles

| Integrante | Rol |
|-----------|-----|
| [Hernández Ramírez Miguel Angel](https://github.com/Miguel07FI) | Desarrollo, Revisor de código, Avances |
| [Hernández Gutiérrez Carlos Mario](https://github.com/C4rlos316) | Desarrollo, Testing, Project Manager |
| [Solís Espinosa Andrea Vianney](https://github.com/aviansol) | Desarrollo, Arquitectura, Diseño del sistema |
| [Rivera Lopez David Zaid](https://github.com/AvalonRD) | Desarrollo, Documentación, Analista de riesgos |
| [Suárez Román Clara Alin](https://github.com/clarasrzfi) | Desarrollo, Documentación técnica, Validación de seguridad |


## Arquitectura y modelo de amenazas

---

## 1. Visión General del Sistema

### ¿Qué problema resuelve este vault?

El **Secure Digital Document Vault** aborda la vulnerabilidad inherente en el intercambio de archivos digitales sobre canales inseguros y el almacenamiento en reposo no confiable. Nuestra propuesta resuelve el problema de la gestión de secretos, eliminando la dependencia de la confianza en el proveedor de almacenamiento y mitigando errores humanos comunes en la gestión manual de claves:

- Solo los destinatarios autorizados puedan acceder al contenido
- El contenido no pueda ser modificado sin detección
- El origen del documento pueda ser verificado de manera confiable
- Las claves privadas de los usuarios estén protegidas incluso si el dispositivo es comprometido

### Características principales

####  Cifrado de archivos
Proceso mediante el cual los documentos se transforman en datos ilegibles para terceros no autorizados, utilizando algoritmos criptográficos avanzados que aseguran confidencialidad y resistencia frente a intentos de descifrado no autorizados.

####  Compartición segura
Mecanismo que permite distribuir archivos cifrados únicamente a destinatarios previamente seleccionados, garantizando que solo ellos puedan acceder al contenido mediante claves o credenciales específicas, evitando filtraciones o accesos indebidos.

####  Firma digital
Técnica criptográfica que vincula de manera única al autor con el documento, proporcionando evidencia verificable de autenticidad y asegurando que el contenido no ha sido alterado desde su firma, además de ofrecer protección contra el repudio.

####  Gestión de claves
Conjunto de procedimientos que abarcan la creación, almacenamiento seguro, distribución controlada y eventual renovación de claves criptográficas, asegurando que estas permanezcan protegidas y disponibles únicamente para usuarios autorizados.

####  Verificación de integridad
Método de comprobación que valida que los documentos no han sufrido modificaciones, mediante el uso de funciones hash o sumas de verificación, garantizando que el contenido recibido es idéntico al original.

####  Control de acceso y auditoría
Sistema que define permisos específicos para cada usuario o grupo, regulando acciones como lectura, edición o eliminación, acompañado de registros detallados de todas las operaciones realizadas para asegurar trazabilidad y cumplimiento normativo.

---

### Fuera del Alcance

Los siguientes elementos **NO** forman parte del sistema:

| Elemento | Razón |
|----------|-------|
| **Almacenamiento en la nube o servidor centralizado** | Requiere infraestructura adicional y gestión de disponibilidad, lo cual excede el objetivo de protección documental. |
| **Sistema de mensajería en tiempo real** | Implica comunicación instantánea y sincronización continua, lo cual no corresponde al enfoque de seguridad de archivos. |
| **Revocación de acceso a documentos ya compartidos** | Demanda un control dinámico posterior a la distribución, lo que requiere arquitecturas más complejas de gestión de derechos digitales. |
| **Versionamiento de documentos** | Implica mantener múltiples estados históricos de un archivo, lo cual pertenece a sistemas de gestión documental más amplios. |
| **Sincronización automática entre dispositivos** | Requiere integración con múltiples plataformas y servicios, lo que añade complejidad operativa fuera del objetivo principal. |
| **Disponibilidad y resistencia a ataques DoS** | Corresponde a medidas de infraestructura y seguridad de red, más relacionadas con servidores que con documentos cifrados. |
| **Anonimato de red** | Involucra técnicas de ocultamiento de identidad en la comunicación, lo cual pertenece al ámbito de privacidad en redes y no al manejo de archivos. |
| **Ocultar la existencia del archivo** | Implica técnicas de esteganografía o disimulación, que van más allá de la protección mediante cifrado y gestión de claves. |
| **Recuperación de contraseñas olvidadas** | Requiere mecanismos adicionales de gestión de credenciales y políticas de soporte al usuario, lo cual no es parte del alcance definido. |
| **Gestión de archivos digitales una vez cifrado** | Corresponde a sistemas de administración documental posteriores al cifrado, como organización, clasificación o eliminación. |

---

## 2. Diagrama de Arquitectura

### Descripción del Flujo Operativo

El diagrama de arquitectura ilustra el flujo operativo de la Bóveda Segura de Documentos Digitales, estableciendo una separación estricta entre los **componentes de confianza**, alojados en el lado del cliente, y los **componentes no confiables**, correspondientes a la red y al almacenamiento remoto.

####  Proceso de Emisión (Cifrado)

El proceso de emisión inicia cuando el usuario proporciona:
- Su **contraseña**
- El **archivo en texto claro**
- La **selección del destinatario**

**Flujo detallado:**

1. **Desbloqueo del Key Store**
   - La contraseña es procesada mediante una función de derivación de claves (**KDF**)
   - Se desbloquea el Key Store local
   - Se extrae de manera segura la clave privada del remitente en memoria temporal

2. **Cifrado del Archivo**
   - El sistema genera una clave simétrica aleatoria y única para el documento
   - Se emplea un esquema de cifrado autenticado (**AEAD**) para transformar el archivo original
   - Se garantiza tanto confidencialidad como integridad

3. **Envolvimiento de Clave**
   - La clave simétrica es "envuelta" mediante cifrado asimétrico
   - Se utiliza la clave pública del receptor
   - Solo el destinatario autorizado podrá acceder a la información

4. **Firma Digital**
   - El sistema calcula una firma digital utilizando la clave privada del remitente
   - Se dota al paquete de evidencia criptográfica para el no repudio
   - Se valida la autenticidad del emisor

5. **Ensamblaje del Contenedor**
   - Todos los elementos se consolidan en un contenedor único:
     - Archivo cifrado
     - Claves envueltas
     - Metadatos
     - Firma digital
   - Se estructura dentro del entorno seguro del cliente

####  Transmisión Segura

Una vez ensamblado, el contenedor es transmitido a través de un canal de red seguro (mediante **TLS/SSL**) hacia el servidor backend. El entorno remoto (API y base de datos central) asume un **modelo de almacenamiento no confiable**. El servidor actúa exclusivamente como un repositorio inerte de los contenedores cifrados y del almacén de claves públicas, careciendo por completo de la capacidad para leer el contenido de los archivos o extraer las claves simétricas.

####  Proceso de Recuperación (Descifrado)

El modelo detalla el flujo de recuperación y verificación ejecutado por el destinatario:

1. **Descarga del Contenedor**
   - El destinatario descarga el contenedor desde el almacenamiento remoto

2. **Verificación de Firma**
   - La aplicación ejecuta una validación de la firma digital **ANTES** de cualquier manipulación
   - ❌ Si la firma es inválida → proceso se detiene inmediatamente
   - ✅ Si la firma es válida → continúa el proceso

3. **Desenvolvimiento de Clave**
   - El sistema desenvuelve la clave simétrica
   - Utiliza la clave privada del receptor (desbloqueada previamente con su contraseña)

4. **Descifrado del Archivo**
   - Se emplea la clave simétrica recuperada para revertir el proceso AEAD
   - Se descifra el archivo original
   - Se entrega al usuario de forma íntegra dentro de su dispositivo local

---

###  Diagrama Visual
![Arquitectura del sistema](diagrama.png)

---

## 3. Requisitos de Seguridad

Para los requisitos de seguridad se tienen las siguientes propiedades:

### RS-1: Confidencialidad del contenido del archivo
**Descripción:** Un atacante que obtenga el contenedor cifrado no debe poder conocer el contenido del archivo sin poseer la clave privada correspondiente del destinatario autorizado.

### RS-2: Integridad del contenido del archivo
**Descripción:** Cualquier modificación al contenido cifrado del archivo debe ser detectada durante el proceso de descifrado, resultando en el rechazo del archivo.

### RS-3: Autenticidad del remitente
**Descripción:** Un destinatario debe poder verificar de manera criptográfica que el archivo fue creado y firmado por el remitente declarado y no por un impostor.

### RS-4: Confidencialidad de las claves privadas
**Descripción:** Las claves privadas almacenadas en el sistema deben estar protegidas mediante derivación de clave basada en contraseña (KDF). Un atacante con acceso al Key Store no debe poder extraer las claves privadas sin conocer la contraseña del usuario.

### RS-5: Protección contra manipulación
**Descripción:** Cualquier alteración de los metadatos del contenedor cifrado (incluyendo las claves envueltas, la firma digital o los identificadores de destinatarios) debe ser detectable e invalidar el archivo completo.

### RS-6: No repudio
**Descripción:** El remitente no debe poder negar haber creado y firmado un documento, ya que la firma digital proporciona evidencia criptográfica de autoría.

### RS-7: Separación de claves por archivo
**Descripción:** Cada archivo debe ser cifrado con una clave simétrica única e independiente. El compromiso de una clave de archivo no debe comprometer otros archivos.

### RS-8: Confidencialidad de claves simétricas de archivo
**Descripción:** Las claves simétricas utilizadas para cifrar archivos individuales no deben ser almacenadas en texto plano. Deben estar protegidas mediante envolvimiento con las claves públicas de los destinatarios.

---

## 4. Modelo de Amenazas

### 4.1 Activos a Proteger

| Activo | Criticidad | Descripción |
|--------|-----------|-------------|
| **Contenido de archivos** |  Alta | El contenido original de los documentos que se comparten |
| **Claves privadas de usuarios** |  **Crítica** | Las claves que permiten descifrar archivos y firmar documentos |
| **Claves simétricas de archivos** |  Alta | Claves únicas generadas para cifrar cada archivo |
| **Contraseñas de usuarios** |  **Crítica** | Credenciales utilizadas para claves de protección del Key Store |
| **Validez de firmas digitales** |  Alta | La confianza en que un documento proviene del remitente declarado |
| **Metadatos de archivos** |  Media | Información como nombre de archivo, tamaño, fecha, destinatarios |
| **Integridad del contenedor** |  Alta | La estructura completa que contiene archivo cifrado + claves + firma |

---

### 4.2 Adversarios

Se detalla una lista de los adversarios que tenemos que considerar:

####  Adversario A1: Atacante Externo con Acceso a Almacenamiento

**Objetivo:** Descifrar el contenido de los archivos o extraer información sensible de los metadatos.

**Capacidades:**
- ✅ Puede leer todos los contenedores cifrados almacenados
- ✅ Puede copiar archivos del sistema de almacenamiento
- ❌ NO tiene acceso a las claves privadas de los usuarios
- ❌ NO conoce las contraseñas de los usuarios
- ❌ NO tiene acceso a la memoria de la aplicación en ejecución

---

####  Adversario A2: Destinatario Malicioso

**Objetivo:** Manipular archivos para que parezcan venir de otro remitente, o modificar contenido sin detección.

**Capacidades:**
- ✅ Tiene acceso legítimo a su propia clave privada
- ✅ Puede descifrar archivos que le fueron compartidos
- ✅ Puede intentar modificar archivos o metadatos
- ✅ Puede intentar suplantar al remitente original
- ❌ NO tiene acceso a las claves privadas de otros usuarios

---

####  Adversario A3: Atacante Man-in-the-Middle

**Objetivo:** Causar que el destinatario acepte un archivo modificado como válido.

**Capacidades:**
- ✅ Puede interceptar y modificar contenedores antes de que lleguen al destinatario
- ✅ Puede alterar bytes del archivo cifrado
- ✅ Puede modificar metadatos, claves envueltas o firmas
- ❌ NO puede generar firmas válidas sin la clave privada del remitente

---

####  Adversario A4: Atacante con Acceso Temporal al Dispositivo

**Objetivo:** Extraer claves privadas para uso futuro.

**Capacidades:**
- ✅ Tiene acceso físico breve al dispositivo del usuario (por ejemplo, dispositivo desbloqueado y desatendido)
- ✅ Puede copiar el Key Store cifrado
- ✅ Puede intentar extraer claves de la memoria
- ❌ NO conoce la contraseña del usuario
- ❌ NO tiene acceso prolongado para realizar ataques sofisticados

---

####  Adversario A5: Atacante con Capacidad de Fuerza Bruta

**Objetivo:** Descifrar el Key Store mediante adivinación de contraseña.

**Capacidades:**
- ✅ Tiene recursos computacionales significativos
- ✅ Puede realizar ataques de diccionario contra contraseñas
- ✅ Puede intentar ataques de fuerza bruta offline contra el Key Store
- ❌ NO puede comprometer los algoritmos criptográficos fundamentales (AES, RSA, etc.)

---

## 5. Supuestos de Confianza

>  El sistema asume que las siguientes condiciones son verdaderas. **Si alguno de estos supuestos es violado, las garantías de seguridad pueden no mantenerse.**

### 1️ Protección de Contraseñas por el Usuario

**Supuesto:** Los usuarios eligen contraseñas suficientemente fuertes y las mantienen secretas. No comparten sus contraseñas ni las almacenan de manera insegura.

**Impacto si se viola:** Un atacante con la contraseña puede descifrar el Key Store y obtener todas las claves privadas del usuario.

---

### 2️ Autenticidad de Claves Públicas

**Supuesto:** Las claves públicas de los destinatarios son auténticas y han sido obtenidas mediante un canal confiable. Los usuarios verifican las claves públicas antes de compartir archivos sensibles.

**Impacto si se viola:** Un atacante podría suplantar a un destinatario y descifrar archivos destinados a ese usuario.

---

### 3️ Integridad de la Aplicación Vault

**Supuesto:** El binario de la aplicación Vault no ha sido modificado por un atacante. Los usuarios obtienen la aplicación de fuentes confiables.

**Impacto si se viola:** Un atacante podría modificar la aplicación para filtrar claves, contraseñas o contenido de archivos.

---

### 4️ Almacenamiento No Confiable

**Supuesto:** Todo almacenamiento persistente (sistema de archivos local, almacenamiento externo) es considerado no confiable. Los atacantes pueden tener acceso de lectura a estos almacenamientos.

**Consecuencia de diseño:** Por esto, todos los datos sensibles se cifran antes del almacenamiento.

---

### 5️ Memoria Segura Durante Ejecución

**Supuesto:** Mientras la aplicación está en ejecución, la memoria del proceso está protegida por el sistema operativo contra acceso no autorizado de otros procesos.

**Impacto si se viola:** Un atacante con acceso a la memoria del proceso podría extraer claves o contraseñas en texto plano.

---

### 6️ Disponibilidad de Claves Privadas para Recuperación

**Supuesto:** Los usuarios son responsables de hacer respaldo de su Key Store cifrado. El sistema no proporciona recuperación de claves si se pierde el Key Store o la contraseña.

**Consecuencia:** La pérdida de la contraseña o del Key Store resulta en pérdida permanente de acceso a todos los archivos cifrados.

---

### 7️ Uso Apropiado del Sistema

**Supuesto:** Los usuarios utilizan el sistema según lo diseñado y siguen las mejores prácticas (por ejemplo, no compartir archivos con destinatarios no confiables, verificar firmas antes de confiar en el contenido).

**Impacto si se viola:** Errores del usuario pueden resultar en exposición de información o aceptación de contenido malicioso.


### RS-9: Verificación antes del descifrado
**Descripción:** La firma digital debe ser verificada **ANTES** de intentar descifrar cualquier contenido. Si la verificación falla, el proceso debe detenerse inmediatamente sin revelar información sobre el contenido.

---
