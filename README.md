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

### RS-9: Verificación antes del descifrado
**Descripción:** La firma digital debe ser verificada **ANTES** de intentar descifrar cualquier contenido. Si la verificación falla, el proceso debe detenerse inmediatamente sin revelar información sobre el contenido.

---
