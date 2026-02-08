# ProyectoCriptografia

### Integrantes del equipo y roles

### Integrantes del equipo y roles

| Integrante | Rol |
|-----------|-----|
| [Hernández Ramírez Miguel Angel](https://github.com/Miguel07FI) | Desarrollo, Revisor de código, Avances |
| [Hernández Gutiérrez Carlos Mario](https://github.com/C4rlos316) | Desarrollo, Testing, Project Manager |
| [Solís Espinosa Andrea Vianney](https://github.com/aviansol) | Desarrollo, Arquitectura, Diseño del sistema |
| [Durán Fernández Elizabeth](https://github.com/FernandezED) | Desarrollo, Documentación, Analista de riesgos |


---

## Assets del sistema

- Los principales activos del sistema son los documentos y mensajes cifrados, así como las claves criptográficas públicas y privadas de los usuarios.En particular, la clave privada del usuario es un activo crítico, ya que permite el descifrado de información y la firma de mensajes.  
- Para reforzar su protección, la clave privada se encuentra cifrada y protegida mediante una contraseña con requisitos mínimos de longitud y complejidad, lo que incrementa la resistencia ante ataques de fuerza bruta en caso de que un atacante obtenga acceso a la clave cifrada.

---

## Atacante

- El atacante principal es un atacante de red, con capacidad para interceptar, modificar o reenviar documentos y mensajes durante su transmisión.  
- Este atacante puede intentar obtener llaves criptográficas, sustituir llaves públicas o alterar la información cifrada, buscando romper la confidencialidad y autenticidad de la comunicación entre emisores y receptores.
