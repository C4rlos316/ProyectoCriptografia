# Resumen
Se implementa la Interfaz de Línea de Comandos (CLI) para interactuar con el motor criptográfico, se asegura el repositorio y se completa la documentación técnica obligatoria del Sprint (D2).

---

# Tipo de Cambio
- [x] Nueva funcionalidad (Feature)
- [ ] Corrección de error (Bug Fix)
- [ ] Refactorización
- [x] Documentación
- [ ] Pruebas (Tests)
- [ ] Otro (Configuración de seguridad / .gitignore)

---

# Descripción del Cambio / Funcionalidad
- **CLI (`main.py`):** Creación del punto de entrada interactivo con comandos `cifrar` y `descifrar` usando `argparse`.
- **Documentación Técnica (`docs/encryption_design.md`):** Redacción exhaustiva del diseño criptográfico, justificando el uso de AES-GCM-256, el manejo del nonce y las defensas contra los adversarios A1 y A3.
- **Manual de Usuario (`docs/manualDeUsuario.md`):** Guía de instalación y uso del CLI con ejemplos de ejecución.
- **Estandarización:** Se agregó la plantilla de Pull Requests en `.github/pull_request_template.md`.

---

# ¿Cuál es el plan?
Este PR cierra la etapa funcional del módulo de Cifrado Autenticado (D2). Deja el sistema preparado y documentado para que el equipo pueda cifrar archivos localmente de forma segura. En la siguiente iteración, este CLI y motor se integrarán con el cifrado híbrido (asimétrico).

---

# Pruebas
- [x] Se verificó que el CLI cifra archivos correctamente y genera el contenedor `.vault`.
- [x] Se validó manualmente que el CLI rechaza el descifrado y arroja error de autenticación si el contenedor `.vault` es modificado.
- [x] Se validó el manejo de rutas inexistentes en consola.
*(Nota: Las pruebas unitarias automatizadas de `pytest` ya fueron desarrolladas previamente por el equipo).*

---

# Checklist para el Revisor
- [ ] El pull request está correctamente documentado  
- [ ] La implementación cumple con los requisitos del proyecto  
- [ ] El código es claro y está bien estructurado  
- [ ] No se incluyen archivos innecesarios en el commit (llaves, .vault, .venv)