# 🔐 Secure Digital Document Vault

<div align="center">

![D1](https://img.shields.io/badge/Sprint_D1-Completado-success)
![D2](https://img.shields.io/badge/Sprint_D2-Completado-success)
![D3](https://img.shields.io/badge/Sprint_D3-Completado-success)
![D4](https://img.shields.io/badge/Sprint_D4-Revisado-success)
![D5](https://img.shields.io/badge/Sprint_D5-Firmas_Digitales-success)
![D6](https://img.shields.io/badge/Sprint_D6-Gestión_de_Claves-success)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-59%20passed-brightgreen?logo=pytest)
![Security](https://img.shields.io/badge/Security-Argon2id%20%7C%20AES--GCM--256%20%7C%20Ed25519-blueviolet?logo=shield)

*Bóveda criptográfica para cifrar, firmar y compartir archivos de forma segura.*

</div>

---

## Tabla de Contenidos

- [Equipo](#equipo)
- [Stack Tecnológico](#stack-tecnológico)
- [Documentación Técnica](#documentación-técnica)
- [Inicio Rápido](#inicio-rápido)
- [Ejemplo Completo](#ejemplo-completo)
- [Flujo de Uso](#flujo-de-uso)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Supuestos de Seguridad](#supuestos-de-seguridad)
- [Limitaciones Conocidas](#limitaciones-conocidas)

---

## 👥 Equipo

| Integrante | Rol |
|-----------|-----|
| [Hernández Ramírez Miguel Angel](https://github.com/Miguel07FI) | Desarrollo, Revisor de código, Avances |
| [Hernández Gutiérrez Carlos Mario](https://github.com/C4rlos316) | Desarrollo, Testing, Project Manager |
| [Solís Espinosa Andrea Vianney](https://github.com/aviansol) | Desarrollo, Arquitectura, Diseño del sistema |
| [Rivera Lopez David Zaid](https://github.com/AvalonRD) | Desarrollo, Documentación, Analista de riesgos |
| [Suárez Román Clara Alin](https://github.com/clarasrzfi) | Desarrollo, Documentación técnica, Validación de seguridad |

---

## 🛠️ Stack Tecnológico

| | Tecnología | Versión | Uso |
|---|---|---|---|
|  | Python | 3.10+ | Runtime principal |
|  | cryptography (PyCA) | ≥ 42.0.0 | AES-GCM-256, RSA-OAEP, Ed25519, scrypt |
|  | argon2-cffi | ≥ 21.0.0 | KDF Argon2id para claves privadas en reposo |
|  | pytest | ≥ 8.0.0 | Suite de pruebas (59 tests) |
|  | hypothesis | ≥ 6.0.0 | Property-based testing |

---

## 📚 Documentación Técnica

| Documento | Descripción | Fase |
|-----------|-------------|------|
| [Architecture & Threat Model](docs/architecture_threat_model.md) | Visión general, diagrama de arquitectura, requisitos RS-1 a RS-9, adversarios A1–A5, supuestos de confianza y restricciones de diseño. | D1 |
| [Diseño de Cifrado Base](docs/encryption_design.md) | AES-GCM-256, estrategia de nonce y prevención de ataques de oráculo de padding. | D2 |
| [Diseño de Cifrado Híbrido](docs/hybrid_encryption_design.md) | Fingerprints SHA-256 en DER, envoltura RSA-OAEP y protección de metadatos en AAD. | D3 |
| [Revisión de Arquitectura](docs/presentacion_d4.pdf) | Material de auditoría de seguridad — modelo de amenazas y diagramas de flujo. | D4 |
| [Diseño de Firmas Digitales](docs/signature_design.md) | Ed25519, verificación previa al descifrado y prevención de ataques de contexto. | D5 |
| [Gestión de Claves](docs/D6_gestion_claves.md) | Argon2id, formato `.keystore`, estrategia de respaldo/restauración. | D6 |
| [Canonicalization Strategy](docs/CANONICALIZATION.md) | Especificación de serialización canónica JSON usada como AAD y material firmable. | Transversal |
| [Vulnerabilidad 1 — Claves en texto claro](docs/vulnerabilidad1.md) | Hallazgo de auditoría: claves privadas almacenadas sin cifrar. Análisis y mitigación. | D4 |
| [Vulnerabilidad 2](docs/vulnerabilidad2.md) | Hallazgo de auditoría: segunda vulnerabilidad identificada. Análisis y mitigación. | D4 |

---

##  Inicio Rápido

### Prerrequisitos

- Python 3.10+
- pip

### Instalación

```bash
# Clonar el repositorio
git clone https://github.com/C4rlos316/ProyectoCriptografia.git
cd ProyectoCriptografia

# Crear y activar entorno virtual
python -m venv .venv
.\.venv\Scripts\activate        # Windows
# source .venv/bin/activate     # Linux/macOS

# Instalar dependencias
pip install -r requirements.txt

# Verificar que todo funciona
python -m pytest tests/ -v
```

---

##  Ejemplo Completo

El flujo completo va de identidad → cifrar → descifrar. Cada paso es independiente y puede realizarse en máquinas distintas.

```bash
# 1. Alice y Bob generan sus identidades (una sola vez)
python main.py identidad alice
python main.py identidad bob
python main.py identidad-firma alice        # para firmar digitalmente

# 2. Alice cifra y firma un documento para ambos
python main.py cifrar contrato.pdf contrato.vault \
    --publicas alice_public.pem bob_public.pem \
    --firma-privada alice_signing_private.keystore

# 3. Bob recibe el .vault y descifra, verificando que fue Alice quien lo envió
python main.py descifrar contrato.vault contrato_recuperado.pdf \
    --privada bob_private.keystore \
    --firma-publica alice_signing_public.pem

# 4. Alice también puede descifrar su propia copia
python main.py descifrar contrato.vault contrato_alice.pdf \
    --privada alice_private.keystore \
    --firma-publica alice_signing_public.pem
```

> ✅ El contenido descifrado es idéntico al original. La firma garantiza que nadie modificó el archivo en tránsito.

---

## 📖 Flujo de Uso

### Paso 1 — Generar identidades

| Paso | Comando | Archivos generados |
|------|---------|-------------------|
| Identidad RSA (cifrado) | `python main.py identidad alice` | `alice_private.keystore` 🔒 · `alice_public.pem` |
| Identidad RSA (cifrado) | `python main.py identidad bob` | `bob_private.keystore` 🔒 · `bob_public.pem` |
| Identidad Ed25519 (firma) | `python main.py identidad-firma alice` | `alice_signing_private.keystore` 🔒 · `alice_signing_public.pem` |

> 🔒 Los archivos `.keystore` están cifrados con contraseña usando Argon2id + AES-256-GCM. La contraseña se solicita en terminal y nunca se almacena.

### Paso 2 — Cifrar un archivo

```bash
# Cifrar para múltiples destinatarios
python main.py cifrar documento.txt documento.vault \
    --publicas alice_public.pem bob_public.pem

# Cifrar y firmar digitalmente (autenticación de origen)
python main.py cifrar documento.txt documento.vault \
    --publicas alice_public.pem bob_public.pem \
    --firma-privada alice_signing_private.keystore
```

### Paso 3 — Descifrar un archivo

```bash
# Descifrar (solicita contraseña maestra del .keystore)
python main.py descifrar documento.vault recuperado.txt \
    --privada alice_private.keystore

# Descifrar y verificar firma (protección total)
python main.py descifrar documento.vault recuperado.txt \
    --privada alice_private.keystore \
    --firma-publica alice_signing_public.pem
```

### Paso 4 — Respaldar y restaurar claves

```bash
# Respaldar keystore (ya está cifrado, se puede copiar libremente)
python main.py respaldar alice /ruta/segura/alice_private.keystore
python main.py respaldar alice /ruta/segura/alice_signing_private.keystore --tipo ed25519

# Restaurar desde respaldo (verifica contraseña antes de restaurar)
python main.py restaurar /ruta/respaldo/alice_private.keystore
```

### Referencia de archivos del sistema

| Archivo | Tipo | Descripción |
|---------|------|-------------|
| `{usuario}_private.keystore` | 🔒 Privado cifrado | Clave RSA protegida con contraseña |
| `{usuario}_public.pem` | 🌐 Público | Clave RSA pública — distribuible libremente |
| `{usuario}_signing_private.keystore` | 🔒 Privado cifrado | Clave Ed25519 protegida con contraseña |
| `{usuario}_signing_public.pem` | 🌐 Público | Clave Ed25519 pública — distribuible libremente |
| `{archivo}.vault` | 📦 Contenedor | Archivo cifrado con AES-GCM-256 + firma opcional |

---

## 📁 Estructura del Proyecto

```
ProyectoCriptografia/
├── vault/                           # Módulo criptográfico principal
│   └── crypto/
│       ├── __init__.py
│       ├── encryption.py            # AES-GCM (D2), RSA-OAEP (D3), Ed25519 (D5)
│       └── keys_manager.py          # Generación, cifrado en reposo y backup (D6)
│
├── tests/
│   └── test_encryption.py           # Suite completa: 59 tests — D2, D3, D5 y D6
│
├── docs/
│   ├── architecture_threat_model.md # Arquitectura, amenazas y requisitos RS-1..RS-9 (D1)
│   ├── encryption_design.md         # AES-GCM-256, nonce, AAD (D2)
│   ├── hybrid_encryption_design.md  # Cifrado híbrido, fingerprints, multi-destinatario (D3)
│   ├── signature_design.md          # Firmas Ed25519, verificación previa (D5)
│   ├── D6_gestion_claves.md         # Argon2id, .keystore, backup/restore (D6)
│   ├── CANONICALIZATION.md          # Estrategia de serialización canónica JSON (AAD)
│   ├── vulnerabilidad1.md           # Hallazgo D4: claves privadas en texto claro
│   ├── vulnerabilidad2.md           # Hallazgo D4: segunda vulnerabilidad identificada
│   └── presentacion_d4.pdf          # Auditoría de seguridad (D4)
│
├── main.py                          # CLI — dispatcher de todos los comandos
├── requirements.txt                 # cryptography, pytest, argon2-cffi, hypothesis
├── diagrama.png                     # Diagrama de arquitectura
└── README.md
```

---

## 🔒 Supuestos de Seguridad

El sistema opera bajo los siguientes supuestos. Si alguno se viola, las garantías de seguridad pueden no mantenerse:

| Supuesto | Impacto si se viola |
|----------|---------------------|
| El usuario elige una contraseña fuerte y la mantiene secreta | Un atacante con la contraseña puede descifrar el `.keystore` y obtener la clave privada |
| Las claves públicas de los destinatarios son auténticas | Un atacante podría suplantar a un destinatario y descifrar archivos dirigidos a él |
| El binario de la aplicación no ha sido modificado | Un atacante podría filtrar claves o contraseñas en tiempo de ejecución |
| Todo almacenamiento persistente es no confiable | Por eso todos los datos sensibles se cifran antes de escribirse en disco |
| La memoria del proceso está protegida por el OS durante la ejecución | Un atacante con acceso a la memoria podría extraer claves en texto plano |
| El usuario es responsable de respaldar su `.keystore` | La pérdida del archivo o la contraseña resulta en pérdida permanente de acceso |

> El detalle completo de supuestos, adversarios y restricciones de diseño está en [Architecture & Threat Model](docs/architecture_threat_model.md).

---

## ⚠️ Limitaciones Conocidas

| Limitación | Descripción |
|------------|-------------|
| **Contraseña débil** | Si el usuario elige una contraseña corta, Argon2id ralentiza los ataques pero no los hace imposibles. El sistema advierte pero no bloquea. |
| **Clave en memoria durante operación** | Mientras se descifra, la clave privada existe en memoria. Un atacante con acceso al proceso podría extraerla. Mitigación solo por software está fuera del alcance. |
| **Sin revocación de claves** | No existe mecanismo para invalidar una clave comprometida. El procedimiento manual es generar un nuevo par y re-cifrar los archivos. |
| **Sin recuperación de contraseña** | Si se pierde la contraseña maestra, la clave privada es irrecuperable. No hay mecanismo de reset. |
| **Claves públicas sin PKI** | No hay infraestructura de clave pública. La autenticidad de las claves públicas depende de que el usuario las obtenga por un canal confiable. |
| **Sin transporte de red** | El sistema opera localmente. El intercambio de archivos `.vault` y claves públicas entre usuarios se hace fuera del sistema. |
| **Archivos grandes en memoria** | El archivo completo se carga en RAM para cifrarlo. Archivos muy grandes (>1 GB) pueden causar problemas de memoria. |

> El análisis detallado de vulnerabilidades identificadas en auditoría está en [vulnerabilidad1.md](docs/vulnerabilidad1.md) y [vulnerabilidad2.md](docs/vulnerabilidad2.md).
