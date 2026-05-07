Vulnerabilidad 2 — Firma Digital Opcional

Descripción

Las banderas CLI --firma-privada (firmar al cifrar) y --firma-publica (verificar al descifrar) se declaran con default=None, haciendo las firmas digitales completamente opcionales y silenciosas. Un usuario puede cifrar, transmitir y descifrar un archivo sin firmarlo ni verificar su origen, y el sistema no emite ninguna advertencia.
 
Esto viola directamente los requisitos de seguridad RS-3 (Autenticidad del Emisor) y RS-6 (No Repudio) documentados en el modelo de amenazas del propio proyecto, y deja al sistema completamente expuesto al Adversario A2 (Receptor Malicioso) quien puede sustituir un archivo .vault por uno falsificado.

Pasos de Reproducción

# 1. Generar claves
python main.py identidad alice

# 2. Cifrar SIN firma
python main.py cifrar doc.txt doc.vault --publicas alice_public.pem

# 3. Descifrar SIN verificación
python main.py descifrar doc.vault recovered.txt --privada alice_private.pem

# Resultado: el descifrado tiene éxito sin ninguna advertencia.
# El archivo pudo haber provenido de cualquier persona.

Impacto

Sin verificación de firma obligatoria, el sistema no puede garantizar autenticidad. Un atacante que pueda colocar un archivo .vault falsificado en la ruta del receptor legítimo lo verá aceptado y descifrado silenciosamente.
