# Resumen

Corrección de HAL-01: el sistema cifraba y descifraba archivos `.vault` sin firmas
digitales sin emitir ninguna advertencia al usuario, permitiendo un bypass silencioso
de autenticación. Se añaden advertencias en `stderr` cuando se omiten `--firma-privada`
o `--firma-publica`.

---

# Tipo de Cambio
- [ ] Nueva funcionalidad (Feature)
- [x] Corrección de error (Bug Fix)
- [ ] Refactorización
- [ ] Documentación
- [ ] Pruebas (Tests)
- [ ] Otro

---

# Descripción del Cambio / Funcionalidad

Las banderas `--firma-privada` y `--firma-publica` tenían `default=None` sin ningún
aviso al usuario cuando se omitían. Esto violaba los requisitos RS-3 (Autenticidad
del Emisor) y RS-6 (No Repudio) del modelo de amenazas del proyecto.

Se añadieron dos bloques de advertencia en `main.py`:

- En el comando `cifrar`: si se omite `--firma-privada`, se imprime en `stderr` que
  el `.vault` no será firmado y el receptor no podrá verificar la identidad del emisor.
- En el comando `descifrar`: si se omite `--firma-publica`, se imprime en `stderr` que
  la firma no será verificada y no se puede confirmar la identidad del emisor.

Las advertencias se emiten **antes** de la operación criptográfica, sin bloquearla,
para mantener compatibilidad con flujos de trabajo existentes.

---

# ¿Cuál es el plan?

1. Añadir bloque `if args.firma_privada is None` en el dispatch de `cifrar` → imprimir
   3 líneas de advertencia en `stderr`.
2. Añadir bloque `if args.firma_publica is None` en el dispatch de `descifrar` →
   imprimir 3 líneas de advertencia en `stderr`.
3. La operación continúa normalmente después de la advertencia (no se interrumpe).

Archivo modificado: `main.py` (+6 líneas efectivas, sin cambios en lógica criptográfica).

---

# Pruebas

**Caso 1 — Cifrar sin firma (debe mostrar advertencia):**
```bash
python main.py cifrar doc.txt doc.vault --publicas alice_public.pem
# Esperado en stderr:
# ⚠️  WARNING: No --firma-privada provided.
#    The .vault will NOT be digitally signed.
#    The recipient cannot verify your identity.
```

**Caso 2 — Descifrar sin verificación (debe mostrar advertencia):**
```bash
python main.py descifrar doc.vault recuperado.txt --privada alice_private.pem
# Esperado en stderr:
# ⚠️  WARNING: No --firma-publica provided.
#    Signature will NOT be verified.
#    You cannot confirm the sender identity.
```

**Caso 3 — Cifrar con firma (no debe mostrar advertencia):**
```bash
python main.py cifrar doc.txt doc.vault --publicas alice_public.pem \
    --firma-privada alice_signing_private.pem
# Esperado: sin advertencia, operación exitosa.
```

**Caso 4 — Descifrar con verificación (no debe mostrar advertencia):**
```bash
python main.py descifrar doc.vault recuperado.txt --privada alice_private.pem \
    --firma-publica alice_signing_public.pem
# Esperado: sin advertencia, operación exitosa.
```

---

# Checklist para el Revisor
- [x] El pull request está correctamente documentado
- [x] La implementación cumple con los requisitos del proyecto
- [x] El código es claro y está bien estructurado
- [x] No se incluyen archivos innecesarios en el commit (llaves, .vault, .venv)