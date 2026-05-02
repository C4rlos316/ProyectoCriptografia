# Especificación de Representación Canónica - Proyecto Criptografía

Este documento define la representación canónica utilizada para asegurar la integridad de los Metadatos, el AAD y la Entrada de Firma en el sistema.

## 1. Reglas de Serialización
Para garantizar que un conjunto de datos produzca siempre el mismo hash (estabilidad), se aplican las siguientes reglas de transformación:

*   **Pedido de Claves:** Todas las claves de los objetos JSON se ordenan lexicográficamente (A-Z) según sus puntos de código Unicode.
*   **Codificación:** El resultado se genera estrictamente en formato **UTF-8**.
*   **Inclusión de campos:** Se omiten campos con valores nulos (`null`).
*   **Espaciado:** Se genera un JSON compacto, eliminando espacios en blanco, tabulaciones o saltos de línea fuera de las cadenas de texto (separadores `,` y `:` sin espacios).

## 2. Ejemplo de Entrada y Salida
**Entrada (Diccionario desordenado):**
```json
{
  "version": "2.0",
  "filename": "archivo.txt",
  "recipients": ["id1", "id2"]
}