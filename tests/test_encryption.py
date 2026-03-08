"""
EXPECTATIVAS PARA PRUEBAS UNITARIAS

Para cumplir con los Requisitos de Seguridad (RS), este módulo debe validar:

1. ROUNDTRIP (RS-1): Cifrar un archivo y luego descifrarlo con la llave correcta 
   debe devolver el contenido original exacto.
   
2. INTEGRIDAD (RS-2): Si se modifica aunque sea UN BYTE del archivo .vault, 
   el descifrado DEBE fallar (lanzar InvalidTag).
   
3. LLAVE INCORRECTA (RS-1): Intentar descifrar con una llave hexadecimal distinta 
   debe ser rechazado inmediatamente.
   
4. NO REPETICIÓN (RS-7): Cifrar el mismo archivo dos veces seguidas debe generar 
   contenedores .vault distintos (uso correcto de nonce/IV).

Nota: Los tests deben crear sus propios archivos temporales de prueba y 
limpiarlos al finalizar (usar fixtures de pytest).

"""