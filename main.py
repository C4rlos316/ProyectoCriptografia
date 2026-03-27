import argparse
import sys
# Importamos la función de generación (la crearemos en el paso 2)
from vault.crypto.keys_manager import generate_user_keys
from vault.crypto.encryption import encrypt_file_hybrid, decrypt_file_hybrid

def main():
    parser = argparse.ArgumentParser(description="Secure Vault - Cifrado Híbrido")
    subparsers = parser.add_subparsers(dest="comando", help="Operaciones disponibles")

    # --- NUEVO COMANDO: Generar Llaves ---
    parser_id = subparsers.add_parser("identidad", help="Genera par de llaves RSA para un usuario")
    parser_id.add_argument("usuario", help="Nombre del usuario (ej. alice)")

    # --- COMANDO: Cifrar (Híbrido) ---
    parser_enc = subparsers.add_parser("cifrar", help="Cifra para N destinatarios")
    parser_enc.add_argument("entrada", help="Archivo original")
    parser_enc.add_argument("salida", help="Archivo .vault")
    parser_enc.add_argument("--publicas", nargs="+", required=True, help="Rutas de llaves públicas (.pem)")

    # --- COMANDO: Descifrar (Híbrido) ---
    parser_dec = subparsers.add_parser("descifrar", help="Descifra usando tu llave privada")
    parser_dec.add_argument("entrada", help="Archivo .vault")
    parser_dec.add_argument("salida", help="Ruta de destino")
    parser_dec.add_argument("--privada", required=True, help="Ruta de tu llave privada (.pem)")

    args = parser.parse_args()

    if args.comando == "identidad":
        generate_user_keys(args.usuario)
    
    elif args.comando == "cifrar":
        encrypt_file_hybrid(args.entrada, args.salida, args.publicas)
        
    elif args.comando == "descifrar":
        try:
            decrypt_file_hybrid(args.entrada, args.salida, args.privada)
        except Exception as e:
            print(f"ERROR: {e}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()