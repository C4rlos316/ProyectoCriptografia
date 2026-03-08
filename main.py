import argparse
import sys
import os
# import endrypt-decrypt desde el módulo de criptografía
from vault.crypto.encryption import encrypt_file, decrypt_file


def main():
    # CLI
    parser = argparse.ArgumentParser(
        description="Secure Digital Document Vault - CLI")
    subparsers = parser.add_subparsers(
        dest="comando", help="Operaciones disponibles")

    # Cifrar
    parser_enc = subparsers.add_parser(
        "cifrar", help="Cifra un archivo de texto")
    parser_enc.add_argument(
        "archivo_entrada", help="Ruta del archivo original")
    parser_enc.add_argument(
        "archivo_salida", help="Ruta para guardar el contenedor (ej. doc.vault)")

    # Descifrar
    parser_dec = subparsers.add_parser(
        "descifrar", help="Descifra un contenedor .vault")
    parser_dec.add_argument(
        "archivo_entrada", help="Ruta del contenedor cifrado (.vault)")
    parser_dec.add_argument(
        "archivo_salida", help="Ruta donde se guardará el archivo recuperado")
    parser_dec.add_argument(
        "llave", help="Llave simétrica en formato hexadecimal")

    args = parser.parse_args()

    if args.comando == "cifrar":
        if not os.path.exists(args.archivo_entrada):
            print(f"Error: El archivo '{args.archivo_entrada}' no existe.")
            sys.exit(1)

        print(f"[*] Cifrando '{args.archivo_entrada}'...")
        llave = encrypt_file(args.archivo_entrada, args.archivo_salida)
        print(f"Archivo cifrado guardado como: {args.archivo_salida}")
        print(f"LLAVE GENERADA (Para descifrar copiala): {llave.hex()}")

    elif args.comando == "descifrar":
        if not os.path.exists(args.archivo_entrada):
            print(f"Error: El archivo '{args.archivo_entrada}' no existe.")
            sys.exit(1)

        print(f"[*] Descifrando '{args.archivo_entrada}'...")

        llave_bytes = bytes.fromhex(args.llave)

        exito = decrypt_file(args.archivo_entrada,
                             args.archivo_salida, llave_bytes)

        if exito:
            print(
                f"[Descifrado y autenticado adecuadamente] Guardado en: {args.archivo_salida}")
        else:
            print(
                "ERROR: Autenticación fallida. El archivo fue manipulado o la llave es incorrecta.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
