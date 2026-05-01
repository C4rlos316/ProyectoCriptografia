import argparse
import sys

from vault.crypto.keys_manager import generate_user_keys, generate_signing_keys
from vault.crypto.encryption import encrypt_file_hybrid, decrypt_file_hybrid


def main():
    parser = argparse.ArgumentParser(
        description="Secure Vault — Cifrado Híbrido + Firmas Digitales",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  # Generar llaves de cifrado RSA
  python main.py identidad alice

  # Generar llaves de firma Ed25519
  python main.py identidad-firma alice

  # Cifrar para múltiples destinatarios (con firma opcional)
  python main.py cifrar doc.txt doc.vault --publicas alice_public.pem bob_public.pem
  python main.py cifrar doc.txt doc.vault --publicas alice_public.pem --firma-privada alice_signing_private.pem

  # Descifrar (con verificación de firma opcional)
  python main.py descifrar doc.vault recuperado.txt --privada alice_private.pem
  python main.py descifrar doc.vault recuperado.txt --privada alice_private.pem --firma-publica alice_signing_public.pem
        """,
    )
    subparsers = parser.add_subparsers(
        dest="comando", help="Operaciones disponibles")

    # ── identidad ───
    parser_id = subparsers.add_parser(
        "identidad",
        help="Genera par de llaves RSA-2048 para cifrado híbrido",
    )
    parser_id.add_argument("usuario", help="Nombre del usuario (ej. alice)")

    # ── identidad-firma ──
    parser_id_firma = subparsers.add_parser(
        "identidad-firma",
        help="Genera par de llaves Ed25519 para firma digital",
    )
    parser_id_firma.add_argument(
        "usuario", help="Nombre del usuario (ej. alice)")

    # ── cifrar ──
    parser_enc = subparsers.add_parser(
        "cifrar",
        help="Cifra un archivo para N destinatarios (opcionalmente firmado)",
    )
    parser_enc.add_argument("entrada", help="Archivo original a cifrar")
    parser_enc.add_argument("salida",  help="Archivo .vault de salida")
    parser_enc.add_argument(
        "--publicas",
        nargs="+",
        required=True,
        metavar="LLAVE_PUB",
        help="Rutas a llaves públicas RSA de destinatarios (.pem)",
    )
    parser_enc.add_argument(
        "--firma-privada",
        default=None,
        metavar="LLAVE_FIRMA_PRIV",
        help="(Opcional) Llave privada Ed25519 del remitente para firmar el contenedor",
    )

    # ── descifrar ──
    parser_dec = subparsers.add_parser(
        "descifrar",
        help="Descifra un archivo .vault con la llave privada del destinatario",
    )
    parser_dec.add_argument("entrada", help="Archivo .vault a descifrar")
    parser_dec.add_argument("salida",  help="Ruta del archivo recuperado")
    parser_dec.add_argument(
        "--privada",
        required=True,
        metavar="LLAVE_PRIV",
        help="Llave privada RSA del destinatario (.pem)",
    )
    parser_dec.add_argument(
        "--firma-publica",
        default=None,
        metavar="LLAVE_FIRMA_PUB",
        help="(Opcional) Llave pública Ed25519 del remitente para verificar la firma",
    )

    # ── dispatch ──
    args = parser.parse_args()

    if args.comando == "identidad":
        generate_user_keys(args.usuario)

    elif args.comando == "identidad-firma":
        generate_signing_keys(args.usuario)

    elif args.comando == "cifrar":
        try:
            encrypt_file_hybrid(
                args.entrada,
                args.salida,
                args.publicas,
                signing_priv_path=args.firma_privada,
            )
        except FileNotFoundError as e:
            print(f"ERROR: No se encontró el archivo: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"ERROR al cifrar: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.comando == "descifrar":
        try:
            decrypt_file_hybrid(
                args.entrada,
                args.salida,
                args.privada,
                signing_pub_path=args.firma_publica,
            )
        except Exception:
            # Fix-D3: Mensaje genérico — no distinguir entre causas de fallo
            print(
                "ERROR: Operación de descifrado fallida. "
                "Verifique que el archivo, la llave y la firma sean correctos.",
                file=sys.stderr,
            )
            sys.exit(1)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
