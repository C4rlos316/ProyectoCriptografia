import argparse
import getpass
import os
import sys

from vault.crypto.keys_manager import (
    generate_user_keys,
    generate_signing_keys,
    export_keystore,
    import_keystore,
)
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

  # Respaldar un keystore
  python main.py respaldar alice /ruta/destino/alice_private.keystore
  python main.py respaldar alice /ruta/destino/alice_signing_private.keystore --tipo ed25519

  # Restaurar un keystore desde respaldo
  python main.py restaurar /ruta/respaldo/alice_private.keystore
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

    # ── respaldar ──
    parser_backup = subparsers.add_parser(
        "respaldar",
        help="Exporta (respalda) un keystore cifrado a una ruta de destino",
    )
    parser_backup.add_argument("usuario", help="Nombre del usuario (ej. alice)")
    parser_backup.add_argument("destino", help="Ruta de destino para el respaldo")
    parser_backup.add_argument(
        "--tipo",
        choices=["rsa", "ed25519"],
        default="rsa",
        help="Tipo de keystore a respaldar: 'rsa' o 'ed25519'",
    )

    # ── restaurar ──
    parser_restore = subparsers.add_parser(
        "restaurar",
        help="Importa un keystore desde un archivo de respaldo",
    )
    parser_restore.add_argument(
        "archivo",
        help="Ruta al archivo .keystore de respaldo a restaurar",
    )

    # ── dispatch ──
    args = parser.parse_args()

    if args.comando == "identidad":
        password = getpass.getpass("Contraseña maestra: ")
        generate_user_keys(args.usuario, password)

    elif args.comando == "identidad-firma":
        password = getpass.getpass("Contraseña maestra: ")
        generate_signing_keys(args.usuario, password)

    elif args.comando == "cifrar":
        if args.firma_privada is None:
            print("  ADVERTENCIA: No se proporcionó --firma-privada.", file=sys.stderr)
            print("   El .vault NO será firmado digitalmente.", file=sys.stderr)
            print("   El destinatario no podrá verificar tu identidad.", file=sys.stderr)

        # Si la llave de firma es un .keystore cifrado, pedir contraseña
        signing_password = None
        if args.firma_privada and args.firma_privada.endswith(".keystore"):
            signing_password = getpass.getpass("Contraseña de firma: ")
        try:
            encrypt_file_hybrid(
                args.entrada,
                args.salida,
                args.publicas,
                signing_priv_path=args.firma_privada,
                signing_password=signing_password,
            )
        except FileNotFoundError as e:
            print(f"ERROR: No se encontró el archivo: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"ERROR al cifrar: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.comando == "descifrar":
        # Fix Vulnerabilidad 1: advertir cuando no se proporciona verificación de firma
        if args.firma_publica is None:
            print("⚠️  ADVERTENCIA: No se proporcionó --firma-publica.", file=sys.stderr)
            print("   La firma NO será verificada.", file=sys.stderr)
            print("   No podrás confirmar la identidad del remitente.",
                  file=sys.stderr)
        password = getpass.getpass("Contraseña maestra: ")
        try:
            decrypt_file_hybrid(
                args.entrada,
                args.salida,
                args.privada,
                signing_pub_path=args.firma_publica,
                password=password,
            )
        except Exception:
            # Fix-D3: Mensaje genérico — no distinguir entre causas de fallo
            print(
                "ERROR: Operación de descifrado fallida. "
                "Verifique que el archivo, la llave y la firma sean correctos.",
                file=sys.stderr,
            )
            sys.exit(1)

    elif args.comando == "respaldar":
        if args.tipo == "rsa":
            keystore_path = f"{args.usuario}_private.keystore"
        else:
            keystore_path = f"{args.usuario}_signing_private.keystore"

        try:
            export_keystore(keystore_path, args.destino)
            print(f"[OK] Keystore exportado a '{args.destino}'")
        except Exception as e:
            print(f"ERROR al respaldar: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.comando == "restaurar":
        password = getpass.getpass("Contraseña maestra: ")
        destination = os.path.basename(args.archivo)
        # Evitar error "same file" si el respaldo está en el mismo directorio
        if os.path.abspath(args.archivo) == os.path.abspath(destination):
            base, ext = os.path.splitext(destination)
            destination = f"{base}_restaurado{ext}"
        try:
            import_keystore(args.archivo, destination, password)
            print(f"[OK] Keystore restaurado como '{destination}'")
        except Exception as e:
            print(f"ERROR al restaurar: {e}", file=sys.stderr)
            sys.exit(1)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
