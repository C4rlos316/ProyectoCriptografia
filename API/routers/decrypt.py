from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from typing import Optional
import tempfile, os, sys, io

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from vault.crypto.encryption import decrypt_file_hybrid

router = APIRouter()

@router.post("/descifrar")
async def descifrar(
    archivo: UploadFile = File(...),
    keystore: str = Form(...),         # contenido JSON del .keystore
    password: str = Form(...),         # contraseña como string
    firma_publica: Optional[str] = Form(None)
):
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, archivo.filename)
            with open(vault_path, "wb") as f:
                f.write(await archivo.read())

            # Guardar keystore como archivo .keystore
            keystore_path = os.path.join(tmpdir, "private.keystore")
            with open(keystore_path, "w") as f:
                f.write(keystore)

            signing_path = None
            if firma_publica:
                signing_path = os.path.join(tmpdir, "signing_pub.pem")
                with open(signing_path, "w") as f:
                    f.write(firma_publica)

            original_name = archivo.filename.replace(".vault", "")
            output_path = os.path.join(tmpdir, original_name)

            decrypt_file_hybrid(
                vault_path, output_path, keystore_path,
                signing_pub_path=signing_path,
                password=password        # str directo
            )

            with open(output_path, "rb") as f:
                data = f.read()

        return StreamingResponse(
            io.BytesIO(data),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={original_name}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail="Descifrado fallido. Verifica el archivo, el keystore, la contraseña y la firma.")