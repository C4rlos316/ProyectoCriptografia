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
    privada: str = Form(...),
    password: str = Form(...),
    firma_publica: Optional[str] = Form(None)
):
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = os.path.join(tmpdir, archivo.filename)
            with open(vault_path, "wb") as f:
                f.write(await archivo.read())

            priv_path = os.path.join(tmpdir, "private.pem")
            with open(priv_path, "w") as f:
                f.write(privada)

            signing_path = None
            if firma_publica:
                signing_path = os.path.join(tmpdir, "signing_pub.pem")
                with open(signing_path, "w") as f:
                    f.write(firma_publica)

            original_name = archivo.filename.replace(".vault", "")
            output_path = os.path.join(tmpdir, original_name)

            decrypt_file_hybrid(
                vault_path, output_path, priv_path,
                signing_pub_path=signing_path,
                password=password.encode("utf-8")
            )

            with open(output_path, "rb") as f:
                data = f.read()

        return StreamingResponse(
            io.BytesIO(data),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={original_name}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail="Descifrado fallido. Verifica el archivo, la llave, la contraseña y la firma.")