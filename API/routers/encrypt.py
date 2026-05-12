from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from typing import List, Optional
import tempfile, os, sys, io

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from vault.crypto.encryption import encrypt_file_hybrid

router = APIRouter()

@router.post("/cifrar")
async def cifrar(
    archivo: UploadFile = File(...),
    publicas: List[str] = Form(...),
    firma_privada: Optional[str] = Form(None),
    firma_password: Optional[str] = Form(None),   # ← nuevo
):
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, archivo.filename)
            with open(input_path, "wb") as f:
                f.write(await archivo.read())

            pub_paths = []
            for i, pem in enumerate(publicas):
                path = os.path.join(tmpdir, f"dest_{i}.pem")
                with open(path, "w") as f:
                    f.write(pem)
                pub_paths.append(path)

            signing_path = None
            if firma_privada:
                signing_path = os.path.join(tmpdir, "signing_priv.pem")
                with open(signing_path, "w") as f:
                    f.write(firma_privada)

            output_path = os.path.join(tmpdir, archivo.filename + ".vault")
            encrypt_file_hybrid(
                input_path, output_path, pub_paths,
                signing_priv_path=signing_path,
                signing_password=firma_password.encode("utf-8") if firma_password else None,  # ← nuevo
            )

            with open(output_path, "rb") as f:
                data = f.read()

        return StreamingResponse(
            io.BytesIO(data),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={archivo.filename}.vault"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))