from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import tempfile, os, sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from vault.crypto.keys_manager import generate_user_keys, generate_signing_keys

router = APIRouter()

class UsuarioRequest(BaseModel):
    usuario: str
    password: str

@router.post("/identidad")
def crear_identidad(req: UsuarioRequest):
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            original_dir = os.getcwd()
            os.chdir(tmpdir)
            generate_user_keys(req.usuario, req.password)

            with open(f"{req.usuario}_private.pem") as f:
                private = f.read()
            with open(f"{req.usuario}_public.pem") as f:
                public = f.read()

            os.chdir(original_dir)
            return {"private_key": private, "public_key": public}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/identidad-firma")
def crear_identidad_firma(req: UsuarioRequest):
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            original_dir = os.getcwd()
            os.chdir(tmpdir)
            generate_signing_keys(req.usuario, req.password)

            with open(f"{req.usuario}_signing_private.pem") as f:
                private = f.read()
            with open(f"{req.usuario}_signing_public.pem") as f:
                public = f.read()

            os.chdir(original_dir)
            return {"signing_private_key": private, "signing_public_key": public}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))