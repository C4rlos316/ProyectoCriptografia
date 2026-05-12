from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from API.routers import keys, encrypt, decrypt

app = FastAPI(title="Secure Vault API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En prod cambiar por tu dominio de GitHub Pages
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(keys.router,    prefix="/api")
app.include_router(encrypt.router, prefix="/api")
app.include_router(decrypt.router, prefix="/api")