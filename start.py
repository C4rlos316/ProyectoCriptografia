import subprocess
import sys
import time
import webbrowser
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
FRONTEND = os.path.join(ROOT, "FRONTEND")

print("[1/3] Iniciando backend...")
backend = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "API.main:app", "--reload"],
    cwd=ROOT
)

print("[2/3] Iniciando frontend...")
frontend = subprocess.Popen(
    ["npm", "run", "dev"],
    cwd=FRONTEND,
    shell=True
)

print("[3/3] Abriendo navegador en 3 segundos...")
time.sleep(3)
webbrowser.open("http://localhost:5173")

print("\n✓ Secure Vault corriendo.")
print("  Backend:  http://127.0.0.1:8000")
print("  Frontend: http://localhost:5173")
print("\nPresiona Ctrl+C para detener todo.\n")

try:
    backend.wait()
except KeyboardInterrupt:
    print("\nDeteniendo servidores...")
    backend.terminate()
    frontend.terminate()