import subprocess
import sys
import time
import webbrowser
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
FRONTEND = os.path.join(ROOT, "FRONTEND")

def run(cmd, cwd=None, shell=False):
    result = subprocess.run(cmd, cwd=cwd, shell=shell)
    if result.returncode != 0:
        print(f"ERROR: falló el comando {cmd}")
        sys.exit(1)

print("=" * 45)
print("       Secure Vault — Arranque automático")
print("=" * 45)

print("\n[1/5] Verificando dependencias Python...")
run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "-q"], cwd=ROOT)
print("      ✓ Dependencias Python OK")

print("[2/5] Verificando dependencias Node...")
run(["npm", "install"], cwd=FRONTEND, shell=True)
print("      ✓ Dependencias Node OK")

print("[3/5] Iniciando backend...")
backend = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "API.main:app", "--reload"],
    cwd=ROOT
)

print("[4/5] Iniciando frontend...")
frontend = subprocess.Popen(
    ["npm", "run", "dev"],
    cwd=FRONTEND,
    shell=True
)

print("[5/5] Abriendo navegador en 3 segundos...")
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