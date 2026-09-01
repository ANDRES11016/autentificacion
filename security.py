import datetime
import os

# import traceback
from pathlib import Path
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.bcrypt import BcryptHasher
from email_template import generar_html_recuperacion

# Cargar archivo .env PRIMERO
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

# Asignar variables de entorno
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

SECRET_KEY = os.getenv("SECRET_KEY", "secret_fallback")
ALGORITHM = "HS256"

password_hash = PasswordHash((BcryptHasher(),))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def encriptar_password(password: str) -> str:
    return password_hash.hash(password)


def verificar_password(password_plano: str, password_encriptado: str) -> bool:
    return password_hash.verify(password_plano, password_encriptado)


def crear_token_acceso(data: dict) -> str:
    payload = data.copy()
    expiracion = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        minutes=30
    )
    payload.update({"exp": expiracion})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def enmascarar_email(email: str) -> str:
    partes = email.split("@")
    usuario, dominio = partes[0], partes[1]
    visibles = usuario[:5]
    oculto = visibles + "*" * max(3, len(usuario) - 5)
    return f"{oculto}@{dominio}"


def obtener_usuario_actual(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        usuario: str = payload.get("sub")
        email: str = payload.get("email")
        rol: str = payload.get("rol")
        if usuario is None or rol is None:
            raise HTTPException(status_code=401, detail="Token inválido")
        return {"usuario": usuario, "email": email, "rol": rol}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="El token ha expirado")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="No se pudo validar el token")


def requerir_roles(roles_permitidos: list[str]):
    def verificador(usuario: dict = Depends(obtener_usuario_actual)):
        if usuario["rol"] not in roles_permitidos:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permisos para realizar esta acción",
            )
        return usuario

    return verificador


def crear_token_recuperacion(email: str) -> str:
    payload = {
        "sub": email,
        "scope": "reset_password",
        "exp": datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(minutes=15),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verificar_token_recuperacion(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("scope") != "reset_password":
            raise HTTPException(
                status_code=400, detail="Token no válido para recuperación"
            )
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=400, detail="El enlace de recuperación ha expirado"
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=400, detail="Token inválido")


def enviar_correo_recuperacion(email_destino: str, usuario: str, token: str):
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        print("❌ Error: Credenciales SMTP no configuradas")
        return

    mensaje = MIMEMultipart("alternative")

    # Nombre visible para el filtro Antispam
    mensaje["From"] = f"Sistema de Autenticación <{SMTP_EMAIL}>"
    mensaje["To"] = email_destino
    mensaje["Subject"] = "Recuperación de contraseña"

    # Versión en Texto Plano (fundamental para reputación antispam)
    texto_plano = f"Hola {usuario},\n\nTu token de recuperación es:\n{token}\n\nCaduca en 15 minutos."
    mensaje.attach(MIMEText(texto_plano, "plain", "utf-8"))

    #  Versión en HTML
    html_contenido = generar_html_recuperacion(usuario=usuario, token=token)
    mensaje.attach(MIMEText(html_contenido, "html", "utf-8"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, email_destino, mensaje.as_string())
        server.quit()
        print(f"✅ Correo enviado correctamente a: {email_destino}")
    except Exception as e:
        print(f"❌ Error al enviar el correo: {e}")
