import os
import datetime
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pwdlib import PasswordHash
from pwdlib.hashers.bcrypt import BcryptHasher
from dotenv import load_dotenv
from pathlib import Path
from email.mime.multipart import MIMEMultipart
import smtplib
from email.mime.text import MIMEText

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

SECRET_KEY = os.getenv("SECRET_KEY", "secret_fallback")
ALGORITHM = "HS256"

password_hash = PasswordHash((BcryptHasher(),))

# Indica a Swagger que el token se obtiene en la ruta /login
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


# crear_token_recuperacion


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


def enviar_correo_recuperacion(email_destino: str, token: str):
    # Enlace hacia tu front-end o formulario donde el usuario ingresa la nueva clave
    enlace_recuperacion = f"http://localhost:8000/docs#/default/restablecer_password_reset_password_post?token={token}"

    mensaje = MIMEMultipart()
    mensaje["From"] = SMTP_EMAIL
    mensaje["To"] = email_destino
    mensaje["Subject"] = "Recuperación de Contraseña"

    cuerpo = f"""
    Hola,

    Has solicitado restablecer tu contraseña. Haz clic o copia el siguiente token para realizar el cambio:

    Token de recuperación:
    {token}

    Este enlace caducará en 15 minutos.

    Si no solicitaste este cambio, puedes ignorar este correo.
    """

    mensaje.attach(MIMEText(cuerpo, "plain"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()  # Conexión segura TLS
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.send_message(mensaje)
        server.quit()
        print(f"Correo de recuperación enviado con éxito a {email_destino}")
    except Exception as e:
        print(f"Error al enviar el correo: {e}")
