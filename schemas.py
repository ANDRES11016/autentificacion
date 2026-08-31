from pydantic import BaseModel, EmailStr


class UsuarioRegistro(BaseModel):
    usuario: str
    email: EmailStr
    password: str
    rol: str = "cliente"  # Puede ser 'cliente' o 'admin'


class UsuarioActualizar(BaseModel):
    password_actual: str
    nuevo_usuario: str | None = None
    nuevo_email: EmailStr | None = None
    nueva_password: str | None = None
    nuevo_rol: str | None = None


# schemas.py


class SolicitudRecuperacion(BaseModel):
    email: EmailStr


class RestablecerPassword(BaseModel):
    token: str
    nueva_password: str


# from pydantic import BaseModel, EmailStr


# class UsuarioRegistro(BaseModel):
#     email: EmailStr
#     password: str


# class UsuarioActualizar(BaseModel):
#     nuevo_email: EmailStr | None = None
#     nueva_password: str | None = None
