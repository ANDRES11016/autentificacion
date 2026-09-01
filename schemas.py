from pydantic import BaseModel, EmailStr, Field


class UsuarioRegistro(BaseModel):
    usuario: str = Field(..., json_schema_extra={"example": "camilo_dev"})
    email: EmailStr = Field(..., json_schema_extra={"example": "usuario@ejemplo.com"})
    password: str = Field(..., json_schema_extra={"example": "MiPasswordSegura123"})
    rol: str = Field(
        default="cliente", json_schema_extra={"example": "cliente"}
    )  # 'cliente' o 'admin'


class UsuarioActualizar(BaseModel):
    password_actual: str = Field(
        ..., json_schema_extra={"example": "MiPasswordSegura123"}
    )
    nuevo_usuario: str | None = Field(
        default=None, json_schema_extra={"example": "camilo_nuevo"}
    )
    nuevo_email: EmailStr | None = Field(
        default=None, json_schema_extra={"example": "nuevo_email@ejemplo.com"}
    )
    nueva_password: str | None = Field(
        default=None, json_schema_extra={"example": "NuevaPassword456"}
    )
    nuevo_rol: str | None = Field(default=None, json_schema_extra={"example": "admin"})


class SolicitudRecuperacion(BaseModel):
    usuario: str = Field(
        ...,
        json_schema_extra={"example": "camilo_dev"},
        description="Nombre de usuario registrado en la plataforma",
    )


class RestablecerPassword(BaseModel):
    token: str = Field(..., description="Token recibido por correo electrónico")
    nueva_password: str = Field(..., json_schema_extra={"example": "NuevaPassword456"})
