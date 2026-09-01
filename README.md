# Sistema de Autenticación y Gestión de Usuarios

API REST de autenticación lista para producción construida con **FastAPI**, **PostgreSQL** y **JWT**. Incluye gestión de roles, actualización segura de perfiles y recuperación de contraseñas mediante correo electrónico en formato HTML estilizado.

---

## Tecnologías Utilizadas

- **Framework:** FastAPI
- **Base de Datos:** PostgreSQL con driver nativo `psycopg2`
- **Seguridad & Hash:** `pwdlib` (Bcrypt) y PyJWT
- **Validaciones:** Pydantic v2
- **Manejo de Correo:** SMTP con plantillas HTML responsivas

---

## Características Principales

- **Registro e Inicio de Sesión:** Autenticación mediante OAuth2 con tokens de acceso JWT.
- **Control de Acceso basado en Roles (RBAC):** Middleware para la restricción de endpoints a usuarios con rol `admin`.
- **Recuperación de Contraseña:** Generación de tokens con caducidad de 15 minutos y envío automático por correo electrónico.
- **Administración de Cuentas:** Modificación de credenciales (correo, rol, contraseña) y eliminación segura de usuarios (protegida contra auto-eliminación de administradores).
- **Documentación Automática:** Integración nativa con OpenAPI / Swagger UI.

---

## Configuración del Entorno Local

### 1. Clonar el repositorio e instalar dependencias

```bash
git clone [https://github.com/ANDRES11016/autentificacion.git](https://github.com/ANDRES11016/autentificacion.git)
cd autentificacion
python -m venv venv
pip install -r requirements.txt\
```
