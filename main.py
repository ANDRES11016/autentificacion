import os
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from psycopg2.extras import RealDictCursor

from database import (
    obtener_conexion,
    crear_tabla,
    # obtener_usuario_por_email,
    obtener_usuario_por_username,
)
from security import (
    encriptar_password,
    verificar_password,
    crear_token_acceso,
    enmascarar_email,
    obtener_usuario_actual,
    requerir_roles,
    crear_token_recuperacion,
    verificar_token_recuperacion,
    enviar_correo_recuperacion,
)
from schemas import (
    UsuarioRegistro,
    UsuarioActualizar,
    RestablecerPassword,
)

# Detectar el entorno
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

# Deshabilitar /docs y /redoc en producción si ENVIRONMENT != 'development'
app = FastAPI(
    title="API de Autenticación",
    docs_url="/docs" if ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if ENVIRONMENT == "development" else None,
)

# Configuración de CORS
origins = [
    "http://127.0.0.1:8000",  # Puerto por defecto de FastAPI
    # "http://localhost:5173",  # Puerto por defecto de Vite / React
    # "https://midominio.com",  # Agrega tu dominio real en producción
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Crear tablas al iniciar la aplicación
crear_tabla()


@app.post("/register", summary="Registrar un nuevo usuario")
def registrar_usuario(usuario: UsuarioRegistro):
    conn = obtener_conexion()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT usuario, email FROM usuarios WHERE usuario = %s OR email = %s",
                (usuario.usuario, usuario.email),
            )
            existente = cursor.fetchone()
            if existente:
                if existente["usuario"] == usuario.usuario:
                    raise HTTPException(
                        status_code=400, detail="El nombre de usuario ya está en uso"
                    )
                raise HTTPException(
                    status_code=400, detail="El correo ya está registrado"
                )

            hashed_pwd = encriptar_password(usuario.password)
            cursor.execute(
                "INSERT INTO usuarios (usuario, email, password, rol) VALUES (%s, %s, %s, %s)",
                (usuario.usuario, usuario.email, hashed_pwd, usuario.rol),
            )
            conn.commit()

            return {
                "mensaje": "Usuario guardado con éxito",
                "usuario": usuario.usuario,
                "email_respaldo": enmascarar_email(usuario.email),
                "rol": usuario.rol,
            }
    finally:
        conn.close()


@app.post("/login", summary="Iniciar sesión")
def iniciar_sesion(form_data: OAuth2PasswordRequestForm = Depends()):
    nombre_usuario = form_data.username
    conn = obtener_conexion()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT usuario, email, password, rol FROM usuarios WHERE usuario = %s",
                (nombre_usuario,),
            )
            user_db = cursor.fetchone()

            if not user_db or not verificar_password(
                form_data.password, user_db["password"]
            ):
                raise HTTPException(status_code=400, detail="Credenciales incorrectas")

            token = crear_token_acceso(
                data={
                    "sub": user_db["usuario"],
                    "email": user_db["email"],
                    "rol": user_db["rol"],
                }
            )

            return {"access_token": token, "token_type": "bearer"}
    finally:
        conn.close()


@app.put("/users/{email_actual}", summary="Actualizar datos de usuario")
def actualizar_usuario(
    email_actual: str,
    datos: UsuarioActualizar,
    usuario_autenticado: dict = Depends(obtener_usuario_actual),
):
    if (
        usuario_autenticado["rol"] != "admin"
        and usuario_autenticado["email"] != email_actual
    ):
        raise HTTPException(
            status_code=403, detail="Solo puedes actualizar tu propia cuenta de usuario"
        )

    conn = obtener_conexion()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT password FROM usuarios WHERE email = %s", (email_actual,)
            )
            usuario_db = cursor.fetchone()
            if not usuario_db:
                raise HTTPException(
                    status_code=404, detail="El usuario especificado no existe"
                )

            if (
                usuario_autenticado["rol"] != "admin"
                or usuario_autenticado["email"] == email_actual
            ):
                if not verificar_password(
                    datos.password_actual, usuario_db["password"]
                ):
                    raise HTTPException(
                        status_code=400, detail="La contraseña actual es incorrecta"
                    )

            if datos.nuevo_email and datos.nuevo_email != email_actual:
                cursor.execute(
                    "SELECT id FROM usuarios WHERE email = %s", (datos.nuevo_email,)
                )
                if cursor.fetchone():
                    raise HTTPException(
                        status_code=400,
                        detail="El nuevo correo ya está registrado por otro usuario",
                    )

            updates = []
            params = []

            if datos.nuevo_email:
                updates.append("email = %s")
                params.append(datos.nuevo_email)

            if datos.nueva_password:
                hashed_pwd = encriptar_password(datos.nueva_password)
                updates.append("password = %s")
                params.append(hashed_pwd)

            if datos.nuevo_rol:
                if usuario_autenticado["rol"] != "admin":
                    raise HTTPException(
                        status_code=403,
                        detail="Solo un administrador puede cambiar roles",
                    )
                updates.append("rol = %s")
                params.append(datos.nuevo_rol)

            if not updates:
                raise HTTPException(
                    status_code=400,
                    detail="Debes enviar al menos un nuevo dato para actualizar",
                )

            params.append(email_actual)
            query = f"UPDATE usuarios SET {', '.join(updates)} WHERE email = %s"

            cursor.execute(query, tuple(params))
            conn.commit()

            email_resultado = datos.nuevo_email if datos.nuevo_email else email_actual

            return {
                "mensaje": "Datos actualizados correctamente",
                "usuario": enmascarar_email(email_resultado),
            }
    finally:
        conn.close()


@app.post(
    "/forgot-password", summary="Solicitar token de recuperación mediante usuario"
)
def solicitar_recuperacion(
    usuario: str = Query(..., description="Ingresa tu nombre de usuario")
):
    usuario_db = obtener_usuario_por_username(usuario)

    if not usuario_db:
        raise HTTPException(
            status_code=404, detail="El nombre de usuario ingresado no existe."
        )

    email_asociado = usuario_db["email"]
    nombre_usuario = usuario_db["usuario"]

    token = crear_token_recuperacion(email_asociado)
    enviar_correo_recuperacion(email_asociado, nombre_usuario, token)

    return {
        "message": f"Se ha enviado el enlace de recuperación al correo asociado a {enmascarar_email(email_asociado)}."
    }


@app.post("/reset-password", summary="Restablecer contraseña con token")
def restablecer_password(datos: RestablecerPassword):
    email = verificar_token_recuperacion(datos.token)
    nueva_password_hashed = encriptar_password(datos.nueva_password)

    conn = obtener_conexion()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT id FROM usuarios WHERE email = %s", (email,))
            usuario = cursor.fetchone()
            if not usuario:
                raise HTTPException(
                    status_code=404, detail="El usuario no fue encontrado"
                )

            cursor.execute(
                "UPDATE usuarios SET password = %s WHERE email = %s",
                (nueva_password_hashed, email),
            )
            conn.commit()

            return {
                "mensaje": f"La contraseña para {enmascarar_email(email)} ha sido restablecida con éxito."
            }
    finally:
        conn.close()


@app.delete(
    "/users/{usuario}",
    dependencies=[Depends(requerir_roles(["admin"]))],
    summary="Eliminar usuario (Admin)",
)
def eliminar_usuario(
    usuario: str, usuario_autenticado: dict = Depends(obtener_usuario_actual)
):
    # Asegúrate de usar la clave correcta del dict (evalúa 'sub' o 'usuario')
    usuario_logueado = usuario_autenticado.get("sub") or usuario_autenticado.get(
        "usuario"
    )

    if usuario_logueado == usuario:
        raise HTTPException(
            status_code=400,
            detail="No puedes eliminar tu propia cuenta de administrador",
        )

    conn = obtener_conexion()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Verificar existencia
            cursor.execute(
                "SELECT id, email FROM usuarios WHERE usuario = %s", (usuario,)
            )
            usuario_db = cursor.fetchone()

            if not usuario_db:
                raise HTTPException(status_code=404, detail="Usuario no encontrado")

            # Eliminar
            cursor.execute("DELETE FROM usuarios WHERE usuario = %s", (usuario,))
            conn.commit()

            return {
                "mensaje": f"Usuario '{usuario}' (asociado a {enmascarar_email(usuario_db['email'])}) eliminado con éxito por el Administrador"
            }
    except HTTPException:
        raise
    except Exception as e:
        # Detalles del error para depuración, pero no exponerlos al usuario final
        raise HTTPException(
            status_code=500, detail=f"Error interno del servidor: {str(e)}"
        )
    finally:
        conn.close()
