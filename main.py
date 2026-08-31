from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm
from psycopg2.extras import RealDictCursor

from database import obtener_conexion, crear_tabla
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
    SolicitudRecuperacion,
    RestablecerPassword,
)

app = FastAPI()

crear_tabla()


@app.post("/register")
def registrar_usuario(usuario: UsuarioRegistro):
    conn = obtener_conexion()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Verificar si el usuario o el correo ya existen
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


@app.post("/login")
def iniciar_sesion(form_data: OAuth2PasswordRequestForm = Depends()):
    # Swagger envía el 'username' del formulario
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

            # El token guarda el 'usuario' como 'sub' y conserva el correo de respaldo
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


@app.put("/users/{email_actual}")
def actualizar_usuario(
    email_actual: str,
    datos: UsuarioActualizar,
    usuario_autenticado: dict = Depends(obtener_usuario_actual),
):
    # 1. Permisos: Solo el dueño o un admin pueden modificar la cuenta
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
            # 2. Consultar contraseña y rol actual del usuario en la base de datos
            cursor.execute(
                "SELECT password FROM usuarios WHERE email = %s", (email_actual,)
            )
            usuario_db = cursor.fetchone()
            if not usuario_db:
                raise HTTPException(
                    status_code=404, detail="El usuario especificado no existe"
                )

            # 3. VERIFICAR CONTRASEÑA ANTIGUA (Si no es admin modificando a otro usuario)
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

            # 4. Validar disponibilidad si desea cambiar de email
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
                    detail="Debes enviar al menos un nuevo dato para actualizar (nuevo_email, nueva_password o nuevo_rol)",
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


@app.post("/forgot-password")
def solicitar_recuperacion(datos: SolicitudRecuperacion):
    conn = obtener_conexion()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT id FROM usuarios WHERE email = %s", (datos.email,))
            if not cursor.fetchone():
                return {
                    "mensaje": "Si el correo existe, se enviará un enlace de recuperación."
                }

            token = crear_token_recuperacion(datos.email)

            # Envío del correo real
            enviar_correo_recuperacion(datos.email, token)

            return {
                "mensaje": "Si el correo existe, se enviará un enlace de recuperación."
            }
    finally:
        conn.close()


@app.post("/reset-password")
def restablecer_password(datos: RestablecerPassword):
    email = verificar_token_recuperacion(datos.token)

    conn = obtener_conexion()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            hashed_pwd = encriptar_password(datos.nueva_password)
            cursor.execute(
                "UPDATE usuarios SET password = %s WHERE email = %s",
                (hashed_pwd, email),
            )
            conn.commit()

            return {
                "mensaje": "Contraseña actualizada con éxito. Ya puedes iniciar sesión."
            }
    finally:
        conn.close()


@app.delete("/users/{email}", dependencies=[Depends(requerir_roles(["admin"]))])
def eliminar_usuario(email: str):
    conn = obtener_conexion()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT id FROM usuarios WHERE email = %s", (email,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Usuario no encontrado")

            cursor.execute("DELETE FROM usuarios WHERE email = %s", (email,))
            conn.commit()

            return {
                "mensaje": f"Usuario {enmascarar_email(email)} eliminado con éxito por el Administrador"
            }
    finally:
        conn.close()
