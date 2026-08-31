# database.py
import os
import psycopg2
from fastapi import HTTPException
from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

DATABASE_URL = os.getenv("DATABASE_URL")


def obtener_conexion():
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error al conectar con la base de datos: {e}"
        )


def crear_tabla():
    try:
        conn = obtener_conexion()
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS usuarios (
                    id SERIAL PRIMARY KEY,
                    usuario VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    rol VARCHAR(50) NOT NULL DEFAULT 'cliente',
                    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
        conn.commit()
        conn.close()
        print("Tabla 'usuarios' verificada en Supabase.")
    except Exception as e:
        print(f"Advertencia al conectar o crear tabla: {e}")
