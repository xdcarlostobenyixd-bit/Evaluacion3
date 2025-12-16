import bcrypt
import requests
import oracledb
import os
import datetime
import re
from dotenv import load_dotenv
from typing import Optional

load_dotenv()

# =========================
# BASE DE DATOS 
# =========================

class Database:
    def __init__(self, username, dsn, password):
        self.username = username
        self.dsn = dsn
        self.password = password

    def get_connection(self):
        return oracledb.connect(
            user=self.username,
            password=self.password,
            dsn=self.dsn
        )

    def query(self, sql: str, parameters: Optional[dict] = None):
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    result = cur.execute(sql, parameters)
                    if sql.strip().upper().startswith("SELECT"):
                        return result.fetchall()
                conn.commit()
        except oracledb.DatabaseError as e:
            print("Error BD:", e)

# =========================
# AUTENTICACIÓN SEGURA
# =========================

class Auth:
    @staticmethod
    def validar_input(texto: str):
        if not re.match(r"^[a-zA-Z0-9_]{4,20}$", texto):
            raise ValueError("Entrada inválida")

    @staticmethod
    def register(db: Database, id: int, username: str, password: str):
        Auth.validar_input(username)

        password_bytes = password.encode("UTF-8")
        salt = bcrypt.gensalt(12)
        hashed_password = bcrypt.hashpw(password_bytes, salt)

        db.query(
            sql="""
                INSERT INTO USERS(id, username, password)
                VALUES (:id, :username, :password)
            """,
            parameters={
                "id": id,
                "username": username,
                "password": hashed_password.hex()
            }
        )

        print("Usuario registrado con éxito")

    @staticmethod
    def login(db: Database, username: str, password: str) -> bool:
        Auth.validar_input(username)

        resultado = db.query(
            sql="SELECT password FROM USERS WHERE username = :username",
            parameters={"username": username}
        )

        if not resultado:
            print("Usuario no existe")
            return False

        hashed_password = bytes.fromhex(resultado[0][0])

        if bcrypt.checkpw(password.encode("UTF-8"), hashed_password):
            print("Login exitoso")
            return True
        else:
            print("Contraseña incorrecta")
            return False

# =========================
# MODELO INDICADOR 
# =========================

class IndicadorEconomico:
    def __init__(self, nombre, fecha_valor, valor):
        self.nombre = nombre
        self.fecha_valor = fecha_valor
        self.valor = valor

# =========================
# CONSUMO API 
# =========================

class Finance:
    BASE_URL = "https://mindicador.cl/api"
    PROVIDER = "mindicador.cl"

    def get_indicator(self, indicator: str, fecha: str = None) -> IndicadorEconomico:
        try:
            if not fecha:
                fecha = datetime.datetime.now().strftime("%d-%m-%Y")

            url = f"{self.BASE_URL}/{indicator}/{fecha}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()
            valor = data["serie"][0]["valor"]
            fecha_valor = data["serie"][0]["fecha"]

            return IndicadorEconomico(
                indicator.upper(),
                fecha_valor,
                valor
            )

        except requests.RequestException as e:
            print("Error al consumir la API:", e)

# =========================
# REGISTRO DE INDICADORES
# =========================

class IndicadorRepository:
    @staticmethod
    def guardar(db: Database, indicador: IndicadorEconomico, usuario: str):
        db.query(
            sql="""
                INSERT INTO INDICADORES_ECONOMICOS
                (nombre_indicador, fecha_valor, fecha_consulta, usuario, proveedor)
                VALUES (:nombre, :fecha_valor, :fecha_consulta, :usuario, :proveedor)
            """,
            parameters={
                "nombre": indicador.nombre,
                "fecha_valor": indicador.fecha_valor,
                "fecha_consulta": datetime.datetime.now(),
                "usuario": usuario,
                "proveedor": Finance.PROVIDER
            }
        )

        print("Indicador registrado en la base de datos")

# =========================
# MAIN 
# =========================

if __name__ == "__main__":

    db = Database(
        username=os.getenv("ORACLE_USER"),
        password=os.getenv("ORACLE_PASSWORD"),
        dsn=os.getenv("ORACLE_DSN")
    )

    print("=== SISTEMA DE INDICADORES ECONÓMICOS ===")

    usuario = input("Usuario: ")
    password = input("Contraseña: ")

    # PRUEBA DE REGISTRO 
    Auth.register(db, 1, "admin", "Admin123")


    if Auth.login(db, usuario, password):

        finance = Finance()

        print("Indicadores disponibles:")
        print("uf, ivp, ipc, utm, dolar, euro")

        indicador_input = input("Seleccione indicador: ").lower()

        indicador = finance.get_indicator(indicador_input)

        if indicador:
            print(f"\nIndicador: {indicador.nombre}")
            print(f"Fecha valor: {indicador.fecha_valor}")
            print(f"Valor: {indicador.valor}")

            guardar = input("¿Desea guardar el indicador? (s/n): ")

            if guardar.lower() == "s":
                IndicadorRepository.guardar(db, indicador, usuario)
