import datetime
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

import bcrypt
import oracledb
import requests
from dotenv import load_dotenv

load_dotenv()

class Database:
    def __init__(self, username, dsn, password):
        self.username = username
        self.dsn = dsn
        self.password = password
    def get_connection(self):
        return oracledb.connect(user=self.username, password=self.password, dsn=self.dsn)
    def create_all_tables(self):
        tables = [
            (
                "CREATE TABLE USERS("
                "id NUMBER PRIMARY KEY,"
                "username VARCHAR(32) UNIQUE,"
                "password VARCHAR(128)"
                ")"
            )
        ]

        for table in tables:
            self.query(table)

    def query(self, sql: str, parameters: Optional[dict] = None):
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    ejecucion = cur.execute(sql, parameters)
                    if sql.startswith("SELECT"):
                        resultado = []
                        for fila in ejecucion:
                            resultado.append(fila)
                        return resultado
                conn.commit()
        except oracledb.DatabaseError as error:
            print(error)

class Auth:
    @staticmethod
    def login(db: Database, username: str, password: str):
        password = password.encode("UTF-8")

        resultado = db.query(
            sql= "SELECT * FROM USERS WHERE username = :username",
            parameters={"username": username}
        )
        print("SELECT * FROM USERS WHERE username = :username", {"username": username}, resultado)

        if not resultado:
            print("No hay coincidencias")
            return None

        # Stored password is hex string of the hashed bytes
        try:
            hashed_password = bytes.fromhex(resultado[0][2])
        except Exception:
            print("Formato de contraseña inválido en la base de datos")
            return None

        if bcrypt.checkpw(password, hashed_password):
            print("Logeado correctamente")
            # return user id if present
            try:
                return int(resultado[0][0])
            except Exception:
                return 0
        else:
            print("Contraseña incorrecta")
            return None

    @staticmethod
    def register(db: Database, id: int, username: str, password: str):
        print("registrando usuario")
        password = password.encode("UTF-8")
        salt = bcrypt.gensalt(12)
        hash_password = bcrypt.hashpw(password,salt)

        usuario = {
            "id": id,
            "username": username,
            # store as hex string to be safe across DB drivers
            "password": hash_password.hex()
        }

        db.query(
            sql= "INSERT INTO USERS(id,username,password) VALUES (:id, :username, :password)",
            parameters=usuario
        )
        print("usuario registrado con exito")

class Finance:
    def __init__(self, base_url: str = "https://mindicador.cl/api"):
        self.base_url = base_url
    def get_indicator(self, indicator: str, fecha: str = None) -> float:
        try:
            # Intento 1: solicitar con fecha (si fue entregada o hoy)
            if not fecha:
                fecha = datetime.datetime.now().strftime("%Y-%m-%d")
            url_with_date = f"{self.base_url}/{indicator}/{fecha}"
            try:
                respuesta = requests.get(url_with_date, timeout=10)
                respuesta.raise_for_status()
                data = respuesta.json()
                print(f"[DEBUG] Respuesta completa para {indicator} en {fecha}: {data}")
                serie = data.get("serie") or []
                if serie:
                    return serie[0].get("valor")
            except Exception:
                # si falla (500 u otro), continuar para intentar sin fecha
                pass

            # Intento 2: solicitar sin fecha (último valor disponible)
            url = f"{self.base_url}/{indicator}"
            try:
                respuesta2 = requests.get(url, timeout=10)
                respuesta2.raise_for_status()
                data2 = respuesta2.json()
                serie2 = data2.get("serie") or []
                if serie2:
                    return serie2[0].get("valor")
                print(f"Sin datos en serie para {indicator} (último disponible)")
                return None
            except Exception as e2:
                print(f"Hubo un error con la solicitud (sin fecha) para {indicator}: {e2}")
                return None
        except Exception as e:
            print(f"Error inesperado obteniendo {indicator}: {e}")
            return None

    def get_currency_rate(self, currency: str, fecha: str = None) -> Optional[float]:
        """Obtiene tasa de `currency` a CLP usando exchangerate.host. Mantiene la misma interfaz."""
        try:
            # exchangerate.host: https://api.exchangerate.host/convert?from=USD&to=CLP&date=YYYY-MM-DD
            params = {"from": currency, "to": "CLP"}
            if fecha:
                params["date"] = fecha
            url = "https://api.exchangerate.host/convert"
            resp = requests.get(url, params=params, timeout=10)
            resp.raise_for_status()
            j = resp.json()
            # campo 'result' contiene la conversión directa
            result = j.get("result")
            if result is None:
                print(f"No se obtuvo tasa para {currency} en {fecha or 'hoy'}")
                return None
            print(f"El valor de {currency} en CLP es: {result}")
            return result
        except Exception as e:
            print(f"Error obteniendo tasa de {currency}: {e}")
            return None
    def get_chilean_indicator(self, indicator: str, fecha: str = None) -> Optional[float]:
        """Intenta obtener indicador desde Banco Central (si está configurado) y luego mindicador como fallback.

        - Si la variable de entorno `BC_BASE_URL` está definida intentará una petición a esa URL
          con la forma: {BC_BASE_URL}/{indicator}?date=YYYY-MM-DD
        - Si no existe `BC_BASE_URL` o la respuesta no contiene datos esperados,
          usará la lógica de `get_indicator` (mindicador con fallback fecha/no-fecha).
        """
        try:
            fecha_param = fecha if fecha else None
            bc_base = os.getenv("BC_BASE_URL")
            if bc_base:
                try:
                    params = {}
                    if fecha_param:
                        params["date"] = fecha_param
                    resp = requests.get(f"{bc_base.rstrip('/')}/{indicator}", params=params, timeout=10)
                    resp.raise_for_status()
                    j = resp.json()
                    # Estructura esperada: similar a mindicador ('serie')
                    if isinstance(j, dict) and j.get("serie"):
                        s = j.get("serie") or []
                        if s:
                            return s[0].get("valor")
                    # Alternativa: buscar campos comunes
                    if isinstance(j, dict):
                        # direct value
                        for k in ("valor", "value", "resultado"):
                            if k in j and isinstance(j[k], (int, float)):
                                return j[k]
                        # data list
                        data_list = j.get("data") or j.get("datos") or []
                        if isinstance(data_list, list) and data_list:
                            first = data_list[0]
                            if isinstance(first, dict):
                                for k in ("valor", "value"):
                                    if k in first:
                                        return first.get(k)
                except Exception:
                    # si falla con BC, seguir al fallback
                    pass

            # Fallback: usar mindicador (get_indicator ya intenta con fecha y sin fecha)
            return self.get_indicator(indicator, fecha)
        except Exception as e:
            print(f"Error obteniendo indicador chileno {indicator}: {e}")
            return None
    def get_usd(self, fecha: str = None):
        # Intentar obtener desde mindicador (dolar) / BC fallback
        valor = self.get_chilean_indicator("dolar", fecha)
        print(f"El valor del dolar en CLP es: {valor}")
        return valor
    def get_eur(self, fecha: str = None):
        valor = self.get_chilean_indicator("euro", fecha)
        print(f"El valor del euro en CLP es: {valor}")
        return valor

    def get_uf(self, fecha: str = None):
        valor = self.get_chilean_indicator("uf", fecha)
        print(f"El valor de la UF en CLP es: {valor}")
        return valor

    def get_ivp(self, fecha: str = None):
        valor = self.get_chilean_indicator("ivp", fecha)
        print(f"El valor del IVP en CLP es: {valor}")
        return valor

    def get_ipc(self, fecha: str = None):
        valor = self.get_chilean_indicator("ipc", fecha)
        print(f"El valor del IPC es: {valor}")
        return valor

    def get_utm(self, fecha: str = None):
        valor = self.get_chilean_indicator("utm", fecha)
        print(f"El valor de la UTM es: {valor}")
        return valor

def _validate_date(date_str: Optional[str]) -> Optional[str]:
    if not date_str:
        return None
    formats = ["%d-%m-%Y", "%Y-%m-%d", "%d/%m/%Y"]
    for fmt in formats:
        try:
            dt = datetime.datetime.strptime(date_str, fmt)
            return dt.strftime("%Y-%m-%d")
        except Exception:
            continue
    return None


def _validate_username(username: str) -> bool:
    if not username or len(username) < 3 or len(username) > 32:
        return False
    return bool(re.match(r"^[A-Za-z0-9_.-]+$", username))


def _validate_password(password: str) -> bool:
    return bool(password) and len(password) >= 6


def prompt_register(db: Database):
    print("== Registro de usuario ==")
    while True:
        try:
            id_str = input("ID (numero entero) [enter para generar]: ").strip()
            if id_str == "":
                user_id = int(datetime.datetime.now().timestamp())
            else:
                user_id = int(id_str)
            break
        except Exception:
            print("ID inválido, ingrese un número entero")

    while True:
        username = input("Usuario: ").strip()
        if not _validate_username(username):
            print("Nombre de usuario inválido. Sólo letras, números y . _ - (3-32 chars)")
            continue
        break

    while True:
        password = input("Contraseña: ").strip()
        if not _validate_password(password):
            print("Contraseña inválida. Mínimo 6 caracteres")
            continue
        confirm = input("Confirmar contraseña: ").strip()
        if password != confirm:
            print("Las contraseñas no coinciden")
            continue
        break

    Auth.register(db, user_id, username, password)


def prompt_login(db: Database) -> Optional[int]:
    print("== Login ==")
    username = input("Usuario: ").strip()
    password = input("Contraseña: ").strip()
    if not _validate_username(username) or not _validate_password(password):
        print("Credenciales con formato inválido")
        return None
    user_id = Auth.login(db, username, password)
    return user_id


def indicators_menu(finance: Finance):
    options = {
        "1": ("USD", finance.get_usd),
        "2": ("EUR", finance.get_eur),
        "3": ("UF", finance.get_uf),
        "4": ("IVP", finance.get_ivp),
        "5": ("IPC", finance.get_ipc),
        "6": ("UTM", finance.get_utm),
    }
    while True:
        print("\n-- Indicadores --")
        for k, v in options.items():
            print(f"{k}. {v[0]}")
        print("0. Volver")
        choice = input("Seleccione una opción: ").strip()
        if choice == "0":
            break
        if choice not in options:
            print("Opción inválida")
            continue
        date_in = input("Fecha opcional (dd-mm-YYYY o yyyy-mm-dd, enter para hoy): ").strip()
        if date_in == "":
            date_arg = None
        else:
            valid = _validate_date(date_in)
            if not valid:
                print("Fecha inválida, use dd-mm-YYYY o yyyy-mm-dd")
                continue
            date_arg = valid
        func = options[choice][1]
        try:
            func(date_arg)
        except Exception as e:
            print("Error al obtener indicador:", e)


def run_cli():
    db = Database(
        username=os.getenv("ORACLE_USER"),
        password=os.getenv("ORACLE_PASSWORD"),
        dsn=os.getenv("ORACLE_DSN")
    )

    print(db.username, db.password, db.dsn)

    finance = Finance()

    print("Bienvenido al CLI de indicadores")
    user_id: Optional[int] = None
    while True:
        print("\n1. Registrar\n2. Login\n3. Consultar indicadores (requiere login)\n0. Salir")
        opt = input("Elija una opción: ").strip()
        if opt == "1":
            prompt_register(db)
        elif opt == "2":
            uid = prompt_login(db)
            if uid:
                user_id = uid
        elif opt == "3":
            if not user_id:
                print("Inicie sesión primero")
                continue
            indicators_menu(finance)
        elif opt == "0":
            print("Saliendo...")
            break
        else:
            print("Opción inválida")


if __name__ == "__main__":
    load_dotenv()

    db = Database(
        username=os.getenv("ORACLE_USER"),
        password=os.getenv("ORACLE_PASSWORD"),
        dsn=os.getenv("ORACLE_DSN")
    )

    db.create_all_tables()

    run_cli()

    """#Conectado a la base de datos a través de Oracle se debe registrar los datos consultados 
    #cuando el usuario lo requiera, para ello deberá almacenar en la base de datos el nombre del indicador, 
    la fecha en que registra el valor, la fecha en que el usuario realiza la consulta, 
    el usuario que la realiza y el sitio que provee los indicadores."""



""" Deserialización y consumo de datos (3.1.3)
Evalúa la creación de una clase en Python que maneje datos JSON/XML,
además de la integración efectiva de información externa según los requerimientos.
"""

class DataParser:
    """Utilidad para cargar/convertir JSON y XML.

    - Cargar desde string, archivo o URL
    - Parsear JSON/XML a dict
    - Convertir dict a JSON o XML (simple)
    """
class DataParser:
    ...
    @staticmethod
    def _normalize_date(date_str: Optional[str]) -> str:
        """Normaliza fechas a 'YYYY-MM-DD' para la BD."""
        if not date_str:
            return datetime.datetime.now().strftime("%Y-%m-%d")
        # ISO datetime (ej. 2023-01-01T00:00:00.000Z)
        if "T" in date_str:
            return date_str.split("T")[0]
        # yyyy-mm-dd (ya correcto)
        if "-" in date_str and len(date_str.split("-")[0]) == 4:
            return date_str
        # dd-mm-yyyy o d-m-yyyy
        if "-" in date_str:
            d, m, y = date_str.split("-")
            return f"{int(y):04d}-{int(m):02d}-{int(d):02d}"
        # dd/mm/yyyy
        if "/" in date_str:
            d, m, y = date_str.split("/")
            return f"{int(y):04d}-{int(m):02d}-{int(d):02d}"
        # fallback
        return date_str

    @staticmethod
    def parse_mindicador_indicator(data: Dict[str, Any], indicator_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Extrae (name, value, value_date, raw_json) desde la estructura de mindicador.cl.
        Lanza ValueError si la estructura no contiene la serie esperada.
        """
        serie = data.get("serie") or []
        if not serie:
            raise ValueError("Respuesta sin 'serie'")

        first = serie[0]
        valor = first.get("valor")
        fecha_raw = first.get("fecha") or first.get("date") or None
        fecha_sql = DataParser._normalize_date(fecha_raw)

        name = indicator_name or data.get("codigo") or data.get("nombre") or "indicator"
        raw_json = json.dumps(data, ensure_ascii=False)

        return {"name": name, "value": valor, "value_date": fecha_sql, "raw_json": raw_json}

    @staticmethod
    def indicator_to_db_params(parsed: Dict[str, Any], user_id: Optional[int] = None, source: Optional[str] = None) -> Dict[str, Any]:
        """
        Devuelve un diccionario listo para bind parameters de la consulta INSERT.
        Ej: {"name":..., "value":..., "value_date":..., "user_id":..., "source":..., "raw_json":...}
        """
        return {
            "name": parsed["name"],
            "value": parsed["value"],
            "value_date": parsed["value_date"],
            "user_id": user_id,
            "source": source or "mindicador.cl",
            "raw_json": parsed.get("raw_json")
        }


""" Almacenamiento en base de datos (3.1.4)
Considera la estructura y persistencia coherente de datos en una base de datos,
 cumpliendo requisitos funcionales y no funcionales (rendimiento, seguridad, usabilidad).
"""
def insert_indicator(self, name: str, value: float, value_date: str, user_id: Optional[int], source: str, raw_json: Optional[str] = None, raw_xml: Optional[str] = None):
    sql = (
        "INSERT INTO INDICATORS(name, value, value_date, user_id, source, raw_json, raw_xml) "
        "VALUES (:name, :value, TO_DATE(:value_date,'YYYY-MM-DD'), :user_id, :source, :raw_json, :raw_xml)"
    )
    params = {
        "name": name,
        "value": value,
        "value_date": value_date,
        "user_id": user_id,
        "source": source,
        "raw_json": raw_json,
        "raw_xml": raw_xml,
    }
    self.query(sql, params)

def insert_indicator_history(self, indicator_name: str, value: float, value_date: str, source: str, retrieved_by: Optional[int] = None):
    sql = (
        "INSERT INTO INDICATOR_HISTORY(indicator_name, value, value_date, source, retrieved_by) "
        "VALUES (:indicator_name, :value, TO_DATE(:value_date,'YYYY-MM-DD'), :source, :retrieved_by)"
    )
    params = {
        "indicator_name": indicator_name,
        "value": value,
        "value_date": value_date,
        "source": source,
        "retrieved_by": retrieved_by,
    }
    self.query(sql, params)

def get_latest_indicator(self, name: str):
    sql = "SELECT name, value, TO_CHAR(value_date,'YYYY-MM-DD'), source, retrieved_at FROM INDICATORS WHERE name = :name ORDER BY retrieved_at DESC FETCH FIRST 1 ROWS ONLY"
    res = self.query(sql, {"name": name})
    return res[0] if res else None
