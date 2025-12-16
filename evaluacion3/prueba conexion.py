import oracledb
import os
from dotenv import load_dotenv

load_dotenv()

try:
    conn = oracledb.connect(
        user=os.getenv("ORACLE_USER"),
        password=os.getenv("ORACLE_PASSWORD"),
        dsn=os.getenv("ORACLE_DSN")
    )
    print("Conexión a Oracle exitosa")

    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM USERS")
    print("Usuarios en BD:", cursor.fetchone()[0])

    conn.close()

except Exception as e:
    print("Error de conexión:", e)
