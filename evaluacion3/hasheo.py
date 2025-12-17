# Autenticación y seguridad (3.1.1)

import bcrypt
from typing import Union


def hash_password(password: Union[str, bytes], rounds: int = 12) -> str:
    """Devuelve el hash (hex) de la contraseña proporcionada.

    - `password`: cadena o bytes en claro
    - `rounds`: costo para `bcrypt.gensalt`
    """
    if isinstance(password, str):
        password = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds)
    hashed = bcrypt.hashpw(password, salt)
    return hashed.hex()


def verify_password(password: Union[str, bytes], hashed_hex: str) -> bool:
    """Verifica si `password` coincide con `hashed_hex` (hex string).

    Acepta `password` como `str` o `bytes`. Devuelve `True` si coincide.
    """
    if isinstance(password, str):
        password = password.encode("utf-8")
    try:
        hashed = bytes.fromhex(hashed_hex)
    except Exception:
        return False
    return bcrypt.checkpw(password, hashed)


if __name__ == "__main__":
    pw = input("Ingresa tu contraseña: ")
    h = hash_password(pw)
    print("Hashed (hex):", h)
    pw2 = input("Reingresa para verificar: ")
    print("Coincide:", verify_password(pw2, h))
