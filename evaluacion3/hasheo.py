import bcrypt

# Paso 1. Obtener contraseña en plano
incoming_password = input("Ingresa tu contraseña: ").encode("UTF-8")
# Paso 2. Crear un pedazo de sal
salt = bcrypt.gensalt(rounds=12)
# Paso 3. Hashear la contraseña en plano y dar una sal al hasheo
hashed_password = bcrypt.hashpw(password=incoming_password, salt=salt)
print("Contraseña hasheada", hashed_password)
# Paso 4. Ingresar de nuevo la contraseña
confirm_password = input("Ingresa nuevamente la contraseña: ").encode("UTF-8")
# Paso 5. Comparar contraseñas
if bcrypt.checkpw(confirm_password, hashed_password):
    print("Contraseña correcta")
else:
    print("Contraseña incorrecta")