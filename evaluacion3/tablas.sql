CREATE TABLE USERS (
    id NUMBER PRIMARY KEY,
    username VARCHAR2(32) UNIQUE,
    password VARCHAR2(128)
);

CREATE TABLE INDICADORES_ECONOMICOS (
    id NUMBER GENERATED ALWAYS AS IDENTITY,
    nombre_indicador VARCHAR2(20),
    fecha_valor DATE,
    fecha_consulta DATE,
    usuario VARCHAR2(32),
    proveedor VARCHAR2(50)
);


INSERT INTO USERS (id, username, password)
VALUES (1, 'carlito', 'inacap');

INSERT INTO INDICADORES_ECONOMICOS
(nombre_indicador, fecha_valor, fecha_consulta, usuario, proveedor)
VALUES
('UF', SYSDATE, SYSDATE, 'carlito', 'mindicador.cl');