#!/usr/bin/env python3
"""
==============================================================================
  EL PROBLEMA DE LOS MILLONARIOS  --  Garbled Circuits (protocolo de Yao)
==============================================================================
  Implementacion real y completa en Python puro

  Alicia (garbler)  cifra el circuito.
  Bob    (evaluator) lo evalua a ciegas.
  Ninguno aprende el numero del otro: solo el resultado.

  USO:
     Terminal 1:  python3 millonarios.py alicia 15
     Terminal 2:  python3 millonarios.py bob 10

  OPCIONES:
     --bits N       tamano de los numeros (default 4, o sea 0..15)
     --puerto P     puerto TCP (default 9999)
     --host H       host al que conecta Bob (default 127.0.0.1)
     --paso-a-paso  pausa en cada etapa (para explicar en vivo)
     --silencioso   sin explicaciones, solo el resultado
==============================================================================
"""

import argparse
import hashlib
import os
import secrets
import socket
import struct
import sys
import time

# ============================================================================
#  Colores para la terminal
# ============================================================================
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    ROJO = "\033[91m"; VERDE = "\033[92m"; AMAR = "\033[93m"
    AZUL = "\033[94m"; MAG = "\033[95m"; CYAN = "\033[96m"

USAR_COLOR = sys.stdout.isatty()
def c(texto, color):
    return f"{color}{texto}{C.RESET}" if USAR_COLOR else texto

VERBOSE = True
PASO_A_PASO = False

def log(msg=""):
    if VERBOSE:
        print(msg)

def titulo(txt):
    if not VERBOSE:
        return
    print()
    print(c("=" * 74, C.CYAN))
    print(c(f"  {txt}", C.BOLD + C.CYAN))
    print(c("=" * 74, C.CYAN))

def pausa(msg="[Enter para continuar]"):
    if PASO_A_PASO and VERBOSE:
        input(c(f"\n   {msg}", C.DIM))

def hx(b, n=8):
    """Muestra los primeros n caracteres hex de unos bytes."""
    return b.hex()[:n].upper()

# ============================================================================
#  RED: mensajes con prefijo de longitud + registro del trafico
# ============================================================================
BYTES_ENVIADOS = 0
ARCHIVO_TRAFICO = None

def enviar(sock, datos: bytes):
    global BYTES_ENVIADOS
    paquete = struct.pack(">I", len(datos)) + datos
    sock.sendall(paquete)
    BYTES_ENVIADOS += len(paquete)
    if ARCHIVO_TRAFICO:
        ARCHIVO_TRAFICO.write(paquete)
        ARCHIVO_TRAFICO.flush()

def recibir(sock) -> bytes:
    cab = b""
    while len(cab) < 4:
        trozo = sock.recv(4 - len(cab))
        if not trozo:
            raise ConnectionError("Se cerro la conexion")
        cab += trozo
    n = struct.unpack(">I", cab)[0]
    datos = b""
    while len(datos) < n:
        trozo = sock.recv(min(65536, n - len(datos)))
        if not trozo:
            raise ConnectionError("Se cerro la conexion")
        datos += trozo
    return datos

def enviar_int(sock, v: int):
    enviar(sock, v.to_bytes((v.bit_length() + 7) // 8 or 1, "big"))

def recibir_int(sock) -> int:
    return int.from_bytes(recibir(sock), "big")

# ============================================================================
#  CIRCUITO BOOLEANO:  x > y
# ============================================================================
#  Se resuelve bit por bit, del mas significativo al menos significativo:
#     mayor = mayor OR (empate AND x_i AND NOT y_i)
#     empate = empate AND (x_i XNOR y_i)
# ============================================================================

class Circuito:
    def __init__(self):
        self.puertas = []      # (tipo, entrada_a, entrada_b, salida)
        self.n_cables = 0
        self.entradas_alicia = []
        self.entradas_bob = []
        self.salida = None

    def nuevo_cable(self):
        w = self.n_cables
        self.n_cables += 1
        return w

    def puerta(self, tipo, a, b=None):
        s = self.nuevo_cable()
        self.puertas.append((tipo, a, b, s))
        return s

    def constante(self, valor):
        """Crea un cable con valor fijo usando XOR consigo mismo."""
        w = self.nuevo_cable()
        self.puertas.append(("CONST", valor, None, w))
        return w


def construir_comparador(n_bits):
    """Circuito que calcula x > y para numeros de n_bits."""
    ct = Circuito()
    x = [ct.nuevo_cable() for _ in range(n_bits)]   # bit 0 = mas significativo
    y = [ct.nuevo_cable() for _ in range(n_bits)]
    ct.entradas_alicia = x
    ct.entradas_bob = y

    mayor = ct.constante(0)
    empate = ct.constante(1)

    for i in range(n_bits):
        ny = ct.puerta("NOT", y[i])            # NOT y_i
        gi = ct.puerta("AND", x[i], ny)        # gano en este bit
        ap = ct.puerta("AND", empate, gi)      # ...y veniamos empatados
        mayor = ct.puerta("OR", mayor, ap)     # acumulo
        ei = ct.puerta("XNOR", x[i], y[i])     # este bit es igual
        empate = ct.puerta("AND", empate, ei)  # seguimos empatados

    ct.salida = mayor
    return ct


COD_TIPO = {"CONST": 0, "AND": 1, "OR": 2, "XOR": 3, "XNOR": 4, "NOT": 5}
TIPO_COD = {v: k for k, v in COD_TIPO.items()}

TABLAS = {
    "AND":  lambda a, b: a & b,
    "OR":   lambda a, b: a | b,
    "XOR":  lambda a, b: a ^ b,
    "XNOR": lambda a, b: 1 - (a ^ b),
    "NOT":  lambda a, b: 1 - a,
}

# ============================================================================
#  CIFRADO DE PUERTAS
# ============================================================================
TAM_ETIQUETA = 16          # 128 bits
TAM_TAG = 8                # marca "OK" para saber que fila abrio

def H(*partes) -> bytes:
    """Funcion de derivacion. Los papers la definen abstracta; las
       implementaciones reales usan AES de llave fija por velocidad.
       Aqui usamos SHA-256 para no depender de librerias externas."""
    h = hashlib.sha256()
    for p in partes:
        h.update(p)
    return h.digest()[: TAM_ETIQUETA + TAM_TAG]

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(i ^ j for i, j in zip(a, b))

def cifrar_fila(la, lb, gid, salida):
    """mascara = H(etiquetas, id) ; fila = mascara XOR (etiqueta_salida || tag)"""
    texto = salida + b"\x00" * TAM_TAG
    return xor(H(la, lb, gid), texto)

def descifrar_fila(fila, la, lb, gid):
    texto = xor(H(la, lb, gid), fila)
    if texto[TAM_ETIQUETA:] == b"\x00" * TAM_TAG:
        return texto[:TAM_ETIQUETA]     # abrio: tag correcto
    return None                          # basura

# ============================================================================
#  TRANSFERENCIA INCONSCIENTE (OT) -- basada en RSA (Even-Goldreich-Lempel)
# ============================================================================
def es_primo(n, k=20):
    if n < 2: return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        v = pow(a, d, n)
        if v in (1, n - 1): continue
        for _ in range(r - 1):
            v = v * v % n
            if v == n - 1: break
        else:
            return False
    return True

def primo(bits):
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if es_primo(p):
            return p

class RSA_OT_Emisor:
    """Alicia: tiene los dos mensajes, no sabe cual pide Bob."""
    def __init__(self, bits=512):
        p, q = primo(bits // 2), primo(bits // 2)
        self.N = p * q
        phi = (p - 1) * (q - 1)
        self.e = 65537
        self.d = pow(self.e, -1, phi)

    def enviar_par(self, sock, m0: bytes, m1: bytes):
        x0 = secrets.randbelow(self.N)
        x1 = secrets.randbelow(self.N)
        enviar_int(sock, x0)
        enviar_int(sock, x1)
        v = recibir_int(sock)
        k0 = pow((v - x0) % self.N, self.d, self.N)
        k1 = pow((v - x1) % self.N, self.d, self.N)
        enviar(sock, xor(m0, H(b"ot", k0.to_bytes(256, "big"))[:len(m0)]))
        enviar(sock, xor(m1, H(b"ot", k1.to_bytes(256, "big"))[:len(m1)]))

class RSA_OT_Receptor:
    """Bob: recibe solo el que eligio, sin revelar cual."""
    def __init__(self, N, e):
        self.N, self.e = N, e

    def recibir_uno(self, sock, bit: int) -> bytes:
        x0 = recibir_int(sock)
        x1 = recibir_int(sock)
        k = secrets.randbelow(self.N)
        xc = x0 if bit == 0 else x1
        v = (xc + pow(k, self.e, self.N)) % self.N
        enviar_int(sock, v)
        c0 = recibir(sock)
        c1 = recibir(sock)
        cifrado = c0 if bit == 0 else c1
        return xor(cifrado, H(b"ot", k.to_bytes(256, "big"))[:len(cifrado)])

# ============================================================================
#  ALICIA  (garbler)
# ============================================================================
def alicia(x, n_bits, puerto, host_bind="0.0.0.0"):
    titulo("ALICIA  (garbler: la que cifra el circuito)")
    log(f"  Mi fortuna secreta: {c(str(x), C.BOLD + C.VERDE)}"
        f"   (en binario: {format(x, '0%db' % n_bits)})")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host_bind, puerto))
    srv.listen(1)
    log(f"\n  Esperando a Bob en el puerto {puerto}...")
    sock, addr = srv.accept()
    log(c(f"  Bob se conecto desde {addr[0]}", C.VERDE))
    t0 = time.time()

    # ---- 1. Circuito -------------------------------------------------------
    ct = construir_comparador(n_bits)
    titulo("PASO 1  --  Construir el circuito booleano")
    log(f"  Funcion: x > y  con numeros de {n_bits} bits")
    log(f"  Cables:  {ct.n_cables}")
    log(f"  Puertas: {c(str(len(ct.puertas)), C.BOLD)}")
    tipos = {}
    for t, *_ in ct.puertas:
        tipos[t] = tipos.get(t, 0) + 1
    log("  Desglose: " + ", ".join(f"{k}={v}" for k, v in sorted(tipos.items())))
    log(c("\n  [Este circuito es PUBLICO: Bob tambien lo conoce]", C.DIM))
    pausa()

    # ---- 2. Etiquetas ------------------------------------------------------
    titulo("PASO 2  --  Generar dos etiquetas aleatorias por cada cable")
    etiquetas = {}
    for w in range(ct.n_cables):
        etiquetas[w] = (os.urandom(TAM_ETIQUETA), os.urandom(TAM_ETIQUETA))
    log(f"  Generadas {c(str(ct.n_cables * 2), C.BOLD)} etiquetas de "
        f"{TAM_ETIQUETA * 8} bits (con os.urandom, criptograficamente seguro)")
    log("\n  Ejemplo, las primeras entradas:")
    for i in range(min(3, n_bits)):
        w = ct.entradas_alicia[i]
        log(f"    cable x{i}:  0 -> {c(hx(etiquetas[w][0]), C.AZUL)}"
            f"    1 -> {c(hx(etiquetas[w][1]), C.MAG)}")
    log(c("\n  [Esta tabla NUNCA sale de mi computadora]", C.ROJO))
    pausa()

    # ---- 3. Cifrar las puertas --------------------------------------------
    titulo("PASO 3  --  Cifrar cada puerta y barajar sus filas")
    tablas = []
    for idx, (tipo, a, b, s) in enumerate(ct.puertas):
        gid = struct.pack(">I", idx)
        if tipo == "CONST":
            # valor publico: mando directamente la etiqueta correspondiente
            tablas.append([etiquetas[s][a]])
            continue
        filas = []
        if tipo == "NOT":
            for va in (0, 1):
                vs = TABLAS["NOT"](va, None)
                filas.append(cifrar_fila(etiquetas[a][va], b"", gid,
                                         etiquetas[s][vs]))
        else:
            for va in (0, 1):
                for vb in (0, 1):
                    vs = TABLAS[tipo](va, vb)
                    filas.append(cifrar_fila(etiquetas[a][va], etiquetas[b][vb],
                                             gid, etiquetas[s][vs]))
        secrets.SystemRandom().shuffle(filas)      # <-- BARAJAR
        tablas.append(filas)

    n_tablas = sum(1 for t in tablas if t and len(t) > 1)
    n_filas = sum(len(t) for t in tablas if t and len(t) > 1)
    log(f"  {n_tablas} puertas cifradas, {n_filas} filas en total")
    log(f"  Tamano: {n_filas * (TAM_ETIQUETA + TAM_TAG)} bytes")
    ej = next(i for i, t in enumerate(tablas) if t and len(t) == 4)
    log(f"\n  Ejemplo, la puerta #{ej} ({ct.puertas[ej][0]}) barajada:")
    for f in tablas[ej]:
        log(f"    {c(hx(f, 16), C.AMAR)}...")
    log(c("\n  [Las filas van barajadas: la posicion no dice nada]", C.DIM))
    pausa()

    # ---- 4. Enviar el circuito cifrado -------------------------------------
    titulo("PASO 4  --  Enviar el circuito cifrado a Bob")
    meta = struct.pack(">IIII", n_bits, ct.n_cables, len(ct.puertas), ct.salida)
    enviar(sock, meta)
    for (tipo, a, b, s), filas in zip(ct.puertas, tablas):
        enviar(sock, bytes([COD_TIPO[tipo]]))
        enviar(sock, struct.pack(">iii", a if a is not None else -1,
                                 b if b is not None else -1, s))
        enviar(sock, struct.pack(">I", len(filas) if filas else 0))
        for f in (filas or []):
            enviar(sock, f)
    log(f"  Enviadas {n_tablas} tablas cifradas")

    # ---- 5. Enviar MIS etiquetas -------------------------------------------
    titulo("PASO 5  --  Enviar las etiquetas de MIS bits")
    log("  Mando UNA sola etiqueta por cable: la de mi valor real.")
    for i in range(n_bits):
        bit = (x >> (n_bits - 1 - i)) & 1
        et = etiquetas[ct.entradas_alicia[i]][bit]
        enviar(sock, et)
        log(f"    x{i} = {bit}  ->  envio {c(hx(et), C.AZUL)}"
            f"   {c('(Bob no sabe si es 0 o 1)', C.DIM)}")
    pausa()

    # ---- 6. OT para las etiquetas de Bob -----------------------------------
    titulo("PASO 6  --  Transferencia inconsciente (OT) para los bits de Bob")
    log("  Genero un par de llaves RSA...")
    ot = RSA_OT_Emisor(bits=512)
    enviar_int(sock, ot.N)
    enviar_int(sock, ot.e)
    log(f"  N publico: {str(ot.N)[:40]}...")
    log(f"\n  Ejecuto {n_bits} OT (uno por cada bit de Bob):")
    for i in range(n_bits):
        w = ct.entradas_bob[i]
        ot.enviar_par(sock, etiquetas[w][0], etiquetas[w][1])
        log(f"    y{i}: ofreci las dos etiquetas   "
            f"{c('<- NO SE cual eligio', C.ROJO)}")
    pausa()

    # ---- 7. Tabla de traduccion --------------------------------------------
    titulo("PASO 7  --  Enviar la tabla de traduccion de la salida")
    enviar(sock, etiquetas[ct.salida][0])
    enviar(sock, etiquetas[ct.salida][1])
    log(f"    {c(hx(etiquetas[ct.salida][0]), C.AZUL)}  significa  0  (x NO es mayor)")
    log(f"    {c(hx(etiquetas[ct.salida][1]), C.MAG)}  significa  1  (x SI es mayor)")

    # ---- 8. Resultado -------------------------------------------------------
    resultado = recibir(sock)[0]
    dt = time.time() - t0

    titulo("RESULTADO")
    log(f"  Mi fortuna:  {c(str(x), C.VERDE)}")
    log(f"  Resultado:   x > y  es  "
        f"{c('VERDADERO' if resultado else 'FALSO', C.BOLD + C.VERDE)}")
    log()
    log(c("  Lo que NO se:", C.BOLD))
    log(c(f"    - Cuanto tiene Bob (solo se que es "
          f"{'menor' if resultado else 'mayor o igual'} que {x})", C.ROJO))
    log(c("    - Que fila abrio en cada puerta", C.ROJO))
    log(c("    - Que etiquetas pidio en el OT", C.ROJO))
    log()
    log(f"  Bytes enviados: {c(f'{BYTES_ENVIADOS:,}', C.BOLD)}")
    log(f"  Tiempo total:   {dt:.3f} s")

    if not VERBOSE:
        print(f"x > y = {bool(resultado)}")

    sock.close(); srv.close()


# ============================================================================
#  BOB  (evaluator)
# ============================================================================
def bob(y, n_bits, host, puerto):
    titulo("BOB  (evaluator: el que evalua a ciegas)")
    log(f"  Mi fortuna secreta: {c(str(y), C.BOLD + C.VERDE)}"
        f"   (en binario: {format(y, '0%db' % n_bits)})")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for intento in range(40):
        try:
            sock.connect((host, puerto)); break
        except ConnectionRefusedError:
            if intento == 0:
                log(f"\n  Esperando a que Alicia abra el puerto {puerto}...")
            time.sleep(0.25)
    else:
        print("No pude conectar con Alicia."); sys.exit(1)
    log(c(f"  Conectado con Alicia en {host}:{puerto}", C.VERDE))
    t0 = time.time()

    # ---- Recibir circuito --------------------------------------------------
    titulo("PASO 1  --  Recibir el circuito cifrado")
    nb, n_cables, n_puertas, cable_salida = struct.unpack(">IIII", recibir(sock))
    puertas, tablas = [], []
    for _ in range(n_puertas):
        tipo = TIPO_COD[recibir(sock)[0]]
        a, b, s = struct.unpack(">iii", recibir(sock))
        nf = struct.unpack(">I", recibir(sock))[0]
        filas = [recibir(sock) for _ in range(nf)]
        puertas.append((tipo, a if a >= 0 else None,
                        b if b >= 0 else None, s))
        tablas.append(filas)
    log(f"  Recibidas {sum(1 for t in tablas if t)} tablas cifradas")
    log(f"  Circuito de {n_puertas} puertas y {n_cables} cables")
    log(c("\n  Para mi todo esto son cadenas aleatorias. Ejemplo:", C.DIM))
    ej = next(i for i, t in enumerate(tablas) if len(t) == 4)
    for f in tablas[ej]:
        log(f"    {c(hx(f, 16), C.AMAR)}...")
    log(c("  No se que puerta es, ni que fila corresponde a que.", C.DIM))
    pausa()

    # ---- Etiquetas de Alicia ------------------------------------------------
    titulo("PASO 2  --  Recibir las etiquetas de Alicia")
    valores = {}                     # cable -> etiqueta que tengo
    entradas_alicia = list(range(nb))
    entradas_bob = list(range(nb, 2 * nb))
    for i in range(nb):
        et = recibir(sock)
        valores[entradas_alicia[i]] = et
        log(f"    x{i}: {c(hx(et), C.AZUL)}   "
            f"{c('<- ??? no se si representa 0 o 1', C.ROJO)}")
    pausa()

    # ---- OT ------------------------------------------------------------------
    titulo("PASO 3  --  Conseguir MIS etiquetas por transferencia inconsciente")
    N = recibir_int(sock); e = recibir_int(sock)
    ot = RSA_OT_Receptor(N, e)
    log(f"  Recibi la llave publica RSA de Alicia")
    log(f"\n  Ejecuto {nb} OT:")
    for i in range(nb):
        bit = (y >> (nb - 1 - i)) & 1
        et = ot.recibir_uno(sock, bit)
        valores[entradas_bob[i]] = et
        log(f"    y{i} = {bit}  ->  recibi {c(hx(et), C.MAG)}   "
            f"{c('(Alicia NO sabe cual pedi)', C.VERDE)}")
    pausa()

    # ---- Evaluar --------------------------------------------------------------
    titulo("PASO 4  --  Evaluar el circuito A CIEGAS, puerta por puerta")
    mostradas = 0
    for idx, ((tipo, a, b, s), filas) in enumerate(zip(puertas, tablas)):
        gid = struct.pack(">I", idx)
        if tipo == "CONST":
            # valor fijo: Alicia lo cifro como una puerta trivial; el
            # evaluador recibe la etiqueta correspondiente en la tabla
            valores[s] = filas[0] if filas else b"\x00" * TAM_ETIQUETA
            continue
        la = valores[a]
        lb = valores[b] if b is not None else b""
        abierta = None
        intentos = 0
        for f in filas:
            intentos += 1
            r = descifrar_fila(f, la, lb, gid)
            if r is not None:
                abierta = r
                break
        if abierta is None:
            print(c(f"\n  ERROR: no pude abrir la puerta {idx} ({tipo})", C.ROJO))
            sys.exit(1)
        valores[s] = abierta
        if mostradas < 4 and len(filas) == 4:
            log(f"\n  Puerta #{idx} ({tipo}):")
            log(f"    tengo:  {c(hx(la), C.AZUL)} y {c(hx(lb), C.MAG)}")
            log(f"    probe {intentos} caja(s), abrio la #{intentos}")
            log(f"    salgo con: {c(hx(abierta), C.AMAR)}   "
                f"{c('<- no se que significa', C.ROJO)}")
            mostradas += 1
    log(f"\n  {c('Evalue las ' + str(n_puertas) + ' puertas sin entender nada.', C.BOLD)}")
    pausa()

    # ---- Traducir --------------------------------------------------------------
    titulo("PASO 5  --  Traducir la etiqueta final")
    et0 = recibir(sock); et1 = recibir(sock)
    final = valores[cable_salida]
    log(f"  Mi etiqueta final:  {c(hx(final), C.AMAR)}")
    log(f"\n  Tabla de traduccion que me mando Alicia:")
    log(f"    {c(hx(et0), C.AZUL)}  ->  0")
    log(f"    {c(hx(et1), C.MAG)}  ->  1")
    if final == et1:
        res = 1
    elif final == et0:
        res = 0
    else:
        print(c("  ERROR: la etiqueta final no coincide", C.ROJO)); sys.exit(1)
    enviar(sock, bytes([res]))

    dt = time.time() - t0
    titulo("RESULTADO")
    log(f"  Mi fortuna:  {c(str(y), C.VERDE)}")
    log(f"  Resultado:   x > y  es  "
        f"{c('VERDADERO' if res else 'FALSO', C.BOLD + C.VERDE)}")
    log()
    log(c("  Lo que NO se:", C.BOLD))
    log(c(f"    - Cuanto tiene Alicia (solo se que es "
          f"{'mayor' if res else 'menor o igual'} que {y})", C.ROJO))
    log(c("    - Que significaban las etiquetas que recibi", C.ROJO))
    log(c("    - Los valores intermedios del circuito", C.ROJO))
    log()
    log(f"  Tiempo total: {dt:.3f} s")

    if not VERBOSE:
        print(f"x > y = {bool(res)}")
    sock.close()



# ============================================================================
#  VISOR DE TRAFICO (para no depender de xxd)
# ============================================================================
def ver_trafico(ruta, lineas=24):
    d = open(ruta, "rb").read()
    print()
    print(c("=" * 74, C.CYAN))
    print(c(f"  TRAFICO CAPTURADO: {ruta}", C.BOLD + C.CYAN))
    print(c("=" * 74, C.CYAN))
    print()
    for i in range(0, min(len(d), lineas * 16), 16):
        b = d[i:i + 16]
        hexa = " ".join(f"{x:02x}" for x in b).ljust(48)
        txt = "".join(chr(x) if 32 <= x < 127 else "." for x in b)
        print(f"  {c(f'{i:08x}', C.DIM)}  {c(hexa, C.AMAR)} |{txt}|")
    if len(d) > lineas * 16:
        print(c(f"  ... ({len(d) - lineas*16:,} bytes mas)", C.DIM))
    print()
    print(f"  Total interceptado: {c(f'{len(d):,} bytes', C.BOLD)}")
    print()
    print(c("  Esto es TODO lo que viajo entre las dos partes.", C.BOLD))
    print(c("  Un espia con acceso total al cable no puede sacar", C.ROJO))
    print(c("  ni la fortuna de Alicia ni la de Bob.", C.ROJO))
    print()


# ============================================================================
#  MAIN
# ============================================================================
def main():
    global VERBOSE, PASO_A_PASO, ARCHIVO_TRAFICO

    p = argparse.ArgumentParser(
        description="Problema de los millonarios con garbled circuits",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Ejemplo:\n"
               "  Terminal 1:  python3 millonarios.py alicia 15\n"
               "  Terminal 2:  python3 millonarios.py bob 10\n")
    p.add_argument("papel", choices=["alicia", "bob", "ver-trafico"],
                   help="alicia = cifra el circuito, bob = lo evalua")
    p.add_argument("valor", nargs="?", default=None,
                   help="tu fortuna secreta (o el archivo si usas ver-trafico)")
    p.add_argument("--bits", type=int, default=4, help="tamano en bits (default 4)")
    p.add_argument("--puerto", type=int, default=9999)
    p.add_argument("--host", default="127.0.0.1", help="solo para bob")
    p.add_argument("--paso-a-paso", action="store_true",
                   help="pausa en cada etapa")
    p.add_argument("--silencioso", action="store_true",
                   help="solo imprime el resultado")
    p.add_argument("--guardar-trafico", metavar="ARCHIVO",
                   help="guarda todo lo enviado (para mostrar que es ruido)")
    args = p.parse_args()

    VERBOSE = not args.silencioso
    PASO_A_PASO = args.paso_a_paso

    if args.papel == "ver-trafico":
        if not args.valor:
            print("Uso: python3 millonarios.py ver-trafico ARCHIVO"); sys.exit(1)
        ver_trafico(args.valor); return

    try:
        args.valor = int(args.valor)
    except (TypeError, ValueError):
        print("Falta tu fortuna. Ej: python3 millonarios.py alicia 15"); sys.exit(1)

    maximo = 2 ** args.bits - 1
    if not 0 <= args.valor <= maximo:
        print(f"El valor debe estar entre 0 y {maximo} con --bits {args.bits}")
        sys.exit(1)

    if args.guardar_trafico:
        ARCHIVO_TRAFICO = open(args.guardar_trafico, "wb")

    try:
        if args.papel == "alicia":
            alicia(args.valor, args.bits, args.puerto)
        else:
            bob(args.valor, args.bits, args.host, args.puerto)
    except KeyboardInterrupt:
        print("\nInterrumpido.")
    finally:
        if ARCHIVO_TRAFICO:
            ARCHIVO_TRAFICO.close()


if __name__ == "__main__":
    main()
