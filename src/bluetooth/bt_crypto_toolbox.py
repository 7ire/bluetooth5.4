from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def f4(U: bytes, V: bytes, X: bytes, Z: bytes) -> bytes:
    # Verifica i requisiti di sicurezza
    assert len(U) == 32, "U deve essere di 256 bit (32 byte)"    # U is 256bits
    assert len(V) == 32, "V deve essere di 256 bit (32 byte)"    # V is 256bits
    assert len(X) == 16, "X deve essere di 128 bit (16 byte)"    # X is 128bits
    assert len(Z) == 1, "Z deve essere di 8 bit (1 byte)"        # Z is 8bits

    # Concatenazione di U, V e Z per formare il messaggio m
    m = U + V + Z

    # Creazione dell'oggetto CMAC con la chiave X e AES come cifratura
    cobj = CMAC.new(X, ciphermod=AES)

    # Calcolo della MAC usando il messaggio m
    cobj.update(m)

    # Ritorna il valore calcolato (128 bit)
    return cobj.digest()

def f5(W: bytes, N1: bytes, N2: bytes, A1: bytes, A2: bytes) -> tuple:
    # Verifica i requisiti di sicurezza
    assert len(W) == 32, "W deve essere di 256 bit (32 byte)"     # W is 256 bits
    assert len(N1) == 16, "N1 deve essere di 128 bit (16 byte)"   # N1 is 128 bits
    assert len(N2) == 16, "N2 deve essere di 128 bit (16 byte)"   # N2 is 128 bits
    assert len(A1) == 7, "A1 deve essere di 56 bit (7 byte)"      # A1 is 56 bits
    assert len(A2) == 7, "A2 deve essere di 56 bit (7 byte)"      # A2 is 56 bits

    # SALT value
    SALT = bytes.fromhex('6C888391AAF5A53860370BDB5A6083BE')

    # Key derivation usando SALT
    t_cmac = CMAC.new(SALT, ciphermod=AES)
    t_cmac.update(W)
    T = t_cmac.digest()  # T e' la derived key (128 bits)

    # KeyID "btle" in ASCII
    keyID = bytes.fromhex('62746C65')

    # Length (256 bits, 2 bytes)
    length = bytes.fromhex('0100')

    # Prepare the input message for Counter = 0 and Counter = 1
    def generate_m(counter: int):
        return bytes([counter]) + keyID + N1 + N2 + A1 + A2 + length

    # Generate MacKey (Counter = 0)
    cobj_mac_key = CMAC.new(T, ciphermod=AES)
    cobj_mac_key.update(generate_m(0))
    MacKey = cobj_mac_key.digest()  # 128 bits

    # Generate LTK (Counter = 1)
    cobj_ltk = CMAC.new(T, ciphermod=AES)
    cobj_ltk.update(generate_m(1))
    LTK = cobj_ltk.digest()  # 128 bits

    return MacKey, LTK

def f6(W: bytes, N1: bytes, N2: bytes, R: bytes, IOcap: bytes, A1: bytes, A2: bytes) -> bytes:
    # Verifica della lunghezza degli input
    assert len(W) == 16, "W deve essere di 128 bit (16 byte)"
    assert len(N1) == 16, "N1 deve essere di 128 bit (16 byte)"
    assert len(N2) == 16, "N2 deve essere di 128 bit (16 byte)"
    assert len(R) == 16, "R deve essere di 128 bit (16 byte)"
    assert len(IOcap) == 3, "IOcap deve essere di 24 bit (3 byte)"
    assert len(A1) == 7, "A1 deve essere di 56 bit (7 byte)"
    assert len(A2) == 7, "A2 deve essere di 56 bit (7 byte)"
    
    # Concatenazione di N1, N2, R, IOcap, A1 e A2 per formare il messaggio m
    m = N1 + N2 + R + IOcap + A1 + A2
    
    # Creazione dell'oggetto CMAC con la chiave W e AES come cifratura
    cobj = CMAC.new(W, ciphermod=AES)
    
    # Calcolo della MAC usando il messaggio m
    cobj.update(m)
    
    # Ritorna il valore calcolato (128 bit)
    return cobj.digest()

def g2(U: bytes, V: bytes, X: bytes, Y: bytes) -> int:
    # Verifica i requisiti di sicurezza
    assert len(U) == 32, "U deve essere di 256 bit (32 byte)"    # U is 256bits
    assert len(V) == 32, "V deve essere di 256 bit (32 byte)"    # V is 256bits
    assert len(X) == 16, "X deve essere di 128 bit (16 byte)"    # X is 128bits
    assert len(Y) == 16, "Y deve essere di 128 bit (16 byte)"    # Y is 128bits

    # Concatenazione di U, V e Y per formare il messaggio m
    m = U + V + Y

    # Creazione dell'oggetto CMAC con la chiave X e AES come cifratura
    cobj = CMAC.new(X, ciphermod=AES)

    # Calcolo della MAC usando il messaggio m
    cobj.update(m)

    # Ottenere il valore CMAC (128 bit) e ridurlo modulo 2^32
    mac_result = cobj.digest()
    mac_value = int.from_bytes(mac_result, byteorder='big') % (2**32)

    # Ridurre il risultato alle 6 cifre decimali meno significative
    compare_value = mac_value % (10**6)

    # Restituisce il valore per il confronto
    return compare_value

def h6(W: bytes, keyID: str) -> bytes:
    # Verifica i requisiti di sicurezza
    assert len(W) == 16, "W deve essere di 128 bit (16 byte)"
    
    # Convertire keyID da stringa a bytes
    keyID_bytes = keyID.encode('utf-8')
    
    # Verifica che keyID, una volta convertito, sia di 32 bit (4 byte)
    assert len(keyID_bytes) == 4, "keyID deve essere una stringa di 4 caratteri"

    # Creazione dell'oggetto CMAC con la chiave W e AES come cifratura
    cobj = CMAC.new(W, ciphermod=AES)
    
    # Calcolo della MAC usando il keyID come messaggio
    cobj.update(keyID_bytes)
    
    # Ritorna il valore calcolato (128 bit)
    return cobj.digest()