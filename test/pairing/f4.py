from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def f4(U: bytes, V: bytes, X: bytes, Z: bytes) -> bytes:
    # Verifica che U e V siano di 256 bit (32 byte), X di 128 bit (16 byte) e Z di 8 bit (1 byte)
    assert len(U) == 32, "U deve essere di 256 bit (32 byte)"
    assert len(V) == 32, "V deve essere di 256 bit (32 byte)"
    assert len(X) == 16, "X deve essere di 128 bit (16 byte)"
    assert len(Z) == 1, "Z deve essere di 8 bit (1 byte)"
    
    # Concatenazione di U, V e Z
    m = U + V + Z
    
    # Creazione dell'oggetto CMAC con la chiave X e AES come cifratura
    cobj = CMAC.new(X, ciphermod=AES)
    
    # Calcolo della MAC usando il messaggio concatenato
    cobj.update(m)
    
    # Ritorna il valore calcolato (128 bit)
    return cobj.digest()

# Esempio di utilizzo
U = bytes.fromhex('AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899')
V = bytes.fromhex('11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF')
X = bytes.fromhex('00112233445566778899AABBCCDDEEFF')
Z = bytes([0x00])  # Z è 0 per Numeric Comparison e OOB

# Calcola il valore di conferma
confirm_value = f4(U, V, X, Z)
print("Valore di conferma:", confirm_value.hex())
