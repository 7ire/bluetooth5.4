from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

def e(key, plaintext):
    """
    Funzione crittografica e che utilizza AES-128 ECB.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def c1(k, r, pres, preq, iat, rat, ia, ra):
    """
    Implementazione della funzione c1 per la generazione del valore di conferma.
    """
    
    # Creazione di iat' e rat'
    iat_prime = (iat & 0x01)
    rat_prime = (rat & 0x01)
    
    # Costruzione di p1
    p1 = pres + preq + bytes([rat_prime]) + bytes([iat_prime])
    print(f'p1: {p1.hex()}')
    
    # XOR tra r e p1
    p1_xor_r = strxor(r, p1)
    print(f'p1 XOR r: {p1_xor_r.hex()}')
    
    # Prima funzione e
    e1 = e(k, p1_xor_r)
    print(f'e1: {e1.hex()}')
    
    # Costruzione di p2
    padding = b'\x00' * 4
    p2 = padding + ia + ra
    print(f'p2: {p2.hex()}')
    
    # XOR tra e1 e p2
    e1_xor_p2 = strxor(e1, p2)
    print(f'e1 XOR p2: {e1_xor_p2.hex()}')
    
    # Seconda funzione e
    confirm_value = e(k, e1_xor_p2)
    print(f'Confirm value: {confirm_value.hex()}')
    
    return confirm_value

# Esempio di utilizzo
k = bytes.fromhex('00000000000000000000000000000000')
r = bytes.fromhex('5783D52156AD6F0E6388274EC6702EE0')
pres = bytes.fromhex('05000800000302')
preq = bytes.fromhex('07071000000101')
iat = 0x01
rat = 0x00
ia = bytes.fromhex('A1A2A3A4A5A6')
ra = bytes.fromhex('B1B2B3B4B5B6')

result = c1(k, r, pres, preq, iat, rat, ia, ra)
print(f'Result: {result.hex()}')
