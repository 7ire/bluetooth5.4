from Crypto.Cipher import AES

def e(key, plaintext):
    """
    Funzione crittografica e che utilizza AES-128 ECB.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def s1(k, r1, r2):
    """
    Implementazione della funzione s1 per la generazione della STK.
    
    k: 128-bit chiave (16 bytes)
    r1: 128-bit valore casuale (16 bytes)
    r2: 128-bit valore casuale (16 bytes)
    """
    
    # Estrazione degli ultimi 64 bit di r1 e r2 per creare r1' e r2'
    r1_prime = r1[8:]  # Ottieni gli ultimi 64 bit (8 bytes) di r1
    r2_prime = r2[8:]  # Ottieni gli ultimi 64 bit (8 bytes) di r2
    
    # Concatenazione di r1' e r2' per formare r'
    r_prime = r1_prime + r2_prime
    print(f'r\': {r_prime.hex()}')
    
    # Generazione della STK utilizzando la funzione di sicurezza e
    stk = e(k, r_prime)
    
    return stk

# Esempio di utilizzo
k = bytes.fromhex('00000000000000000000000000000000')
r1 = bytes.fromhex('000F0E0D0C0B0A091122334455667788')
r2 = bytes.fromhex('010203040506070899AABBCCDDEEFF00')

stk = s1(k, r1, r2)
print(f'STK: {stk.hex()}')
