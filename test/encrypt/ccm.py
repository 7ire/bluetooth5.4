from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes

# Funzione AES manuale per AES-CTR e CBC
def aes_encrypt_block(key, block):
    assert len(block) == 16, "Il blocco deve essere di 16 byte"  # Verifica che il blocco sia di 16 byte
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(block)

# AES-CTR per la crittografia del messaggio
def aes_ctr_encrypt(key, nonce, plaintext):
    counter_value = int.from_bytes(nonce + b'\x00\x00\x00\x01', byteorder='big')  # Inizializzazione del contatore (CTR con L=2)
    ciphertext = bytearray()

    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        counter_block = (counter_value).to_bytes(16, byteorder='big')
        keystream_block = aes_encrypt_block(key, counter_block)
        cipher_block = bytes([b ^ k for b, k in zip(block, keystream_block)])
        ciphertext.extend(cipher_block)
        counter_value += 1

    return bytes(ciphertext)

# Funzione di padding per AES-CBC-MAC
def pad(data):
    block_size = 16
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len] * pad_len)

# AES-CBC-MAC per l'integrità
def aes_cbc_mac(key, nonce, auth_data, plaintext):
    block_size = 16
    mac = bytearray([0] * block_size)  # Blocco di inizializzazione zero

    def xor_blocks(b1, b2):
        return bytes([x ^ y for x, y in zip(b1, b2)])

    # Creazione del B0 secondo lo schema CCM
    flags = (len(auth_data) > 0) << 6 | ((15 - len(nonce)) - 1)  # Flag con bit per AAD e la lunghezza di L
    b0 = bytes([flags]) + nonce + len(plaintext).to_bytes(2, byteorder='big')  # B0 deve essere di 16 byte
    mac = aes_encrypt_block(key, xor_blocks(mac, b0))

    # MAC per l'auth_data (AAD)
    if len(auth_data) > 0:
        aad_len = len(auth_data).to_bytes(2, byteorder='big')  # Lunghezza dell'AAD
        block = aad_len + auth_data[:14]  # Deve essere di 16 byte
        mac = aes_encrypt_block(key, xor_blocks(mac, block))

    # Padding del plaintext
    padded_plaintext = pad(plaintext)

    # MAC per il plaintext (con padding)
    for i in range(0, len(padded_plaintext), block_size):
        block = padded_plaintext[i:i + block_size]
        mac = aes_encrypt_block(key, xor_blocks(mac, block))

    return mac[:16]  # Restituisci solo i primi 16 byte del MAC

# Implementazione AES-CCM
def aes_ccm_encrypt(key, nonce, plaintext, auth_data):
    # Calcolare il CBC-MAC usando il plaintext e auth_data
    mac = aes_cbc_mac(key, nonce, auth_data, plaintext)

    # Generare il ciphertext usando AES-CTR
    ciphertext = aes_ctr_encrypt(key, nonce, plaintext)

    # Aggiungi il MAC al ciphertext
    return ciphertext, mac

# Funzione per verificare il risultato con pycryptodome
def verify_with_pycryptodome(key, nonce, plaintext, auth_data):
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=16)
    cipher.update(auth_data)
    ciphertext = cipher.encrypt(plaintext)
    mac = cipher.digest()
    return ciphertext, mac

# Testare la funzione AES-CCM
key = get_random_bytes(16)
nonce = get_random_bytes(12)  # CCM usa tipicamente nonce da 12 byte
plaintext = b"Questo e' un messaggio segreto."
auth_data = b"Autenticazione"

# Risultato manuale
ciphertext, mac = aes_ccm_encrypt(key, nonce, plaintext, auth_data)
print("Ciphertext manuale:", ciphertext.hex())
print("MAC manuale:", mac.hex())

# Risultato con pycryptodome
ciphertext_ref, mac_ref = verify_with_pycryptodome(key, nonce, plaintext, auth_data)
print("Ciphertext pycryptodome:", ciphertext_ref.hex())
print("MAC pycryptodome:", mac_ref.hex())

# Verifica
assert ciphertext == ciphertext_ref, "Il ciphertext non coincide!"
assert mac == mac_ref, "Il MAC non coincide!"
