from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes

# Funzione AES manuale per AES-CTR e CBC
def aes_encrypt_block(key, block):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(block)

# AES-CTR per la crittografia del messaggio
def aes_ctr_encrypt(key, nonce, plaintext):
    counter_value = int.from_bytes(nonce, byteorder='big')  # Inizializzazione del contatore
    ciphertext = bytearray()

    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        counter_block = (counter_value).to_bytes(16, byteorder='big')
        keystream_block = aes_encrypt_block(key, counter_block)
        cipher_block = bytes([b ^ k for b, k in zip(block, keystream_block)])
        ciphertext.extend(cipher_block)
        counter_value += 1

    return bytes(ciphertext)

# AES-CBC-MAC per l'integrità
def aes_cbc_mac(key, auth_data, plaintext):
    block_size = 16
    mac = bytearray([0] * block_size)  # Blocco di inizializzazione zero

    def xor_blocks(b1, b2):
        return bytes([x ^ y for x, y in zip(b1, b2)])

    def pad(data):
        # Padding per gli ultimi blocchi
        pad_len = block_size - len(data) % block_size
        return data + bytes([pad_len] * pad_len)

    # MAC per l'auth_data
    for i in range(0, len(auth_data), block_size):
        block = auth_data[i:i + block_size]
        mac = aes_encrypt_block(key, xor_blocks(mac, block))

    # MAC per il plaintext
    padded_plaintext = pad(plaintext)
    for i in range(0, len(padded_plaintext), block_size):
        block = padded_plaintext[i:i + block_size]
        mac = aes_encrypt_block(key, xor_blocks(mac, block))

    return mac

# Implementazione AES-CCM
def aes_ccm_encrypt(key, nonce, plaintext, auth_data):
    # Generare il ciphertext usando AES-CTR
    ciphertext = aes_ctr_encrypt(key, nonce, plaintext)

    # Calcolare il CBC-MAC usando il plaintext e auth_data
    mac = aes_cbc_mac(key, auth_data, plaintext)

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
