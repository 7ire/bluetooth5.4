from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import struct

# Funzione per XOR di due blocchi di byte
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Funzione per incrementare un contatore utilizzato nel CTR
def increment_counter(counter):
    counter_value = int.from_bytes(counter, byteorder='big')
    counter_value += 1
    return counter_value.to_bytes(len(counter), byteorder='big')

# Implementazione di CBC-MAC
def cbc_mac(key, message):
    cipher = AES.new(key, AES.MODE_ECB)
    block_size = AES.block_size
    mac = bytes([0] * block_size)
    for i in range(0, len(message), block_size):
        block = message[i:i + block_size]
        if len(block) < block_size:
            block += b'\x00' * (block_size - len(block))  # Aggiunta di padding per l'ultimo blocco
        mac = cipher.encrypt(xor_bytes(mac, block))
    return mac

# Implementazione di CTR per la cifratura
def ctr_encrypt(key, nonce, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    block_size = AES.block_size
    encrypted = b''
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        counter = nonce + struct.pack('>I', i // block_size).rjust(16 - len(nonce), b'\x00')
        keystream_block = cipher.encrypt(counter)
        encrypted_block = xor_bytes(block, keystream_block)
        encrypted += encrypted_block
    return encrypted

# Funzione per cifrare i dati utilizzando CCM (implementazione manuale)
def encrypt_ccm_manual(key, plaintext, associated_data, nonce):
    block_size = AES.block_size
    q = 15 - len(nonce)
    flags = (64 * (len(associated_data) > 0)) + ((q - 1) << 3) + 1
    b0 = struct.pack('B', flags) + nonce + struct.pack('>Q', len(plaintext))[-q:]

    mac_input = b0 + associated_data + plaintext
    tag = cbc_mac(key, mac_input)[:block_size // 2]

    # Costruzione corretta del contatore per CTR
    initial_counter = nonce + b'\x00\x00\x00\x01'
    ciphertext = ctr_encrypt(key, initial_counter, plaintext)
    encrypted_tag = ctr_encrypt(key, initial_counter, tag)

    return ciphertext, encrypted_tag

# Funzione per cifrare i dati utilizzando CCM (implementazione PyCryptodome)
def encrypt_ccm_lib(key, plaintext, associated_data, nonce):
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
    cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag

# Esempio di utilizzo per confrontare le due implementazioni
def main():
    key = get_random_bytes(16)  # Chiave AES-128
    plaintext = b'Testo segreto da cifrare'
    associated_data = b'Dati associati'
    nonce = get_random_bytes(11)  # Nonce di 11 byte

    # Cifratura con implementazione manuale
    ciphertext_manual, tag_manual = encrypt_ccm_manual(key, plaintext, associated_data, nonce)
    print("Ciphertext (manual):", ciphertext_manual)
    print("Tag (manual):", tag_manual)

    # Cifratura con PyCryptodome
    ciphertext_lib, tag_lib = encrypt_ccm_lib(key, plaintext, associated_data, nonce)
    print("Ciphertext (lib):", ciphertext_lib)
    print("Tag (lib):", tag_lib)

    # Confronto dei risultati
    if ciphertext_manual == ciphertext_lib and tag_manual == tag_lib:
        print("Le due implementazioni producono lo stesso output.")
    else:
        print("Le due implementazioni producono output diversi.")

if __name__ == "__main__":
    main()
