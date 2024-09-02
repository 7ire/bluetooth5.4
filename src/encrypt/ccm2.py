import struct
from Crypto.Cipher import AES

# Funzione per XOR di due blocchi di byte
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Funzione per incrementare un contatore utilizzato nel CTR
def increment_counter(counter):
    counter_value = int.from_bytes(counter, byteorder='big')
    counter_value += 1
    return counter_value.to_bytes(len(counter), byteorder='big')

# Implementazione di CBC-MAC senza padding
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
        if len(block) < block_size:
            block += b'\x00' * (block_size - len(block))  # Padding per l'ultimo blocco
        counter = nonce + i.to_bytes(4, byteorder='big').rjust(16 - len(nonce), b'\x00')
        keystream_block = cipher.encrypt(counter)
        encrypted_block = xor_bytes(block, keystream_block)
        encrypted += encrypted_block[:len(plaintext[i:i + block_size])]  # Rimuove il padding alla fine
    return encrypted

# Funzione per cifrare i dati utilizzando CCM
def encrypt_ccm(key, plaintext, associated_data, nonce):
    block_size = AES.block_size
    q = 15 - len(nonce)
    flags = (64 * (len(associated_data) > 0)) + ((q - 1) << 3) + 1
    b0 = struct.pack('B', flags) + nonce + struct.pack('>Q', len(plaintext))[-q:]

    auth_data_len = struct.pack('>H', len(associated_data)) if len(associated_data) > 0 else b''
    mac_input = b0 + associated_data + plaintext
    tag = cbc_mac(key, mac_input)[:block_size // 2]

    ciphertext = ctr_encrypt(key, nonce, plaintext)
    encrypted_tag = ctr_encrypt(key, nonce, tag)

    return ciphertext, encrypted_tag

# Funzione per decifrare i dati utilizzando CCM
def decrypt_ccm(key, ciphertext, associated_data, nonce, tag):
    block_size = AES.block_size

    plaintext = ctr_encrypt(key, nonce, ciphertext)
    computed_tag = ctr_encrypt(key, nonce, tag)

    q = 15 - len(nonce)
    flags = (64 * (len(associated_data) > 0)) + ((q - 1) << 3) + 1
    b0 = struct.pack('B', flags) + nonce + struct.pack('>Q', len(plaintext))[-q:]
    
    auth_data_len = struct.pack('>H', len(associated_data)) if len(associated_data) > 0 else b''
    mac_input = b0 + associated_data + plaintext
    expected_tag = cbc_mac(key, mac_input)[:block_size // 2]

    if computed_tag != expected_tag:
        raise ValueError("Invalid tag! Message authentication failed.")
    
    return plaintext

# Esempio di utilizzo
def main():
    key = b'This is a key123'  # Chiave AES-128
    plaintext = b'Testo segreto da cifrare'
    associated_data = b'Dati associati'
    nonce = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a'  # 11-byte nonce

    # Cifratura
    ciphertext, tag = encrypt_ccm(key, plaintext, associated_data, nonce)
    print("Ciphertext:", ciphertext)
    print("Tag:", tag)

    # Decifratura
    decrypted_text = decrypt_ccm(key, ciphertext, associated_data, nonce, tag)
    print("Decrypted text:", decrypted_text)

if __name__ == "__main__":
    main()
