from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Funzione per cifrare i dati utilizzando CCM
def encrypt_ccm(key, plaintext, associated_data):
    nonce = get_random_bytes(11)  # Lunghezza del nonce per CCM è tipicamente di 11 byte
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
    cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag, nonce

# Funzione per decifrare i dati utilizzando CCM
def decrypt_ccm(key, ciphertext, associated_data, nonce, tag):
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
    cipher.update(associated_data)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# Esempio di utilizzo
def main():
    key = get_random_bytes(16)  # Chiave AES-128
    plaintext = b'Testo segreto da cifrare'
    associated_data = b'Dati associati'

    # Cifratura
    ciphertext, tag, nonce = encrypt_ccm(key, plaintext, associated_data)
    print("Ciphertext:", ciphertext)
    print("Tag:", tag)
    print("Nonce:", nonce)

    # Decifratura
    decrypted_text = decrypt_ccm(key, ciphertext, associated_data, nonce, tag)
    print("Decrypted text:", decrypted_text)

if __name__ == "__main__":
    main()
