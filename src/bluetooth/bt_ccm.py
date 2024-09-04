from Crypto.Cipher import AES
from Crypto.Util import Counter

# AES-CCM Encrypt con chiave
def aes_ccm_encrypt(key, nonce, plaintext, auth_data):
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=16)
    cipher.update(auth_data)
    ciphertext = cipher.encrypt(plaintext)
    mac = cipher.digest()
    return ciphertext, mac

# AES-CCM Decrypt con chiave
def aes_ccm_decrypt_with_key(key: bytes, nonce: bytes, ciphertext: bytes, auth_data: bytes, mac: bytes):
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=16)
    cipher.update(auth_data)
    plaintext = cipher.decrypt_and_verify(ciphertext, mac)
    return plaintext