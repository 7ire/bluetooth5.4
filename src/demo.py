from bluetooth.bt_device import BTDevice
from bluetooth.bt_crypto_toolbox import *
import os

# Funzione di utilità per convertire un indirizzo Bluetooth da stringa a bytes
def bt_address_to_bytes(bt_address: str) -> bytes:
    # Rimuove i due punti e converte in bytes
    return bytes.fromhex(bt_address.replace(':', ''))

mode = "DEBUG"

OOB = 0
AuthReq = 112 # 01110000

# Creo 2 oggetti Bluetooth - Alice e Bob
alice = BTDevice()  # Creazione di un'istanza di BTDevice per Alice
bob = BTDevice()    # Creazione di un'istanza di BTDevice per Bob

# 1. Scambio delle chiavi pubbliche e calcolo della chiave Diffie-Hellman
PKa = alice.pK
PKb = bob.pK

# Alice calcola la chiave Diffie-Hellman utilizzando la chiave pubblica di Bob
alice.computeDHKey(PKb)

# Bob calcola la chiave Diffie-Hellman utilizzando la chiave pubblica di Alice
bob.computeDHKey(PKa)

if "DEBUG" == mode: print(f"Alice_DHKey =\t {alice.dhkey.hex()}\nBob_DHKey = \t {bob.dhkey.hex()}")
assert alice.dhkey == bob.dhkey, "Alice e Bob non condividono la stessa chiave Diffie-Hellman!"

# 2. Selezionare per Alice e Bob un nonce a 128bits
bob.nonce = os.urandom(16)
alice.nonce = os.urandom(16)

# 3. Calcolare il commit di Bob (Challenge/Response)
Z = bytes([0x00])  # Z è 0 per Numeric Comparison
# Convertire pK_x da intero a bytes (32 byte, big endian)
bob_pK_x_bytes = bob.pK_x.to_bytes(32, byteorder='big')
alice_pK_x_bytes = alice.pK_x.to_bytes(32, byteorder='big')

Cb = f4(bob_pK_x_bytes, alice_pK_x_bytes, bob.nonce, Z)

# 5. Condividere il nonce di Alice
Na = alice.nonce

# 6. Condividere il nonce di Bob e controllare il commit di Bob
Nb = bob.nonce

Cb1 = f4(bob_pK_x_bytes, alice_pK_x_bytes, Nb, Z)

if "DEBUG" == mode: print(f"Bob_Cb =\t {Cb.hex()}\nAlice_Ca =\t {Cb1.hex()}")
assert Cb1 == Cb, "Alice e Bob non hanno lo stevvo commit!"

# 7. Generare il valore a 6 cifre da validare ad Alice e a Bob
Va = g2(alice_pK_x_bytes, bob_pK_x_bytes, alice.nonce, Nb)  # Valore a 6 cifre di Alice
Vb = g2(alice_pK_x_bytes, bob_pK_x_bytes, Na, bob.nonce)    # Valore a 6 cifre di Bob

if "DEBUG" == mode: print(f"Alice_Va =\t {Va}\nBob_Vb =\t {Vb}")
else: print(f"Alice =\t {Va}\nBob =\t {Vb}")

assert Va == Vb, "Alice e Bob hanno validatori diversi, possimile attaco MitM da parte di Eve!"

# 8. Scambio di informazioni per il calcolo di LTK
IOcapA = bytes([AuthReq, OOB, alice.IOCap])  # Capability di Alice
IOcapB = bytes([AuthReq, OOB, bob.IOCap])    # Capability di Bob
# Converti gli indirizzi Bluetooth di Alice e Bob in bytes
A = bt_address_to_bytes(alice.address)  # Indirizzo di Alice
B = bt_address_to_bytes(bob.address)    # Indirizzo di Bob

# 9. Generare la LTK
MacKey_a, LTK_a = f5(alice.dhkey, alice.nonce, Nb, bt_address_to_bytes(alice.address), B) 
MacKey_b, LTK_b = f5(bob.dhkey, Na, bob.nonce, A, bt_address_to_bytes(bob.address))

if "DEBUG" == mode: print(f"Alice:\n\t - LTK = {LTK_a.hex()}\n\t - MAC = {MacKey_a.hex()}")
if "DEBUG" == mode: print(f"Bob:\n\t - LTK = {LTK_b.hex()}\n\t - MAC = {MacKey_b.hex()}")

# 10. Calcolare le challenges per verificare LTK
R = bytes(16)  # R è 0 per Numeric Comparison
EA = f6(MacKey_a, alice.nonce, Nb, R, IOcapA, bt_address_to_bytes(alice.address), B)
EB = f6(MacKey_b, bob.nonce, Na, R, IOcapB, bt_address_to_bytes(bob.address), A)

# 11. Controllo incrociato dei valori (simulato)
assert f6(MacKey_b, Na, bob.nonce, R, IOcapA, A, bt_address_to_bytes(bob.address)) == EA, "La challege ricevuta da Alice non coindice con quella calcolata da Bob!"
assert f6(MacKey_a, Nb, alice.nonce, R, IOcapB, B, bt_address_to_bytes(alice.address)) == EB, "La challege ricevuta da Bob non coindice con quella calcolata da Alice!"

print(f"Alice e Bob condividono la stessa LTK = {LTK_a}")